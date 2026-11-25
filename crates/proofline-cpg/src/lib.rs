//! Code Property Graph (CPG) intermediate representation and language frontends.
//! Combines Abstract Syntax Trees (AST), Control Flow Graphs (CFG),
//! and Data Dependence Graphs (DDG) into a unified queryable graph.

mod ts_frontends;

use proofline_core::{ProoflineError, Result};
use proofline_intelligence::IngestionEngine;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use walkdir::WalkDir;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NodeId(pub u32);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CpgNodeKind {
    FunctionDef { name: String, return_type: String },
    Parameter { name: String, index: usize },
    VariableDecl { name: String, var_type: String },
    Assignment { target: String, value_expr: String },
    CallExpression { callee: String, arguments: Vec<String> },
    BranchCondition { condition_expr: String },
    ReturnStatement { expr: Option<String> },
    SecurityIngress { source_type: String, variable: String },
    SecuritySink { sink_type: String, target_variable: String },
    SanitizerGuard { checked_variable: String, guard_expr: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CpgEdgeKind {
    AstChild { order: usize },
    CfgNext,
    CfgBranchTrue,
    CfgBranchFalse,
    DataFlow { variable: String },
    CallEdge,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpgNode {
    pub id: NodeId,
    pub kind: CpgNodeKind,
    pub code_snippet: String,
    pub file_path: String,
    pub line_number: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpgEdge {
    pub from: NodeId,
    pub to: NodeId,
    pub kind: CpgEdgeKind,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CodePropertyGraph {
    pub nodes: Vec<CpgNode>,
    pub edges: Vec<CpgEdge>,
    #[serde(skip)]
    node_lookup: HashMap<NodeId, usize>,
    #[serde(skip)]
    outgoing_adj: HashMap<NodeId, Vec<usize>>,
    #[serde(skip)]
    incoming_adj: HashMap<NodeId, Vec<usize>>,
}

impl CodePropertyGraph {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_node(&mut self, kind: CpgNodeKind, code: impl Into<String>, file: impl Into<String>, line: usize) -> NodeId {
        let id = NodeId(self.nodes.len() as u32);
        let node = CpgNode {
            id,
            kind,
            code_snippet: code.into(),
            file_path: file.into(),
            line_number: line,
        };
        let idx = self.nodes.len();
        self.nodes.push(node);
        self.node_lookup.insert(id, idx);
        id
    }

    pub fn add_edge(&mut self, from: NodeId, to: NodeId, kind: CpgEdgeKind) {
        let edge_idx = self.edges.len();
        self.edges.push(CpgEdge { from, to, kind });
        self.outgoing_adj.entry(from).or_default().push(edge_idx);
        self.incoming_adj.entry(to).or_default().push(edge_idx);
    }

    pub fn get_node(&self, id: NodeId) -> Option<&CpgNode> {
        self.node_lookup.get(&id).and_then(|&idx| self.nodes.get(idx))
    }

    pub fn outgoing_edges(&self, id: NodeId) -> Vec<&CpgEdge> {
        self.outgoing_adj
            .get(&id)
            .map(|indices| indices.iter().filter_map(|&idx| self.edges.get(idx)).collect())
            .unwrap_or_default()
    }

    pub fn incoming_edges(&self, id: NodeId) -> Vec<&CpgEdge> {
        self.incoming_adj
            .get(&id)
            .map(|indices| indices.iter().filter_map(|&idx| self.edges.get(idx)).collect())
            .unwrap_or_default()
    }

    pub fn find_ingress_nodes(&self) -> Vec<NodeId> {
        self.nodes
            .iter()
            .filter(|n| matches!(n.kind, CpgNodeKind::SecurityIngress { .. }))
            .map(|n| n.id)
            .collect()
    }

    pub fn find_sink_nodes(&self) -> Vec<NodeId> {
        self.nodes
            .iter()
            .filter(|n| matches!(n.kind, CpgNodeKind::SecuritySink { .. }))
            .map(|n| n.id)
            .collect()
    }

    pub fn find_guards(&self) -> Vec<NodeId> {
        self.nodes
            .iter()
            .filter(|n| matches!(n.kind, CpgNodeKind::SanitizerGuard { .. }))
            .map(|n| n.id)
            .collect()
    }

    /// Rebuilds index tables after deserialization
    pub fn rebuild_indices(&mut self) {
        self.node_lookup.clear();
        self.outgoing_adj.clear();
        self.incoming_adj.clear();

        for (idx, node) in self.nodes.iter().enumerate() {
            self.node_lookup.insert(node.id, idx);
        }

        for (edge_idx, edge) in self.edges.iter().enumerate() {
            self.outgoing_adj.entry(edge.from).or_default().push(edge_idx);
            self.incoming_adj.entry(edge.to).or_default().push(edge_idx);
        }
    }
}

fn contains_identifier(expr: &str, ident: &str) -> bool {
    if ident.is_empty() {
        return false;
    }
    let bytes = expr.as_bytes();
    let ident_bytes = ident.as_bytes();
    let is_ident_char = |b: u8| b.is_ascii_alphanumeric() || b == b'_';

    let mut start = 0;
    while let Some(pos) = expr[start..].find(ident) {
        let abs_start = start + pos;
        let abs_end = abs_start + ident_bytes.len();
        let left_ok = abs_start == 0 || !is_ident_char(bytes[abs_start - 1]);
        let right_ok = abs_end == bytes.len() || !is_ident_char(bytes[abs_end]);
        if left_ok && right_ok {
            return true;
        }
        start = abs_start + 1;
    }
    false
}

#[derive(Debug, Clone)]
struct ParsedFunctionInfo {
    func_node_id: NodeId,
    params: Vec<(String, NodeId)>,
}

#[derive(Debug, Clone)]
struct PendingCallSite {
    call_node_id: NodeId,
    callee_name: String,
    tainted_args: Vec<(usize, String)>,
}

fn link_interprocedural_calls(
    cpg: &mut CodePropertyGraph,
    functions: &HashMap<String, ParsedFunctionInfo>,
    calls: &[PendingCallSite],
) {
    for call in calls {
        if let Some(target_fn) = functions.get(&call.callee_name) {
            cpg.add_edge(call.call_node_id, target_fn.func_node_id, CpgEdgeKind::CallEdge);
            for (arg_idx, _arg_expr) in &call.tainted_args {
                if let Some((param_name, param_node)) = target_fn.params.get(*arg_idx) {
                    cpg.add_edge(
                        call.call_node_id,
                        *param_node,
                        CpgEdgeKind::DataFlow {
                            variable: param_name.clone(),
                        },
                    );
                }
            }
        }
    }
}

/// Specialized parser for C source files to construct interprocedural CPG with memory-safety boundaries.
pub struct CSourceParser;

impl CSourceParser {
    /// Parses C source code into an interprocedural CPG using `tree-sitter-c`.
    pub fn parse_snippet(source: &str, file_name: &str) -> Result<CodePropertyGraph> {
        ts_frontends::parse_c_with_treesitter(source, file_name)
    }
}

/// Specialized parser for Python source files to construct interprocedural CPGs.
pub struct PythonSourceParser;

impl PythonSourceParser {
    /// Parses Python source code into an interprocedural CPG using `tree-sitter-python`.
    pub fn parse_snippet(source: &str, file_name: &str) -> Result<CodePropertyGraph> {
        ts_frontends::parse_python_with_treesitter(source, file_name)
    }
}

/// Specialized parser for Rust source files auditing `unsafe` blocks, FFI, and Command sinks.
pub struct RustSourceParser;

impl RustSourceParser {
    /// Parses Rust source code into an interprocedural CPG using `tree-sitter-rust`.
    pub fn parse_snippet(source: &str, file_name: &str) -> Result<CodePropertyGraph> {
        ts_frontends::parse_rust_with_treesitter(source, file_name)
    }
}

/// Phase 2 parser for JavaScript / TypeScript (Node.js & Web APIs).
pub struct JsTsSourceParser;

impl JsTsSourceParser {
    /// Parses JavaScript or TypeScript source code into an interprocedural CPG using Tree-sitter.
    pub fn parse_snippet(source: &str, file_name: &str) -> Result<CodePropertyGraph> {
        ts_frontends::parse_js_ts_with_treesitter(source, file_name)
    }
}

/// Parser for Go cloud-native services backed by `tree-sitter-go`.
pub struct GoSourceParser;

impl GoSourceParser {
    /// Parses Go source code into an interprocedural CPG using `tree-sitter-go`.
    pub fn parse_snippet(source: &str, file_name: &str) -> Result<CodePropertyGraph> {
        ts_frontends::parse_go_with_treesitter(source, file_name)
    }
}

/// Parser for Java JVM applications backed by `tree-sitter-java`.
pub struct JavaSourceParser;

impl JavaSourceParser {
    /// Parses Java source code into an interprocedural CPG using `tree-sitter-java`.
    pub fn parse_snippet(source: &str, file_name: &str) -> Result<CodePropertyGraph> {
        ts_frontends::parse_java_with_treesitter(source, file_name)
    }
}

/// Builds a unified multi-file interprocedural Code Property Graph across an untrusted directory,
/// delegating traversal safety checks to `IngestionEngine` first.
pub struct ProjectCpgBuilder;

impl ProjectCpgBuilder {
    pub fn build_from_directory<P: AsRef<Path>>(repo_dir: P) -> Result<CodePropertyGraph> {
        let root = repo_dir.as_ref();
        // Run safe ingestion checks (rejects symlink escapes and resource bombs)
        let _inspection = IngestionEngine::default().inspect_repository(root)?;
        let canonical_root = root.canonicalize().map_err(ProoflineError::Io)?;

        let mut merged = CodePropertyGraph::new();
        let mut all_functions: HashMap<String, ParsedFunctionInfo> = HashMap::new();
        let mut all_calls: Vec<PendingCallSite> = Vec::new();

        for entry in WalkDir::new(&canonical_root)
            .follow_links(false)
            .sort_by_file_name()
        {
            let entry = entry.map_err(|e| ProoflineError::ParseFailure(e.to_string()))?;
            if !entry.file_type().is_file() {
                continue;
            }
            let path = entry.path();
            let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
            if !matches!(ext, "c" | "h" | "py" | "rs" | "js" | "ts" | "go" | "java") {
                continue;
            }

            let source = fs::read_to_string(path).map_err(ProoflineError::Io)?;
            let rel = path
                .strip_prefix(&canonical_root)
                .unwrap_or(path)
                .to_string_lossy()
                .to_string();

            let file_cpg = match ext {
                "c" | "h" => CSourceParser::parse_snippet(&source, &rel)?,
                "py" => PythonSourceParser::parse_snippet(&source, &rel)?,
                "rs" => RustSourceParser::parse_snippet(&source, &rel)?,
                "js" | "ts" => JsTsSourceParser::parse_snippet(&source, &rel)?,
                "go" => GoSourceParser::parse_snippet(&source, &rel)?,
                "java" => JavaSourceParser::parse_snippet(&source, &rel)?,
                _ => continue,
            };

            let mut id_remap: HashMap<NodeId, NodeId> = HashMap::new();
            for node in &file_cpg.nodes {
                let new_id = merged.add_node(
                    node.kind.clone(),
                    node.code_snippet.clone(),
                    node.file_path.clone(),
                    node.line_number,
                );
                id_remap.insert(node.id, new_id);
            }
            for edge in &file_cpg.edges {
                if let (Some(&from), Some(&to)) = (id_remap.get(&edge.from), id_remap.get(&edge.to)) {
                    merged.add_edge(from, to, edge.kind.clone());
                }
            }

            // Collect FunctionDef + Parameters and CallExpressions across files for cross-file CallEdge linking
            for node in &file_cpg.nodes {
                if let CpgNodeKind::FunctionDef { ref name, .. } = node.kind {
                    if let Some(&new_fn_id) = id_remap.get(&node.id) {
                        let mut params = Vec::new();
                        for edge in file_cpg.outgoing_edges(node.id) {
                            if let CpgEdgeKind::AstChild { order } = edge.kind {
                                if let Some(pnode) = file_cpg.get_node(edge.to) {
                                    if let CpgNodeKind::Parameter { name: ref pname, .. } = pnode.kind {
                                        if let Some(&new_pid) = id_remap.get(&edge.to) {
                                            params.push((order, pname.clone(), new_pid));
                                        }
                                    }
                                }
                            }
                        }
                        params.sort_by_key(|(ord, _, _)| *ord);
                        all_functions.insert(
                            name.clone(),
                            ParsedFunctionInfo {
                                func_node_id: new_fn_id,
                                params: params.into_iter().map(|(_, n, id)| (n, id)).collect(),
                            },
                        );
                    }
                }
                if let CpgNodeKind::CallExpression { ref callee, ref arguments } = node.kind {
                    if let Some(&new_call_id) = id_remap.get(&node.id) {
                        let has_incoming_taint = !file_cpg.incoming_edges(node.id).is_empty();
                        if has_incoming_taint {
                            let mut tainted_args = Vec::new();
                            for (idx, arg) in arguments.iter().enumerate() {
                                for edge in file_cpg.incoming_edges(node.id) {
                                    if let CpgEdgeKind::DataFlow { ref variable } = edge.kind {
                                        if contains_identifier(arg, variable) {
                                            tainted_args.push((idx, arg.clone()));
                                            break;
                                        }
                                    }
                                }
                            }
                            all_calls.push(PendingCallSite {
                                call_node_id: new_call_id,
                                callee_name: callee.clone(),
                                tainted_args,
                            });
                        }
                    }
                }
            }
        }

        link_interprocedural_calls(&mut merged, &all_functions, &all_calls);
        Ok(merged)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_interprocedural_c_call_graph_linking() {
        let c_code = r#"
        int copy_helper(char *s) {
            char dst[16];
            strcpy(dst, s);
            return 0;
        }
        int main() {
            char buf[64];
            fgets(buf, 256, stdin);
            copy_helper(buf);
            return 0;
        }
        "#;
        let cpg = CSourceParser::parse_snippet(c_code, "interproc.c").unwrap();
        assert_eq!(cpg.find_ingress_nodes().len(), 1);
        assert_eq!(cpg.find_sink_nodes().len(), 1);
        assert!(cpg
            .edges
            .iter()
            .any(|e| matches!(e.kind, CpgEdgeKind::CallEdge)));
    }

    #[test]
    fn test_rust_unsafe_and_command_cpg() {
        let rs_code = r#"
        pub fn run_tool(arg: String) {
            Command::new(arg);
        }
        fn main() {
            let user = std::env::var("CMD").unwrap();
            run_tool(user);
        }
        "#;
        let mut cpg = RustSourceParser::parse_snippet(rs_code, "tool.rs").unwrap();
        assert_eq!(cpg.find_ingress_nodes().len(), 1);
        assert_eq!(cpg.find_sink_nodes().len(), 1);

        let json = serde_json::to_string(&cpg).unwrap();
        let mut decoded: CodePropertyGraph = serde_json::from_str(&json).unwrap();
        decoded.rebuild_indices();
        assert_eq!(decoded.find_sink_nodes().len(), 1);
        cpg.rebuild_indices();
    }

    #[test]
    fn test_phase2_js_go_java_and_multifile_project_cpg() {
        let js_cpg = JsTsSourceParser::parse_snippet(
            "const q = req.query.cmd;\nexec(q);",
            "app.js",
        )
        .unwrap();
        assert_eq!(js_cpg.find_ingress_nodes().len(), 1);
        assert_eq!(js_cpg.find_sink_nodes().len(), 1);

        let go_cpg = GoSourceParser::parse_snippet(
            "cmd := r.URL.Query().Get(\"c\")\nexec.Command(cmd)",
            "main.go",
        )
        .unwrap();
        assert_eq!(go_cpg.find_ingress_nodes().len(), 1);
        assert_eq!(go_cpg.find_sink_nodes().len(), 1);

        let java_cpg = JavaSourceParser::parse_snippet(
            "String u = request.getParameter(\"id\");\nstmt.executeQuery(u);",
            "App.java",
        )
        .unwrap();
        assert_eq!(java_cpg.find_ingress_nodes().len(), 1);
        assert_eq!(java_cpg.find_sink_nodes().len(), 1);

        // Multi-file cross-file CPG linking
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join("parser.c"),
            "int sink_copy(char *input) {\n  char d[16];\n  strcpy(d, input);\n  return 0;\n}\n",
        )
        .unwrap();
        fs::write(
            dir.path().join("main.c"),
            "int main() {\n  char buf[128];\n  fgets(buf, 512, stdin);\n  sink_copy(buf);\n  return 0;\n}\n",
        )
        .unwrap();
        let proj_cpg = ProjectCpgBuilder::build_from_directory(dir.path()).unwrap();
        assert_eq!(proj_cpg.find_ingress_nodes().len(), 1);
        assert_eq!(proj_cpg.find_sink_nodes().len(), 1);
        assert!(proj_cpg
            .edges
            .iter()
            .any(|e| matches!(e.kind, CpgEdgeKind::CallEdge)));
    }
}
