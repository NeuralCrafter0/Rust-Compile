//! Code Property Graph (CPG) intermediate representation and language frontends.
//! Combines Abstract Syntax Trees (AST), Control Flow Graphs (CFG),
//! and Data Dependence Graphs (DDG) into a unified queryable graph.

use proofline_core::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

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

/// Specialized parser for C source files to construct CPG with memory-safety boundaries.
pub struct CSourceParser;

impl CSourceParser {
    pub fn parse_snippet(source: &str, file_name: &str) -> Result<CodePropertyGraph> {
        let mut cpg = CodePropertyGraph::new();
        let mut prev_stmt: Option<NodeId> = None;
        let mut var_def_map: HashMap<String, NodeId> = HashMap::new();

        for (line_idx, line) in source.lines().enumerate() {
            let line_no = line_idx + 1;
            let trimmed = line.trim();

            if trimmed.is_empty() || trimmed.starts_with("//") || trimmed.starts_with("/*") {
                continue;
            }

            // Function declaration detection
            if (trimmed.starts_with("void ") || trimmed.starts_with("int ") || trimmed.starts_with("char* "))
                && trimmed.contains('(')
                && trimmed.ends_with('{')
            {
                let func_name = trimmed.split('(').next().unwrap_or("").split_whitespace().last().unwrap_or("func");
                let func_id = cpg.add_node(
                    CpgNodeKind::FunctionDef {
                        name: func_name.to_string(),
                        return_type: "int".to_string(),
                    },
                    trimmed,
                    file_name,
                    line_no,
                );
                prev_stmt = Some(func_id);
                continue;
            }

            // Ingress Source Detection: fgets, read, recv, getenv
            if trimmed.contains("fgets(") || trimmed.contains("getenv(") || trimmed.contains("read(") || trimmed.contains("recv(") {
                let var_name = Self::extract_c_buffer_name(trimmed);
                let ingress_id = cpg.add_node(
                    CpgNodeKind::SecurityIngress {
                        source_type: "UNTRUSTED_INPUT_BUFFER".to_string(),
                        variable: var_name.clone(),
                    },
                    trimmed,
                    file_name,
                    line_no,
                );

                if let Some(prev) = prev_stmt {
                    cpg.add_edge(prev, ingress_id, CpgEdgeKind::CfgNext);
                }
                var_def_map.insert(var_name.clone(), ingress_id);
                prev_stmt = Some(ingress_id);
                continue;
            }

            // Sanitizer / Bounds Guard: if (len < sizeof(dest)) or if (strlen(src) < MAX)
            if trimmed.starts_with("if") && (trimmed.contains('<') || trimmed.contains('>') || trimmed.contains("sizeof")) {
                let guard_id = cpg.add_node(
                    CpgNodeKind::SanitizerGuard {
                        checked_variable: "input".to_string(),
                        guard_expr: trimmed.to_string(),
                    },
                    trimmed,
                    file_name,
                    line_no,
                );

                if let Some(prev) = prev_stmt {
                    cpg.add_edge(prev, guard_id, CpgEdgeKind::CfgNext);
                }
                prev_stmt = Some(guard_id);
                continue;
            }

            // Dangerous Memory Sink: strcpy, strcat, sprintf, memcpy, system
            if trimmed.contains("strcpy(") || trimmed.contains("strcat(") || trimmed.contains("sprintf(") || trimmed.contains("memcpy(") || trimmed.contains("system(") {
                let (sink_type, tainted_arg) = Self::extract_c_sink_target(trimmed);
                let sink_id = cpg.add_node(
                    CpgNodeKind::SecuritySink {
                        sink_type,
                        target_variable: tainted_arg.clone(),
                    },
                    trimmed,
                    file_name,
                    line_no,
                );

                if let Some(prev) = prev_stmt {
                    cpg.add_edge(prev, sink_id, CpgEdgeKind::CfgNext);
                }

                // Connect DataFlow edge if defined earlier
                if let Some(&def_node) = var_def_map.get(&tainted_arg) {
                    cpg.add_edge(def_node, sink_id, CpgEdgeKind::DataFlow { variable: tainted_arg });
                }

                prev_stmt = Some(sink_id);
                continue;
            }

            // Generic assignment or statement
            if trimmed.contains('=') && !trimmed.starts_with("==") {
                let parts: Vec<&str> = trimmed.splitn(2, '=').collect();
                let var_name = parts[0].split_whitespace().last().unwrap_or("").trim_matches('*');
                let value_expr = parts[1].trim_matches(';').trim();

                let assign_id = cpg.add_node(
                    CpgNodeKind::Assignment {
                        target: var_name.to_string(),
                        value_expr: value_expr.to_string(),
                    },
                    trimmed,
                    file_name,
                    line_no,
                );

                if let Some(prev) = prev_stmt {
                    cpg.add_edge(prev, assign_id, CpgEdgeKind::CfgNext);
                }

                // Connect incoming dataflow if right-hand-side references known tainted var
                for (tainted_var, &def_node) in &var_def_map {
                    if value_expr.contains(tainted_var) {
                        cpg.add_edge(def_node, assign_id, CpgEdgeKind::DataFlow { variable: tainted_var.clone() });
                    }
                }

                var_def_map.insert(var_name.to_string(), assign_id);
                prev_stmt = Some(assign_id);
            }
        }

        Ok(cpg)
    }

    fn extract_c_buffer_name(line: &str) -> String {
        if line.contains("fgets(") {
            let inside = line.split("fgets(").nth(1).unwrap_or("");
            return inside.split(',').next().unwrap_or("buf").trim().to_string();
        }
        if line.contains("read(") {
            let inside = line.split("read(").nth(1).unwrap_or("");
            let parts: Vec<&str> = inside.split(',').collect();
            if parts.len() >= 2 {
                return parts[1].trim().trim_matches('&').to_string();
            }
        }
        "input".to_string()
    }

    fn extract_c_sink_target(line: &str) -> (String, String) {
        if line.contains("strcpy(") {
            let inside = line.split("strcpy(").nth(1).unwrap_or("");
            let parts: Vec<&str> = inside.split(',').collect();
            let src = parts.get(1).unwrap_or(&"src").trim().trim_matches(|c| c == ')' || c == ';' || c == ' ');
            return ("CWE-119_UNBOUNDED_COPY".to_string(), src.to_string());
        }
        if line.contains("system(") {
            let inside = line.split("system(").nth(1).unwrap_or("");
            let arg = inside.split(')').next().unwrap_or("cmd").trim();
            return ("CWE-78_COMMAND_INJECTION".to_string(), arg.to_string());
        }
        ("DANGEROUS_SINK".to_string(), "target".to_string())
    }
}

/// Specialized parser for Python source files to construct CPG with injection boundaries.
pub struct PythonSourceParser;

impl PythonSourceParser {
    pub fn parse_snippet(source: &str, file_name: &str) -> Result<CodePropertyGraph> {
        let mut cpg = CodePropertyGraph::new();
        let mut prev_stmt: Option<NodeId> = None;
        let mut var_def_map: HashMap<String, NodeId> = HashMap::new();

        for (line_idx, line) in source.lines().enumerate() {
            let line_no = line_idx + 1;
            let trimmed = line.trim();

            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            // Ingress Source Detection: request.args.get, request.form, input, sys.stdin
            if trimmed.contains("request.args.get") || trimmed.contains("request.form") || trimmed.contains("input(") || trimmed.contains("sys.stdin") {
                let target_var = trimmed.split('=').next().unwrap_or("user_input").trim().to_string();
                let ingress_id = cpg.add_node(
                    CpgNodeKind::SecurityIngress {
                        source_type: "UNTRUSTED_WEB_PARAM".to_string(),
                        variable: target_var.clone(),
                    },
                    trimmed,
                    file_name,
                    line_no,
                );

                if let Some(prev) = prev_stmt {
                    cpg.add_edge(prev, ingress_id, CpgEdgeKind::CfgNext);
                }
                var_def_map.insert(target_var, ingress_id);
                prev_stmt = Some(ingress_id);
                continue;
            }

            // Sanitizer / Parameterization Guard: parameterized query or sanitization function
            if trimmed.contains("isinstance(") || trimmed.contains("sanitize(") || trimmed.contains("execute(query, (") {
                let guard_id = cpg.add_node(
                    CpgNodeKind::SanitizerGuard {
                        checked_variable: "user_input".to_string(),
                        guard_expr: trimmed.to_string(),
                    },
                    trimmed,
                    file_name,
                    line_no,
                );

                if let Some(prev) = prev_stmt {
                    cpg.add_edge(prev, guard_id, CpgEdgeKind::CfgNext);
                }
                prev_stmt = Some(guard_id);
                continue;
            }

            // Dangerous Injection Sink: cursor.execute, eval, os.system
            if trimmed.contains("cursor.execute(") || trimmed.contains("eval(") || trimmed.contains("os.system(") {
                let sink_type = if trimmed.contains("cursor.execute") {
                    "CWE-89_SQL_INJECTION".to_string()
                } else if trimmed.contains("os.system") {
                    "CWE-78_COMMAND_INJECTION".to_string()
                } else {
                    "CWE-95_CODE_INJECTION".to_string()
                };

                // Find which tainted var flows into this sink
                let mut tainted_target = "query".to_string();
                for var in var_def_map.keys() {
                    if trimmed.contains(var) {
                        tainted_target = var.clone();
                        break;
                    }
                }

                let sink_id = cpg.add_node(
                    CpgNodeKind::SecuritySink {
                        sink_type,
                        target_variable: tainted_target.clone(),
                    },
                    trimmed,
                    file_name,
                    line_no,
                );

                if let Some(prev) = prev_stmt {
                    cpg.add_edge(prev, sink_id, CpgEdgeKind::CfgNext);
                }

                if let Some(&def_node) = var_def_map.get(&tainted_target) {
                    cpg.add_edge(def_node, sink_id, CpgEdgeKind::DataFlow { variable: tainted_target });
                }

                prev_stmt = Some(sink_id);
                continue;
            }

            // String formatting / assignment propagating taint
            if trimmed.contains('=') && !trimmed.starts_with("==") {
                let parts: Vec<&str> = trimmed.splitn(2, '=').collect();
                let target_var = parts[0].trim().to_string();
                let expr = parts[1].trim();

                let assign_id = cpg.add_node(
                    CpgNodeKind::Assignment {
                        target: target_var.clone(),
                        value_expr: expr.to_string(),
                    },
                    trimmed,
                    file_name,
                    line_no,
                );

                if let Some(prev) = prev_stmt {
                    cpg.add_edge(prev, assign_id, CpgEdgeKind::CfgNext);
                }

                for (tainted_var, &def_node) in &var_def_map {
                    if expr.contains(tainted_var) {
                        cpg.add_edge(def_node, assign_id, CpgEdgeKind::DataFlow { variable: tainted_var.clone() });
                        var_def_map.insert(target_var.clone(), assign_id);
                        break;
                    }
                }

                prev_stmt = Some(assign_id);
            }
        }

        Ok(cpg)
    }
}
