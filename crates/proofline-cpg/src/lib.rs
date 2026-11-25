//! Code Property Graph (CPG) intermediate representation and language frontends.
//! Combines Abstract Syntax Trees (AST), Control Flow Graphs (CFG),
//! and Data Dependence Graphs (DDG) into a unified queryable graph.

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

fn extract_call_and_args(trimmed: &str) -> Option<(String, Vec<String>)> {
    let open = trimmed.find('(')?;
    let close = trimmed.rfind(')')?;
    if close <= open {
        return None;
    }
    let before = trimmed[..open].trim();
    // Ignore assignments like `x = foo(y)` on LHS; handle LHS separately or unwrap after `=`
    let callee_part = before.rsplit('=').next().unwrap_or(before).trim();
    let callee = callee_part
        .split(|c: char| !c.is_ascii_alphanumeric() && c != '_' && c != ':')
        .last()
        .unwrap_or("")
        .to_string();
    if callee.is_empty()
        || matches!(
            callee.as_str(),
            "if" | "while" | "for" | "return" | "sizeof" | "elif"
        )
    {
        return None;
    }
    let args_raw = &trimmed[open + 1..close];
    let args: Vec<String> = if args_raw.trim().is_empty() {
        Vec::new()
    } else {
        args_raw.split(',').map(|a| a.trim().to_string()).collect()
    };
    Some((callee, args))
}

/// Specialized parser for C source files to construct interprocedural CPG with memory-safety boundaries.
pub struct CSourceParser;

impl CSourceParser {
    pub fn parse_snippet(source: &str, file_name: &str) -> Result<CodePropertyGraph> {
        let mut cpg = CodePropertyGraph::new();
        let mut prev_stmt: Option<NodeId> = None;
        let mut var_def_map: HashMap<String, NodeId> = HashMap::new();
        let mut functions: HashMap<String, ParsedFunctionInfo> = HashMap::new();
        let mut pending_calls: Vec<PendingCallSite> = Vec::new();

        for (line_idx, line) in source.lines().enumerate() {
            let line_no = line_idx + 1;
            let trimmed = line.trim();

            if trimmed.is_empty() || trimmed.starts_with("//") || trimmed.starts_with("/*") {
                continue;
            }

            // Function declaration detection (resets per-function local scope)
            if (trimmed.starts_with("void ")
                || trimmed.starts_with("int ")
                || trimmed.starts_with("char*")
                || trimmed.starts_with("char *")
                || trimmed.starts_with("static "))
                && trimmed.contains('(')
                && trimmed.ends_with('{')
            {
                let open = trimmed.find('(').unwrap();
                let close = trimmed.rfind(')').unwrap_or(open);
                let header_left = trimmed[..open].trim();
                let func_name = header_left
                    .split_whitespace()
                    .last()
                    .unwrap_or("func")
                    .trim_start_matches('*');
                let func_id = cpg.add_node(
                    CpgNodeKind::FunctionDef {
                        name: func_name.to_string(),
                        return_type: "int".to_string(),
                    },
                    trimmed,
                    file_name,
                    line_no,
                );

                var_def_map.clear();
                let mut params = Vec::new();
                if close > open {
                    let params_str = trimmed[open + 1..close].trim();
                    if !params_str.is_empty() && params_str != "void" {
                        for (idx, p) in params_str.split(',').enumerate() {
                            let pname = p
                                .trim()
                                .split_whitespace()
                                .last()
                                .unwrap_or("")
                                .trim_matches('*')
                                .split('[')
                                .next()
                                .unwrap_or("")
                                .to_string();
                            if !pname.is_empty() {
                                let p_id = cpg.add_node(
                                    CpgNodeKind::Parameter {
                                        name: pname.clone(),
                                        index: idx,
                                    },
                                    p.trim(),
                                    file_name,
                                    line_no,
                                );
                                cpg.add_edge(func_id, p_id, CpgEdgeKind::AstChild { order: idx });
                                var_def_map.insert(pname.clone(), p_id);
                                params.push((pname, p_id));
                            }
                        }
                    }
                }
                functions.insert(
                    func_name.to_string(),
                    ParsedFunctionInfo {
                        func_node_id: func_id,
                        params,
                    },
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

            // Sanitizer / Bounds Guard: must check a tainted variable with bounds expression
            if (trimmed.starts_with("if ") || trimmed.starts_with("if("))
                && (trimmed.contains('<') || trimmed.contains('>') || trimmed.contains("sizeof"))
            {
                if let Some(checked_var) = var_def_map
                    .keys()
                    .find(|v| contains_identifier(trimmed, v))
                    .cloned()
                {
                    let guard_id = cpg.add_node(
                        CpgNodeKind::SanitizerGuard {
                            checked_variable: checked_var,
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
                } else {
                    let branch_id = cpg.add_node(
                        CpgNodeKind::BranchCondition {
                            condition_expr: trimmed.to_string(),
                        },
                        trimmed,
                        file_name,
                        line_no,
                    );
                    if let Some(prev) = prev_stmt {
                        cpg.add_edge(prev, branch_id, CpgEdgeKind::CfgNext);
                    }
                    prev_stmt = Some(branch_id);
                    continue;
                }
            }

            // Dangerous Memory Sink: strcpy, strcat, sprintf, memcpy, system
            if trimmed.contains("strcpy(") || trimmed.contains("strcat(") || trimmed.contains("sprintf(") || trimmed.contains("memcpy(") || trimmed.contains("system(") {
                let (sink_type, source_expr, tainted_arg) = Self::extract_c_sink_target(trimmed);
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

                // Connect DataFlow edges from any tainted variable referenced in the sink's source expression
                let mut linked = false;
                if let Some(&def_node) = var_def_map.get(&tainted_arg) {
                    cpg.add_edge(def_node, sink_id, CpgEdgeKind::DataFlow { variable: tainted_arg });
                    linked = true;
                }
                if !linked {
                    for (tainted_var, &def_node) in &var_def_map {
                        if contains_identifier(&source_expr, tainted_var) {
                            cpg.add_edge(def_node, sink_id, CpgEdgeKind::DataFlow { variable: tainted_var.clone() });
                        }
                    }
                }

                prev_stmt = Some(sink_id);
                continue;
            }

            // Generic assignment (avoid misparsing ==, !=, <=, >= or control-flow conditions)
            let is_ctrl_flow = trimmed.starts_with("if ")
                || trimmed.starts_with("if(")
                || trimmed.starts_with("while ")
                || trimmed.starts_with("while(")
                || trimmed.starts_with("for ")
                || trimmed.starts_with("for(");
            let is_condition = is_ctrl_flow || trimmed.starts_with("return ");
            if !is_condition
                && trimmed.contains('=')
                && !trimmed.contains("==")
                && !trimmed.contains("!=")
                && !trimmed.contains("<=")
                && !trimmed.contains(">=")
            {
                let parts: Vec<&str> = trimmed.splitn(2, '=').collect();
                let var_name = parts[0]
                    .split_whitespace()
                    .last()
                    .unwrap_or("")
                    .trim_matches('*')
                    .split('[')
                    .next()
                    .unwrap_or("")
                    .to_string();
                let value_expr = parts[1].trim_matches(';').trim();

                let assign_id = cpg.add_node(
                    CpgNodeKind::Assignment {
                        target: var_name.clone(),
                        value_expr: value_expr.to_string(),
                    },
                    trimmed,
                    file_name,
                    line_no,
                );

                if let Some(prev) = prev_stmt {
                    cpg.add_edge(prev, assign_id, CpgEdgeKind::CfgNext);
                }

                // Connect incoming dataflow if RHS references known tainted var; kill taint on clean overwrite
                let matched_taint: Vec<(String, NodeId)> = var_def_map
                    .iter()
                    .filter(|(tainted_var, _)| contains_identifier(value_expr, tainted_var))
                    .map(|(k, &v)| (k.clone(), v))
                    .collect();

                if !matched_taint.is_empty() {
                    for (tainted_var, def_node) in matched_taint {
                        cpg.add_edge(def_node, assign_id, CpgEdgeKind::DataFlow { variable: tainted_var });
                    }
                    if !var_name.is_empty() {
                        var_def_map.insert(var_name, assign_id);
                    }
                } else if !var_name.is_empty() {
                    var_def_map.remove(&var_name);
                }

                prev_stmt = Some(assign_id);
                continue;
            }

            // Interprocedural function call site (e.g., `helper(buf);` or `return handle_route(buf);`)
            if !is_ctrl_flow && trimmed.ends_with(';') {
                let call_slice = trimmed.strip_prefix("return ").unwrap_or(trimmed).trim();
                if let Some((callee, args)) = extract_call_and_args(call_slice) {
                    let call_id = cpg.add_node(
                        CpgNodeKind::CallExpression {
                            callee: callee.clone(),
                            arguments: args.clone(),
                        },
                        trimmed,
                        file_name,
                        line_no,
                    );
                    if let Some(prev) = prev_stmt {
                        cpg.add_edge(prev, call_id, CpgEdgeKind::CfgNext);
                    }
                    let mut tainted_args = Vec::new();
                    for (idx, arg) in args.iter().enumerate() {
                        for (tainted_var, &def_node) in &var_def_map {
                            if contains_identifier(arg, tainted_var) {
                                cpg.add_edge(
                                    def_node,
                                    call_id,
                                    CpgEdgeKind::DataFlow {
                                        variable: tainted_var.clone(),
                                    },
                                );
                                tainted_args.push((idx, arg.clone()));
                                break;
                            }
                        }
                    }
                    pending_calls.push(PendingCallSite {
                        call_node_id: call_id,
                        callee_name: callee,
                        tainted_args,
                    });
                    prev_stmt = Some(call_id);
                }
            }
        }

        link_interprocedural_calls(&mut cpg, &functions, &pending_calls);
        Ok(cpg)
    }

    fn extract_c_buffer_name(line: &str) -> String {
        if line.contains("fgets(") {
            let inside = line.split("fgets(").nth(1).unwrap_or("");
            return inside.split(',').next().unwrap_or("buf").trim().to_string();
        }
        if line.contains("read(") || line.contains("recv(") {
            let inside = line.split("read(").nth(1).or_else(|| line.split("recv(").nth(1)).unwrap_or("");
            let parts: Vec<&str> = inside.split(',').collect();
            if parts.len() >= 2 {
                return parts[1].trim().trim_matches('&').to_string();
            }
        }
        if line.contains("getenv(") && line.contains('=') {
            return line
                .split('=')
                .next()
                .unwrap_or("input")
                .split_whitespace()
                .last()
                .unwrap_or("input")
                .trim_matches('*')
                .to_string();
        }
        "input".to_string()
    }

    fn extract_c_sink_target(line: &str) -> (String, String, String) {
        if let Some(inside) = line.split("strcpy(").nth(1) {
            let parts: Vec<&str> = inside.split(',').collect();
            let raw = parts.get(1).unwrap_or(&"src").trim().trim_matches(|c| c == ')' || c == ';' || c == ' ');
            return ("CWE-119_UNBOUNDED_COPY".to_string(), raw.to_string(), raw.to_string());
        }
        if let Some(inside) = line.split("strcat(").nth(1) {
            let parts: Vec<&str> = inside.split(',').collect();
            let raw = parts.get(1).unwrap_or(&"src").trim().trim_matches(|c| c == ')' || c == ';' || c == ' ');
            return ("CWE-119_UNBOUNDED_COPY".to_string(), raw.to_string(), raw.to_string());
        }
        if let Some(inside) = line.split("memcpy(").nth(1) {
            let parts: Vec<&str> = inside.split(',').collect();
            let raw = parts.get(1).unwrap_or(&"src").trim().trim_matches(|c| c == ')' || c == ';' || c == ' ');
            return ("CWE-119_UNBOUNDED_COPY".to_string(), raw.to_string(), raw.to_string());
        }
        if let Some(inside) = line.split("sprintf(").nth(1) {
            let after_dest = inside.split_once(',').map(|(_, rest)| rest).unwrap_or(inside);
            let raw = after_dest
                .split(',')
                .last()
                .unwrap_or("src")
                .trim()
                .trim_matches(|c| c == ')' || c == ';' || c == ' ');
            return ("CWE-119_UNBOUNDED_COPY".to_string(), after_dest.to_string(), raw.to_string());
        }
        if let Some(inside) = line.split("system(").nth(1) {
            let arg = inside.split(')').next().unwrap_or("cmd").trim();
            return ("CWE-78_COMMAND_INJECTION".to_string(), arg.to_string(), arg.to_string());
        }
        ("DANGEROUS_SINK".to_string(), line.to_string(), "target".to_string())
    }
}

/// Specialized parser for Python source files to construct interprocedural CPGs.
pub struct PythonSourceParser;

impl PythonSourceParser {
    pub fn parse_snippet(source: &str, file_name: &str) -> Result<CodePropertyGraph> {
        let mut cpg = CodePropertyGraph::new();
        let mut prev_stmt: Option<NodeId> = None;
        let mut var_def_map: HashMap<String, NodeId> = HashMap::new();
        let mut functions: HashMap<String, ParsedFunctionInfo> = HashMap::new();
        let mut pending_calls: Vec<PendingCallSite> = Vec::new();

        for (line_idx, line) in source.lines().enumerate() {
            let line_no = line_idx + 1;
            let trimmed = line.trim();

            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            // Python function definition (`def foo(a, b):`)
            if trimmed.starts_with("def ") && trimmed.contains('(') && trimmed.ends_with(':') {
                let open = trimmed.find('(').unwrap();
                let close = trimmed.rfind(')').unwrap_or(open);
                let func_name = trimmed[4..open].trim();
                let func_id = cpg.add_node(
                    CpgNodeKind::FunctionDef {
                        name: func_name.to_string(),
                        return_type: "Any".to_string(),
                    },
                    trimmed,
                    file_name,
                    line_no,
                );
                var_def_map.clear();
                let mut params = Vec::new();
                if close > open {
                    let params_str = trimmed[open + 1..close].trim();
                    for (idx, p) in params_str.split(',').enumerate() {
                        let pname = p
                            .split(':')
                            .next()
                            .unwrap_or("")
                            .split('=')
                            .next()
                            .unwrap_or("")
                            .trim()
                            .to_string();
                        if !pname.is_empty() && pname != "self" {
                            let p_id = cpg.add_node(
                                CpgNodeKind::Parameter {
                                    name: pname.clone(),
                                    index: params.len(),
                                },
                                p.trim(),
                                file_name,
                                line_no,
                            );
                            cpg.add_edge(func_id, p_id, CpgEdgeKind::AstChild { order: idx });
                            var_def_map.insert(pname.clone(), p_id);
                            params.push((pname, p_id));
                        }
                    }
                }
                functions.insert(
                    func_name.to_string(),
                    ParsedFunctionInfo {
                        func_node_id: func_id,
                        params,
                    },
                );
                prev_stmt = Some(func_id);
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

            // Sanitizer / Parameterization Guard: must guard a known tainted variable
            if trimmed.contains("isinstance(") || trimmed.contains("sanitize(") || trimmed.contains("execute(query, (") {
                if let Some(checked_var) = var_def_map
                    .keys()
                    .find(|v| contains_identifier(trimmed, v))
                    .cloned()
                {
                    let guard_id = cpg.add_node(
                        CpgNodeKind::SanitizerGuard {
                            checked_variable: checked_var,
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

                // Find all tainted vars flowing into this sink
                let matching_tainted: Vec<(String, NodeId)> = var_def_map
                    .iter()
                    .filter(|(var, _)| contains_identifier(trimmed, var))
                    .map(|(k, &v)| (k.clone(), v))
                    .collect();

                let tainted_target = matching_tainted
                    .first()
                    .map(|(k, _)| k.clone())
                    .unwrap_or_else(|| "query".to_string());

                let sink_id = cpg.add_node(
                    CpgNodeKind::SecuritySink {
                        sink_type,
                        target_variable: tainted_target,
                    },
                    trimmed,
                    file_name,
                    line_no,
                );

                if let Some(prev) = prev_stmt {
                    cpg.add_edge(prev, sink_id, CpgEdgeKind::CfgNext);
                }

                for (tainted_var, def_node) in matching_tainted {
                    cpg.add_edge(def_node, sink_id, CpgEdgeKind::DataFlow { variable: tainted_var });
                }

                prev_stmt = Some(sink_id);
                continue;
            }

            // String formatting / assignment propagating taint (or clearing taint on clean overwrite)
            let is_condition = trimmed.starts_with("if ")
                || trimmed.starts_with("elif ")
                || trimmed.starts_with("while ")
                || trimmed.starts_with("return ");
            if !is_condition
                && trimmed.contains('=')
                && !trimmed.contains("==")
                && !trimmed.contains("!=")
                && !trimmed.contains("<=")
                && !trimmed.contains(">=")
            {
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

                let matched_taint: Vec<(String, NodeId)> = var_def_map
                    .iter()
                    .filter(|(tainted_var, _)| contains_identifier(expr, tainted_var))
                    .map(|(k, &v)| (k.clone(), v))
                    .collect();

                if !matched_taint.is_empty() {
                    for (tainted_var, def_node) in matched_taint {
                        cpg.add_edge(def_node, assign_id, CpgEdgeKind::DataFlow { variable: tainted_var });
                    }
                    var_def_map.insert(target_var, assign_id);
                } else {
                    var_def_map.remove(&target_var);
                }

                prev_stmt = Some(assign_id);
                continue;
            }

            // Interprocedural Python call site
            if !is_condition {
                if let Some((callee, args)) = extract_call_and_args(trimmed) {
                    let call_id = cpg.add_node(
                        CpgNodeKind::CallExpression {
                            callee: callee.clone(),
                            arguments: args.clone(),
                        },
                        trimmed,
                        file_name,
                        line_no,
                    );
                    if let Some(prev) = prev_stmt {
                        cpg.add_edge(prev, call_id, CpgEdgeKind::CfgNext);
                    }
                    let mut tainted_args = Vec::new();
                    for (idx, arg) in args.iter().enumerate() {
                        for (tainted_var, &def_node) in &var_def_map {
                            if contains_identifier(arg, tainted_var) {
                                cpg.add_edge(
                                    def_node,
                                    call_id,
                                    CpgEdgeKind::DataFlow {
                                        variable: tainted_var.clone(),
                                    },
                                );
                                tainted_args.push((idx, arg.clone()));
                                break;
                            }
                        }
                    }
                    pending_calls.push(PendingCallSite {
                        call_node_id: call_id,
                        callee_name: callee,
                        tainted_args,
                    });
                    prev_stmt = Some(call_id);
                }
            }
        }

        link_interprocedural_calls(&mut cpg, &functions, &pending_calls);
        Ok(cpg)
    }
}

/// Specialized parser for Rust source files auditing `unsafe` blocks, FFI, and Command sinks.
pub struct RustSourceParser;

impl RustSourceParser {
    pub fn parse_snippet(source: &str, file_name: &str) -> Result<CodePropertyGraph> {
        let mut cpg = CodePropertyGraph::new();
        let mut prev_stmt: Option<NodeId> = None;
        let mut var_def_map: HashMap<String, NodeId> = HashMap::new();
        let mut functions: HashMap<String, ParsedFunctionInfo> = HashMap::new();
        let mut pending_calls: Vec<PendingCallSite> = Vec::new();

        for (line_idx, line) in source.lines().enumerate() {
            let line_no = line_idx + 1;
            let trimmed = line.trim();

            if trimmed.is_empty() || trimmed.starts_with("//") {
                continue;
            }

            if (trimmed.starts_with("fn ") || trimmed.starts_with("pub fn ")) && trimmed.contains('(') {
                let open = trimmed.find('(').unwrap();
                let close = trimmed.rfind(')').unwrap_or(open);
                let before_paren = trimmed[..open].trim();
                let func_name = before_paren.split_whitespace().last().unwrap_or("fn");
                let func_id = cpg.add_node(
                    CpgNodeKind::FunctionDef {
                        name: func_name.to_string(),
                        return_type: "Result".to_string(),
                    },
                    trimmed,
                    file_name,
                    line_no,
                );
                var_def_map.clear();
                let mut params = Vec::new();
                if close > open {
                    for (idx, p) in trimmed[open + 1..close].split(',').enumerate() {
                        let pname = p
                            .split(':')
                            .next()
                            .unwrap_or("")
                            .trim()
                            .trim_start_matches("mut ")
                            .to_string();
                        if !pname.is_empty() && !pname.contains("self") {
                            let p_id = cpg.add_node(
                                CpgNodeKind::Parameter {
                                    name: pname.clone(),
                                    index: params.len(),
                                },
                                p.trim(),
                                file_name,
                                line_no,
                            );
                            cpg.add_edge(func_id, p_id, CpgEdgeKind::AstChild { order: idx });
                            var_def_map.insert(pname.clone(), p_id);
                            params.push((pname, p_id));
                        }
                    }
                }
                functions.insert(
                    func_name.to_string(),
                    ParsedFunctionInfo {
                        func_node_id: func_id,
                        params,
                    },
                );
                prev_stmt = Some(func_id);
                continue;
            }

            // Untrusted ingress: std::env::args, std::env::var, std::io::stdin, read_to_string
            if trimmed.contains("env::var")
                || trimmed.contains("env::args")
                || trimmed.contains("stdin()")
                || trimmed.contains("read_line(")
            {
                let target_var = if trimmed.contains('=') {
                    trimmed
                        .split('=')
                        .next()
                        .unwrap_or("input")
                        .split_whitespace()
                        .last()
                        .unwrap_or("input")
                        .trim_start_matches("mut ")
                        .to_string()
                } else {
                    "input".to_string()
                };
                let ingress_id = cpg.add_node(
                    CpgNodeKind::SecurityIngress {
                        source_type: "RUST_UNTRUSTED_INPUT".to_string(),
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

            // Guards: bounds checks or allowlist checks
            if (trimmed.starts_with("if ") || trimmed.starts_with("if("))
                && (trimmed.contains('<') || trimmed.contains("is_empty") || trimmed.contains("contains("))
            {
                if let Some(checked_var) = var_def_map
                    .keys()
                    .find(|v| contains_identifier(trimmed, v))
                    .cloned()
                {
                    let guard_id = cpg.add_node(
                        CpgNodeKind::SanitizerGuard {
                            checked_variable: checked_var,
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
            }

            // Dangerous Rust sinks: unsafe pointer copy / slice_from_raw_parts / Command::new
            if trimmed.contains("Command::new(")
                || trimmed.contains("ptr::copy")
                || trimmed.contains("from_raw_parts")
                || trimmed.contains("unsafe {")
            {
                let sink_type = if trimmed.contains("Command::new") {
                    "CWE-78_COMMAND_INJECTION".to_string()
                } else {
                    "RUST_UNSAFE_MEMORY_BOUNDARY".to_string()
                };
                let matching: Vec<(String, NodeId)> = var_def_map
                    .iter()
                    .filter(|(v, _)| contains_identifier(trimmed, v))
                    .map(|(k, &id)| (k.clone(), id))
                    .collect();
                let target_var = matching
                    .first()
                    .map(|(v, _)| v.clone())
                    .unwrap_or_else(|| "unsafe_op".to_string());
                let sink_id = cpg.add_node(
                    CpgNodeKind::SecuritySink {
                        sink_type,
                        target_variable: target_var,
                    },
                    trimmed,
                    file_name,
                    line_no,
                );
                if let Some(prev) = prev_stmt {
                    cpg.add_edge(prev, sink_id, CpgEdgeKind::CfgNext);
                }
                for (var, def_id) in matching {
                    cpg.add_edge(def_id, sink_id, CpgEdgeKind::DataFlow { variable: var });
                }
                prev_stmt = Some(sink_id);
                continue;
            }

            if trimmed.contains('=')
                && !trimmed.contains("==")
                && !trimmed.contains("!=")
                && !trimmed.contains("<=")
                && !trimmed.contains(">=")
                && !trimmed.starts_with("if ")
            {
                let parts: Vec<&str> = trimmed.splitn(2, '=').collect();
                let target_var = parts[0]
                    .split_whitespace()
                    .last()
                    .unwrap_or("")
                    .trim_start_matches("mut ")
                    .to_string();
                let expr = parts[1].trim_matches(';').trim();
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
                let matched: Vec<(String, NodeId)> = var_def_map
                    .iter()
                    .filter(|(v, _)| contains_identifier(expr, v))
                    .map(|(k, &id)| (k.clone(), id))
                    .collect();
                if !matched.is_empty() {
                    for (v, id) in matched {
                        cpg.add_edge(id, assign_id, CpgEdgeKind::DataFlow { variable: v });
                    }
                    if !target_var.is_empty() {
                        var_def_map.insert(target_var, assign_id);
                    }
                } else if !target_var.is_empty() {
                    var_def_map.remove(&target_var);
                }
                prev_stmt = Some(assign_id);
                continue;
            }

            if trimmed.ends_with(';') {
                if let Some((callee, args)) = extract_call_and_args(trimmed) {
                    let call_id = cpg.add_node(
                        CpgNodeKind::CallExpression {
                            callee: callee.clone(),
                            arguments: args.clone(),
                        },
                        trimmed,
                        file_name,
                        line_no,
                    );
                    if let Some(prev) = prev_stmt {
                        cpg.add_edge(prev, call_id, CpgEdgeKind::CfgNext);
                    }
                    let mut tainted_args = Vec::new();
                    for (idx, arg) in args.iter().enumerate() {
                        for (v, &def_id) in &var_def_map {
                            if contains_identifier(arg, v) {
                                cpg.add_edge(def_id, call_id, CpgEdgeKind::DataFlow { variable: v.clone() });
                                tainted_args.push((idx, arg.clone()));
                                break;
                            }
                        }
                    }
                    pending_calls.push(PendingCallSite {
                        call_node_id: call_id,
                        callee_name: callee,
                        tainted_args,
                    });
                    prev_stmt = Some(call_id);
                }
            }
        }

        link_interprocedural_calls(&mut cpg, &functions, &pending_calls);
        Ok(cpg)
    }
}

/// Phase 2 parser for JavaScript / TypeScript (Node.js & Web APIs).
pub struct JsTsSourceParser;

impl JsTsSourceParser {
    pub fn parse_snippet(source: &str, file_name: &str) -> Result<CodePropertyGraph> {
        let mut cpg = CodePropertyGraph::new();
        let mut prev_stmt: Option<NodeId> = None;
        let mut var_def_map: HashMap<String, NodeId> = HashMap::new();
        let mut functions: HashMap<String, ParsedFunctionInfo> = HashMap::new();
        let mut pending_calls: Vec<PendingCallSite> = Vec::new();

        for (line_idx, line) in source.lines().enumerate() {
            let line_no = line_idx + 1;
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with("//") || trimmed.starts_with("/*") {
                continue;
            }

            if (trimmed.starts_with("function ") || trimmed.starts_with("export function ") || trimmed.starts_with("async function "))
                && trimmed.contains('(')
            {
                let open = trimmed.find('(').unwrap();
                let close = trimmed.rfind(')').unwrap_or(open);
                let func_name = trimmed[..open].split_whitespace().last().unwrap_or("fn");
                let func_id = cpg.add_node(
                    CpgNodeKind::FunctionDef {
                        name: func_name.to_string(),
                        return_type: "any".to_string(),
                    },
                    trimmed,
                    file_name,
                    line_no,
                );
                var_def_map.clear();
                let mut params = Vec::new();
                if close > open {
                    for (idx, p) in trimmed[open + 1..close].split(',').enumerate() {
                        let pname = p.split(':').next().unwrap_or("").trim().to_string();
                        if !pname.is_empty() {
                            let p_id = cpg.add_node(
                                CpgNodeKind::Parameter {
                                    name: pname.clone(),
                                    index: params.len(),
                                },
                                p.trim(),
                                file_name,
                                line_no,
                            );
                            cpg.add_edge(func_id, p_id, CpgEdgeKind::AstChild { order: idx });
                            var_def_map.insert(pname.clone(), p_id);
                            params.push((pname, p_id));
                        }
                    }
                }
                functions.insert(func_name.to_string(), ParsedFunctionInfo { func_node_id: func_id, params });
                prev_stmt = Some(func_id);
                continue;
            }

            if trimmed.contains("req.query")
                || trimmed.contains("req.body")
                || trimmed.contains("req.params")
                || trimmed.contains("process.argv")
            {
                let var = trimmed
                    .split('=')
                    .next()
                    .unwrap_or("input")
                    .split_whitespace()
                    .last()
                    .unwrap_or("input")
                    .trim()
                    .to_string();
                let id = cpg.add_node(
                    CpgNodeKind::SecurityIngress {
                        source_type: "JS_HTTP_OR_CLI_INPUT".to_string(),
                        variable: var.clone(),
                    },
                    trimmed,
                    file_name,
                    line_no,
                );
                if let Some(prev) = prev_stmt {
                    cpg.add_edge(prev, id, CpgEdgeKind::CfgNext);
                }
                var_def_map.insert(var, id);
                prev_stmt = Some(id);
                continue;
            }

            if trimmed.contains("escapeHtml(") || trimmed.contains("validator.") || trimmed.contains("path.basename(") {
                if let Some(checked) = var_def_map.keys().find(|v| contains_identifier(trimmed, v)).cloned() {
                    let g_id = cpg.add_node(
                        CpgNodeKind::SanitizerGuard {
                            checked_variable: checked,
                            guard_expr: trimmed.to_string(),
                        },
                        trimmed,
                        file_name,
                        line_no,
                    );
                    if let Some(prev) = prev_stmt {
                        cpg.add_edge(prev, g_id, CpgEdgeKind::CfgNext);
                    }
                    prev_stmt = Some(g_id);
                    continue;
                }
            }

            if trimmed.contains("exec(")
                || trimmed.contains("execSync(")
                || trimmed.contains("eval(")
                || trimmed.contains("db.query(")
                || trimmed.contains("res.send(")
            {
                let sink_type = if trimmed.contains("db.query") {
                    "CWE-89_SQL_INJECTION"
                } else if trimmed.contains("res.send") {
                    "CWE-79_XSS"
                } else {
                    "CWE-78_COMMAND_INJECTION"
                };
                let matching: Vec<(String, NodeId)> = var_def_map
                    .iter()
                    .filter(|(v, _)| contains_identifier(trimmed, v))
                    .map(|(k, &id)| (k.clone(), id))
                    .collect();
                let target_var = matching.first().map(|(v, _)| v.clone()).unwrap_or_else(|| "arg".to_string());
                let sink_id = cpg.add_node(
                    CpgNodeKind::SecuritySink {
                        sink_type: sink_type.to_string(),
                        target_variable: target_var,
                    },
                    trimmed,
                    file_name,
                    line_no,
                );
                if let Some(prev) = prev_stmt {
                    cpg.add_edge(prev, sink_id, CpgEdgeKind::CfgNext);
                }
                for (v, id) in matching {
                    cpg.add_edge(id, sink_id, CpgEdgeKind::DataFlow { variable: v });
                }
                prev_stmt = Some(sink_id);
                continue;
            }

            if trimmed.contains('=') && !trimmed.contains("==") && !trimmed.contains("===") && !trimmed.starts_with("if ") {
                let parts: Vec<&str> = trimmed.splitn(2, '=').collect();
                let target_var = parts[0].split_whitespace().last().unwrap_or("").trim().to_string();
                let expr = parts[1].trim_matches(';').trim();
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
                let matched: Vec<(String, NodeId)> = var_def_map
                    .iter()
                    .filter(|(v, _)| contains_identifier(expr, v))
                    .map(|(k, &id)| (k.clone(), id))
                    .collect();
                if !matched.is_empty() {
                    for (v, id) in matched {
                        cpg.add_edge(id, assign_id, CpgEdgeKind::DataFlow { variable: v });
                    }
                    if !target_var.is_empty() {
                        var_def_map.insert(target_var, assign_id);
                    }
                } else if !target_var.is_empty() {
                    var_def_map.remove(&target_var);
                }
                prev_stmt = Some(assign_id);
                continue;
            }

            if let Some((callee, args)) = extract_call_and_args(trimmed) {
                let call_id = cpg.add_node(
                    CpgNodeKind::CallExpression {
                        callee: callee.clone(),
                        arguments: args.clone(),
                    },
                    trimmed,
                    file_name,
                    line_no,
                );
                if let Some(prev) = prev_stmt {
                    cpg.add_edge(prev, call_id, CpgEdgeKind::CfgNext);
                }
                let mut tainted_args = Vec::new();
                for (idx, arg) in args.iter().enumerate() {
                    for (v, &def_id) in &var_def_map {
                        if contains_identifier(arg, v) {
                            cpg.add_edge(def_id, call_id, CpgEdgeKind::DataFlow { variable: v.clone() });
                            tainted_args.push((idx, arg.clone()));
                            break;
                        }
                    }
                }
                pending_calls.push(PendingCallSite { call_node_id: call_id, callee_name: callee, tainted_args });
                prev_stmt = Some(call_id);
            }
        }

        link_interprocedural_calls(&mut cpg, &functions, &pending_calls);
        Ok(cpg)
    }
}

/// Phase 2 parser for Go cloud-native services.
pub struct GoSourceParser;

impl GoSourceParser {
    pub fn parse_snippet(source: &str, file_name: &str) -> Result<CodePropertyGraph> {
        let mut cpg = CodePropertyGraph::new();
        let mut prev_stmt: Option<NodeId> = None;
        let mut var_def_map: HashMap<String, NodeId> = HashMap::new();
        let mut functions: HashMap<String, ParsedFunctionInfo> = HashMap::new();
        let mut pending_calls: Vec<PendingCallSite> = Vec::new();

        for (line_idx, line) in source.lines().enumerate() {
            let line_no = line_idx + 1;
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with("//") {
                continue;
            }

            if trimmed.starts_with("func ") && trimmed.contains('(') {
                let open = trimmed.find('(').unwrap();
                let close = trimmed.rfind(')').unwrap_or(open);
                let func_name = trimmed[5..open].trim();
                let func_id = cpg.add_node(
                    CpgNodeKind::FunctionDef {
                        name: func_name.to_string(),
                        return_type: "error".to_string(),
                    },
                    trimmed,
                    file_name,
                    line_no,
                );
                var_def_map.clear();
                let mut params = Vec::new();
                if close > open {
                    for (idx, p) in trimmed[open + 1..close].split(',').enumerate() {
                        let pname = p.split_whitespace().next().unwrap_or("").trim().to_string();
                        if !pname.is_empty() {
                            let p_id = cpg.add_node(
                                CpgNodeKind::Parameter {
                                    name: pname.clone(),
                                    index: params.len(),
                                },
                                p.trim(),
                                file_name,
                                line_no,
                            );
                            cpg.add_edge(func_id, p_id, CpgEdgeKind::AstChild { order: idx });
                            var_def_map.insert(pname.clone(), p_id);
                            params.push((pname, p_id));
                        }
                    }
                }
                functions.insert(func_name.to_string(), ParsedFunctionInfo { func_node_id: func_id, params });
                prev_stmt = Some(func_id);
                continue;
            }

            if trimmed.contains("r.URL.Query()") || trimmed.contains("r.FormValue(") || trimmed.contains("os.Args") {
                let var = trimmed
                    .split(":=")
                    .next()
                    .or_else(|| trimmed.split('=').next())
                    .unwrap_or("input")
                    .trim()
                    .to_string();
                let id = cpg.add_node(
                    CpgNodeKind::SecurityIngress {
                        source_type: "GO_HTTP_OR_CLI_INPUT".to_string(),
                        variable: var.clone(),
                    },
                    trimmed,
                    file_name,
                    line_no,
                );
                if let Some(prev) = prev_stmt {
                    cpg.add_edge(prev, id, CpgEdgeKind::CfgNext);
                }
                var_def_map.insert(var, id);
                prev_stmt = Some(id);
                continue;
            }

            if trimmed.contains("filepath.Clean(") || trimmed.contains("strconv.Atoi(") {
                if let Some(checked) = var_def_map.keys().find(|v| contains_identifier(trimmed, v)).cloned() {
                    let g_id = cpg.add_node(
                        CpgNodeKind::SanitizerGuard {
                            checked_variable: checked,
                            guard_expr: trimmed.to_string(),
                        },
                        trimmed,
                        file_name,
                        line_no,
                    );
                    if let Some(prev) = prev_stmt {
                        cpg.add_edge(prev, g_id, CpgEdgeKind::CfgNext);
                    }
                    prev_stmt = Some(g_id);
                    continue;
                }
            }

            if trimmed.contains("exec.Command(") || trimmed.contains("db.Query(") || trimmed.contains("db.Exec(") {
                let sink_type = if trimmed.contains("exec.Command") {
                    "CWE-78_COMMAND_INJECTION"
                } else {
                    "CWE-89_SQL_INJECTION"
                };
                let matching: Vec<(String, NodeId)> = var_def_map
                    .iter()
                    .filter(|(v, _)| contains_identifier(trimmed, v))
                    .map(|(k, &id)| (k.clone(), id))
                    .collect();
                let target_var = matching.first().map(|(v, _)| v.clone()).unwrap_or_else(|| "arg".to_string());
                let sink_id = cpg.add_node(
                    CpgNodeKind::SecuritySink {
                        sink_type: sink_type.to_string(),
                        target_variable: target_var,
                    },
                    trimmed,
                    file_name,
                    line_no,
                );
                if let Some(prev) = prev_stmt {
                    cpg.add_edge(prev, sink_id, CpgEdgeKind::CfgNext);
                }
                for (v, id) in matching {
                    cpg.add_edge(id, sink_id, CpgEdgeKind::DataFlow { variable: v });
                }
                prev_stmt = Some(sink_id);
                continue;
            }

            if (trimmed.contains(":=") || trimmed.contains('=')) && !trimmed.contains("==") && !trimmed.starts_with("if ") {
                let (lhs, rhs) = if let Some((l, r)) = trimmed.split_once(":=") {
                    (l, r)
                } else if let Some((l, r)) = trimmed.split_once('=') {
                    (l, r)
                } else {
                    continue;
                };
                let target_var = lhs.trim().to_string();
                let expr = rhs.trim();
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
                let matched: Vec<(String, NodeId)> = var_def_map
                    .iter()
                    .filter(|(v, _)| contains_identifier(expr, v))
                    .map(|(k, &id)| (k.clone(), id))
                    .collect();
                if !matched.is_empty() {
                    for (v, id) in matched {
                        cpg.add_edge(id, assign_id, CpgEdgeKind::DataFlow { variable: v });
                    }
                    var_def_map.insert(target_var, assign_id);
                } else {
                    var_def_map.remove(&target_var);
                }
                prev_stmt = Some(assign_id);
                continue;
            }

            if let Some((callee, args)) = extract_call_and_args(trimmed) {
                let call_id = cpg.add_node(
                    CpgNodeKind::CallExpression {
                        callee: callee.clone(),
                        arguments: args.clone(),
                    },
                    trimmed,
                    file_name,
                    line_no,
                );
                if let Some(prev) = prev_stmt {
                    cpg.add_edge(prev, call_id, CpgEdgeKind::CfgNext);
                }
                let mut tainted_args = Vec::new();
                for (idx, arg) in args.iter().enumerate() {
                    for (v, &def_id) in &var_def_map {
                        if contains_identifier(arg, v) {
                            cpg.add_edge(def_id, call_id, CpgEdgeKind::DataFlow { variable: v.clone() });
                            tainted_args.push((idx, arg.clone()));
                            break;
                        }
                    }
                }
                pending_calls.push(PendingCallSite { call_node_id: call_id, callee_name: callee, tainted_args });
                prev_stmt = Some(call_id);
            }
        }

        link_interprocedural_calls(&mut cpg, &functions, &pending_calls);
        Ok(cpg)
    }
}

/// Phase 2 parser for Java JVM applications.
pub struct JavaSourceParser;

impl JavaSourceParser {
    pub fn parse_snippet(source: &str, file_name: &str) -> Result<CodePropertyGraph> {
        let mut cpg = CodePropertyGraph::new();
        let mut prev_stmt: Option<NodeId> = None;
        let mut var_def_map: HashMap<String, NodeId> = HashMap::new();
        let mut functions: HashMap<String, ParsedFunctionInfo> = HashMap::new();
        let mut pending_calls: Vec<PendingCallSite> = Vec::new();

        for (line_idx, line) in source.lines().enumerate() {
            let line_no = line_idx + 1;
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with("//") || trimmed.starts_with("/*") {
                continue;
            }

            if (trimmed.starts_with("public ") || trimmed.starts_with("private ") || trimmed.starts_with("static "))
                && trimmed.contains('(')
                && trimmed.ends_with('{')
            {
                let open = trimmed.find('(').unwrap();
                let close = trimmed.rfind(')').unwrap_or(open);
                let func_name = trimmed[..open].split_whitespace().last().unwrap_or("method");
                let func_id = cpg.add_node(
                    CpgNodeKind::FunctionDef {
                        name: func_name.to_string(),
                        return_type: "Object".to_string(),
                    },
                    trimmed,
                    file_name,
                    line_no,
                );
                var_def_map.clear();
                let mut params = Vec::new();
                if close > open {
                    for (idx, p) in trimmed[open + 1..close].split(',').enumerate() {
                        let pname = p.split_whitespace().last().unwrap_or("").trim().to_string();
                        if !pname.is_empty() {
                            let p_id = cpg.add_node(
                                CpgNodeKind::Parameter {
                                    name: pname.clone(),
                                    index: params.len(),
                                },
                                p.trim(),
                                file_name,
                                line_no,
                            );
                            cpg.add_edge(func_id, p_id, CpgEdgeKind::AstChild { order: idx });
                            var_def_map.insert(pname.clone(), p_id);
                            params.push((pname, p_id));
                        }
                    }
                }
                functions.insert(func_name.to_string(), ParsedFunctionInfo { func_node_id: func_id, params });
                prev_stmt = Some(func_id);
                continue;
            }

            if trimmed.contains("getParameter(") || trimmed.contains("System.getenv(") {
                let var = trimmed
                    .split('=')
                    .next()
                    .unwrap_or("input")
                    .split_whitespace()
                    .last()
                    .unwrap_or("input")
                    .to_string();
                let id = cpg.add_node(
                    CpgNodeKind::SecurityIngress {
                        source_type: "JAVA_SERVLET_OR_ENV_INPUT".to_string(),
                        variable: var.clone(),
                    },
                    trimmed,
                    file_name,
                    line_no,
                );
                if let Some(prev) = prev_stmt {
                    cpg.add_edge(prev, id, CpgEdgeKind::CfgNext);
                }
                var_def_map.insert(var, id);
                prev_stmt = Some(id);
                continue;
            }

            if trimmed.contains("PreparedStatement") || trimmed.contains("setString(") {
                if let Some(checked) = var_def_map.keys().find(|v| contains_identifier(trimmed, v)).cloned() {
                    let g_id = cpg.add_node(
                        CpgNodeKind::SanitizerGuard {
                            checked_variable: checked,
                            guard_expr: trimmed.to_string(),
                        },
                        trimmed,
                        file_name,
                        line_no,
                    );
                    if let Some(prev) = prev_stmt {
                        cpg.add_edge(prev, g_id, CpgEdgeKind::CfgNext);
                    }
                    prev_stmt = Some(g_id);
                    continue;
                }
            }

            if trimmed.contains("executeQuery(") || trimmed.contains("Runtime.getRuntime().exec(") || trimmed.contains("readObject(") {
                let sink_type = if trimmed.contains("executeQuery") {
                    "CWE-89_SQL_INJECTION"
                } else if trimmed.contains("readObject") {
                    "CWE-502_DESERIALIZATION"
                } else {
                    "CWE-78_COMMAND_INJECTION"
                };
                let matching: Vec<(String, NodeId)> = var_def_map
                    .iter()
                    .filter(|(v, _)| contains_identifier(trimmed, v))
                    .map(|(k, &id)| (k.clone(), id))
                    .collect();
                let target_var = matching.first().map(|(v, _)| v.clone()).unwrap_or_else(|| "arg".to_string());
                let sink_id = cpg.add_node(
                    CpgNodeKind::SecuritySink {
                        sink_type: sink_type.to_string(),
                        target_variable: target_var,
                    },
                    trimmed,
                    file_name,
                    line_no,
                );
                if let Some(prev) = prev_stmt {
                    cpg.add_edge(prev, sink_id, CpgEdgeKind::CfgNext);
                }
                for (v, id) in matching {
                    cpg.add_edge(id, sink_id, CpgEdgeKind::DataFlow { variable: v });
                }
                prev_stmt = Some(sink_id);
                continue;
            }

            if trimmed.contains('=') && !trimmed.contains("==") && !trimmed.starts_with("if ") {
                let parts: Vec<&str> = trimmed.splitn(2, '=').collect();
                let target_var = parts[0].split_whitespace().last().unwrap_or("").trim().to_string();
                let expr = parts[1].trim_matches(';').trim();
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
                let matched: Vec<(String, NodeId)> = var_def_map
                    .iter()
                    .filter(|(v, _)| contains_identifier(expr, v))
                    .map(|(k, &id)| (k.clone(), id))
                    .collect();
                if !matched.is_empty() {
                    for (v, id) in matched {
                        cpg.add_edge(id, assign_id, CpgEdgeKind::DataFlow { variable: v });
                    }
                    if !target_var.is_empty() {
                        var_def_map.insert(target_var, assign_id);
                    }
                } else if !target_var.is_empty() {
                    var_def_map.remove(&target_var);
                }
                prev_stmt = Some(assign_id);
                continue;
            }

            if trimmed.ends_with(';') {
                if let Some((callee, args)) = extract_call_and_args(trimmed) {
                    let call_id = cpg.add_node(
                        CpgNodeKind::CallExpression {
                            callee: callee.clone(),
                            arguments: args.clone(),
                        },
                        trimmed,
                        file_name,
                        line_no,
                    );
                    if let Some(prev) = prev_stmt {
                        cpg.add_edge(prev, call_id, CpgEdgeKind::CfgNext);
                    }
                    let mut tainted_args = Vec::new();
                    for (idx, arg) in args.iter().enumerate() {
                        for (v, &def_id) in &var_def_map {
                            if contains_identifier(arg, v) {
                                cpg.add_edge(def_id, call_id, CpgEdgeKind::DataFlow { variable: v.clone() });
                                tainted_args.push((idx, arg.clone()));
                                break;
                            }
                        }
                    }
                    pending_calls.push(PendingCallSite { call_node_id: call_id, callee_name: callee, tainted_args });
                    prev_stmt = Some(call_id);
                }
            }
        }

        link_interprocedural_calls(&mut cpg, &functions, &pending_calls);
        Ok(cpg)
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
