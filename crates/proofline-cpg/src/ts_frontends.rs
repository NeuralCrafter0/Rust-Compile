//! Tree-sitter CST/AST CPG builders for C, Python, and Rust.

use crate::{
    link_interprocedural_calls, CodePropertyGraph, CpgEdgeKind, CpgNodeKind, NodeId,
    ParsedFunctionInfo, PendingCallSite,
};
use proofline_core::{ProoflineError, Result};
use std::collections::HashMap;
use tree_sitter::{Node, Parser};

fn node_text<'a>(node: Node, src: &'a [u8]) -> &'a str {
    node.utf8_text(src).unwrap_or("")
}

fn collect_identifiers(node: Node, src: &[u8], out: &mut Vec<String>) {
    if matches!(
        node.kind(),
        "identifier" | "field_identifier" | "type_identifier"
    ) {
        let name = node_text(node, src).trim();
        if !name.is_empty() && !out.iter().any(|s| s == name) {
            out.push(name.to_string());
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_identifiers(child, src, out);
    }
}

fn find_first_call<'a>(node: Node<'a>) -> Option<Node<'a>> {
    if node.kind() == "call_expression" || node.kind() == "call" {
        return Some(node);
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if let Some(found) = find_first_call(child) {
            return Some(found);
        }
    }
    None
}

fn collect_calls<'a>(node: Node<'a>, out: &mut Vec<Node<'a>>) {
    if node.kind() == "call_expression" || node.kind() == "call" {
        out.push(node);
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_calls(child, out);
    }
}

// ================================
// C Tree-sitter CPG Builder
// ================================

pub fn parse_c_with_treesitter(source: &str, file_name: &str) -> Result<CodePropertyGraph> {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_c::LANGUAGE.into())
        .map_err(|e| ProoflineError::ParseFailure(format!("Failed loading C grammar: {}", e)))?;
    let tree = parser
        .parse(source, None)
        .ok_or_else(|| ProoflineError::ParseFailure("Tree-sitter C parse returned None".to_string()))?;

    let src = source.as_bytes();
    let mut builder = CBuilder {
        cpg: CodePropertyGraph::new(),
        src,
        file_name,
        functions: HashMap::new(),
        pending_calls: Vec::new(),
    };
    builder.visit_root(tree.root_node());
    let mut cpg = builder.cpg;
    link_interprocedural_calls(&mut cpg, &builder.functions, &builder.pending_calls);
    Ok(cpg)
}

struct CBuilder<'a> {
    cpg: CodePropertyGraph,
    src: &'a [u8],
    file_name: &'a str,
    functions: HashMap<String, ParsedFunctionInfo>,
    pending_calls: Vec<PendingCallSite>,
}

impl<'a> CBuilder<'a> {
    fn visit_root(&mut self, root: Node) {
        let mut cursor = root.walk();
        for child in root.children(&mut cursor) {
            if child.kind() == "function_definition" {
                self.visit_function(child);
            } else {
                // Handle top-level declarations/statements if snippet lacks function wrapper
                let mut local_vars = HashMap::new();
                let mut prev = None;
                self.visit_c_node(child, &mut local_vars, &mut prev, None);
            }
        }
    }

    fn visit_function(&mut self, func_node: Node) {
        let line_no = func_node.start_position().row + 1;
        let header_text = node_text(func_node, self.src)
            .lines()
            .next()
            .unwrap_or("")
            .trim()
            .to_string();

        let decl = func_node.child_by_field_name("declarator");
        let func_name = decl
            .and_then(|d| self.extract_c_fn_name(d))
            .unwrap_or_else(|| "func".to_string());

        let func_id = self.cpg.add_node(
            CpgNodeKind::FunctionDef {
                name: func_name.clone(),
                return_type: "int".to_string(),
            },
            header_text,
            self.file_name,
            line_no,
        );

        let mut var_def_map = HashMap::new();
        let mut params = Vec::new();

        if let Some(d) = decl {
            if let Some(plist) = self.find_parameter_list(d) {
                let mut cursor = plist.walk();
                for param in plist.children(&mut cursor) {
                    if param.kind() == "parameter_declaration" {
                        let p_text = node_text(param, self.src).trim();
                        if p_text == "void" || p_text.is_empty() {
                            continue;
                        }
                        if let Some(p_decl) = param.child_by_field_name("declarator") {
                            if let Some(pname) = self.extract_c_ident(p_decl) {
                                let idx = params.len();
                                let p_id = self.cpg.add_node(
                                    CpgNodeKind::Parameter {
                                        name: pname.clone(),
                                        index: idx,
                                    },
                                    p_text,
                                    self.file_name,
                                    param.start_position().row + 1,
                                );
                                self.cpg
                                    .add_edge(func_id, p_id, CpgEdgeKind::AstChild { order: idx });
                                var_def_map.insert(pname.clone(), p_id);
                                params.push((pname, p_id));
                            }
                        }
                    }
                }
            }
        }

        self.functions.insert(
            func_name,
            ParsedFunctionInfo {
                func_node_id: func_id,
                params,
            },
        );

        let mut prev_stmt = Some(func_id);
        if let Some(body) = func_node.child_by_field_name("body") {
            self.visit_c_node(body, &mut var_def_map, &mut prev_stmt, Some(func_id));
        }
    }

    fn visit_c_node(
        &mut self,
        node: Node,
        var_def_map: &mut HashMap<String, NodeId>,
        prev_stmt: &mut Option<NodeId>,
        parent_fn: Option<NodeId>,
    ) {
        match node.kind() {
            "compound_statement" | "translation_unit" => {
                let mut cursor = node.walk();
                for child in node.children(&mut cursor) {
                    self.visit_c_node(child, var_def_map, prev_stmt, parent_fn);
                }
            }
            "declaration" => {
                self.handle_c_declaration(node, var_def_map, prev_stmt, parent_fn);
            }
            "expression_statement" => {
                let mut cursor = node.walk();
                for child in node.children(&mut cursor) {
                    if child.kind() == "assignment_expression" {
                        self.handle_c_assignment(child, var_def_map, prev_stmt, parent_fn);
                    } else if child.kind() == "call_expression" {
                        self.handle_c_call(child, None, var_def_map, prev_stmt, parent_fn);
                    }
                }
            }
            "return_statement" => {
                let mut calls = Vec::new();
                collect_calls(node, &mut calls);
                for call in calls {
                    self.handle_c_call(call, None, var_def_map, prev_stmt, parent_fn);
                }
            }
            "if_statement" => {
                let line_no = node.start_position().row + 1;
                let text = node_text(node, self.src).lines().next().unwrap_or("").trim();
                if let Some(cond) = node.child_by_field_name("condition") {
                    let cond_text = node_text(cond, self.src);
                    // Handle ingress calls inside conditions (e.g., `if (fgets(buf, sizeof(buf), stdin) == NULL)`)
                    let mut cond_calls = Vec::new();
                    collect_calls(cond, &mut cond_calls);
                    let mut had_ingress_call = false;
                    for ccall in &cond_calls {
                        let callee = ccall
                            .child_by_field_name("function")
                            .map(|f| node_text(f, self.src))
                            .unwrap_or("");
                        if matches!(callee, "fgets" | "read" | "recv" | "getenv") {
                            self.handle_c_call(*ccall, None, var_def_map, prev_stmt, parent_fn);
                            had_ingress_call = true;
                        }
                    }

                    if !had_ingress_call
                        && (cond_text.contains('<')
                            || cond_text.contains('>')
                            || cond_text.contains("sizeof"))
                    {
                        let mut cond_idents = Vec::new();
                        collect_identifiers(cond, self.src, &mut cond_idents);
                        if let Some(checked) = cond_idents
                            .into_iter()
                            .find(|id| var_def_map.contains_key(id))
                        {
                            let guard_id = self.cpg.add_node(
                                CpgNodeKind::SanitizerGuard {
                                    checked_variable: checked,
                                    guard_expr: text.to_string(),
                                },
                                text,
                                self.file_name,
                                line_no,
                            );
                            self.link_stmt(guard_id, prev_stmt, parent_fn);
                        } else {
                            let b_id = self.cpg.add_node(
                                CpgNodeKind::BranchCondition {
                                    condition_expr: text.to_string(),
                                },
                                text,
                                self.file_name,
                                line_no,
                            );
                            self.link_stmt(b_id, prev_stmt, parent_fn);
                        }
                    }
                }
                if let Some(cons) = node.child_by_field_name("consequence") {
                    self.visit_c_node(cons, var_def_map, prev_stmt, parent_fn);
                }
                if let Some(alt) = node.child_by_field_name("alternative") {
                    self.visit_c_node(alt, var_def_map, prev_stmt, parent_fn);
                }
            }
            "while_statement" | "for_statement" | "else_clause" => {
                let mut cursor = node.walk();
                for child in node.children(&mut cursor) {
                    if matches!(
                        child.kind(),
                        "compound_statement"
                            | "expression_statement"
                            | "if_statement"
                            | "return_statement"
                    ) {
                        self.visit_c_node(child, var_def_map, prev_stmt, parent_fn);
                    }
                }
            }
            "function_definition" => self.visit_function(node),
            _ => {}
        }
    }

    fn handle_c_declaration(
        &mut self,
        decl_node: Node,
        var_def_map: &mut HashMap<String, NodeId>,
        prev_stmt: &mut Option<NodeId>,
        parent_fn: Option<NodeId>,
    ) {
        let full_text = node_text(decl_node, self.src).trim();
        let line_no = decl_node.start_position().row + 1;
        let mut cursor = decl_node.walk();
        for child in decl_node.children(&mut cursor) {
            if child.kind() == "init_declarator" {
                let target = child
                    .child_by_field_name("declarator")
                    .and_then(|d| self.extract_c_ident(d))
                    .unwrap_or_default();
                if let Some(val) = child.child_by_field_name("value") {
                    if let Some(call) = find_first_call(val) {
                        let callee = call
                            .child_by_field_name("function")
                            .map(|f| node_text(f, self.src))
                            .unwrap_or("");
                        if matches!(callee, "fgets" | "getenv" | "read" | "recv") {
                            self.handle_c_call(
                                call,
                                Some(target),
                                var_def_map,
                                prev_stmt,
                                parent_fn,
                            );
                            continue;
                        }
                    }
                    let val_text = node_text(val, self.src).trim();
                    let assign_id = self.cpg.add_node(
                        CpgNodeKind::Assignment {
                            target: target.clone(),
                            value_expr: val_text.to_string(),
                        },
                        full_text,
                        self.file_name,
                        line_no,
                    );
                    self.link_stmt(assign_id, prev_stmt, parent_fn);

                    let mut rhs_idents = Vec::new();
                    collect_identifiers(val, self.src, &mut rhs_idents);
                    let mut tainted = false;
                    for id in rhs_idents {
                        if let Some(&def_id) = var_def_map.get(&id) {
                            self.cpg.add_edge(
                                def_id,
                                assign_id,
                                CpgEdgeKind::DataFlow { variable: id },
                            );
                            tainted = true;
                        }
                    }
                    if !target.is_empty() {
                        if tainted {
                            var_def_map.insert(target, assign_id);
                        } else {
                            var_def_map.remove(&target);
                        }
                    }
                }
            }
        }
    }

    fn handle_c_assignment(
        &mut self,
        assign_node: Node,
        var_def_map: &mut HashMap<String, NodeId>,
        prev_stmt: &mut Option<NodeId>,
        parent_fn: Option<NodeId>,
    ) {
        let full_text = node_text(assign_node, self.src).trim();
        let line_no = assign_node.start_position().row + 1;
        let target = assign_node
            .child_by_field_name("left")
            .and_then(|l| self.extract_c_ident(l))
            .unwrap_or_default();
        if let Some(right) = assign_node.child_by_field_name("right") {
            if let Some(call) = find_first_call(right) {
                let callee = call
                    .child_by_field_name("function")
                    .map(|f| node_text(f, self.src))
                    .unwrap_or("");
                if matches!(callee, "fgets" | "getenv" | "read" | "recv") {
                    self.handle_c_call(call, Some(target), var_def_map, prev_stmt, parent_fn);
                    return;
                }
            }

            let val_text = node_text(right, self.src).trim();
            let assign_id = self.cpg.add_node(
                CpgNodeKind::Assignment {
                    target: target.clone(),
                    value_expr: val_text.to_string(),
                },
                full_text,
                self.file_name,
                line_no,
            );
            self.link_stmt(assign_id, prev_stmt, parent_fn);

            let mut rhs_idents = Vec::new();
            collect_identifiers(right, self.src, &mut rhs_idents);
            let mut tainted = false;
            for id in rhs_idents {
                if let Some(&def_id) = var_def_map.get(&id) {
                    self.cpg
                        .add_edge(def_id, assign_id, CpgEdgeKind::DataFlow { variable: id });
                    tainted = true;
                }
            }
            if !target.is_empty() {
                if tainted {
                    var_def_map.insert(target, assign_id);
                } else {
                    var_def_map.remove(&target);
                }
            }
        }
    }

    fn handle_c_call(
        &mut self,
        call_node: Node,
        assigned_lhs: Option<String>,
        var_def_map: &mut HashMap<String, NodeId>,
        prev_stmt: &mut Option<NodeId>,
        parent_fn: Option<NodeId>,
    ) {
        let full_text = node_text(call_node, self.src).trim();
        let line_no = call_node.start_position().row + 1;
        let callee = call_node
            .child_by_field_name("function")
            .map(|f| node_text(f, self.src).trim().to_string())
            .unwrap_or_default();

        let mut arg_nodes = Vec::new();
        if let Some(arg_list) = call_node.child_by_field_name("arguments") {
            let mut cursor = arg_list.walk();
            for ch in arg_list.named_children(&mut cursor) {
                arg_nodes.push(ch);
            }
        }

        // Ingress calls
        if matches!(callee.as_str(), "fgets" | "read" | "recv" | "getenv") {
            let var_name = match callee.as_str() {
                "fgets" => arg_nodes
                    .first()
                    .and_then(|n| self.extract_c_ident(*n))
                    .unwrap_or_else(|| "buf".to_string()),
                "read" | "recv" => arg_nodes
                    .get(1)
                    .and_then(|n| self.extract_c_ident(*n))
                    .unwrap_or_else(|| "buf".to_string()),
                _ => assigned_lhs.unwrap_or_else(|| "input".to_string()),
            };
            let ingress_id = self.cpg.add_node(
                CpgNodeKind::SecurityIngress {
                    source_type: "UNTRUSTED_INPUT_BUFFER".to_string(),
                    variable: var_name.clone(),
                },
                full_text,
                self.file_name,
                line_no,
            );
            self.link_stmt(ingress_id, prev_stmt, parent_fn);
            var_def_map.insert(var_name, ingress_id);
            return;
        }

        // Dangerous memory/command sinks
        if matches!(
            callee.as_str(),
            "strcpy" | "strcat" | "memcpy" | "sprintf" | "gets" | "system"
        ) {
            let (sink_type, source_args): (&str, &[Node]) = match callee.as_str() {
                "system" => ("CWE-78_COMMAND_INJECTION", &arg_nodes),
                "gets" => ("CWE-119_UNBOUNDED_COPY", &arg_nodes),
                _ => (
                    "CWE-119_UNBOUNDED_COPY",
                    if arg_nodes.len() > 1 {
                        &arg_nodes[1..]
                    } else {
                        &arg_nodes
                    },
                ),
            };
            let mut src_idents = Vec::new();
            for arg in source_args {
                collect_identifiers(*arg, self.src, &mut src_idents);
            }
            let target_var = src_idents
                .iter()
                .find(|id| var_def_map.contains_key(*id))
                .cloned()
                .or_else(|| src_idents.first().cloned())
                .unwrap_or_else(|| "target".to_string());

            let sink_id = self.cpg.add_node(
                CpgNodeKind::SecuritySink {
                    sink_type: sink_type.to_string(),
                    target_variable: target_var,
                },
                full_text,
                self.file_name,
                line_no,
            );
            self.link_stmt(sink_id, prev_stmt, parent_fn);

            for id in src_idents {
                if let Some(&def_id) = var_def_map.get(&id) {
                    self.cpg
                        .add_edge(def_id, sink_id, CpgEdgeKind::DataFlow { variable: id });
                }
            }
            return;
        }

        // Interprocedural call site
        let arg_texts: Vec<String> = arg_nodes
            .iter()
            .map(|a| node_text(*a, self.src).trim().to_string())
            .collect();
        let call_id = self.cpg.add_node(
            CpgNodeKind::CallExpression {
                callee: callee.clone(),
                arguments: arg_texts,
            },
            full_text,
            self.file_name,
            line_no,
        );
        self.link_stmt(call_id, prev_stmt, parent_fn);

        let mut tainted_args = Vec::new();
        for (idx, arg) in arg_nodes.iter().enumerate() {
            let mut idents = Vec::new();
            collect_identifiers(*arg, self.src, &mut idents);
            for id in idents {
                if let Some(&def_id) = var_def_map.get(&id) {
                    self.cpg
                        .add_edge(def_id, call_id, CpgEdgeKind::DataFlow { variable: id });
                    tainted_args.push((idx, node_text(*arg, self.src).trim().to_string()));
                    break;
                }
            }
        }
        self.pending_calls.push(PendingCallSite {
            call_node_id: call_id,
            callee_name: callee,
            tainted_args,
        });
    }

    fn link_stmt(
        &mut self,
        node_id: NodeId,
        prev_stmt: &mut Option<NodeId>,
        parent_fn: Option<NodeId>,
    ) {
        if let Some(prev) = *prev_stmt {
            self.cpg.add_edge(prev, node_id, CpgEdgeKind::CfgNext);
        }
        if let Some(fn_id) = parent_fn {
            let order = self.cpg.outgoing_edges(fn_id).len();
            self.cpg
                .add_edge(fn_id, node_id, CpgEdgeKind::AstChild { order });
        }
        *prev_stmt = Some(node_id);
    }

    fn extract_c_fn_name(&self, decl: Node) -> Option<String> {
        if decl.kind() == "function_declarator" {
            if let Some(inner) = decl.child_by_field_name("declarator") {
                return Some(node_text(inner, self.src).trim().to_string());
            }
        }
        let mut cursor = decl.walk();
        for child in decl.children(&mut cursor) {
            if let Some(found) = self.extract_c_fn_name(child) {
                return Some(found);
            }
        }
        None
    }

    fn find_parameter_list<'b>(&self, decl: Node<'b>) -> Option<Node<'b>> {
        if decl.kind() == "parameter_list" {
            return Some(decl);
        }
        let mut cursor = decl.walk();
        for child in decl.children(&mut cursor) {
            if let Some(found) = self.find_parameter_list(child) {
                return Some(found);
            }
        }
        None
    }

    fn extract_c_ident(&self, node: Node) -> Option<String> {
        if node.kind() == "identifier" {
            return Some(node_text(node, self.src).trim().to_string());
        }
        if let Some(inner) = node.child_by_field_name("declarator") {
            return self.extract_c_ident(inner);
        }
        if let Some(arg) = node.child_by_field_name("argument") {
            return self.extract_c_ident(arg);
        }
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if let Some(found) = self.extract_c_ident(child) {
                return Some(found);
            }
        }
        None
    }
}

// ================================
// Python Tree-sitter CPG Builder
// ================================

pub fn parse_python_with_treesitter(source: &str, file_name: &str) -> Result<CodePropertyGraph> {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_python::LANGUAGE.into())
        .map_err(|e| ProoflineError::ParseFailure(format!("Failed loading Python grammar: {}", e)))?;
    let tree = parser
        .parse(source, None)
        .ok_or_else(|| ProoflineError::ParseFailure("Tree-sitter Python parse returned None".to_string()))?;

    let src = source.as_bytes();
    let mut builder = PyBuilder {
        cpg: CodePropertyGraph::new(),
        src,
        file_name,
        functions: HashMap::new(),
        pending_calls: Vec::new(),
    };
    let mut top_vars = HashMap::new();
    let mut prev = None;
    builder.visit_py_node(tree.root_node(), &mut top_vars, &mut prev, None);
    let mut cpg = builder.cpg;
    link_interprocedural_calls(&mut cpg, &builder.functions, &builder.pending_calls);
    Ok(cpg)
}

struct PyBuilder<'a> {
    cpg: CodePropertyGraph,
    src: &'a [u8],
    file_name: &'a str,
    functions: HashMap<String, ParsedFunctionInfo>,
    pending_calls: Vec<PendingCallSite>,
}

impl<'a> PyBuilder<'a> {
    fn visit_py_node(
        &mut self,
        node: Node,
        var_def_map: &mut HashMap<String, NodeId>,
        prev_stmt: &mut Option<NodeId>,
        parent_fn: Option<NodeId>,
    ) {
        match node.kind() {
            "module" | "block" => {
                let mut cursor = node.walk();
                for ch in node.children(&mut cursor) {
                    self.visit_py_node(ch, var_def_map, prev_stmt, parent_fn);
                }
            }
            "function_definition" => {
                let line_no = node.start_position().row + 1;
                let func_name = node
                    .child_by_field_name("name")
                    .map(|n| node_text(n, self.src).trim().to_string())
                    .unwrap_or_else(|| "func".to_string());
                let header = node_text(node, self.src).lines().next().unwrap_or("").trim();
                let fn_id = self.cpg.add_node(
                    CpgNodeKind::FunctionDef {
                        name: func_name.clone(),
                        return_type: "Any".to_string(),
                    },
                    header,
                    self.file_name,
                    line_no,
                );
                let mut local_vars = HashMap::new();
                let mut params = Vec::new();
                if let Some(plist) = node.child_by_field_name("parameters") {
                    let mut idents = Vec::new();
                    let mut cursor = plist.walk();
                    for ch in plist.named_children(&mut cursor) {
                        idents.clear();
                        collect_identifiers(ch, self.src, &mut idents);
                        if let Some(pname) = idents.first() {
                            if pname != "self" {
                                let idx = params.len();
                                let p_id = self.cpg.add_node(
                                    CpgNodeKind::Parameter {
                                        name: pname.clone(),
                                        index: idx,
                                    },
                                    node_text(ch, self.src).trim(),
                                    self.file_name,
                                    ch.start_position().row + 1,
                                );
                                self.cpg.add_edge(fn_id, p_id, CpgEdgeKind::AstChild { order: idx });
                                local_vars.insert(pname.clone(), p_id);
                                params.push((pname.clone(), p_id));
                            }
                        }
                    }
                }
                self.functions.insert(
                    func_name,
                    ParsedFunctionInfo {
                        func_node_id: fn_id,
                        params,
                    },
                );
                let mut fn_prev = Some(fn_id);
                if let Some(body) = node.child_by_field_name("body") {
                    self.visit_py_node(body, &mut local_vars, &mut fn_prev, Some(fn_id));
                }
            }
            "expression_statement" => {
                let mut cursor = node.walk();
                for ch in node.children(&mut cursor) {
                    self.visit_py_node(ch, var_def_map, prev_stmt, parent_fn);
                }
            }
            "assignment" => {
                let full_text = node_text(node, self.src).trim();
                let line_no = node.start_position().row + 1;
                let target_var = node
                    .child_by_field_name("left")
                    .map(|l| node_text(l, self.src).trim().to_string())
                    .unwrap_or_else(|| "user_input".to_string());
                if let Some(right) = node.child_by_field_name("right") {
                    let right_text = node_text(right, self.src).trim();
                    if right_text.contains("request.args.get")
                        || right_text.contains("request.form")
                        || right_text.contains("input(")
                        || right_text.contains("sys.stdin")
                    {
                        let ingress_id = self.cpg.add_node(
                            CpgNodeKind::SecurityIngress {
                                source_type: "UNTRUSTED_WEB_PARAM".to_string(),
                                variable: target_var.clone(),
                            },
                            full_text,
                            self.file_name,
                            line_no,
                        );
                        self.link_stmt(ingress_id, prev_stmt, parent_fn);
                        var_def_map.insert(target_var, ingress_id);
                        return;
                    }

                    let assign_id = self.cpg.add_node(
                        CpgNodeKind::Assignment {
                            target: target_var.clone(),
                            value_expr: right_text.to_string(),
                        },
                        full_text,
                        self.file_name,
                        line_no,
                    );
                    self.link_stmt(assign_id, prev_stmt, parent_fn);

                    let mut idents = Vec::new();
                    collect_identifiers(right, self.src, &mut idents);
                    let mut tainted = false;
                    for id in idents {
                        if let Some(&def_id) = var_def_map.get(&id) {
                            self.cpg
                                .add_edge(def_id, assign_id, CpgEdgeKind::DataFlow { variable: id });
                            tainted = true;
                        }
                    }
                    if tainted {
                        var_def_map.insert(target_var, assign_id);
                    } else {
                        var_def_map.remove(&target_var);
                    }
                }
            }
            "call" => {
                let full_text = node_text(node, self.src).trim();
                let line_no = node.start_position().row + 1;
                let callee = node
                    .child_by_field_name("function")
                    .map(|f| node_text(f, self.src).trim().to_string())
                    .unwrap_or_default();

                let mut arg_nodes = Vec::new();
                if let Some(alist) = node.child_by_field_name("arguments") {
                    let mut cursor = alist.walk();
                    for ch in alist.named_children(&mut cursor) {
                        arg_nodes.push(ch);
                    }
                }

                let is_parameterized_sql = callee == "cursor.execute" && arg_nodes.len() >= 2;
                if matches!(callee.as_str(), "isinstance" | "sanitize") || is_parameterized_sql {
                    let mut idents = Vec::new();
                    collect_identifiers(node, self.src, &mut idents);
                    if let Some(checked) = idents.into_iter().find(|id| var_def_map.contains_key(id))
                    {
                        let g_id = self.cpg.add_node(
                            CpgNodeKind::SanitizerGuard {
                                checked_variable: checked,
                                guard_expr: full_text.to_string(),
                            },
                            full_text,
                            self.file_name,
                            line_no,
                        );
                        self.link_stmt(g_id, prev_stmt, parent_fn);
                        return;
                    }
                }

                if matches!(callee.as_str(), "cursor.execute" | "eval" | "os.system") {
                    let sink_type = match callee.as_str() {
                        "cursor.execute" => "CWE-89_SQL_INJECTION",
                        "os.system" => "CWE-78_COMMAND_INJECTION",
                        _ => "CWE-95_CODE_INJECTION",
                    };
                    let mut idents = Vec::new();
                    for a in &arg_nodes {
                        collect_identifiers(*a, self.src, &mut idents);
                    }
                    let target_var = idents
                        .iter()
                        .find(|id| var_def_map.contains_key(*id))
                        .cloned()
                        .unwrap_or_else(|| "query".to_string());
                    let sink_id = self.cpg.add_node(
                        CpgNodeKind::SecuritySink {
                            sink_type: sink_type.to_string(),
                            target_variable: target_var,
                        },
                        full_text,
                        self.file_name,
                        line_no,
                    );
                    self.link_stmt(sink_id, prev_stmt, parent_fn);
                    for id in idents {
                        if let Some(&def_id) = var_def_map.get(&id) {
                            self.cpg
                                .add_edge(def_id, sink_id, CpgEdgeKind::DataFlow { variable: id });
                        }
                    }
                    return;
                }

                let arg_texts: Vec<String> = arg_nodes
                    .iter()
                    .map(|a| node_text(*a, self.src).trim().to_string())
                    .collect();
                let call_id = self.cpg.add_node(
                    CpgNodeKind::CallExpression {
                        callee: callee.clone(),
                        arguments: arg_texts,
                    },
                    full_text,
                    self.file_name,
                    line_no,
                );
                self.link_stmt(call_id, prev_stmt, parent_fn);
                let mut tainted_args = Vec::new();
                for (idx, a) in arg_nodes.iter().enumerate() {
                    let mut idents = Vec::new();
                    collect_identifiers(*a, self.src, &mut idents);
                    for id in idents {
                        if let Some(&def_id) = var_def_map.get(&id) {
                            self.cpg
                                .add_edge(def_id, call_id, CpgEdgeKind::DataFlow { variable: id });
                            tainted_args.push((idx, node_text(*a, self.src).trim().to_string()));
                            break;
                        }
                    }
                }
                self.pending_calls.push(PendingCallSite {
                    call_node_id: call_id,
                    callee_name: callee,
                    tainted_args,
                });
            }
            "if_statement" | "return_statement" => {
                let mut cursor = node.walk();
                for ch in node.named_children(&mut cursor) {
                    self.visit_py_node(ch, var_def_map, prev_stmt, parent_fn);
                }
            }
            _ => {}
        }
    }

    fn link_stmt(
        &mut self,
        node_id: NodeId,
        prev_stmt: &mut Option<NodeId>,
        parent_fn: Option<NodeId>,
    ) {
        if let Some(prev) = *prev_stmt {
            self.cpg.add_edge(prev, node_id, CpgEdgeKind::CfgNext);
        }
        if let Some(fn_id) = parent_fn {
            let order = self.cpg.outgoing_edges(fn_id).len();
            self.cpg
                .add_edge(fn_id, node_id, CpgEdgeKind::AstChild { order });
        }
        *prev_stmt = Some(node_id);
    }
}

// ================================
// Rust Tree-sitter CPG Builder
// ================================

pub fn parse_rust_with_treesitter(source: &str, file_name: &str) -> Result<CodePropertyGraph> {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_rust::LANGUAGE.into())
        .map_err(|e| ProoflineError::ParseFailure(format!("Failed loading Rust grammar: {}", e)))?;
    let tree = parser
        .parse(source, None)
        .ok_or_else(|| ProoflineError::ParseFailure("Tree-sitter Rust parse returned None".to_string()))?;

    let src = source.as_bytes();
    let mut builder = RustBuilder {
        cpg: CodePropertyGraph::new(),
        src,
        file_name,
        functions: HashMap::new(),
        pending_calls: Vec::new(),
    };
    let mut top_vars = HashMap::new();
    let mut prev = None;
    builder.visit_rs_node(tree.root_node(), &mut top_vars, &mut prev, None);
    let mut cpg = builder.cpg;
    link_interprocedural_calls(&mut cpg, &builder.functions, &builder.pending_calls);
    Ok(cpg)
}

struct RustBuilder<'a> {
    cpg: CodePropertyGraph,
    src: &'a [u8],
    file_name: &'a str,
    functions: HashMap<String, ParsedFunctionInfo>,
    pending_calls: Vec<PendingCallSite>,
}

impl<'a> RustBuilder<'a> {
    fn visit_rs_node(
        &mut self,
        node: Node,
        var_def_map: &mut HashMap<String, NodeId>,
        prev_stmt: &mut Option<NodeId>,
        parent_fn: Option<NodeId>,
    ) {
        match node.kind() {
            "source_file" | "block" => {
                let mut cursor = node.walk();
                for ch in node.children(&mut cursor) {
                    self.visit_rs_node(ch, var_def_map, prev_stmt, parent_fn);
                }
            }
            "function_item" => {
                let line_no = node.start_position().row + 1;
                let func_name = node
                    .child_by_field_name("name")
                    .map(|n| node_text(n, self.src).trim().to_string())
                    .unwrap_or_else(|| "fn".to_string());
                let header = node_text(node, self.src).lines().next().unwrap_or("").trim();
                let fn_id = self.cpg.add_node(
                    CpgNodeKind::FunctionDef {
                        name: func_name.clone(),
                        return_type: "Result".to_string(),
                    },
                    header,
                    self.file_name,
                    line_no,
                );
                let mut local_vars = HashMap::new();
                let mut params = Vec::new();
                if let Some(plist) = node.child_by_field_name("parameters") {
                    let mut cursor = plist.walk();
                    for ch in plist.named_children(&mut cursor) {
                        if ch.kind() == "parameter" {
                            if let Some(pat) = ch.child_by_field_name("pattern") {
                                let pname = node_text(pat, self.src)
                                    .trim()
                                    .trim_start_matches("mut ")
                                    .to_string();
                                if !pname.is_empty() && !pname.contains("self") {
                                    let idx = params.len();
                                    let p_id = self.cpg.add_node(
                                        CpgNodeKind::Parameter {
                                            name: pname.clone(),
                                            index: idx,
                                        },
                                        node_text(ch, self.src).trim(),
                                        self.file_name,
                                        ch.start_position().row + 1,
                                    );
                                    self.cpg
                                        .add_edge(fn_id, p_id, CpgEdgeKind::AstChild { order: idx });
                                    local_vars.insert(pname.clone(), p_id);
                                    params.push((pname, p_id));
                                }
                            }
                        }
                    }
                }
                self.functions.insert(
                    func_name,
                    ParsedFunctionInfo {
                        func_node_id: fn_id,
                        params,
                    },
                );
                let mut fn_prev = Some(fn_id);
                if let Some(body) = node.child_by_field_name("body") {
                    self.visit_rs_node(body, &mut local_vars, &mut fn_prev, Some(fn_id));
                }
            }
            "let_declaration" => {
                let full_text = node_text(node, self.src).trim();
                let line_no = node.start_position().row + 1;
                let target_var = node
                    .child_by_field_name("pattern")
                    .map(|p| {
                        node_text(p, self.src)
                            .trim()
                            .trim_start_matches("mut ")
                            .to_string()
                    })
                    .unwrap_or_default();
                if let Some(val) = node.child_by_field_name("value") {
                    let val_text = node_text(val, self.src).trim();
                    if val_text.contains("env::var")
                        || val_text.contains("env::args")
                        || val_text.contains("stdin(")
                        || val_text.contains("read_line(")
                    {
                        let ingress_id = self.cpg.add_node(
                            CpgNodeKind::SecurityIngress {
                                source_type: "RUST_UNTRUSTED_INPUT".to_string(),
                                variable: target_var.clone(),
                            },
                            full_text,
                            self.file_name,
                            line_no,
                        );
                        self.link_stmt(ingress_id, prev_stmt, parent_fn);
                        if !target_var.is_empty() {
                            var_def_map.insert(target_var, ingress_id);
                        }
                        return;
                    }

                    let assign_id = self.cpg.add_node(
                        CpgNodeKind::Assignment {
                            target: target_var.clone(),
                            value_expr: val_text.to_string(),
                        },
                        full_text,
                        self.file_name,
                        line_no,
                    );
                    self.link_stmt(assign_id, prev_stmt, parent_fn);
                    let mut idents = Vec::new();
                    collect_identifiers(val, self.src, &mut idents);
                    let mut tainted = false;
                    for id in idents {
                        if let Some(&def_id) = var_def_map.get(&id) {
                            self.cpg
                                .add_edge(def_id, assign_id, CpgEdgeKind::DataFlow { variable: id });
                            tainted = true;
                        }
                    }
                    if !target_var.is_empty() {
                        if tainted {
                            var_def_map.insert(target_var, assign_id);
                        } else {
                            var_def_map.remove(&target_var);
                        }
                    }
                }
            }
            "expression_statement" => {
                let mut cursor = node.walk();
                for ch in node.children(&mut cursor) {
                    self.visit_rs_node(ch, var_def_map, prev_stmt, parent_fn);
                }
            }
            "if_expression" => {
                let line_no = node.start_position().row + 1;
                let text = node_text(node, self.src).lines().next().unwrap_or("").trim();
                if let Some(cond) = node.child_by_field_name("condition") {
                    let cond_text = node_text(cond, self.src);
                    if cond_text.contains('<')
                        || cond_text.contains("is_empty")
                        || cond_text.contains("contains(")
                    {
                        let mut idents = Vec::new();
                        collect_identifiers(cond, self.src, &mut idents);
                        if let Some(checked) =
                            idents.into_iter().find(|id| var_def_map.contains_key(id))
                        {
                            let g_id = self.cpg.add_node(
                                CpgNodeKind::SanitizerGuard {
                                    checked_variable: checked,
                                    guard_expr: text.to_string(),
                                },
                                text,
                                self.file_name,
                                line_no,
                            );
                            self.link_stmt(g_id, prev_stmt, parent_fn);
                        }
                    }
                }
                if let Some(cons) = node.child_by_field_name("consequence") {
                    self.visit_rs_node(cons, var_def_map, prev_stmt, parent_fn);
                }
                if let Some(alt) = node.child_by_field_name("alternative") {
                    self.visit_rs_node(alt, var_def_map, prev_stmt, parent_fn);
                }
            }
            "unsafe_block" => {
                let text = node_text(node, self.src).trim();
                let line_no = node.start_position().row + 1;
                let mut idents = Vec::new();
                collect_identifiers(node, self.src, &mut idents);
                let target_var = idents
                    .iter()
                    .find(|id| var_def_map.contains_key(*id))
                    .cloned()
                    .unwrap_or_else(|| "unsafe_op".to_string());
                let sink_id = self.cpg.add_node(
                    CpgNodeKind::SecuritySink {
                        sink_type: "RUST_UNSAFE_MEMORY_BOUNDARY".to_string(),
                        target_variable: target_var,
                    },
                    text,
                    self.file_name,
                    line_no,
                );
                self.link_stmt(sink_id, prev_stmt, parent_fn);
                for id in idents {
                    if let Some(&def_id) = var_def_map.get(&id) {
                        self.cpg
                            .add_edge(def_id, sink_id, CpgEdgeKind::DataFlow { variable: id });
                    }
                }
            }
            "call_expression" => {
                let full_text = node_text(node, self.src).trim();
                let line_no = node.start_position().row + 1;
                let callee = node
                    .child_by_field_name("function")
                    .map(|f| node_text(f, self.src).trim().to_string())
                    .unwrap_or_default();

                let mut arg_nodes = Vec::new();
                if let Some(alist) = node.child_by_field_name("arguments") {
                    let mut cursor = alist.walk();
                    for ch in alist.named_children(&mut cursor) {
                        arg_nodes.push(ch);
                    }
                }

                if callee == "Command::new"
                    || callee.ends_with("::ptr::copy")
                    || callee.contains("from_raw_parts")
                {
                    let sink_type = if callee == "Command::new" {
                        "CWE-78_COMMAND_INJECTION"
                    } else {
                        "RUST_UNSAFE_MEMORY_BOUNDARY"
                    };
                    let mut idents = Vec::new();
                    for a in &arg_nodes {
                        collect_identifiers(*a, self.src, &mut idents);
                    }
                    let target_var = idents
                        .iter()
                        .find(|id| var_def_map.contains_key(*id))
                        .cloned()
                        .unwrap_or_else(|| "unsafe_op".to_string());
                    let sink_id = self.cpg.add_node(
                        CpgNodeKind::SecuritySink {
                            sink_type: sink_type.to_string(),
                            target_variable: target_var,
                        },
                        full_text,
                        self.file_name,
                        line_no,
                    );
                    self.link_stmt(sink_id, prev_stmt, parent_fn);
                    for id in idents {
                        if let Some(&def_id) = var_def_map.get(&id) {
                            self.cpg
                                .add_edge(def_id, sink_id, CpgEdgeKind::DataFlow { variable: id });
                        }
                    }
                    return;
                }

                let arg_texts: Vec<String> = arg_nodes
                    .iter()
                    .map(|a| node_text(*a, self.src).trim().to_string())
                    .collect();
                let call_id = self.cpg.add_node(
                    CpgNodeKind::CallExpression {
                        callee: callee.clone(),
                        arguments: arg_texts,
                    },
                    full_text,
                    self.file_name,
                    line_no,
                );
                self.link_stmt(call_id, prev_stmt, parent_fn);
                let mut tainted_args = Vec::new();
                for (idx, a) in arg_nodes.iter().enumerate() {
                    let mut idents = Vec::new();
                    collect_identifiers(*a, self.src, &mut idents);
                    for id in idents {
                        if let Some(&def_id) = var_def_map.get(&id) {
                            self.cpg
                                .add_edge(def_id, call_id, CpgEdgeKind::DataFlow { variable: id });
                            tainted_args.push((idx, node_text(*a, self.src).trim().to_string()));
                            break;
                        }
                    }
                }
                self.pending_calls.push(PendingCallSite {
                    call_node_id: call_id,
                    callee_name: callee,
                    tainted_args,
                });
            }
            _ => {}
        }
    }

    fn link_stmt(
        &mut self,
        node_id: NodeId,
        prev_stmt: &mut Option<NodeId>,
        parent_fn: Option<NodeId>,
    ) {
        if let Some(prev) = *prev_stmt {
            self.cpg.add_edge(prev, node_id, CpgEdgeKind::CfgNext);
        }
        if let Some(fn_id) = parent_fn {
            let order = self.cpg.outgoing_edges(fn_id).len();
            self.cpg
                .add_edge(fn_id, node_id, CpgEdgeKind::AstChild { order });
        }
        *prev_stmt = Some(node_id);
    }
}
