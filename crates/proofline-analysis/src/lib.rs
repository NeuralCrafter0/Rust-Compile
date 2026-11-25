//! Hybrid Security Analysis Engine for Project Proofline.
//! Interprocedural taint propagation, sanitization detection,
//! and SMT (Z3) path constraint generation.

use proofline_core::{EpistemicTier, IngressBoundary};
use proofline_cpg::{CpgEdgeKind, CpgNodeKind, CodePropertyGraph, NodeId};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PathVerificationStatus {
    UnguardedExploitableTaint,
    SanitizedOrGuarded,
    ProvenUnreachable,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReachabilityTrace {
    pub ingress_node_id: u32,
    pub sink_node_id: u32,
    pub sink_type: String,
    pub path_node_ids: Vec<u32>,
    pub status: PathVerificationStatus,
    pub recommended_epistemic_tier: EpistemicTier,
    pub smt_constraint_formula: Option<String>,
}

pub struct TaintAnalysisEngine;

impl TaintAnalysisEngine {
    /// Analyzes a Code Property Graph to identify reachability paths from Ingress to Sinks.
    pub fn analyze(cpg: &CodePropertyGraph) -> Vec<ReachabilityTrace> {
        let ingress_nodes = cpg.find_ingress_nodes();
        let sink_nodes = cpg.find_sink_nodes();
        let guards = cpg.find_guards();
        let mut traces = Vec::new();

        for &ingress in &ingress_nodes {
            for &sink in &sink_nodes {
                if let Some(trace) = Self::find_path(cpg, ingress, sink, &guards) {
                    traces.push(trace);
                }
            }
        }

        traces
    }

    fn find_path(
        cpg: &CodePropertyGraph,
        start: NodeId,
        target: NodeId,
        all_guards: &[NodeId],
    ) -> Option<ReachabilityTrace> {
        // First, check if true dataflow exists from start to target (never conflate CfgNext with DataFlow)
        let dataflow_path = Self::find_dataflow_path(cpg, start, target)?;

        // Collect variable names along the dataflow path to match guards accurately
        let mut path_vars: HashSet<String> = HashSet::new();
        for &node_id in &dataflow_path {
            if let Some(node) = cpg.get_node(node_id) {
                match &node.kind {
                    CpgNodeKind::SecurityIngress { variable, .. }
                    | CpgNodeKind::Parameter { name: variable, .. } => {
                        path_vars.insert(variable.clone());
                    }
                    CpgNodeKind::Assignment { target, .. } => {
                        path_vars.insert(target.clone());
                    }
                    CpgNodeKind::SecuritySink { target_variable, .. } => {
                        path_vars.insert(target_variable.clone());
                    }
                    _ => {}
                }
            }
        }

        // Second, check if a valid CFG guard targeting a variable on this path dominates start -> target
        let has_guard = all_guards.iter().any(|&g| {
            let guards_path_var = cpg
                .get_node(g)
                .map(|n| match &n.kind {
                    CpgNodeKind::SanitizerGuard { checked_variable, .. } => {
                        path_vars.contains(checked_variable)
                    }
                    _ => false,
                })
                .unwrap_or(false);
            guards_path_var
                && Self::reaches_via_cfg(cpg, start, g)
                && Self::reaches_via_cfg(cpg, g, target)
        });

        let target_node = cpg.get_node(target)?;
        let sink_type = match &target_node.kind {
            CpgNodeKind::SecuritySink { sink_type, .. } => sink_type.clone(),
            _ => "GENERIC_SINK".to_string(),
        };

        let (status, tier) = if has_guard {
            (PathVerificationStatus::SanitizedOrGuarded, EpistemicTier::VerifiedMitigation)
        } else {
            (PathVerificationStatus::UnguardedExploitableTaint, EpistemicTier::StaticallyTainted)
        };

        let smt_formula = if status == PathVerificationStatus::UnguardedExploitableTaint {
            Some(SmtPathConstraintGenerator::generate_formula_for_trace(
                cpg, start, target, &sink_type,
            ))
        } else {
            None
        };

        Some(ReachabilityTrace {
            ingress_node_id: start.0,
            sink_node_id: target.0,
            sink_type,
            path_node_ids: dataflow_path.into_iter().map(|n| n.0).collect(),
            status,
            recommended_epistemic_tier: tier,
            smt_constraint_formula: smt_formula,
        })
    }

    /// Runs taint reachability and solves extracted SMT-LIB2 path constraints via `SmtSolverBackend` (`z3` or bounded native fallback).
    pub fn analyze_with_smt(cpg: &CodePropertyGraph, timeout_ms: u64) -> Vec<ReachabilityTrace> {
        let mut traces = Self::analyze(cpg);
        for trace in &mut traces {
            if trace.status != PathVerificationStatus::UnguardedExploitableTaint {
                continue;
            }
            if let Some(ref formula) = trace.smt_constraint_formula {
                match SmtSolverBackend::solve_smt_lib2(formula, timeout_ms) {
                    SmtSolveResult::Satisfiable {
                        recommended_tier, ..
                    } => {
                        trace.recommended_epistemic_tier = recommended_tier;
                    }
                    SmtSolveResult::Unsatisfiable => {
                        trace.status = PathVerificationStatus::SanitizedOrGuarded;
                        trace.recommended_epistemic_tier = EpistemicTier::VerifiedMitigation;
                    }
                    SmtSolveResult::UnavailableOrTimeout {
                        recommended_tier, ..
                    } => {
                        trace.recommended_epistemic_tier = recommended_tier;
                    }
                }
            }
        }
        traces
    }

    fn find_dataflow_path(cpg: &CodePropertyGraph, start: NodeId, target: NodeId) -> Option<Vec<NodeId>> {
        let mut queue = VecDeque::new();
        let mut visited = HashSet::new();
        let mut parent: HashMap<NodeId, NodeId> = HashMap::new();

        queue.push_back(start);
        visited.insert(start);

        while let Some(curr) = queue.pop_front() {
            if curr == target {
                let mut path = vec![target];
                let mut cur = target;
                while let Some(&prev) = parent.get(&cur) {
                    path.push(prev);
                    cur = prev;
                }
                path.reverse();
                return Some(path);
            }
            for edge in cpg.outgoing_edges(curr) {
                if matches!(edge.kind, CpgEdgeKind::DataFlow { .. } | CpgEdgeKind::CallEdge) {
                    if !visited.contains(&edge.to) {
                        visited.insert(edge.to);
                        parent.insert(edge.to, curr);
                        queue.push_back(edge.to);
                    }
                }
            }
        }
        None
    }

    fn reaches_via_cfg(cpg: &CodePropertyGraph, start: NodeId, target: NodeId) -> bool {
        let mut queue = VecDeque::new();
        let mut visited = HashSet::new();

        queue.push_back(start);
        visited.insert(start);

        while let Some(curr) = queue.pop_front() {
            if curr == target {
                return true;
            }
            for edge in cpg.outgoing_edges(curr) {
                if matches!(edge.kind, CpgEdgeKind::CfgNext | CpgEdgeKind::CfgBranchTrue | CpgEdgeKind::CfgBranchFalse) {
                    if !visited.contains(&edge.to) {
                        visited.insert(edge.to);
                        queue.push_back(edge.to);
                    }
                }
            }
        }
        false
    }
}

/// SMT-LIB2 / Z3 First-Order Logic Constraint Generator.
pub struct SmtPathConstraintGenerator;

impl SmtPathConstraintGenerator {
    pub fn generate_formula(sink_type: &str) -> String {
        Self::generate_cwe119_formula(64, None)
            .filter(|_| sink_type == "CWE-119_UNBOUNDED_COPY")
            .unwrap_or_else(|| Self::generate_non_cwe119_formula(sink_type))
    }

    /// Synthesizes an SMT-LIB2 query grounded in AST-extracted buffer sizes and ingress read bounds.
    pub fn generate_formula_for_trace(
        cpg: &CodePropertyGraph,
        ingress_id: NodeId,
        sink_id: NodeId,
        sink_type: &str,
    ) -> String {
        if sink_type != "CWE-119_UNBOUNDED_COPY" {
            return Self::generate_non_cwe119_formula(sink_type);
        }

        let sink_node = cpg.get_node(sink_id);
        let ingress_node = cpg.get_node(ingress_id);
        let dest_var = sink_node.and_then(|n| extract_first_call_arg_ident(&n.code_snippet));
        let dest_cap = dest_var
            .as_deref()
            .and_then(|v| lookup_array_capacity(cpg, v, sink_node.map(|n| n.file_path.as_str())))
            .unwrap_or(64);
        let ingress_bound = ingress_node.and_then(|n| extract_ingress_read_limit(cpg, n));

        Self::generate_cwe119_formula(dest_cap, ingress_bound).expect("CWE-119 formula")
    }

    fn generate_cwe119_formula(dest_capacity: u64, ingress_upper_bound: Option<u64>) -> Option<String> {
        let mut formula = String::new();
        formula.push_str("; SMT-LIB2 Formulated Path Condition for CWE-119 Memory Safety\n");
        formula.push_str("(set-logic QF_BV)\n");
        formula.push_str("(declare-const input_len (_ BitVec 64))\n");
        formula.push_str("(declare-const dest_capacity (_ BitVec 64))\n");
        formula.push_str(&format!("(assert (= dest_capacity (_ bv{} 64)))\n", dest_capacity));
        if let Some(bound) = ingress_upper_bound {
            formula.push_str(&format!("(assert (bvule input_len (_ bv{} 64)))\n", bound));
        }
        formula.push_str("; Fault invariant: input length exceeds destination buffer\n");
        formula.push_str("(assert (bvugt input_len dest_capacity))\n");
        formula.push_str("(check-sat)\n");
        formula.push_str("(get-model)\n");
        Some(formula)
    }

    fn generate_non_cwe119_formula(sink_type: &str) -> String {
        match sink_type {
            "CWE-89_SQL_INJECTION" => {
                let mut formula = String::new();
                formula.push_str("; SMT-LIB2 Formulated Path Condition for CWE-89 SQL Injection\n");
                formula.push_str("(set-logic QF_SLIA)\n");
                formula.push_str("(declare-const user_input String)\n");
                formula.push_str("(declare-const query String)\n");
                formula.push_str("(assert (str.contains user_input \"' OR 1=1--\"))\n");
                formula.push_str("(assert (= query (str.++ \"SELECT * FROM users WHERE name = '\" user_input \"'\")))\n");
                formula.push_str("(check-sat)\n");
                formula.push_str("(get-model)\n");
                formula
            }
            "CWE-78_COMMAND_INJECTION" => {
                let mut formula = String::new();
                formula.push_str("; SMT-LIB2 Formulated Path Condition for CWE-78 Command Injection\n");
                formula.push_str("(set-logic QF_SLIA)\n");
                formula.push_str("(declare-const cmd_arg String)\n");
                formula.push_str("(assert (str.contains cmd_arg \"; id\"))\n");
                formula.push_str("(check-sat)\n");
                formula.push_str("(get-model)\n");
                formula
            }
            _ => {
                let mut formula = String::new();
                formula.push_str("; Generic SMT reachability query\n");
                formula.push_str("(declare-const reachable Bool)\n");
                formula.push_str("(assert (= reachable true))\n");
                formula.push_str("(check-sat)\n");
                formula
            }
        }
    }
}

fn parse_array_bracket_size(decl_text: &str) -> Option<u64> {
    let open = decl_text.find('[')?;
    let close = decl_text[open + 1..].find(']')?;
    decl_text[open + 1..open + 1 + close].trim().parse::<u64>().ok()
}

fn lookup_array_capacity(cpg: &CodePropertyGraph, var_name: &str, file_hint: Option<&str>) -> Option<u64> {
    cpg.nodes.iter().find_map(|n| match &n.kind {
        CpgNodeKind::VariableDecl { name, var_type }
            if name == var_name && file_hint.map(|f| f == n.file_path).unwrap_or(true) =>
        {
            parse_array_bracket_size(var_type)
        }
        _ => None,
    })
}

fn extract_first_call_arg_ident(snippet: &str) -> Option<String> {
    let open = snippet.find('(')?;
    let rest = &snippet[open + 1..];
    let first = rest.split(',').next()?.trim();
    let ident: String = first
        .trim_start_matches('&')
        .trim_start_matches('*')
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
        .collect();
    if ident.is_empty() { None } else { Some(ident) }
}

fn extract_ingress_read_limit(cpg: &CodePropertyGraph, ingress: &proofline_cpg::CpgNode) -> Option<u64> {
    let s = ingress.code_snippet.as_str();
    let (callee, arg_idx) = if s.contains("fgets(") {
        ("fgets(", 1)
    } else if s.contains("read(") {
        ("read(", 2)
    } else if s.contains("recv(") {
        ("recv(", 2)
    } else {
        return None;
    };
    let after = s.split(callee).nth(1)?;
    let arg = after.split(',').nth(arg_idx)?.trim();
    if let Ok(n) = arg.trim_end_matches(')').trim().parse::<u64>() {
        return Some(n);
    }
    if let Some(inner) = arg.strip_prefix("sizeof(") {
        let var = inner.trim_end_matches(')').trim();
        return lookup_array_capacity(cpg, var, Some(ingress.file_path.as_str()));
    }
    None
}

/// Attacker authentication tier for Subsystem D Exploitability & Reachability analysis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AttackerAuthTier {
    Anonymous,
    LowPrivilege,
    HighPrivilege,
    InternalService,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ExploitabilityClassification {
    ExploitableUnderAttackerModel,
    GatedByAuthenticationBoundary,
    MitigatedBySanitizer,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExploitabilityAssessment {
    pub sink_type: String,
    pub ingress_boundary: IngressBoundary,
    pub attacker_auth: AttackerAuthTier,
    pub classification: ExploitabilityClassification,
    pub concrete_seed_preview: Vec<u8>,
}

/// Subsystem D: Evaluates whether statically tainted paths are reachable under a specific attacker model.
pub struct ExploitabilityEvaluator;

impl ExploitabilityEvaluator {
    pub fn evaluate(
        cpg: &CodePropertyGraph,
        traces: &[ReachabilityTrace],
        ingress_boundary: IngressBoundary,
        attacker_auth: AttackerAuthTier,
    ) -> Vec<ExploitabilityAssessment> {
        let auth_nodes: Vec<NodeId> = cpg
            .nodes
            .iter()
            .filter(|n| {
                let s = n.code_snippet.to_ascii_lowercase();
                s.contains("require_auth")
                    || s.contains("login_required")
                    || s.contains("is_authenticated")
                    || s.contains("check_admin")
            })
            .map(|n| n.id)
            .collect();

        traces
            .iter()
            .map(|trace| {
                let classification = if trace.status == PathVerificationStatus::SanitizedOrGuarded {
                    ExploitabilityClassification::MitigatedBySanitizer
                } else {
                    let start = NodeId(trace.ingress_node_id);
                    let target = NodeId(trace.sink_node_id);
                    let gated_by_auth = attacker_auth == AttackerAuthTier::Anonymous
                        && auth_nodes.iter().any(|&a| {
                            TaintAnalysisEngine::reaches_via_cfg(cpg, a, target)
                                || TaintAnalysisEngine::reaches_via_cfg(cpg, start, a)
                        });
                    if gated_by_auth {
                        ExploitabilityClassification::GatedByAuthenticationBoundary
                    } else {
                        ExploitabilityClassification::ExploitableUnderAttackerModel
                    }
                };

                let concrete_seed_preview = WitnessSeedSynthesizer::synthesize_seed(
                    &trace.sink_type,
                    trace.smt_constraint_formula.as_deref(),
                );

                ExploitabilityAssessment {
                    sink_type: trace.sink_type.clone(),
                    ingress_boundary: ingress_boundary.clone(),
                    attacker_auth,
                    classification,
                    concrete_seed_preview,
                }
            })
            .collect()
    }
}

/// Result of invoking a bounded external SMT solver (e.g., Z3) on a path condition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SmtSolveResult {
    Satisfiable {
        model_output: String,
        recommended_tier: EpistemicTier,
    },
    Unsatisfiable,
    UnavailableOrTimeout {
        reason: String,
        recommended_tier: EpistemicTier,
    },
}

/// Bounded SMT-LIB2 solver adapter invoking `z3` when installed, failing closed to `StaticallyTainted`.
pub struct SmtSolverBackend;

impl SmtSolverBackend {
    pub fn solve_smt_lib2(formula: &str, timeout_ms: u64) -> SmtSolveResult {
        use std::io::Write as _;
        use std::process::{Command, Stdio};
        use std::time::{Duration, Instant};

        let timeout_secs = ((timeout_ms + 999) / 1000).max(1);
        let mut child = match Command::new("z3")
            .arg("-in")
            .arg(format!("-T:{}", timeout_secs))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
        {
            Ok(c) => c,
            Err(_) => {
                // Fall back to pure-Rust bounded SMT evaluator when external `z3` binary is absent
                return Self::solve_bounded_native(formula);
            }
        };

        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin.write_all(formula.as_bytes());
        }

        let start = Instant::now();
        let deadline = start + Duration::from_millis(timeout_ms.max(100));
        loop {
            match child.try_wait() {
                Ok(Some(_status)) => {
                    let output = child.wait_with_output();
                    if let Ok(out) = output {
                        let stdout = String::from_utf8_lossy(&out.stdout).to_string();
                        if stdout.lines().any(|l| l.trim() == "sat") {
                            return SmtSolveResult::Satisfiable {
                                model_output: stdout,
                                recommended_tier: EpistemicTier::SymbolicallySatisfiable,
                            };
                        }
                        if stdout.lines().any(|l| l.trim() == "unsat") {
                            return SmtSolveResult::Unsatisfiable;
                        }
                        return SmtSolveResult::UnavailableOrTimeout {
                            reason: format!("z3 returned inconclusive output: {}", stdout.trim()),
                            recommended_tier: EpistemicTier::StaticallyTainted,
                        };
                    }
                    return SmtSolveResult::UnavailableOrTimeout {
                        reason: "Failed reading z3 output".to_string(),
                        recommended_tier: EpistemicTier::StaticallyTainted,
                    };
                }
                Ok(None) => {
                    if Instant::now() >= deadline {
                        let _ = child.kill();
                        let _ = child.wait();
                        return SmtSolveResult::UnavailableOrTimeout {
                            reason: format!("z3 exceeded {} ms timeout", timeout_ms),
                            recommended_tier: EpistemicTier::StaticallyTainted,
                        };
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(e) => {
                    return SmtSolveResult::UnavailableOrTimeout {
                        reason: format!("Error polling z3 process: {}", e),
                        recommended_tier: EpistemicTier::StaticallyTainted,
                    };
                }
            }
        }
    }

    /// Pure-Rust bounded SMT-LIB2 evaluator for `QF_BV` buffer constraints and `QF_SLIA` injection queries.
    pub fn solve_bounded_native(formula: &str) -> SmtSolveResult {
        if formula.contains("bvugt input_len dest_capacity") {
            let mut dest_cap: Option<u64> = None;
            let mut upper_bound: Option<u64> = None;
            for line in formula.lines() {
                let t = line.trim();
                if let Some(rest) = t.strip_prefix("(assert (= dest_capacity (_ bv") {
                    if let Some(num) = rest.split_whitespace().next() {
                        dest_cap = num.parse::<u64>().ok();
                    }
                }
                if let Some(rest) = t.strip_prefix("(assert (bvule input_len (_ bv") {
                    if let Some(num) = rest.split_whitespace().next() {
                        upper_bound = num.parse::<u64>().ok();
                    }
                }
            }
            if let Some(cap) = dest_cap {
                let candidate = cap.saturating_add(1);
                if let Some(ub) = upper_bound {
                    if candidate > ub {
                        return SmtSolveResult::Unsatisfiable;
                    }
                }
                return SmtSolveResult::Satisfiable {
                    model_output: format!(
                        "sat\n(model\n  (define-fun dest_capacity () (_ BitVec 64) #x{:016x})\n  (define-fun input_len () (_ BitVec 64) #x{:016x})\n)",
                        cap, candidate
                    ),
                    recommended_tier: EpistemicTier::SymbolicallySatisfiable,
                };
            }
        }

        if formula.contains("str.contains user_input \"' OR 1=1--\"") {
            return SmtSolveResult::Satisfiable {
                model_output: "sat\n(model\n  (define-fun user_input () String \"' OR 1=1--\")\n)"
                    .to_string(),
                recommended_tier: EpistemicTier::SymbolicallySatisfiable,
            };
        }

        if formula.contains("str.contains cmd_arg \"; id\"") {
            return SmtSolveResult::Satisfiable {
                model_output: "sat\n(model\n  (define-fun cmd_arg () String \"; id\")\n)"
                    .to_string(),
                recommended_tier: EpistemicTier::SymbolicallySatisfiable,
            };
        }

        SmtSolveResult::UnavailableOrTimeout {
            reason: "Formula theory outside bounded native SMT fragment and z3 not installed"
                .to_string(),
            recommended_tier: EpistemicTier::StaticallyTainted,
        }
    }
}

/// Generates concrete witness seed bytes aligned with SMT path constraint theories.
pub struct WitnessSeedSynthesizer;

impl WitnessSeedSynthesizer {
    pub fn synthesize_seed(sink_type: &str, smt_formula: Option<&str>) -> Vec<u8> {
        match sink_type {
            "CWE-119_UNBOUNDED_COPY" => {
                let cap = smt_formula
                    .and_then(extract_formula_dest_capacity)
                    .unwrap_or(64);
                let len = (cap.saturating_add(16)).clamp(16, 4096) as usize;
                vec![b'A'; len]
            }
            "CWE-89_SQL_INJECTION" => b"' OR 1=1--".to_vec(),
            "CWE-78_COMMAND_INJECTION" => b"; id".to_vec(),
            "CWE-22_PATH_TRAVERSAL" => b"../../etc/passwd".to_vec(),
            _ => b"PROOFLINE_SEED_INPUT".to_vec(),
        }
    }
}

fn extract_formula_dest_capacity(formula: &str) -> Option<u64> {
    for line in formula.lines() {
        let t = line.trim();
        if let Some(rest) = t.strip_prefix("(assert (= dest_capacity (_ bv") {
            if let Some(num) = rest.split_whitespace().next() {
                return num.parse::<u64>().ok();
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use proofline_cpg::{CSourceParser, PythonSourceParser};

    #[test]
    fn test_cwe_119_unguarded_reachability_and_smt() {
        let vulnerable_c = r#"
        int process_network_packet() {
            char buffer[128];
            fgets(buffer, 1024, stdin);
            char dest[64];
            strcpy(dest, buffer);
            return 0;
        }
        "#;
        let cpg = CSourceParser::parse_snippet(vulnerable_c, "cwe119.c").unwrap();
        let traces = TaintAnalysisEngine::analyze(&cpg);

        assert_eq!(traces.len(), 1);
        let trace = &traces[0];
        assert_eq!(trace.status, PathVerificationStatus::UnguardedExploitableTaint);
        assert_eq!(trace.recommended_epistemic_tier, EpistemicTier::StaticallyTainted);
        assert!(trace.smt_constraint_formula.is_some());

        let smt = trace.smt_constraint_formula.as_ref().unwrap();
        assert!(smt.contains("bvugt input_len dest_capacity"));
    }

    #[test]
    fn test_cwe_119_guarded_mitigation() {
        let safe_c = r#"
        int process_network_packet() {
            char buffer[128];
            fgets(buffer, 1024, stdin);
            char dest[64];
            if (strlen(buffer) < sizeof(dest)) {
                strcpy(dest, buffer);
            }
            return 0;
        }
        "#;
        let cpg = CSourceParser::parse_snippet(safe_c, "cwe119_safe.c").unwrap();
        let traces = TaintAnalysisEngine::analyze(&cpg);

        assert_eq!(traces.len(), 1);
        let trace = &traces[0];
        assert_eq!(trace.status, PathVerificationStatus::SanitizedOrGuarded);
        assert_eq!(trace.recommended_epistemic_tier, EpistemicTier::VerifiedMitigation);
        assert!(trace.smt_constraint_formula.is_none());
    }

    #[test]
    fn test_cwe_89_python_sqli_reachability() {
        let vuln_py = r#"
        def handle_login():
            user = request.args.get("user")
            query = f"SELECT * FROM users WHERE name = '{user}'"
            cursor.execute(query)
        "#;
        let cpg = PythonSourceParser::parse_snippet(vuln_py, "login.py").unwrap();
        let traces = TaintAnalysisEngine::analyze(&cpg);

        assert_eq!(traces.len(), 1);
        let trace = &traces[0];
        assert_eq!(trace.status, PathVerificationStatus::UnguardedExploitableTaint);
        assert_eq!(trace.sink_type, "CWE-89_SQL_INJECTION");

        let smt = trace.smt_constraint_formula.as_ref().unwrap();
        assert!(smt.contains("str.contains user_input \"' OR 1=1--\""));
    }

    #[test]
    fn test_clean_variable_not_falsely_tainted_across_cfg() {
        let safe_c = r#"
        int handler() {
            char buffer[128];
            fgets(buffer, 128, stdin);
            char* clean = "constant_literal";
            char dest[64];
            strcpy(dest, clean);
            return 0;
        }
        "#;
        let cpg = CSourceParser::parse_snippet(safe_c, "clean_cfg.c").unwrap();
        let traces = TaintAnalysisEngine::analyze(&cpg);
        assert!(
            traces.is_empty(),
            "Clean literal copy must not be flagged as tainted via CfgNext"
        );
    }

    #[test]
    fn test_bogus_constant_guard_does_not_suppress_taint() {
        let bogus_guard_c = r#"
        int handler() {
            char buffer[128];
            fgets(buffer, 1024, stdin);
            char dest[64];
            if (1 < 2) {
                memcpy(dest, buffer, 1024);
            }
            return 0;
        }
        "#;
        let cpg = CSourceParser::parse_snippet(bogus_guard_c, "bogus_guard.c").unwrap();
        let traces = TaintAnalysisEngine::analyze(&cpg);
        assert_eq!(traces.len(), 1);
        assert_eq!(traces[0].status, PathVerificationStatus::UnguardedExploitableTaint);
    }

    #[test]
    fn test_taint_cleared_on_clean_reassignment() {
        let py = r#"
        def handler():
            user = request.args.get("user")
            user = "anonymous"
            cursor.execute(user)
        "#;
        let cpg = PythonSourceParser::parse_snippet(py, "reassigned.py").unwrap();
        let traces = TaintAnalysisEngine::analyze(&cpg);
        assert!(traces.is_empty(), "Reassigning user to literal must clear taint");
    }

    #[test]
    fn test_exploitability_auth_boundary_vs_anonymous() {
        let py_auth = r#"
        def admin_query():
            is_authenticated = check_admin(request)
            user = request.args.get("user")
            query = f"SELECT * FROM users WHERE name = '{user}'"
            cursor.execute(query)
        "#;
        let cpg = PythonSourceParser::parse_snippet(py_auth, "admin.py").unwrap();
        let traces = TaintAnalysisEngine::analyze(&cpg);
        assert_eq!(traces.len(), 1);

        let anon = ExploitabilityEvaluator::evaluate(
            &cpg,
            &traces,
            IngressBoundary::UntrustedNetworkInput,
            AttackerAuthTier::Anonymous,
        );
        assert_eq!(
            anon[0].classification,
            ExploitabilityClassification::GatedByAuthenticationBoundary
        );

        let priv_user = ExploitabilityEvaluator::evaluate(
            &cpg,
            &traces,
            IngressBoundary::AuthenticatedNetworkInput,
            AttackerAuthTier::HighPrivilege,
        );
        assert_eq!(
            priv_user[0].classification,
            ExploitabilityClassification::ExploitableUnderAttackerModel
        );
        assert_eq!(priv_user[0].concrete_seed_preview, b"' OR 1=1--");
    }

    #[test]
    fn test_interprocedural_c_and_rust_taint_reachability() {
        let c_code = r#"
        int vulnerable_sink(char *s) {
            char dst[16];
            strcpy(dst, s);
            return 0;
        }
        int main() {
            char buf[64];
            fgets(buf, 512, stdin);
            vulnerable_sink(buf);
            return 0;
        }
        "#;
        let cpg = proofline_cpg::CSourceParser::parse_snippet(c_code, "interproc.c").unwrap();
        let traces = TaintAnalysisEngine::analyze(&cpg);
        assert_eq!(traces.len(), 1);
        assert_eq!(traces[0].status, PathVerificationStatus::UnguardedExploitableTaint);
        assert!(traces[0].path_node_ids.len() >= 4);

        let rs_code = r#"
        pub fn exec_cmd(cmd: String) {
            Command::new(cmd);
        }
        fn main() {
            let input = std::env::var("ARG").unwrap();
            exec_cmd(input);
        }
        "#;
        let rs_cpg = proofline_cpg::RustSourceParser::parse_snippet(rs_code, "cmd.rs").unwrap();
        let rs_traces = TaintAnalysisEngine::analyze(&rs_cpg);
        assert_eq!(rs_traces.len(), 1);
        assert_eq!(rs_traces[0].sink_type, "CWE-78_COMMAND_INJECTION");
    }

    #[test]
    fn test_bounded_native_smt_solver_sat_and_unsat() {
        let sat_formula = SmtPathConstraintGenerator::generate_formula("CWE-119_UNBOUNDED_COPY");
        let sat_res = SmtSolverBackend::solve_smt_lib2(&sat_formula, 2000);
        assert!(matches!(
            sat_res,
            SmtSolveResult::Satisfiable {
                recommended_tier: EpistemicTier::SymbolicallySatisfiable,
                ..
            }
        ));

        let mut unsat_formula = sat_formula;
        unsat_formula.push_str("(assert (bvule input_len (_ bv32 64)))\n");
        let unsat_res = SmtSolverBackend::solve_bounded_native(&unsat_formula);
        assert_eq!(unsat_res, SmtSolveResult::Unsatisfiable);
    }

    #[test]
    fn test_ast_extracted_buffer_bounds_and_analyze_with_smt() {
        // Case 1: dst[16] with fgets(512) -> AST extracts bv16 & bv512 -> SMT solver proves SAT & sizes seed to 32
        let small_dst = r#"
        int handler() {
            char buf[256];
            fgets(buf, 512, stdin);
            char dst[16];
            strcpy(dst, buf);
            return 0;
        }
        "#;
        let cpg_sat = proofline_cpg::CSourceParser::parse_snippet(small_dst, "small_dst.c").unwrap();
        let traces_sat = TaintAnalysisEngine::analyze_with_smt(&cpg_sat, 2000);
        assert_eq!(traces_sat.len(), 1);
        assert_eq!(
            traces_sat[0].recommended_epistemic_tier,
            EpistemicTier::SymbolicallySatisfiable
        );
        let formula_sat = traces_sat[0].smt_constraint_formula.as_deref().unwrap();
        assert!(formula_sat.contains("(= dest_capacity (_ bv16 64))"));
        assert!(formula_sat.contains("(bvule input_len (_ bv512 64))"));
        let seed = WitnessSeedSynthesizer::synthesize_seed(&traces_sat[0].sink_type, Some(formula_sat));
        assert_eq!(seed.len(), 32);

        // Case 2: buf[32] read via sizeof(buf) into dst[64] -> input_len <= 32 && input_len > 64 -> UNSAT!
        let bounded_read = r#"
        int safe_handler() {
            char buf[32];
            fgets(buf, sizeof(buf), stdin);
            char dst[64];
            strcpy(dst, buf);
            return 0;
        }
        "#;
        let cpg_unsat = proofline_cpg::CSourceParser::parse_snippet(bounded_read, "safe_cap.c").unwrap();
        let traces_unsat = TaintAnalysisEngine::analyze_with_smt(&cpg_unsat, 2000);
        assert_eq!(traces_unsat.len(), 1);
        assert_eq!(traces_unsat[0].status, PathVerificationStatus::SanitizedOrGuarded);
        assert_eq!(
            traces_unsat[0].recommended_epistemic_tier,
            EpistemicTier::VerifiedMitigation
        );
    }
}
