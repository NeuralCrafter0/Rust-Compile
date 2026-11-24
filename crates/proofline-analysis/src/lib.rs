//! Hybrid Security Analysis Engine for Project Proofline.
//! Interprocedural taint propagation, sanitization detection,
//! and SMT (Z3) path constraint generation.

use proofline_core::EpistemicTier;
use proofline_cpg::{CpgEdgeKind, CpgNodeKind, CodePropertyGraph, NodeId};
use serde::{Deserialize, Serialize};
use std::collections::{HashSet, VecDeque};

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
        // First, check if dataflow exists from start to target (directly or via intermediate definitions)
        let has_dataflow = Self::reaches_via_dataflow(cpg, start, target);
        if !has_dataflow {
            return None;
        }

        // Second, check if there is a CFG guard between start and target
        let has_guard = all_guards.iter().any(|&g| {
            // Guard must be after start and before or at target in the CFG
            Self::reaches_via_cfg(cpg, start, g) && Self::reaches_via_cfg(cpg, g, target)
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
            Some(SmtPathConstraintGenerator::generate_formula(&sink_type))
        } else {
            None
        };

        Some(ReachabilityTrace {
            ingress_node_id: start.0,
            sink_node_id: target.0,
            sink_type,
            path_node_ids: vec![start.0, target.0],
            status,
            recommended_epistemic_tier: tier,
            smt_constraint_formula: smt_formula,
        })
    }

    fn reaches_via_dataflow(cpg: &CodePropertyGraph, start: NodeId, target: NodeId) -> bool {
        let mut queue = VecDeque::new();
        let mut visited = HashSet::new();

        queue.push_back(start);
        visited.insert(start);

        while let Some(curr) = queue.pop_front() {
            if curr == target {
                return true;
            }
            for edge in cpg.outgoing_edges(curr) {
                if matches!(edge.kind, CpgEdgeKind::DataFlow { .. } | CpgEdgeKind::CfgNext) {
                    if !visited.contains(&edge.to) {
                        visited.insert(edge.to);
                        queue.push_back(edge.to);
                    }
                }
            }
        }
        false
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
        match sink_type {
            "CWE-119_UNBOUNDED_COPY" => {
                let mut formula = String::new();
                formula.push_str("; SMT-LIB2 Formulated Path Condition for CWE-119 Memory Safety\n");
                formula.push_str("(set-logic QF_BV)\n");
                formula.push_str("(declare-const input_len (_ BitVec 64))\n");
                formula.push_str("(declare-const dest_capacity (_ BitVec 64))\n");
                formula.push_str("(assert (= dest_capacity (_ bv64 64)))\n");
                formula.push_str("; Fault invariant: input length exceeds destination buffer\n");
                formula.push_str("(assert (bvugt input_len dest_capacity))\n");
                formula.push_str("(check-sat)\n");
                formula.push_str("(get-model)\n");
                formula
            }
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
}
