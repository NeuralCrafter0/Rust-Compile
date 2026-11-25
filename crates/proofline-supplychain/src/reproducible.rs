//! Bit-for-bit reproducible build comparison and human-readable Markdown report generation.

use crate::bundle::BundleManifest;
use crate::hex_encode;
use proofline_analysis::ReachabilityTrace;
use proofline_core::{sanitize_terminal_trace, ProoflineError, Result};
use proofline_differential::DifferentialPatchReport;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReproducibleBuildReport {
    pub identical_bit_for_bit: bool,
    pub build_a_size_bytes: usize,
    pub build_b_size_bytes: usize,
    pub build_a_blake3: String,
    pub build_b_blake3: String,
    pub build_a_sha256: String,
    pub build_b_sha256: String,
    pub first_diverging_offset: Option<usize>,
}

pub struct ReproducibleBuildVerifier;

impl ReproducibleBuildVerifier {
    pub fn compare_bytes(a: &[u8], b: &[u8]) -> ReproducibleBuildReport {
        let identical = a == b;
        let first_diverging_offset = if identical {
            None
        } else {
            let min_len = a.len().min(b.len());
            (0..min_len).find(|&i| a[i] != b[i]).or(Some(min_len))
        };

        ReproducibleBuildReport {
            identical_bit_for_bit: identical,
            build_a_size_bytes: a.len(),
            build_b_size_bytes: b.len(),
            build_a_blake3: blake3::hash(a).to_hex().to_string(),
            build_b_blake3: blake3::hash(b).to_hex().to_string(),
            build_a_sha256: hex_encode(&Sha256::digest(a)),
            build_b_sha256: hex_encode(&Sha256::digest(b)),
            first_diverging_offset,
        }
    }

    pub fn compare_files(path_a: &Path, path_b: &Path) -> Result<ReproducibleBuildReport> {
        let a = fs::read(path_a).map_err(ProoflineError::Io)?;
        let b = fs::read(path_b).map_err(ProoflineError::Io)?;
        Ok(Self::compare_bytes(&a, &b))
    }
}

pub struct VerificationMarkdownRenderer;

impl VerificationMarkdownRenderer {
    pub fn render_summary(
        manifest: Option<&BundleManifest>,
        diff_report: &DifferentialPatchReport,
        traces: &[ReachabilityTrace],
    ) -> String {
        let mut md = String::new();
        md.push_str("# Proofline Verification Report\n\n");
        md.push_str(&format!(
            "- **Epistemic Tier**: `{:?}`\n",
            diff_report.final_epistemic_tier
        ));
        md.push_str(&format!(
            "- **Original Reproducer Crashed on `V_vuln`**: `{}`\n",
            diff_report.original_reproducer_on_vuln_crashed
        ));
        md.push_str(&format!(
            "- **Original Reproducer Mitigated on `V_patch`**: `{}`\n",
            diff_report.original_reproducer_on_patch_mitigated
        ));
        md.push_str(&format!(
            "- **Bypass Mutations Evaluated**: `{}` (bypasses found: `{}`)\n",
            diff_report.total_mutations_evaluated,
            diff_report.bypasses.len()
        ));
        md.push_str(&format!(
            "- **Golden Regression Divergence Detected**: `{}`\n",
            diff_report.regressions_detected
        ));

        if let Some(m) = manifest {
            md.push_str("\n## Evidence Bundle Attestation\n\n");
            md.push_str(&format!(
                "- **Bundle ID**: `{}`\n",
                sanitize_terminal_trace(&m.bundle_id)
            ));
            md.push_str(&format!(
                "- **Target Repository**: `{}`\n",
                sanitize_terminal_trace(&m.target_repository)
            ));
            md.push_str(&format!(
                "- **Vulnerable Commit**: `{}`\n",
                sanitize_terminal_trace(&m.target_commits.vulnerable)
            ));
            if let Some(ref p) = m.target_commits.candidate_patch {
                md.push_str(&format!(
                    "- **Candidate Patch Commit**: `{}`\n",
                    sanitize_terminal_trace(p)
                ));
            }
            md.push_str(&format!(
                "- **CAS Merkle Root (BLAKE3)**: `{}`\n",
                m.cas_hashes.merkle_root_hash
            ));
            md.push_str(&format!(
                "- **Signing Key ID**: `{}` (`{}`)\n",
                sanitize_terminal_trace(&m.attestation.key_id),
                sanitize_terminal_trace(&m.attestation.signature_algorithm)
            ));
        }

        if !diff_report.bypasses.is_empty() {
            md.push_str("\n## Discovered Patch Bypasses\n\n");
            for b in &diff_report.bypasses {
                md.push_str(&format!(
                    "- `{}` -> fault `{}` (payload BLAKE3: `{}`)\n",
                    sanitize_terminal_trace(&b.mutation_name),
                    sanitize_terminal_trace(&b.crash_signature.fault_type),
                    b.payload_bytes_blake3
                ));
            }
        }

        if !traces.is_empty() {
            md.push_str("\n## Static Reachability Traces\n\n");
            for t in traces {
                md.push_str(&format!(
                    "- Node `{}` -> `{}` (`{}`): `{:?}` (path length: {})\n",
                    t.ingress_node_id,
                    t.sink_node_id,
                    sanitize_terminal_trace(&t.sink_type),
                    t.status,
                    t.path_node_ids.len()
                ));
            }
        }

        md.push_str("\n## Verification Scope & Known Limitations\n\n");
        md.push_str(
            "- Passing differential checks establishes mitigation only against the tested reproducer, bounded adversarial mutation set, and golden regression suite; it does not constitute a universal correctness proof.\n",
        );
        md
    }
}
