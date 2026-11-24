//! Differential Patch Verification Engine for Project Proofline.
//! Executes original reproducers across dual branches (V_vuln vs V_patch),
//! mutates reproducers along boundary conditions to discover patch bypasses,
//! and guards against semantic regressions on golden test suites.

use proofline_core::{DifferentialVerificationResult, EpistemicTier, ProoflineError, Result};
use proofline_fuzzer::{CrashOracle, CrashSignature};
use proofline_sandbox::{ExecutionConfig, NetworkPolicy, SandboxRunner};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BypassFinding {
    pub mutation_name: String,
    pub payload_bytes_blake3: String,
    pub crash_signature: CrashSignature,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DifferentialPatchReport {
    pub original_reproducer_on_vuln_crashed: bool,
    pub original_reproducer_on_patch_mitigated: bool,
    pub regressions_detected: bool,
    pub bypasses: Vec<BypassFinding>,
    pub total_mutations_evaluated: u64,
    pub final_epistemic_tier: EpistemicTier,
}

pub struct AdversarialMutator;

impl AdversarialMutator {
    /// Generates mutated variants of an exploit reproducer targeting common patch bypass flaws:
    /// URL double-encodings, null byte injections, path normalization variants, and integer bounds.
    pub fn generate_mutations(base_payload: &[u8]) -> Vec<(String, Vec<u8>)> {
        let mut mutations = Vec::new();
        let payload_str = String::from_utf8_lossy(base_payload);

        // Path Traversal Mutation Strategies (CWE-22 / CWE-20 bypasses)
        if payload_str.contains("../") || payload_str.contains("..\\") {
            // URL double-encoding bypass
            mutations.push((
                "URL_DOUBLE_ENCODING".to_string(),
                payload_str.replace("../", "..%252f").into_bytes(),
            ));
            // Single URL-encoding bypass
            mutations.push((
                "URL_ENCODING".to_string(),
                payload_str.replace("../", "..%2f").into_bytes(),
            ));
            // Slashes doubling bypass (....//)
            mutations.push((
                "NESTED_STRIP_BYPASS".to_string(),
                payload_str.replace("../", "....//").into_bytes(),
            ));
            // Windows backslash bypass
            mutations.push((
                "BACKSLASH_TRAVERSAL".to_string(),
                payload_str.replace("../", "..\\").into_bytes(),
            ));
            // Null-byte termination bypass
            let mut null_terminated = base_payload.to_vec();
            null_terminated.extend_from_slice(b"%00.png");
            mutations.push(("NULL_BYTE_INJECTION".to_string(), null_terminated));
        }

        // Buffer length perturbation (Off-by-one / Boundary checks)
        let mut off_by_one = base_payload.to_vec();
        off_by_one.push(b'A');
        mutations.push(("BOUNDARY_OFF_BY_ONE_PLUS_ONE".to_string(), off_by_one));

        let mut double_size = base_payload.to_vec();
        double_size.extend_from_slice(base_payload);
        mutations.push(("BOUNDARY_DOUBLE_PAYLOAD_SIZE".to_string(), double_size));

        mutations
    }
}

pub struct DifferentialVerificationEngine;

impl DifferentialVerificationEngine {
    /// Executes the complete differential patch verification loop:
    /// 1. Verifies reproducer on V_vuln (must crash).
    /// 2. Verifies reproducer on V_patch (must be mitigated).
    /// 3. Fuzzes V_patch with adversarial mutations to detect bypasses.
    /// 4. Executes golden regression suite to detect semantic divergence.
    pub fn verify_patch<RV: SandboxRunner, RP: SandboxRunner>(
        vuln_runner: &RV,
        patch_runner: &RP,
        working_dir: &Path,
        command: &[String],
        reproducer_payload: &[u8],
        regression_test_inputs: &[Vec<u8>],
    ) -> Result<(DifferentialPatchReport, DifferentialVerificationResult)> {
        let mut config_vuln = ExecutionConfig::default();
        config_vuln.working_dir = working_dir.to_path_buf();
        config_vuln.command = command.to_vec();
        config_vuln.network_policy = NetworkPolicy::Denied;
        config_vuln.env_vars.insert(
            "PROOFLINE_INPUT_PAYLOAD".to_string(),
            String::from_utf8_lossy(reproducer_payload).to_string(),
        );

        // Step 1: Execute on V_vuln - Must trigger crash oracle
        let vuln_output = vuln_runner.execute(&config_vuln)?;
        let vuln_crashed = CrashOracle::evaluate_trace(
            vuln_output.exit_code,
            &vuln_output.stderr,
            &vuln_output.stdout,
        )
        .is_some();

        if !vuln_crashed {
            return Err(ProoflineError::ReproductionFailed(
                "Original reproducer failed to trigger vulnerability on unpatched revision V_vuln".to_string(),
            ));
        }

        // Step 2: Execute on V_patch - Must be mitigated (no crash)
        let config_patch = config_vuln.clone();
        let patch_output = patch_runner.execute(&config_patch)?;
        let patch_still_crashed = CrashOracle::evaluate_trace(
            patch_output.exit_code,
            &patch_output.stderr,
            &patch_output.stdout,
        )
        .is_some();

        if patch_still_crashed {
            // Patch completely failed to mitigate the known reproducer!
            let report = DifferentialPatchReport {
                original_reproducer_on_vuln_crashed: true,
                original_reproducer_on_patch_mitigated: false,
                regressions_detected: false,
                bypasses: Vec::new(),
                total_mutations_evaluated: 0,
                final_epistemic_tier: EpistemicTier::ConfirmedReproduced,
            };
            let diff_result = DifferentialVerificationResult {
                original_reproducer_on_patch_mitigated: false,
                regression_tests_passed: false,
                bypass_mutations_evaluated: 0,
                bypasses_discovered: 0,
                execution_divergence_notes: vec!["Patch failed: original reproducer still triggers crash on V_patch".to_string()],
            };
            return Ok((report, diff_result));
        }

        // Step 3: Adversarial Mutation Fuzzing (Bypass Discovery)
        let mutations = AdversarialMutator::generate_mutations(reproducer_payload);
        let mut bypasses = Vec::new();
        let total_mutations = mutations.len() as u64;

        for (mut_name, mut_payload) in &mutations {
            let mut mut_config = config_patch.clone();
            mut_config.env_vars.insert(
                "PROOFLINE_INPUT_PAYLOAD".to_string(),
                String::from_utf8_lossy(mut_payload).to_string(),
            );

            let mut_output = patch_runner.execute(&mut_config)?;
            if let Some(crash_sig) = CrashOracle::evaluate_trace(
                mut_output.exit_code,
                &mut_output.stderr,
                &mut_output.stdout,
            ) {
                bypasses.push(BypassFinding {
                    mutation_name: mut_name.clone(),
                    payload_bytes_blake3: blake3::hash(mut_payload).to_hex().to_string(),
                    crash_signature: crash_sig,
                });
            }
        }

        // Step 4: Golden Regression Suite Execution
        let mut regressions_detected = false;
        let mut regression_notes = Vec::new();

        for (idx, reg_payload) in regression_test_inputs.iter().enumerate() {
            let mut reg_config = config_patch.clone();
            reg_config.env_vars.insert(
                "PROOFLINE_INPUT_PAYLOAD".to_string(),
                String::from_utf8_lossy(reg_payload).to_string(),
            );

            let reg_output = patch_runner.execute(&reg_config)?;
            if reg_output.exit_code != 0 {
                regressions_detected = true;
                regression_notes.push(format!("Regression in test case #{}: exit code {}", idx, reg_output.exit_code));
            }
        }

        let has_bypasses = !bypasses.is_empty();
        let final_epistemic_tier = if has_bypasses {
            EpistemicTier::ConfirmedReproduced // Patch is bypassed! The vulnerability is still alive
        } else if regressions_detected {
            EpistemicTier::Inconclusive // Semantic regression broke non-vulnerable paths
        } else {
            EpistemicTier::VerifiedMitigation // Sound patch!
        };

        let report = DifferentialPatchReport {
            original_reproducer_on_vuln_crashed: true,
            original_reproducer_on_patch_mitigated: true,
            regressions_detected,
            bypasses: bypasses.clone(),
            total_mutations_evaluated: total_mutations,
            final_epistemic_tier,
        };

        let diff_result = DifferentialVerificationResult {
            original_reproducer_on_patch_mitigated: true,
            regression_tests_passed: !regressions_detected,
            bypass_mutations_evaluated: total_mutations,
            bypasses_discovered: bypasses.len() as u64,
            execution_divergence_notes: regression_notes,
        };

        Ok((report, diff_result))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proofline_sandbox::ExecutionOutput;

    struct MockBranchRunner {
        crashes_on_substring: Option<String>,
        crashes_on_reproducer: bool,
    }

    impl SandboxRunner for MockBranchRunner {
        fn execute(&self, config: &ExecutionConfig) -> Result<ExecutionOutput> {
            let payload = config.env_vars.get("PROOFLINE_INPUT_PAYLOAD").cloned().unwrap_or_default();

            if self.crashes_on_reproducer && payload.contains("../../etc/passwd") {
                return Ok(ExecutionOutput {
                    exit_code: 139,
                    stdout: String::new(),
                    stderr: "==1==ERROR: AddressSanitizer: global-buffer-overflow on 0x123".to_string(),
                    duration_ms: 5,
                    stdout_blake3: "hash".to_string(),
                    stderr_blake3: "hash".to_string(),
                });
            }

            if let Some(ref sub) = self.crashes_on_substring {
                if payload.contains(sub) {
                    return Ok(ExecutionOutput {
                        exit_code: 139,
                        stdout: String::new(),
                        stderr: "==1==ERROR: AddressSanitizer: global-buffer-overflow on 0x123".to_string(),
                        duration_ms: 5,
                        stdout_blake3: "hash".to_string(),
                        stderr_blake3: "hash".to_string(),
                    });
                }
            }

            Ok(ExecutionOutput {
                exit_code: 0,
                stdout: "Success".to_string(),
                stderr: String::new(),
                duration_ms: 5,
                stdout_blake3: "hash".to_string(),
                stderr_blake3: "hash".to_string(),
            })
        }
    }

    #[test]
    fn test_sound_patch_verified() {
        let vuln_runner = MockBranchRunner {
            crashes_on_substring: None,
            crashes_on_reproducer: true,
        };
        let patch_runner = MockBranchRunner {
            crashes_on_substring: None,
            crashes_on_reproducer: false, // Patch completely fixes it and all variants
        };

        let temp_dir = tempfile::tempdir().unwrap();
        let cmd = vec!["/app/server".to_string()];
        let reproducer = b"GET ../../etc/passwd HTTP/1.1";
        let regression_suite = vec![b"GET /index.html HTTP/1.1".to_vec()];

        let (report, diff_result) = DifferentialVerificationEngine::verify_patch(
            &vuln_runner,
            &patch_runner,
            temp_dir.path(),
            &cmd,
            reproducer,
            &regression_suite,
        )
        .unwrap();

        assert!(report.original_reproducer_on_vuln_crashed);
        assert!(report.original_reproducer_on_patch_mitigated);
        assert_eq!(report.bypasses.len(), 0);
        assert!(!report.regressions_detected);
        assert_eq!(report.final_epistemic_tier, EpistemicTier::VerifiedMitigation);
        assert!(diff_result.regression_tests_passed);
    }

    #[test]
    fn test_incomplete_patch_bypass_discovered() {
        let vuln_runner = MockBranchRunner {
            crashes_on_substring: None,
            crashes_on_reproducer: true,
        };
        // Naive patch: Maintainer blocked literal "../" but missed "..%2f" URL encoding!
        let patch_runner = MockBranchRunner {
            crashes_on_substring: Some("..%2f".to_string()),
            crashes_on_reproducer: false,
        };

        let temp_dir = tempfile::tempdir().unwrap();
        let cmd = vec!["/app/server".to_string()];
        let reproducer = b"GET ../../etc/passwd HTTP/1.1";
        let regression_suite = vec![b"GET /index.html HTTP/1.1".to_vec()];

        let (report, _diff_result) = DifferentialVerificationEngine::verify_patch(
            &vuln_runner,
            &patch_runner,
            temp_dir.path(),
            &cmd,
            reproducer,
            &regression_suite,
        )
        .unwrap();

        assert!(report.original_reproducer_on_patch_mitigated); // Passed shallow test!
        assert!(!report.bypasses.is_empty(), "Adversarial mutator should detect URL encoding bypass!");
        assert_eq!(report.final_epistemic_tier, EpistemicTier::ConfirmedReproduced);
        assert_eq!(report.bypasses[0].mutation_name, "URL_ENCODING");
    }
}
