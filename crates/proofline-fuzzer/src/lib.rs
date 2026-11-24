//! Vulnerability Reproducer Synthesis and Fuzzing Harnesses for Project Proofline.
//! Compiles targets with AddressSanitizer/UBSan, executes concrete reproducers inside
//! isolated sandboxes, and verifies N-run crash determinism.

use proofline_core::{EpistemicTier, ProoflineError, ReproductionWitness, Result};
use proofline_sandbox::{ExecutionConfig, NetworkPolicy, SandboxRunner};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SanitizerKind {
    AddressSanitizer,
    UndefinedBehaviorSanitizer,
    ThreadSanitizer,
    MemorySanitizer,
}

impl SanitizerKind {
    pub fn clang_compiler_flags(&self) -> Vec<String> {
        match self {
            SanitizerKind::AddressSanitizer => vec![
                "-fsanitize=address".to_string(),
                "-fno-omit-frame-pointer".to_string(),
                "-g".to_string(),
                "-O1".to_string(),
            ],
            SanitizerKind::UndefinedBehaviorSanitizer => vec![
                "-fsanitize=undefined".to_string(),
                "-fno-omit-frame-pointer".to_string(),
                "-g".to_string(),
                "-O1".to_string(),
            ],
            SanitizerKind::ThreadSanitizer => vec![
                "-fsanitize=thread".to_string(),
                "-fno-omit-frame-pointer".to_string(),
                "-g".to_string(),
                "-O1".to_string(),
            ],
            SanitizerKind::MemorySanitizer => vec![
                "-fsanitize=memory".to_string(),
                "-fno-omit-frame-pointer".to_string(),
                "-g".to_string(),
                "-O1".to_string(),
            ],
        }
    }
}

/// Structured representation of a verified crash / security fault.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrashSignature {
    pub fault_type: String,
    pub faulting_function: Option<String>,
    pub exit_code: i32,
    pub sanitized_trace_blake3: String,
    pub detected_sanitizer: Option<SanitizerKind>,
}

/// Oracle capable of inspecting runtime traces for security violations.
pub struct CrashOracle;

impl CrashOracle {
    pub fn evaluate_trace(exit_code: i32, stderr: &str, stdout: &str) -> Option<CrashSignature> {
        let combined = format!("{}\n{}", stderr, stdout);

        // Detect AddressSanitizer crashes
        if combined.contains("AddressSanitizer:") {
            let fault_type = if combined.contains("heap-buffer-overflow") {
                "HEAP_BUFFER_OVERFLOW".to_string()
            } else if combined.contains("stack-buffer-overflow") {
                "STACK_BUFFER_OVERFLOW".to_string()
            } else if combined.contains("global-buffer-overflow") {
                "GLOBAL_BUFFER_OVERFLOW".to_string()
            } else if combined.contains("use-after-free") || combined.contains("heap-use-after-free") {
                "USE_AFTER_FREE".to_string()
            } else if combined.contains("SEGV") {
                "NULL_POINTER_OR_SEGV".to_string()
            } else {
                "ADDRESS_SANITIZER_VIOLATION".to_string()
            };

            let faulting_fn = Self::extract_faulting_frame(&combined);
            let trace_hash = blake3::hash(stderr.as_bytes()).to_hex().to_string();

            return Some(CrashSignature {
                fault_type,
                faulting_function: faulting_fn,
                exit_code,
                sanitized_trace_blake3: trace_hash,
                detected_sanitizer: Some(SanitizerKind::AddressSanitizer),
            });
        }

        // Detect UndefinedBehaviorSanitizer violations
        if combined.contains("runtime error:") {
            let fault_type = if combined.contains("signed integer overflow") {
                "INTEGER_OVERFLOW".to_string()
            } else if combined.contains("null pointer") {
                "NULL_POINTER_DEREFERENCE".to_string()
            } else {
                "UNDEFINED_BEHAVIOR".to_string()
            };

            let trace_hash = blake3::hash(stderr.as_bytes()).to_hex().to_string();
            return Some(CrashSignature {
                fault_type,
                faulting_function: None,
                exit_code,
                sanitized_trace_blake3: trace_hash,
                detected_sanitizer: Some(SanitizerKind::UndefinedBehaviorSanitizer),
            });
        }

        // Detect Native Segmentation Fault / Abort
        if exit_code == 139 || exit_code == -11 || combined.contains("Segmentation fault") {
            return Some(CrashSignature {
                fault_type: "SIGSEGV".to_string(),
                faulting_function: None,
                exit_code,
                sanitized_trace_blake3: blake3::hash(combined.as_bytes()).to_hex().to_string(),
                detected_sanitizer: None,
            });
        }

        // Detect Panic (Rust/Python)
        if combined.contains("panicked at") || combined.contains("Traceback (most recent call last):") {
            let fault_type = if combined.contains("panicked at") {
                "RUST_PANIC".to_string()
            } else {
                "PYTHON_UNHANDLED_EXCEPTION".to_string()
            };

            return Some(CrashSignature {
                fault_type,
                faulting_function: Self::extract_faulting_frame(&combined),
                exit_code,
                sanitized_trace_blake3: blake3::hash(combined.as_bytes()).to_hex().to_string(),
                detected_sanitizer: None,
            });
        }

        None
    }

    fn extract_faulting_frame(trace: &str) -> Option<String> {
        for line in trace.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("#0 ") || trimmed.starts_with("#1 ") {
                let parts: Vec<&str> = trimmed.split_whitespace().collect();
                if parts.len() >= 4 {
                    return Some(parts[3].to_string());
                }
            }
        }
        None
    }
}

/// Synthesizes and deterministically verifies vulnerability reproducers.
pub struct ReproducerSynthesizer;

impl ReproducerSynthesizer {
    /// Executes a concrete input against a target under a sandbox runner,
    /// verifying determinism across N consecutive clean runs.
    pub fn verify_deterministic_reproduction<R: SandboxRunner>(
        runner: &R,
        working_dir: &Path,
        command: &[String],
        input_payload: &[u8],
        required_runs: u32,
    ) -> Result<(ReproductionWitness, CrashSignature, EpistemicTier)> {
        if required_runs < 1 {
            return Err(ProoflineError::ContractUnmet(
                "Determinism verification requires at least 1 run".to_string(),
            ));
        }

        let input_hash = blake3::hash(input_payload).to_hex().to_string();
        let payload_b64 = String::from_utf8_lossy(input_payload).to_string();

        let mut config = ExecutionConfig::default();
        config.working_dir = working_dir.to_path_buf();
        config.command = command.to_vec();
        config.network_policy = NetworkPolicy::Denied;
        config.env_vars.insert("PROOFLINE_INPUT_PAYLOAD".to_string(), payload_b64);

        let mut baseline_signature: Option<CrashSignature> = None;
        let mut total_duration_ms = 0u64;
        let mut matching_runs = 0u32;

        for _ in 0..required_runs {
            let output = runner.execute(&config)?;
            total_duration_ms += output.duration_ms;

            let sig = CrashOracle::evaluate_trace(output.exit_code, &output.stderr, &output.stdout);

            match (sig, &baseline_signature) {
                (Some(current_sig), None) => {
                    baseline_signature = Some(current_sig);
                    matching_runs += 1;
                }
                (Some(current_sig), Some(base)) => {
                    if current_sig.fault_type == base.fault_type
                        && current_sig.exit_code == base.exit_code
                    {
                        matching_runs += 1;
                    }
                }
                _ => {}
            }
        }

        let signature = baseline_signature.ok_or_else(|| {
            ProoflineError::ReproductionFailed(
                "Execution did not trigger any detectable crash or security violation oracle".to_string(),
            )
        })?;

        let is_deterministic = matching_runs == required_runs;
        let epistemic_tier = if is_deterministic {
            EpistemicTier::ConfirmedReproduced
        } else {
            EpistemicTier::Inconclusive
        };

        let witness = ReproductionWitness {
            deterministic: is_deterministic,
            successful_runs: matching_runs,
            total_attempted_runs: required_runs,
            input_artifact_blake3: input_hash,
            fault_signal_or_oracle: signature.fault_type.clone(),
            execution_trace_blake3: signature.sanitized_trace_blake3.clone(),
            execution_duration_ms: total_duration_ms / required_runs as u64,
        };

        Ok((witness, signature, epistemic_tier))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proofline_sandbox::ExecutionOutput;

    struct MockCrashingRunner {
        simulated_asan_stderr: String,
        simulated_exit_code: i32,
    }

    impl SandboxRunner for MockCrashingRunner {
        fn execute(&self, _config: &ExecutionConfig) -> Result<ExecutionOutput> {
            Ok(ExecutionOutput {
                exit_code: self.simulated_exit_code,
                stdout: String::new(),
                stderr: self.simulated_asan_stderr.clone(),
                duration_ms: 15,
                stdout_blake3: "dummy".to_string(),
                stderr_blake3: blake3::hash(self.simulated_asan_stderr.as_bytes()).to_hex().to_string(),
            })
        }
    }

    #[test]
    fn test_asan_heap_buffer_overflow_detection() {
        let asan_log = r#"
=================================================================
==12345==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000050 at pc 0x000000401234 bp 0x7ffd12345678 sp 0x7ffd12345670
WRITE of size 128 at 0x602000000050 thread T0
    #0 0x401233 in process_packet /workspace/vuln.c:12
    #1 0x401345 in main /workspace/main.c:20
=================================================================
        "#;

        let sig = CrashOracle::evaluate_trace(1, asan_log, "").unwrap();
        assert_eq!(sig.fault_type, "HEAP_BUFFER_OVERFLOW");
        assert_eq!(sig.faulting_function.as_deref(), Some("process_packet"));
        assert_eq!(sig.detected_sanitizer, Some(SanitizerKind::AddressSanitizer));
    }

    #[test]
    fn test_5_run_determinism_verification() {
        let asan_log = r#"
=================================================================
==999==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x7ffd
WRITE of size 64 at 0x7ffd thread T0
    #0 0x401111 in vuln_function /app/vuln.c:8
=================================================================
        "#;

        let runner = MockCrashingRunner {
            simulated_asan_stderr: asan_log.to_string(),
            simulated_exit_code: 1,
        };

        let temp_dir = tempfile::tempdir().unwrap();
        let cmd = vec!["/workspace/vuln_bin".to_string()];
        let payload = vec![0x41; 256];

        let (witness, sig, tier) = ReproducerSynthesizer::verify_deterministic_reproduction(
            &runner,
            temp_dir.path(),
            &cmd,
            &payload,
            5,
        )
        .unwrap();

        assert!(witness.deterministic);
        assert_eq!(witness.successful_runs, 5);
        assert_eq!(witness.total_attempted_runs, 5);
        assert_eq!(sig.fault_type, "STACK_BUFFER_OVERFLOW");
        assert_eq!(tier, EpistemicTier::ConfirmedReproduced);
    }
}
