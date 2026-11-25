//! Vulnerability Reproducer Synthesis and Fuzzing Harnesses for Project Proofline.
//! Compiles targets with AddressSanitizer/UBSan, executes concrete reproducers inside
//! isolated sandboxes, and verifies N-run crash determinism.

use proofline_core::{sanitize_terminal_trace, EpistemicTier, ProoflineError, ReproductionWitness, Result};
use proofline_sandbox::{attach_input_payload, ExecutionConfig, NetworkPolicy, SandboxRunner};
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
    pub fn evaluate_trace(exit_code: i32, stderr: &str, _stdout: &str) -> Option<CrashSignature> {
        let clean_stderr = sanitize_terminal_trace(stderr);

        // Evaluate sanitizers strictly on stderr so untrusted stdout echoes cannot spoof crashes.
        if clean_stderr.contains("AddressSanitizer:") || clean_stderr.contains("LeakSanitizer:") {
            let fault_type = if clean_stderr.contains("heap-buffer-overflow") {
                "HEAP_BUFFER_OVERFLOW".to_string()
            } else if clean_stderr.contains("stack-buffer-overflow") {
                "STACK_BUFFER_OVERFLOW".to_string()
            } else if clean_stderr.contains("global-buffer-overflow") {
                "GLOBAL_BUFFER_OVERFLOW".to_string()
            } else if clean_stderr.contains("use-after-free") || clean_stderr.contains("heap-use-after-free") {
                "USE_AFTER_FREE".to_string()
            } else if clean_stderr.contains("SEGV") {
                "NULL_POINTER_OR_SEGV".to_string()
            } else if clean_stderr.contains("LeakSanitizer:") {
                "MEMORY_LEAK".to_string()
            } else {
                "ADDRESS_SANITIZER_VIOLATION".to_string()
            };

            let faulting_fn = Self::extract_faulting_frame(&clean_stderr);
            let trace_hash = blake3::hash(clean_stderr.as_bytes()).to_hex().to_string();

            return Some(CrashSignature {
                fault_type,
                faulting_function: faulting_fn,
                exit_code,
                sanitized_trace_blake3: trace_hash,
                detected_sanitizer: Some(SanitizerKind::AddressSanitizer),
            });
        }

        if clean_stderr.contains("ThreadSanitizer:") {
            return Some(CrashSignature {
                fault_type: "DATA_RACE".to_string(),
                faulting_function: Self::extract_faulting_frame(&clean_stderr),
                exit_code,
                sanitized_trace_blake3: blake3::hash(clean_stderr.as_bytes()).to_hex().to_string(),
                detected_sanitizer: Some(SanitizerKind::ThreadSanitizer),
            });
        }

        if clean_stderr.contains("MemorySanitizer:") {
            return Some(CrashSignature {
                fault_type: "UNINITIALIZED_MEMORY_READ".to_string(),
                faulting_function: Self::extract_faulting_frame(&clean_stderr),
                exit_code,
                sanitized_trace_blake3: blake3::hash(clean_stderr.as_bytes()).to_hex().to_string(),
                detected_sanitizer: Some(SanitizerKind::MemorySanitizer),
            });
        }

        // Detect UndefinedBehaviorSanitizer violations
        if clean_stderr.contains("runtime error:") {
            let fault_type = if clean_stderr.contains("signed integer overflow") {
                "INTEGER_OVERFLOW".to_string()
            } else if clean_stderr.contains("null pointer") {
                "NULL_POINTER_DEREFERENCE".to_string()
            } else {
                "UNDEFINED_BEHAVIOR".to_string()
            };

            let trace_hash = blake3::hash(clean_stderr.as_bytes()).to_hex().to_string();
            return Some(CrashSignature {
                fault_type,
                faulting_function: None,
                exit_code,
                sanitized_trace_blake3: trace_hash,
                detected_sanitizer: Some(SanitizerKind::UndefinedBehaviorSanitizer),
            });
        }

        // Require non-zero exit for native signals or unhandled runtime panics
        if exit_code != 0 {
            if exit_code == 139 || exit_code == -11 || clean_stderr.contains("Segmentation fault") {
                return Some(CrashSignature {
                    fault_type: "SIGSEGV".to_string(),
                    faulting_function: None,
                    exit_code,
                    sanitized_trace_blake3: blake3::hash(clean_stderr.as_bytes()).to_hex().to_string(),
                    detected_sanitizer: None,
                });
            }
            if exit_code == 134 || exit_code == -6 {
                return Some(CrashSignature {
                    fault_type: "SIGABRT".to_string(),
                    faulting_function: Self::extract_faulting_frame(&clean_stderr),
                    exit_code,
                    sanitized_trace_blake3: blake3::hash(clean_stderr.as_bytes()).to_hex().to_string(),
                    detected_sanitizer: None,
                });
            }
            if matches!(exit_code, 132 | -4 | 135 | -7 | 136 | -8) {
                return Some(CrashSignature {
                    fault_type: format!("FATAL_SIGNAL_{}", exit_code),
                    faulting_function: Self::extract_faulting_frame(&clean_stderr),
                    exit_code,
                    sanitized_trace_blake3: blake3::hash(clean_stderr.as_bytes()).to_hex().to_string(),
                    detected_sanitizer: None,
                });
            }

            // Detect Panic (Rust/Python) on stderr
            if clean_stderr.contains("panicked at") || clean_stderr.contains("Traceback (most recent call last):") {
                let fault_type = if clean_stderr.contains("panicked at") {
                    "RUST_PANIC".to_string()
                } else {
                    "PYTHON_UNHANDLED_EXCEPTION".to_string()
                };

                return Some(CrashSignature {
                    fault_type,
                    faulting_function: Self::extract_faulting_frame(&clean_stderr),
                    exit_code,
                    sanitized_trace_blake3: blake3::hash(clean_stderr.as_bytes()).to_hex().to_string(),
                    detected_sanitizer: None,
                });
            }
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

        let mut config = ExecutionConfig::default();
        config.working_dir = working_dir.to_path_buf();
        config.command = command.to_vec();
        config.network_policy = NetworkPolicy::Denied;
        attach_input_payload(&mut config, input_payload);

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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MutationFuzzResult {
    pub iterations_executed: usize,
    pub discovered_payload: Option<Vec<u8>>,
    pub witness: Option<ReproductionWitness>,
    pub crash_signature: Option<CrashSignature>,
    pub epistemic_tier: EpistemicTier,
}

/// Bounded deterministic mutation fuzzer that discovers crashing witnesses from initial seeds
/// inside an isolated `SandboxRunner` and verifies N-run determinism.
pub struct MutationFuzzer;

impl MutationFuzzer {
    pub fn fuzz_until_reproduced<R: SandboxRunner>(
        runner: &R,
        working_dir: &Path,
        command: &[String],
        seed_inputs: &[Vec<u8>],
        max_iterations: usize,
        required_determinism_runs: u32,
    ) -> Result<MutationFuzzResult> {
        if max_iterations == 0 {
            return Err(ProoflineError::ContractUnmet(
                "Fuzzing budget max_iterations must be >= 1".to_string(),
            ));
        }

        let mut corpus: Vec<Vec<u8>> = if seed_inputs.is_empty() {
            vec![b"A".to_vec()]
        } else {
            seed_inputs.to_vec()
        };

        // High-signal vulnerability dictionary probes
        let dictionary: &[&[u8]] = &[
            b"%s%s%s%s%n",
            b"../../etc/passwd",
            b"' OR 1=1--",
            b"; id",
            &[b'A'; 128],
            &[b'A'; 256],
            &[b'A'; 1024],
        ];
        for probe in dictionary {
            corpus.push(probe.to_vec());
        }

        let mut rng_state: u64 = 0x5EED_CAFE_BEEF_1337;
        let mut iterations = 0usize;

        for iter in 0..max_iterations {
            iterations = iter + 1;
            let candidate = if iter < corpus.len() {
                corpus[iter].clone()
            } else {
                let base = &corpus[iter % corpus.len()];
                Self::mutate_bytes(base, &mut rng_state)
            };

            let mut config = ExecutionConfig::default();
            config.working_dir = working_dir.to_path_buf();
            config.command = command.to_vec();
            config.network_policy = NetworkPolicy::Denied;
            attach_input_payload(&mut config, &candidate);

            let out = runner.execute(&config)?;
            if CrashOracle::evaluate_trace(out.exit_code, &out.stderr, &out.stdout).is_some() {
                let (witness, sig, tier) = ReproducerSynthesizer::verify_deterministic_reproduction(
                    runner,
                    working_dir,
                    command,
                    &candidate,
                    required_determinism_runs,
                )?;
                return Ok(MutationFuzzResult {
                    iterations_executed: iterations,
                    discovered_payload: Some(candidate),
                    witness: Some(witness),
                    crash_signature: Some(sig),
                    epistemic_tier: tier,
                });
            }
        }

        Ok(MutationFuzzResult {
            iterations_executed: iterations,
            discovered_payload: None,
            witness: None,
            crash_signature: None,
            epistemic_tier: EpistemicTier::Inconclusive,
        })
    }

    fn mutate_bytes(base: &[u8], rng: &mut u64) -> Vec<u8> {
        // Deterministic XorShift64 PRNG
        *rng ^= *rng << 13;
        *rng ^= *rng >> 7;
        *rng ^= *rng << 17;

        let mut out = if base.is_empty() {
            vec![b'A']
        } else {
            base.to_vec()
        };
        match *rng % 4 {
            0 => {
                // Length expansion (buffer boundary pressure)
                let extra = ((*rng >> 8) % 256) as usize + 16;
                out.extend(std::iter::repeat_n(b'A', extra));
            }
            1 => {
                // Deterministic byte flip
                let idx = ((*rng >> 8) as usize) % out.len();
                out[idx] ^= ((*rng >> 16) as u8) | 1;
            }
            2 => {
                // Duplicate payload
                if out.len() < 4096 {
                    let copy = out.clone();
                    out.extend_from_slice(&copy);
                }
            }
            _ => {
                // Append format/control delimiter
                out.extend_from_slice(b"%n\x00../");
            }
        }
        out
    }
}

/// Compiles C/C++ targets inside an isolated `SandboxRunner` with sanitizer instrumentation.
pub struct SanitizedBuildPipeline;

impl SanitizedBuildPipeline {
    pub fn compile_c_with_sanitizers<R: SandboxRunner>(
        runner: &R,
        working_dir: &Path,
        compiler: &str,
        source_rel_path: &str,
        output_rel_path: &str,
        sanitizers: &[SanitizerKind],
    ) -> Result<proofline_sandbox::ExecutionOutput> {
        for field in [compiler, source_rel_path, output_rel_path] {
            if field.is_empty()
                || field.starts_with('-')
                || field.contains('\0')
                || field.contains("..")
            {
                return Err(ProoflineError::IsolationViolation(format!(
                    "Unsafe build parameter rejected: {:?}",
                    field
                )));
            }
        }

        let mut cmd = vec![compiler.to_string()];
        for san in sanitizers {
            cmd.extend(san.clang_compiler_flags());
        }
        cmd.push(source_rel_path.to_string());
        cmd.push("-o".to_string());
        cmd.push(output_rel_path.to_string());

        let mut config = ExecutionConfig::default();
        config.working_dir = working_dir.to_path_buf();
        config.command = cmd;
        config.network_policy = NetworkPolicy::Denied;
        config.read_only_rootfs = false;

        runner.execute(&config)
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

    #[test]
    fn test_mutation_fuzzer_discovers_length_overflow_from_short_seed() {
        struct LengthThresholdRunner;
        impl SandboxRunner for LengthThresholdRunner {
            fn execute(&self, config: &ExecutionConfig) -> Result<ExecutionOutput> {
                let len = config.stdin_input.as_ref().map(|v| v.len()).unwrap_or(0);
                if len >= 128 {
                    return Ok(ExecutionOutput {
                        exit_code: 1,
                        stdout: String::new(),
                        stderr: "==1==ERROR: AddressSanitizer: stack-buffer-overflow on 0x7fff\n    #0 0x401000 in parse_buf /app/main.c:9".to_string(),
                        duration_ms: 3,
                        stdout_blake3: "h1".to_string(),
                        stderr_blake3: "h2".to_string(),
                    });
                }
                Ok(ExecutionOutput {
                    exit_code: 0,
                    stdout: "ok".to_string(),
                    stderr: String::new(),
                    duration_ms: 2,
                    stdout_blake3: "h3".to_string(),
                    stderr_blake3: "h4".to_string(),
                })
            }
        }

        let temp_dir = tempfile::tempdir().unwrap();
        let res = MutationFuzzer::fuzz_until_reproduced(
            &LengthThresholdRunner,
            temp_dir.path(),
            &["/workspace/target".to_string()],
            &[b"hello".to_vec()],
            32,
            3,
        )
        .unwrap();

        assert_eq!(res.epistemic_tier, EpistemicTier::ConfirmedReproduced);
        assert!(res.discovered_payload.unwrap().len() >= 128);
        assert_eq!(res.witness.unwrap().successful_runs, 3);
    }
}
