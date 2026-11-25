use proofline_core::{EpistemicTier, Result};
use proofline_fuzzer::{CrashOracle, ReproducerSynthesizer, SanitizerKind};
use proofline_sandbox::{ExecutionConfig, ExecutionOutput, SandboxRunner};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

struct FlakyRunner {
    counter: Arc<AtomicUsize>,
}

impl SandboxRunner for FlakyRunner {
    fn execute(&self, _config: &ExecutionConfig) -> Result<ExecutionOutput> {
        let count = self.counter.fetch_add(1, Ordering::SeqCst);
        if count % 2 == 0 {
            // Crash on even runs
            Ok(ExecutionOutput {
                exit_code: 1,
                stdout: String::new(),
                stderr: "==1==ERROR: AddressSanitizer: heap-buffer-overflow on 0x123".to_string(),
                duration_ms: 10,
                stdout_blake3: "hash1".to_string(),
                stderr_blake3: "hash2".to_string(),
            })
        } else {
            // Clean exit on odd runs (non-deterministic race condition)
            Ok(ExecutionOutput {
                exit_code: 0,
                stdout: "success".to_string(),
                stderr: String::new(),
                duration_ms: 10,
                stdout_blake3: "hash3".to_string(),
                stderr_blake3: "hash4".to_string(),
            })
        }
    }
}

#[test]
fn test_flaky_reproducer_classified_inconclusive() {
    let runner = FlakyRunner {
        counter: Arc::new(AtomicUsize::new(0)),
    };

    let temp_dir = tempfile::tempdir().unwrap();
    let cmd = vec!["/workspace/flaky_bin".to_string()];
    let payload = vec![0x90; 64];

    let (witness, _sig, tier) = ReproducerSynthesizer::verify_deterministic_reproduction(
        &runner,
        temp_dir.path(),
        &cmd,
        &payload,
        5,
    )
    .unwrap();

    // Must NOT be ConfirmedReproduced because it failed determinism
    assert!(!witness.deterministic);
    assert_eq!(tier, EpistemicTier::Inconclusive);
    assert!(witness.successful_runs < witness.total_attempted_runs);
}

#[test]
fn test_ubsan_overflow_detection() {
    let ubsan_err = "runtime error: signed integer overflow: 2147483647 + 1 cannot be represented in type 'int'";
    let sig = CrashOracle::evaluate_trace(1, ubsan_err, "").unwrap();
    assert_eq!(sig.fault_type, "INTEGER_OVERFLOW");
    assert_eq!(sig.detected_sanitizer, Some(SanitizerKind::UndefinedBehaviorSanitizer));
}

#[test]
fn test_stdout_spoofing_ignored_by_crash_oracle() {
    let echoed_stdout = "HTTP/1.1 200 OK\nAddressSanitizer: heap-buffer-overflow\n";
    assert!(
        CrashOracle::evaluate_trace(0, "", echoed_stdout).is_none(),
        "Echoed stdout must never spoof a crash signature"
    );
}
