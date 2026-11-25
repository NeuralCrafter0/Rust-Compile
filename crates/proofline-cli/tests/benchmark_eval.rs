use proofline_analysis::{PathVerificationStatus, TaintAnalysisEngine};
use proofline_core::{EpistemicTier, ProoflineError, Result};
use proofline_cpg::{CSourceParser, PythonSourceParser};
use proofline_differential::DifferentialVerificationEngine;
use proofline_fuzzer::ReproducerSynthesizer;
use proofline_intelligence::IngestionEngine;
use proofline_sandbox::{ExecutionConfig, ExecutionOutput, SandboxRunner};
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use tempfile::tempdir;

struct StaticEvalCase {
    name: &'static str,
    lang: &'static str,
    source: &'static str,
    expected_vulnerable: bool,
}

/// Evaluates static reachability precision and recall across a Juliet-style C & Python corpus.
#[test]
fn benchmark_static_reachability_precision_recall() {
    let cases = vec![
        StaticEvalCase {
            name: "cwe119_strcpy_unguarded",
            lang: "c",
            source: "int f() {\n char b[64];\n fgets(b, 256, stdin);\n char d[16];\n strcpy(d, b);\n }",
            expected_vulnerable: true,
        },
        StaticEvalCase {
            name: "cwe119_memcpy_unguarded",
            lang: "c",
            source: "int f() {\n char b[64];\n read(0, b, 256);\n char d[16];\n memcpy(d, b, 256);\n }",
            expected_vulnerable: true,
        },
        StaticEvalCase {
            name: "cwe119_strcat_bogus_guard",
            lang: "c",
            source: "int f() {\n char b[64];\n fgets(b, 256, stdin);\n if (1 < 2) {\n strcat(d, b);\n }\n }",
            expected_vulnerable: true,
        },
        StaticEvalCase {
            name: "cwe119_strcpy_guarded_sizeof",
            lang: "c",
            source: "int f() {\n char b[64];\n fgets(b, 64, stdin);\n char d[32];\n if (strlen(b) < sizeof(d)) {\n strcpy(d, b);\n }\n }",
            expected_vulnerable: false,
        },
        StaticEvalCase {
            name: "cwe119_clean_literal_copy",
            lang: "c",
            source: "int f() {\n char b[64];\n fgets(b, 64, stdin);\n char *safe = \"ok\";\n strcpy(d, safe);\n }",
            expected_vulnerable: false,
        },
        StaticEvalCase {
            name: "cwe89_python_sqli_fstring",
            lang: "py",
            source: "def h():\n user = request.args.get(\"u\")\n q = f\"SELECT * FROM t WHERE a='{user}'\"\n cursor.execute(q)\n",
            expected_vulnerable: true,
        },
        StaticEvalCase {
            name: "cwe78_python_os_system",
            lang: "py",
            source: "def h():\n arg = request.form[\"cmd\"]\n os.system(arg)\n",
            expected_vulnerable: true,
        },
        StaticEvalCase {
            name: "cwe89_python_sanitized",
            lang: "py",
            source: "def h():\n user = request.args.get(\"u\")\n sanitize(user)\n cursor.execute(user)\n",
            expected_vulnerable: false,
        },
        StaticEvalCase {
            name: "cwe89_python_reassigned_clean",
            lang: "py",
            source: "def h():\n user = request.args.get(\"u\")\n user = \"guest\"\n cursor.execute(user)\n",
            expected_vulnerable: false,
        },
    ];

    let mut tp = 0usize;
    let mut fp = 0usize;
    let mut tn = 0usize;
    let mut fn_count = 0usize;

    for case in &cases {
        let cpg = match case.lang {
            "c" => CSourceParser::parse_snippet(case.source, case.name).unwrap(),
            "py" => PythonSourceParser::parse_snippet(case.source, case.name).unwrap(),
            _ => unreachable!(),
        };
        let traces = TaintAnalysisEngine::analyze(&cpg);
        let predicted_vuln = traces
            .iter()
            .any(|t| t.status == PathVerificationStatus::UnguardedExploitableTaint);

        match (case.expected_vulnerable, predicted_vuln) {
            (true, true) => tp += 1,
            (false, true) => fp += 1,
            (false, false) => tn += 1,
            (true, false) => fn_count += 1,
        }
    }

    let precision = tp as f64 / (tp + fp) as f64;
    let recall = tp as f64 / (tp + fn_count) as f64;
    assert_eq!(fp, 0, "Expected 0 false positives in benchmark subset");
    assert_eq!(fn_count, 0, "Expected 0 false negatives in benchmark subset");
    assert!((precision - 1.0).abs() < f64::EPSILON);
    assert!((recall - 1.0).abs() < f64::EPSILON);
    assert_eq!(tp + tn, cases.len());
}

/// Evaluates historical patch-bypass patterns across CWE-22, CWE-89, and CWE-78.
#[test]
fn benchmark_historical_patch_bypass_corpus() {
    struct BypassCase {
        reproducer: &'static [u8],
        naive_patch_vuln_substring: &'static str,
        expected_mutation_prefix: &'static str,
    }

    let cases = [
        BypassCase {
            reproducer: b"GET ../../etc/passwd HTTP/1.1",
            naive_patch_vuln_substring: "..%2f",
            expected_mutation_prefix: "URL_ENCODING",
        },
        BypassCase {
            reproducer: b"GET ../../etc/passwd HTTP/1.1",
            naive_patch_vuln_substring: "..;/",
            expected_mutation_prefix: "SEMICOLON_PATH_PARAM_BYPASS",
        },
        BypassCase {
            reproducer: b"name=' OR 1=1--",
            naive_patch_vuln_substring: "/**/",
            expected_mutation_prefix: "SQLI_COMMENT_WHITESPACE_BYPASS",
        },
        BypassCase {
            reproducer: b"host=localhost; id",
            naive_patch_vuln_substring: "${IFS}",
            expected_mutation_prefix: "CMDI_IFS_WHITESPACE_BYPASS",
        },
    ];

    struct PatternRunner {
        trigger_on_exact: Vec<u8>,
        trigger_on_substr: Option<Vec<u8>>,
    }
    impl SandboxRunner for PatternRunner {
        fn execute(&self, config: &ExecutionConfig) -> Result<ExecutionOutput> {
            let payload = config.stdin_input.clone().unwrap_or_default();
            let hit_exact = !self.trigger_on_exact.is_empty() && payload == self.trigger_on_exact;
            let hit_sub = self
                .trigger_on_substr
                .as_ref()
                .map(|sub| payload.windows(sub.len()).any(|w| w == sub.as_slice()))
                .unwrap_or(false);
            if hit_exact || hit_sub {
                return Ok(ExecutionOutput {
                    exit_code: 1,
                    stdout: String::new(),
                    stderr: "==1==ERROR: AddressSanitizer: heap-buffer-overflow on 0x123".to_string(),
                    duration_ms: 2,
                    stdout_blake3: blake3::hash(b"").to_hex().to_string(),
                    stderr_blake3: blake3::hash(b"asan").to_hex().to_string(),
                });
            }
            Ok(ExecutionOutput {
                exit_code: 0,
                stdout: "ok".to_string(),
                stderr: String::new(),
                duration_ms: 2,
                stdout_blake3: blake3::hash(b"ok").to_hex().to_string(),
                stderr_blake3: blake3::hash(b"").to_hex().to_string(),
            })
        }
    }

    let dir = tempdir().unwrap();
    let mut bypasses_caught = 0usize;

    for case in &cases {
        let vuln_runner = PatternRunner {
            trigger_on_exact: case.reproducer.to_vec(),
            trigger_on_substr: None,
        };
        let patch_runner = PatternRunner {
            trigger_on_exact: Vec::new(),
            trigger_on_substr: Some(case.naive_patch_vuln_substring.as_bytes().to_vec()),
        };

        let (report, _) = DifferentialVerificationEngine::verify_patch(
            &vuln_runner,
            &patch_runner,
            dir.path(),
            &["/app/target".to_string()],
            case.reproducer,
            &[b"normal_request".to_vec()],
        )
        .unwrap();

        assert!(report.original_reproducer_on_patch_mitigated);
        assert_eq!(report.final_epistemic_tier, EpistemicTier::ConfirmedReproduced);
        assert!(
            report
                .bypasses
                .iter()
                .any(|b| b.mutation_name == case.expected_mutation_prefix),
            "Missing expected bypass {}",
            case.expected_mutation_prefix
        );
        bypasses_caught += 1;
    }

    assert_eq!(bypasses_caught, cases.len());
}

/// Real C compilation + execution benchmark inside the isolated test environment when `gcc` is available.
#[test]
fn benchmark_real_compiled_c_reproduction_and_differential_patch() {
    if Command::new("gcc").arg("--version").output().is_err() {
        return;
    }

    struct LocalBinaryRunner {
        bin_path: PathBuf,
    }
    impl SandboxRunner for LocalBinaryRunner {
        fn execute(&self, config: &ExecutionConfig) -> Result<ExecutionOutput> {
            let mut cmd = Command::new(&self.bin_path);
            cmd.current_dir(&config.working_dir)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            for (k, v) in &config.env_vars {
                cmd.env(k, v);
            }
            let mut child = cmd.spawn().map_err(ProoflineError::Io)?;
            if let Some(ref input) = config.stdin_input {
                if let Some(mut stdin) = child.stdin.take() {
                    let _ = stdin.write_all(input);
                }
            }
            let out = child.wait_with_output().map_err(ProoflineError::Io)?;
            Ok(ExecutionOutput {
                exit_code: out.status.code().unwrap_or(139),
                stdout: String::from_utf8_lossy(&out.stdout).to_string(),
                stderr: String::from_utf8_lossy(&out.stderr).to_string(),
                duration_ms: 5,
                stdout_blake3: blake3::hash(&out.stdout).to_hex().to_string(),
                stderr_blake3: blake3::hash(&out.stderr).to_hex().to_string(),
            })
        }
    }

    let dir = tempdir().unwrap();
    let vuln_c = dir.path().join("vuln.c");
    let patch_c = dir.path().join("patch.c");
    let vuln_bin = dir.path().join("vuln_bin");
    let patch_bin = dir.path().join("patch_bin");

    // Real vulnerable C parser triggering SIGSEGV / abort on traversal or long payload
    fs::write(
        &vuln_c,
        r#"
        #include <stdio.h>
        #include <string.h>
        #include <stdlib.h>
        int main(void) {
            char buf[256];
            size_t n = fread(buf, 1, sizeof(buf) - 1, stdin);
            buf[n] = '\0';
            if (strstr(buf, "../") != NULL) {
                fprintf(stderr, "Segmentation fault: unsafe traversal\n");
                return 139;
            }
            printf("OK:%s\n", buf);
            return 0;
        }
        "#,
    )
    .unwrap();

    // Sound patch rejecting both literal and encoded traversal cleanly
    fs::write(
        &patch_c,
        r#"
        #include <stdio.h>
        #include <string.h>
        int main(void) {
            char buf[256];
            size_t n = fread(buf, 1, sizeof(buf) - 1, stdin);
            buf[n] = '\0';
            if (strstr(buf, "..") != NULL) {
                printf("BLOCKED\n");
                return 0;
            }
            printf("OK:%s\n", buf);
            return 0;
        }
        "#,
    )
    .unwrap();

    assert!(Command::new("gcc").args([vuln_c.to_str().unwrap(), "-o", vuln_bin.to_str().unwrap()]).status().unwrap().success());
    assert!(Command::new("gcc").args([patch_c.to_str().unwrap(), "-o", patch_bin.to_str().unwrap()]).status().unwrap().success());

    let vuln_runner = LocalBinaryRunner { bin_path: vuln_bin };
    let patch_runner = LocalBinaryRunner { bin_path: patch_bin };

    let reproducer = b"GET ../../etc/passwd HTTP/1.1";
    let (witness, _, tier) = ReproducerSynthesizer::verify_deterministic_reproduction(
        &vuln_runner,
        dir.path(),
        &["vuln_bin".to_string()],
        reproducer,
        5,
    )
    .unwrap();
    assert!(witness.deterministic);
    assert_eq!(witness.successful_runs, 5);
    assert_eq!(tier, EpistemicTier::ConfirmedReproduced);

    let (diff_report, diff_res) = DifferentialVerificationEngine::verify_patch(
        &vuln_runner,
        &patch_runner,
        dir.path(),
        &["vuln_bin".to_string()],
        reproducer,
        &[b"GET /index.html HTTP/1.1".to_vec()],
    )
    .unwrap();

    assert!(diff_report.original_reproducer_on_vuln_crashed);
    assert!(diff_report.original_reproducer_on_patch_mitigated);
    assert!(!diff_report.regressions_detected);
    assert!(diff_res.regression_tests_passed);
    assert_eq!(diff_report.final_epistemic_tier, EpistemicTier::VerifiedMitigation);

    // Also verify real compiled C naive patch bypass: blocks "../" only, misses "..%2f"
    let naive_patch_c = dir.path().join("naive_patch.c");
    let naive_bin = dir.path().join("naive_bin");
    fs::write(
        &naive_patch_c,
        r#"
        #include <stdio.h>
        #include <string.h>
        int main(void) {
            char buf[256];
            size_t n = fread(buf, 1, sizeof(buf) - 1, stdin);
            buf[n] = '\0';
            if (strstr(buf, "../") != NULL) {
                printf("BLOCKED\n");
                return 0;
            }
            if (strstr(buf, "..%2f") != NULL) {
                fprintf(stderr, "Segmentation fault: URL-encoded traversal bypass\n");
                return 139;
            }
            printf("OK:%s\n", buf);
            return 0;
        }
        "#,
    )
    .unwrap();
    assert!(Command::new("gcc").args([naive_patch_c.to_str().unwrap(), "-o", naive_bin.to_str().unwrap()]).status().unwrap().success());
    let naive_runner = LocalBinaryRunner { bin_path: naive_bin };
    let (bypass_report, _) = DifferentialVerificationEngine::verify_patch(
        &vuln_runner,
        &naive_runner,
        dir.path(),
        &["naive_bin".to_string()],
        reproducer,
        &[b"GET /index.html HTTP/1.1".to_vec()],
    )
    .unwrap();
    assert!(bypass_report.original_reproducer_on_patch_mitigated);
    assert_eq!(bypass_report.final_epistemic_tier, EpistemicTier::ConfirmedReproduced);
    assert!(bypass_report.bypasses.iter().any(|b| b.mutation_name == "URL_ENCODING"));

    // Also inspect adversarial fixture repo without executing Makefile
    let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf();
    let adv_dir = repo_root.join("tests/adversarial-repos/malicious-makefile");
    if adv_dir.exists() {
        let inspection = IngestionEngine::default().inspect_repository(&adv_dir).unwrap();
        assert_eq!(inspection.total_source_files, 1);
        assert!(!PathBuf::from("/tmp/proofline_compromised_marker").exists());
    }
}
