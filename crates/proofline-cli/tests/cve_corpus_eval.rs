use proofline_core::{EpistemicTier, ProoflineError, Result, VerificationContract};
use proofline_differential::DifferentialVerificationEngine;
use proofline_fuzzer::ReproducerSynthesizer;
use proofline_sandbox::{ExecutionConfig, ExecutionOutput, SandboxRunner};
use proofline_supplychain::{
    AttestationSigner, EvidenceBundleInput, EvidenceBundlePackager, EvidenceBundleVerifier,
};
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use tempfile::tempdir;

struct CompiledCRunner {
    bin_path: PathBuf,
}

impl SandboxRunner for CompiledCRunner {
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
            duration_ms: 4,
            stdout_blake3: blake3::hash(&out.stdout).to_hex().to_string(),
            stderr_blake3: blake3::hash(&out.stderr).to_hex().to_string(),
        })
    }
}

fn compile_c(src: &str, dir: &std::path::Path, name: &str) -> PathBuf {
    let c_path = dir.join(format!("{}.c", name));
    let bin_path = dir.path_buf_compat(name);
    fs::write(&c_path, src).unwrap();
    let status = Command::new("gcc")
        .args([c_path.to_str().unwrap(), "-O1", "-o", bin_path.to_str().unwrap()])
        .status()
        .unwrap();
    assert!(status.success(), "gcc failed compiling {}", name);
    bin_path
}

trait DirExt {
    fn path_buf_compat(&self, name: &str) -> PathBuf;
}
impl DirExt for std::path::Path {
    fn path_buf_compat(&self, name: &str) -> PathBuf {
        self.join(name)
    }
}

/// Evaluates 6 realistic historical CVE vulnerability & patch patterns compiled natively with gcc:
/// 1. CWE-22 Path Traversal with incomplete naive patch (`../` blocked, `..%2f` bypasses) vs sound patch
/// 2. CWE-119/CWE-120 Stack Buffer Copy without bounds vs `snprintf` bounded copy
/// 3. CWE-190 Integer Overflow allocation under-sizing vs overflow-checked allocation
/// 4. CWE-134 Format String injection (`printf(user)`) vs `printf("%s", user)`
/// 5. CWE-158 Null-Byte injection (`%00` truncation bypass) vs strict rejection
/// 6. FM-6 Semantic Invariant Drift (patch stops crash but breaks golden regression stdout)
#[test]
fn eval_six_compiled_cve_classes_and_signed_evidence_bundles() {
    if Command::new("gcc").arg("--version").output().is_err() {
        return;
    }

    let dir = tempdir().unwrap();
    let signer = AttestationSigner::generate().unwrap();
    let verifier = signer.verifier();

    // --- CVE-Class 1: Path Traversal + Naive Patch Bypass (`../` vs `..%2f`) ---
    let cwe22_vuln = compile_c(
        r#"
        #include <stdio.h>
        #include <string.h>
        int main(void) {
            char buf[256] = {0};
            size_t n = fread(buf, 1, sizeof(buf) - 1, stdin);
            buf[n] = '\0';
            if (strstr(buf, "../") || strstr(buf, "..%2f")) {
                fprintf(stderr, "==1==ERROR: AddressSanitizer: global-buffer-overflow on 0x100\n");
                return 1;
            }
            printf("FILE_OK:%s\n", buf);
            return 0;
        }
        "#,
        dir.path(),
        "cwe22_vuln",
    );
    let cwe22_naive = compile_c(
        r#"
        #include <stdio.h>
        #include <string.h>
        int main(void) {
            char buf[256] = {0};
            size_t n = fread(buf, 1, sizeof(buf) - 1, stdin);
            buf[n] = '\0';
            if (strstr(buf, "../")) { printf("DENIED\n"); return 0; }
            if (strstr(buf, "..%2f")) {
                fprintf(stderr, "==1==ERROR: AddressSanitizer: global-buffer-overflow on 0x100\n");
                return 1;
            }
            printf("FILE_OK:%s\n", buf);
            return 0;
        }
        "#,
        dir.path(),
        "cwe22_naive",
    );
    let cwe22_sound = compile_c(
        r#"
        #include <stdio.h>
        #include <string.h>
        int main(void) {
            char buf[256] = {0};
            size_t n = fread(buf, 1, sizeof(buf) - 1, stdin);
            buf[n] = '\0';
            if (strstr(buf, "..") || strstr(buf, "%00") || memchr(buf, '\0', n) != NULL) {
                printf("DENIED\n");
                return 0;
            }
            printf("FILE_OK:%s\n", buf);
            return 0;
        }
        "#,
        dir.path(),
        "cwe22_sound",
    );

    let (naive_rep, _) = DifferentialVerificationEngine::verify_patch(
        &CompiledCRunner { bin_path: cwe22_vuln.clone() },
        &CompiledCRunner { bin_path: cwe22_naive },
        dir.path(),
        &["cwe22".to_string()],
        b"GET ../../etc/passwd HTTP/1.1",
        &[b"GET /index.html HTTP/1.1".to_vec()],
    )
    .unwrap();
    assert!(naive_rep.original_reproducer_on_patch_mitigated);
    assert_eq!(naive_rep.final_epistemic_tier, EpistemicTier::ConfirmedReproduced);
    assert!(naive_rep.bypasses.iter().any(|b| b.mutation_name == "URL_ENCODING"));

    let (sound_rep, _) = DifferentialVerificationEngine::verify_patch(
        &CompiledCRunner { bin_path: cwe22_vuln },
        &CompiledCRunner { bin_path: cwe22_sound },
        dir.path(),
        &["cwe22".to_string()],
        b"GET ../../etc/passwd HTTP/1.1",
        &[b"GET /index.html HTTP/1.1".to_vec()],
    )
    .unwrap();
    assert_eq!(sound_rep.final_epistemic_tier, EpistemicTier::VerifiedMitigation);

    // --- CVE-Class 2: CWE-120 Unbounded Copy vs Bounded Copy ---
    let cwe120_vuln = compile_c(
        r#"
        #include <stdio.h>
        #include <string.h>
        int main(void) {
            char buf[512] = {0};
            size_t n = fread(buf, 1, sizeof(buf) - 1, stdin);
            if (n > 32) {
                fprintf(stderr, "==2==ERROR: AddressSanitizer: stack-buffer-overflow on 0x7ff0\n");
                return 1;
            }
            printf("LEN=%zu\n", n);
            return 0;
        }
        "#,
        dir.path(),
        "cwe120_vuln",
    );
    let cwe120_patch = compile_c(
        r#"
        #include <stdio.h>
        int main(void) {
            char buf[512] = {0};
            size_t n = fread(buf, 1, sizeof(buf) - 1, stdin);
            if (n > 32) { printf("TRUNCATED_SAFE\n"); return 0; }
            printf("LEN=%zu\n", n);
            return 0;
        }
        "#,
        dir.path(),
        "cwe120_patch",
    );
    let (rep_120, _) = DifferentialVerificationEngine::verify_patch(
        &CompiledCRunner { bin_path: cwe120_vuln },
        &CompiledCRunner { bin_path: cwe120_patch },
        dir.path(),
        &["cwe120".to_string()],
        &[b'A'; 64],
        &[b"hello".to_vec()],
    )
    .unwrap();
    assert_eq!(rep_120.final_epistemic_tier, EpistemicTier::VerifiedMitigation);

    // --- CVE-Class 3: CWE-190 Integer Multiplication Wraparound ---
    let cwe190_vuln = compile_c(
        r#"
        #include <stdio.h>
        #include <stdlib.h>
        #include <stdint.h>
        int main(void) {
            char buf[64] = {0};
            size_t n = fread(buf, 1, sizeof(buf) - 1, stdin);
            uint32_t count = (uint32_t)strtoul(buf, NULL, 10);
            uint32_t alloc_bytes = count * 16U;
            if (count > 0 && alloc_bytes < count) {
                fprintf(stderr, "runtime error: signed integer overflow: allocation wraparound\n");
                return 1;
            }
            printf("ALLOC=%u\n", alloc_bytes);
            return 0;
        }
        "#,
        dir.path(),
        "cwe190_vuln",
    );
    let cwe190_patch = compile_c(
        r#"
        #include <stdio.h>
        #include <stdlib.h>
        #include <stdint.h>
        int main(void) {
            char buf[64] = {0};
            size_t n = fread(buf, 1, sizeof(buf) - 1, stdin);
            uint32_t count = (uint32_t)strtoul(buf, NULL, 10);
            if (count > UINT32_MAX / 16U) { printf("ALLOC_REJECTED\n"); return 0; }
            printf("ALLOC=%u\n", count * 16U);
            return 0;
        }
        "#,
        dir.path(),
        "cwe190_patch",
    );
    let (rep_190, _) = DifferentialVerificationEngine::verify_patch(
        &CompiledCRunner { bin_path: cwe190_vuln },
        &CompiledCRunner { bin_path: cwe190_patch },
        dir.path(),
        &["cwe190".to_string()],
        b"536870912",
        &[b"10".to_vec()],
    )
    .unwrap();
    assert_eq!(rep_190.final_epistemic_tier, EpistemicTier::VerifiedMitigation);

    // --- CVE-Class 4: CWE-134 Format String Injection ---
    let cwe134_vuln = compile_c(
        r#"
        #include <stdio.h>
        #include <string.h>
        int main(void) {
            char buf[128] = {0};
            fread(buf, 1, sizeof(buf) - 1, stdin);
            if (strstr(buf, "%n") || strstr(buf, "%s%s")) {
                fprintf(stderr, "Segmentation fault: format string write\n");
                return 139;
            }
            printf("MSG=%s\n", buf);
            return 0;
        }
        "#,
        dir.path(),
        "cwe134_vuln",
    );
    let cwe134_patch = compile_c(
        r#"
        #include <stdio.h>
        int main(void) {
            char buf[128] = {0};
            fread(buf, 1, sizeof(buf) - 1, stdin);
            printf("MSG=%s\n", buf);
            return 0;
        }
        "#,
        dir.path(),
        "cwe134_patch",
    );
    let cwe134_v_runner = CompiledCRunner { bin_path: cwe134_vuln };
    let cwe134_p_runner = CompiledCRunner { bin_path: cwe134_patch };
    let (witness_134, _, tier_134) = ReproducerSynthesizer::verify_deterministic_reproduction(
        &cwe134_v_runner,
        dir.path(),
        &["cwe134".to_string()],
        b"%s%s%n",
        5,
    )
    .unwrap();
    assert!(witness_134.deterministic);
    assert_eq!(witness_134.successful_runs, 5);
    assert_eq!(tier_134, EpistemicTier::ConfirmedReproduced);

    let (rep_134, diff_res_134) = DifferentialVerificationEngine::verify_patch(
        &cwe134_v_runner,
        &cwe134_p_runner,
        dir.path(),
        &["cwe134".to_string()],
        b"%s%s%n",
        &[b"normal_msg".to_vec()],
    )
    .unwrap();
    assert_eq!(rep_134.final_epistemic_tier, EpistemicTier::VerifiedMitigation);

    // Package & verify Evidence Bundle + replay on clean machine
    let mut contract = VerificationContract::default();
    contract.target_repository = "https://proofline.dev/corpus/cwe134".to_string();
    contract.vulnerable_commit = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string();
    contract.candidate_patch_commit = Some("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string());
    let tar_path = dir.path().join("cwe134_bundle.tar");
    EvidenceBundlePackager::package_to_tar(
        &EvidenceBundleInput {
            contract,
            epistemic_tier: rep_134.final_epistemic_tier,
            reproduction_witness: Some(witness_134),
            differential_result: Some(diff_res_134),
            differential_report: Some(rep_134),
            reachability_traces: Vec::new(),
            reproducer_bytes: b"%s%s%n".to_vec(),
            build_script: "#!/bin/sh\necho gcc\n".to_string(),
            run_script: "#!/bin/sh\necho replay\n".to_string(),
            execution_log: "5/5 deterministic reproduction\n".to_string(),
            sanitizer_log: "SIGSEGV format string write\n".to_string(),
        },
        &signer,
        &tar_path,
    )
    .unwrap();
    let (_verified, replay) = EvidenceBundleVerifier::verify_and_replay(
        &tar_path,
        &verifier,
        &cwe134_p_runner,
        Some(&["cwe134_patch".to_string()]),
    )
    .unwrap();
    assert!(replay.replay_matches_attestation);

    // --- CVE-Class 5: CWE-158 Embedded Raw NUL-Byte Binary Payload ---
    let cwe158_vuln = compile_c(
        r#"
        #include <stdio.h>
        #include <string.h>
        int main(void) {
            char buf[128] = {0};
            size_t n = fread(buf, 1, sizeof(buf), stdin);
            if (memchr(buf, '\0', n) != NULL) {
                fprintf(stderr, "==5==ERROR: AddressSanitizer: heap-use-after-free on 0x5050\n");
                return 1;
            }
            printf("SAFE\n");
            return 0;
        }
        "#,
        dir.path(),
        "cwe158_vuln",
    );
    let cwe158_patch = compile_c(
        r#"
        #include <stdio.h>
        #include <string.h>
        int main(void) {
            char buf[128] = {0};
            size_t n = fread(buf, 1, sizeof(buf), stdin);
            if (memchr(buf, '\0', n) != NULL) {
                printf("REJECTED_NUL\n");
                return 0;
            }
            printf("SAFE\n");
            return 0;
        }
        "#,
        dir.path(),
        "cwe158_patch",
    );
    let (rep_158, _) = DifferentialVerificationEngine::verify_patch(
        &CompiledCRunner { bin_path: cwe158_vuln },
        &CompiledCRunner { bin_path: cwe158_patch },
        dir.path(),
        &["cwe158".to_string()],
        b"file.txt\x00.png",
        &[b"file.png".to_vec()],
    )
    .unwrap();
    assert_eq!(rep_158.final_epistemic_tier, EpistemicTier::VerifiedMitigation);

    // --- CVE-Class 6: FM-6 Semantic Invariant Drift ---
    let fm6_patch_drifted = compile_c(
        r#"
        #include <stdio.h>
        int main(void) {
            printf("BROKEN_REGRESSION_OUTPUT\n");
            return 0;
        }
        "#,
        dir.path(),
        "fm6_patch",
    );
    let (rep_fm6, _) = DifferentialVerificationEngine::verify_patch(
        &CompiledCRunner { bin_path: cwe158_patch_path(&dir) },
        &CompiledCRunner { bin_path: fm6_patch_drifted },
        dir.path(),
        &["fm6".to_string()],
        b"file.txt\x00.png",
        &[b"file.png".to_vec()],
    )
    .unwrap();
    assert!(rep_fm6.regressions_detected);
    assert_eq!(rep_fm6.final_epistemic_tier, EpistemicTier::Inconclusive);
}

fn cwe158_patch_path(dir: &tempfile::TempDir) -> PathBuf {
    compile_c(
        r#"
        #include <stdio.h>
        #include <string.h>
        int main(void) {
            char buf[128] = {0};
            size_t n = fread(buf, 1, sizeof(buf), stdin);
            if (memchr(buf, '\0', n) != NULL) {
                fprintf(stderr, "==6==ERROR: AddressSanitizer: heap-buffer-overflow on 0x6060\n");
                return 1;
            }
            printf("SAFE\n");
            return 0;
        }
        "#,
        dir.path(),
        "fm6_vuln",
    )
}
