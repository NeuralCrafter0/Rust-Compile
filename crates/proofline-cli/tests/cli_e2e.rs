use proofline_cli::{
    analyze_source_file, generate_keypair, inspect_repo, verify_and_replay_bundle, verify_bundle,
    verify_patch_pipeline, PatchVerificationArgs, SourceLang,
};
use proofline_core::{EpistemicTier, Result, VerificationContract};
use proofline_sandbox::{ExecutionConfig, ExecutionOutput, SandboxRunner};
use proofline_supplychain::AttestationSigner;
use std::fs;
use std::process::Command;
use tempfile::tempdir;

struct VulnSimRunner;
impl SandboxRunner for VulnSimRunner {
    fn execute(&self, config: &ExecutionConfig) -> Result<ExecutionOutput> {
        let payload = config
            .env_vars
            .get("PROOFLINE_INPUT_PAYLOAD")
            .cloned()
            .unwrap_or_default();
        if payload.contains("../../etc/passwd") {
            return Ok(ExecutionOutput {
                exit_code: 139,
                stdout: String::new(),
                stderr: "==1==ERROR: AddressSanitizer: heap-buffer-overflow on 0x602000\n    #0 0x401234 in serve_file /app/http.c:21".to_string(),
                duration_ms: 5,
                stdout_blake3: blake3::hash(b"").to_hex().to_string(),
                stderr_blake3: blake3::hash(b"asan").to_hex().to_string(),
            });
        }
        Ok(ExecutionOutput {
            exit_code: 0,
            stdout: "OK".to_string(),
            stderr: String::new(),
            duration_ms: 5,
            stdout_blake3: blake3::hash(b"OK").to_hex().to_string(),
            stderr_blake3: blake3::hash(b"").to_hex().to_string(),
        })
    }
}

struct PatchSimRunner;
impl SandboxRunner for PatchSimRunner {
    fn execute(&self, _config: &ExecutionConfig) -> Result<ExecutionOutput> {
        Ok(ExecutionOutput {
            exit_code: 0,
            stdout: "OK".to_string(),
            stderr: String::new(),
            duration_ms: 5,
            stdout_blake3: blake3::hash(b"OK").to_hex().to_string(),
            stderr_blake3: blake3::hash(b"").to_hex().to_string(),
        })
    }
}

#[test]
fn test_full_end_to_end_pipeline_and_cli_binary() {
    let workspace = tempdir().unwrap();
    let repo_dir = workspace.path().join("repo");
    fs::create_dir_all(&repo_dir).unwrap();
    let c_path = repo_dir.join("vuln.c");
    fs::write(
        &c_path,
        r#"
        int process_packet() {
            char buffer[128];
            fgets(buffer, 1024, stdin);
            char dest[64];
            strcpy(dest, buffer);
            return 0;
        }
        "#,
    )
    .unwrap();
    fs::write(repo_dir.join("Makefile"), "all:\n\techo ok\n").unwrap();

    // 1. Inspect repo + SBOM
    let (inspection, sbom) = inspect_repo(&repo_dir, Some("demo-c-app")).unwrap();
    assert_eq!(inspection.total_source_files, 2);
    assert_eq!(sbom.bom_format, "CycloneDX");

    // 2. CPG + Taint + SARIF
    let (traces, sarif) = analyze_source_file(&c_path, Some(SourceLang::C)).unwrap();
    assert_eq!(traces.len(), 1);
    assert_eq!(sarif.version, "2.1.0");

    // 3. Keygen
    let key_dir = workspace.path().join("keys");
    let (priv_path, pub_path, _key_id) = generate_keypair(&key_dir).unwrap();
    let signer = AttestationSigner::from_key_file(&priv_path).unwrap();

    // 4. Patch Verification + Tar Bundle Packaging
    let tar_path = workspace.path().join("evidence.tar");
    let mut contract = VerificationContract::default();
    contract.target_repository = "https://github.com/example/demo-c-app".to_string();
    contract.vulnerable_commit = "1111111111111111111111111111111111111111".to_string();
    contract.candidate_patch_commit = Some("2222222222222222222222222222222222222222".to_string());

    let outcome = verify_patch_pipeline(
        &VulnSimRunner,
        &PatchSimRunner,
        PatchVerificationArgs {
            contract,
            working_dir: &repo_dir,
            vuln_command: &["/app/vuln".to_string()],
            patch_command: &["/app/patch".to_string()],
            reproducer_bytes: b"GET ../../etc/passwd HTTP/1.1",
            regression_inputs: &[b"GET /health HTTP/1.1".to_vec()],
            reproduction_runs: 3,
            reachability_traces: traces,
        },
        Some(&signer),
        Some(&tar_path),
    )
    .unwrap();

    assert_eq!(outcome.report.final_epistemic_tier, EpistemicTier::VerifiedMitigation);
    assert!(tar_path.exists());

    // 5. Independent Verification + Replay
    let verified = verify_bundle(&tar_path, &pub_path).unwrap();
    assert_eq!(verified.manifest.epistemic_tier, EpistemicTier::VerifiedMitigation);
    let (_verified2, replay) =
        verify_and_replay_bundle(&tar_path, &pub_path, &PatchSimRunner, None).unwrap();
    assert!(replay.replay_matches_attestation);

    // 6. Real compiled `proofline` binary CLI execution for inspect, analyze, keygen, verify-bundle
    let bin = env!("CARGO_BIN_EXE_proofline");
    let out = Command::new(bin)
        .args([
            "verify-bundle",
            "--bundle",
            tar_path.to_str().unwrap(),
            "--pubkey",
            pub_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "CLI verify-bundle failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("Verified bundle EVD-"));

    let inspect_out = Command::new(bin)
        .args(["inspect", repo_dir.to_str().unwrap(), "--json"])
        .output()
        .unwrap();
    assert!(inspect_out.status.success());

    let analyze_out = Command::new(bin)
        .args(["analyze", c_path.to_str().unwrap(), "--json"])
        .output()
        .unwrap();
    assert!(analyze_out.status.success());

    // 7. Verify contract validation & reproducible builds CLI commands
    let contract_file = workspace.path().join("contract.json");
    let mut c_obj = VerificationContract::default();
    c_obj.target_repository = "https://github.com/example/demo".to_string();
    c_obj.vulnerable_commit = "1111111111111111111111111111111111111111".to_string();
    fs::write(&contract_file, serde_json::to_string_pretty(&c_obj).unwrap()).unwrap();
    let vc_out = Command::new(bin)
        .args(["verify-contract", "--contract", contract_file.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(vc_out.status.success());

    let art_a = workspace.path().join("bin_a");
    let art_b = workspace.path().join("bin_b");
    fs::write(&art_a, b"deterministic-elf-bytes").unwrap();
    fs::write(&art_b, b"deterministic-elf-bytes").unwrap();
    let vb_out = Command::new(bin)
        .args(["verify-builds", art_a.to_str().unwrap(), art_b.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(vb_out.status.success());

    // 8. Multi-file repository interprocedural CPG analysis on tests/integration/cve-sim
    let repo_root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf();
    let cve_sim_dir = repo_root.join("tests/integration/cve-sim");
    if cve_sim_dir.exists() {
        let ar_out = Command::new(bin)
            .args(["analyze-repo", cve_sim_dir.to_str().unwrap(), "--json"])
            .output()
            .unwrap();
        assert!(
            ar_out.status.success(),
            "analyze-repo failed: {}",
            String::from_utf8_lossy(&ar_out.stderr)
        );
        let parsed: serde_json::Value = serde_json::from_slice(&ar_out.stdout).unwrap();
        assert_eq!(parsed.as_array().unwrap().len(), 1);
    }
}
