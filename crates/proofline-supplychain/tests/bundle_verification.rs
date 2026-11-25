use proofline_analysis::TaintAnalysisEngine;
use proofline_core::{EpistemicTier, ProoflineError, Result, VerificationContract};
use proofline_cpg::CSourceParser;
use proofline_differential::DifferentialVerificationEngine;
use proofline_fuzzer::ReproducerSynthesizer;
use proofline_intelligence::IngestionEngine;
use proofline_sandbox::{ExecutionConfig, ExecutionOutput, SandboxRunner};
use proofline_supplychain::{
    read_deterministic_tar, write_deterministic_tar, AttestationSigner, EvidenceBundleInput,
    EvidenceBundlePackager, EvidenceBundleVerifier, RekorInclusionMetadata,
    ReproducibleBuildVerifier, SbomGenerator, SignerTrustVerdict, TrustedIdentityPolicy,
    VerificationMarkdownRenderer,
};
use std::collections::BTreeMap;
use std::fs;
use tempfile::tempdir;

struct MockVulnRunner;
impl SandboxRunner for MockVulnRunner {
    fn execute(&self, config: &ExecutionConfig) -> Result<ExecutionOutput> {
        let payload = config
            .env_vars
            .get("PROOFLINE_INPUT_PAYLOAD")
            .cloned()
            .unwrap_or_default();
        if payload.contains("../../etc/passwd") {
            return Ok(ExecutionOutput {
                exit_code: 1,
                stdout: String::new(),
                stderr: "==10==ERROR: AddressSanitizer: stack-buffer-overflow on 0x7fff\n    #0 0x401000 in handle_path /src/server.c:42".to_string(),
                duration_ms: 8,
                stdout_blake3: blake3::hash(b"").to_hex().to_string(),
                stderr_blake3: blake3::hash(b"asan").to_hex().to_string(),
            });
        }
        Ok(ExecutionOutput {
            exit_code: 0,
            stdout: "200 OK".to_string(),
            stderr: String::new(),
            duration_ms: 4,
            stdout_blake3: blake3::hash(b"200 OK").to_hex().to_string(),
            stderr_blake3: blake3::hash(b"").to_hex().to_string(),
        })
    }
}

struct MockPatchRunner;
impl SandboxRunner for MockPatchRunner {
    fn execute(&self, _config: &ExecutionConfig) -> Result<ExecutionOutput> {
        Ok(ExecutionOutput {
            exit_code: 0,
            stdout: "200 OK".to_string(),
            stderr: String::new(),
            duration_ms: 4,
            stdout_blake3: blake3::hash(b"200 OK").to_hex().to_string(),
            stderr_blake3: blake3::hash(b"").to_hex().to_string(),
        })
    }
}

fn build_sample_bundle_input(workdir: &std::path::Path) -> EvidenceBundleInput {
    let reproducer = b"GET ../../etc/passwd HTTP/1.1".to_vec();
    let cmd = vec!["/bin/sh".to_string(), "harness/run.sh".to_string()];

    let (witness, _sig, _tier) = ReproducerSynthesizer::verify_deterministic_reproduction(
        &MockVulnRunner,
        workdir,
        &cmd,
        &reproducer,
        5,
    )
    .unwrap();

    let (diff_report, diff_result) = DifferentialVerificationEngine::verify_patch(
        &MockVulnRunner,
        &MockPatchRunner,
        workdir,
        &cmd,
        &reproducer,
        &[b"GET /index.html HTTP/1.1".to_vec()],
    )
    .unwrap();

    let cpg = CSourceParser::parse_snippet(
        "int f() {\n char buf[64];\n fgets(buf, 512, stdin);\n char dst[16];\n strcpy(dst, buf);\n }",
        "server.c",
    )
    .unwrap();
    let traces = TaintAnalysisEngine::analyze(&cpg);

    let mut contract = VerificationContract::default();
    contract.target_repository = "https://github.com/example/http-codec".to_string();
    contract.vulnerable_commit = "a1b2c3d4e5f67890123456789012345678901234".to_string();
    contract.candidate_patch_commit = Some("f6e5d4c3b2a10987654321098765432109876543".to_string());

    EvidenceBundleInput {
        contract,
        epistemic_tier: diff_report.final_epistemic_tier,
        reproduction_witness: Some(witness),
        differential_result: Some(diff_result),
        differential_report: Some(diff_report),
        reachability_traces: traces,
        reproducer_bytes: reproducer,
        build_script: "#!/bin/sh\necho built\n".to_string(),
        run_script: "#!/bin/sh\necho running\n".to_string(),
        execution_log: "run ok\x1b[31mANSI\x1b[0m\n".to_string(),
        sanitizer_log: "==10==ERROR: AddressSanitizer: stack-buffer-overflow\n".to_string(),
    }
}

#[test]
fn test_bundle_tar_and_dir_sign_verify_and_replay() {
    let workdir = tempdir().unwrap();
    let out_dir = tempdir().unwrap();
    let key_dir = tempdir().unwrap();

    let signer = AttestationSigner::generate().unwrap();
    let (_priv_path, pub_path) = signer.save_keypair_files(key_dir.path()).unwrap();

    let input = build_sample_bundle_input(workdir.path());
    let bundle_dir = out_dir.path().join("bundle_dir");
    let tar_path = out_dir.path().join("bundle.tar");

    let dir_manifest =
        EvidenceBundlePackager::package_to_dir(&input, &signer, &bundle_dir).unwrap();
    let tar_manifest =
        EvidenceBundlePackager::package_to_tar(&input, &signer, &tar_path).unwrap();

    assert_eq!(dir_manifest.epistemic_tier, EpistemicTier::VerifiedMitigation);
    assert_eq!(tar_manifest.epistemic_tier, EpistemicTier::VerifiedMitigation);

    // Clean machine verifier loads ONLY public key
    let clean_verifier = proofline_supplychain::AttestationVerifier::from_key_file(&pub_path).unwrap();

    let verified_dir = EvidenceBundleVerifier::verify_bundle_dir(&bundle_dir, &clean_verifier).unwrap();
    assert_eq!(verified_dir.manifest.bundle_id, dir_manifest.bundle_id);
    assert!(verified_dir.verified_artifact_count >= 8);

    let (verified_tar, replay) =
        EvidenceBundleVerifier::verify_and_replay(&tar_path, &clean_verifier, &MockPatchRunner, None)
            .unwrap();
    assert_eq!(verified_tar.manifest.bundle_id, tar_manifest.bundle_id);
    assert!(replay.replay_matches_attestation);

    // Confirm ANSI escape sequence was sanitized in execution.log
    let exec_log = fs::read_to_string(bundle_dir.join("traces/execution.log")).unwrap();
    assert!(!exec_log.contains('\x1b'));
    assert_eq!(exec_log, "run okANSI\n");
}

#[test]
fn test_tampered_bundle_and_rogue_file_rejected() {
    let workdir = tempdir().unwrap();
    let out_dir = tempdir().unwrap();

    let signer = AttestationSigner::generate().unwrap();
    let verifier = signer.verifier();
    let input = build_sample_bundle_input(workdir.path());

    let bundle_dir = out_dir.path().join("bundle_tamper");
    EvidenceBundlePackager::package_to_dir(&input, &signer, &bundle_dir).unwrap();

    // 1. Modify reproducer.bin -> must fail digest/Merkle check
    fs::write(bundle_dir.join("harness/reproducer.bin"), b"TAMPERED").unwrap();
    assert!(matches!(
        EvidenceBundleVerifier::verify_bundle_dir(&bundle_dir, &verifier),
        Err(ProoflineError::CryptoError(_))
    ));

    // Restore via fresh bundle and test rogue extra file injection
    let bundle_dir2 = out_dir.path().join("bundle_rogue");
    EvidenceBundlePackager::package_to_dir(&input, &signer, &bundle_dir2).unwrap();
    fs::write(bundle_dir2.join("harness/evil.sh"), b"rm -rf /").unwrap();
    assert!(matches!(
        EvidenceBundleVerifier::verify_bundle_dir(&bundle_dir2, &verifier),
        Err(ProoflineError::CryptoError(_))
    ));

    // Wrong verifying key must fail
    let wrong_signer = AttestationSigner::generate().unwrap();
    let bundle_dir3 = out_dir.path().join("bundle_wrong_key");
    EvidenceBundlePackager::package_to_dir(&input, &signer, &bundle_dir3).unwrap();
    assert!(matches!(
        EvidenceBundleVerifier::verify_bundle_dir(&bundle_dir3, &wrong_signer.verifier()),
        Err(ProoflineError::CryptoError(_))
    ));
}

#[test]
fn test_tar_rejects_path_traversal_and_symlinks() {
    let dir = tempdir().unwrap();
    let tar_path = dir.path().join("evil.tar");

    let mut entries = BTreeMap::new();
    entries.insert("../escape.txt".to_string(), b"pwned".to_vec());
    assert!(matches!(
        write_deterministic_tar(&entries, &tar_path),
        Err(ProoflineError::IsolationViolation(_))
    ));

    // Craft a raw USTAR tar entry with symlink typeflag '2'
    let mut header = [0u8; 512];
    header[..9].copy_from_slice(b"evil_link");
    header[100..108].copy_from_slice(b"0000777\0");
    header[108..116].copy_from_slice(b"0000000\0");
    header[116..124].copy_from_slice(b"0000000\0");
    header[124..136].copy_from_slice(b"00000000000\0");
    header[136..148].copy_from_slice(b"00000000000\0");
    header[148..156].copy_from_slice(b"        ");
    header[156] = b'2'; // symlink
    header[157..168].copy_from_slice(b"/etc/passwd");
    header[257..263].copy_from_slice(b"ustar\0");
    header[263..265].copy_from_slice(b"00");
    let sum: u32 = header.iter().map(|&b| b as u32).sum();
    let chk = format!("{:06o}\0 ", sum);
    header[148..156].copy_from_slice(chk.as_bytes());

    let mut raw = Vec::new();
    raw.extend_from_slice(&header);
    raw.extend_from_slice(&[0u8; 1024]);
    let evil_tar = dir.path().join("symlink.tar");
    fs::write(&evil_tar, raw).unwrap();

    assert!(matches!(
        read_deterministic_tar(&evil_tar),
        Err(ProoflineError::IsolationViolation(_))
    ));
}

#[test]
fn test_cyclonedx_sbom_from_inspection() {
    let dir = tempdir().unwrap();
    fs::write(
        dir.path().join("Cargo.toml"),
        "[package]\nname = \"demo\"\nversion = \"0.1.0\"\n[dependencies]\nblake3 = \"1.5\"\n",
    )
    .unwrap();
    let inspection = IngestionEngine::default().inspect_repository(dir.path()).unwrap();
    let bom = SbomGenerator::to_cyclonedx("demo", &inspection);
    assert_eq!(bom.bom_format, "CycloneDX");
    assert_eq!(bom.spec_version, "1.5");
    assert_eq!(bom.components.len(), 1);
    assert_eq!(bom.components[0].name, "blake3");
    assert_eq!(bom.components[0].version, "1.5");
}

#[test]
fn test_signature_validity_distinct_from_trusted_signer_policy() {
    let workdir = tempdir().unwrap();
    let out_dir = tempdir().unwrap();
    let signer = AttestationSigner::generate().unwrap();
    let input = build_sample_bundle_input(workdir.path());

    let tar_path = out_dir.path().join("policy.tar");
    EvidenceBundlePackager::package_to_tar(&input, &signer, &tar_path).unwrap();

    // Cryptographically valid signature under signer's public key
    let verified = EvidenceBundleVerifier::verify_bundle_tar(&tar_path, &signer.verifier()).unwrap();

    // Untrusted signer policy rejects even a cryptographically valid signature
    let strict_policy = TrustedIdentityPolicy {
        trusted_key_ids: vec!["ed25519:0000000000000000".to_string()],
        trusted_builder_ids: vec!["https://proofline.dev/cli/".to_string()],
    };
    assert!(matches!(
        EvidenceBundleVerifier::evaluate_trust_policy(&verified, &strict_policy),
        SignerTrustVerdict::ValidSignatureUntrustedSigner { .. }
    ));

    // Matching key_id + builder_id passes
    let matching_policy = TrustedIdentityPolicy {
        trusted_key_ids: vec![signer.key_id().to_string()],
        trusted_builder_ids: vec!["https://proofline.dev/cli/".to_string()],
    };
    assert!(matches!(
        EvidenceBundleVerifier::evaluate_trust_policy(&verified, &matching_policy),
        SignerTrustVerdict::TrustedIdentityAndBuilder { .. }
    ));

    // Bit-for-bit reproducible build verification + Markdown rendering
    let eq = ReproducibleBuildVerifier::compare_bytes(b"ELF\x7fbuild1", b"ELF\x7fbuild1");
    assert!(eq.identical_bit_for_bit);
    assert_eq!(eq.first_diverging_offset, None);

    let diff = ReproducibleBuildVerifier::compare_bytes(b"ELF\x7fbuild1", b"ELF\x7fbuild2");
    assert!(!diff.identical_bit_for_bit);
    assert_eq!(diff.first_diverging_offset, Some(9));

    let md = VerificationMarkdownRenderer::render_summary(
        Some(&verified.manifest),
        input.differential_report.as_ref().unwrap(),
        &input.reachability_traces,
    );
    assert!(md.contains("Proofline Verification Report"));
    assert!(md.contains("CAS Merkle Root"));

    // Rekor offline inclusion metadata binding check
    let mut sha = [0u8; 64];
    sha.fill(b'a');
    let sha_str = std::str::from_utf8(&sha).unwrap();
    let rekor = RekorInclusionMetadata {
        log_id: sha_str.to_string(),
        log_index: 42,
        integrated_time: 1_764_000_000,
        artifact_sha256: sha_str.to_string(),
        set_signature_b64: "c2lnbmF0dXJl".to_string(),
    };
    assert!(rekor.validate_binding(sha_str).is_ok());
    assert!(rekor.validate_binding("bbbb").is_err());
}
