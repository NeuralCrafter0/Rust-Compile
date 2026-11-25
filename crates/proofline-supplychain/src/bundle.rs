//! Evidence Bundle Packaging, Merkle Tree CAS Verification, and Clean Replay.
//! Implements the layout in RFC-001 Section 14.1 and schema `schemas/evidence-bundle.schema.json`.

use crate::archive::{
    extract_entries_safely, read_deterministic_tar, validate_archive_rel_path, write_deterministic_tar,
};
use crate::attestation::{
    AttestationSigner, AttestationVerifier, DsseEnvelope, InTotoStatement, InTotoSubject,
    ProoflineVerificationPredicate, SignerTrustVerdict, TrustedIdentityPolicy,
    IN_TOTO_STATEMENT_TYPE_V1, PROOFLINE_PREDICATE_TYPE_V1,
};
use crate::hex_encode;
use crate::sarif::SarifExporter;
use chrono::{DateTime, Utc};
use proofline_analysis::ReachabilityTrace;
use proofline_core::{
    sanitize_terminal_trace, DifferentialVerificationResult, EpistemicTier, EvidenceBundle,
    ProoflineError, ReproductionWitness, Result, VerificationContract,
};
use proofline_differential::DifferentialPatchReport;
use proofline_fuzzer::CrashOracle;
use proofline_sandbox::{attach_input_payload, ExecutionConfig, NetworkPolicy, SandboxRunner};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;
use uuid::Uuid;
use walkdir::WalkDir;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetCommitsManifest {
    pub vulnerable: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub candidate_patch: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReproductionWitnessManifest {
    pub deterministic: bool,
    pub successful_runs: u32,
    pub total_attempted_runs: u32,
    pub input_artifact_hash: String,
    pub fault_signal_or_oracle: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stack_trace_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DifferentialVerificationManifest {
    pub original_reproducer_on_patch: String,
    pub regression_suite_status: String,
    pub mutation_fuzzing_bypasses_found: u64,
    pub mutation_iterations_completed: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CasArtifactEntry {
    pub path: String,
    pub digest: String,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CasHashesManifest {
    pub hash_algorithm: String,
    pub merkle_root_hash: String,
    pub artifacts: Vec<CasArtifactEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestAttestation {
    pub signature_algorithm: String,
    pub key_id: String,
    pub signature: String,
}

/// Schema-compliant Evidence Bundle `manifest.json` matching `schemas/evidence-bundle.schema.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleManifest {
    pub schema_version: String,
    pub bundle_id: String,
    pub timestamp: DateTime<Utc>,
    pub target_repository: String,
    pub target_commits: TargetCommitsManifest,
    pub epistemic_tier: EpistemicTier,
    pub reproduction_witness: ReproductionWitnessManifest,
    pub differential_verification: DifferentialVerificationManifest,
    pub cas_hashes: CasHashesManifest,
    pub attestation: ManifestAttestation,
}

#[derive(Serialize)]
struct ManifestSignableView<'a> {
    schema_version: &'a str,
    bundle_id: &'a str,
    timestamp: &'a DateTime<Utc>,
    target_repository: &'a str,
    target_commits: &'a TargetCommitsManifest,
    epistemic_tier: EpistemicTier,
    reproduction_witness: &'a ReproductionWitnessManifest,
    differential_verification: &'a DifferentialVerificationManifest,
    cas_hashes: &'a CasHashesManifest,
    signature_algorithm: &'a str,
    key_id: &'a str,
}

#[derive(Debug, Clone)]
pub struct EvidenceBundleInput {
    pub contract: VerificationContract,
    pub epistemic_tier: EpistemicTier,
    pub reproduction_witness: Option<ReproductionWitness>,
    pub differential_result: Option<DifferentialVerificationResult>,
    pub differential_report: Option<DifferentialPatchReport>,
    pub reachability_traces: Vec<ReachabilityTrace>,
    pub reproducer_bytes: Vec<u8>,
    pub build_script: String,
    pub run_script: String,
    pub execution_log: String,
    pub sanitizer_log: String,
}

#[derive(Debug, Clone)]
pub struct VerifiedBundleReport {
    pub manifest: BundleManifest,
    pub statement: InTotoStatement,
    pub verified_artifact_count: usize,
}

#[derive(Debug, Clone)]
pub struct ReplayVerificationReport {
    pub bundle_id: String,
    pub attested_tier: EpistemicTier,
    pub observed_exit_code: i32,
    pub observed_fault_type: Option<String>,
    pub replay_matches_attestation: bool,
}

/// Computes a domain-separated binary BLAKE3 Merkle tree root over sorted CAS artifact leaves.
pub fn compute_cas_merkle_root(artifacts: &[CasArtifactEntry]) -> String {
    if artifacts.is_empty() {
        return blake3::hash(b"proofline.cas.empty.v1").to_hex().to_string();
    }

    let mut sorted = artifacts.to_vec();
    sorted.sort_by(|a, b| a.path.cmp(&b.path));

    let mut layer: Vec<[u8; 32]> = sorted
        .iter()
        .map(|entry| {
            let mut h = blake3::Hasher::new();
            h.update(&[0x00]); // Leaf domain separator
            h.update(&(entry.path.len() as u64).to_le_bytes());
            h.update(entry.path.as_bytes());
            h.update(&entry.size_bytes.to_le_bytes());
            h.update(entry.digest.as_bytes());
            *h.finalize().as_bytes()
        })
        .collect();

    while layer.len() > 1 {
        let mut next_layer = Vec::with_capacity((layer.len() + 1) / 2);
        for pair in layer.chunks(2) {
            if pair.len() == 2 {
                let mut h = blake3::Hasher::new();
                h.update(&[0x01]); // Internal node domain separator
                h.update(&pair[0]);
                h.update(&pair[1]);
                next_layer.push(*h.finalize().as_bytes());
            } else {
                // Promote odd node cleanly
                next_layer.push(pair[0]);
            }
        }
        layer = next_layer;
    }

    hex_encode(&layer[0])
}

pub struct EvidenceBundlePackager;

impl EvidenceBundlePackager {
    /// Builds all Evidence Bundle contents, signs both `manifest.json` and `attestation.in-toto.json`,
    /// and writes the directory structure to `out_dir`.
    pub fn package_to_dir(
        input: &EvidenceBundleInput,
        signer: &AttestationSigner,
        out_dir: &Path,
    ) -> Result<BundleManifest> {
        let (files, manifest) = Self::build_bundle_files(input, signer)?;
        fs::create_dir_all(out_dir).map_err(ProoflineError::Io)?;
        for (rel_path, bytes) in files {
            validate_archive_rel_path(&rel_path)?;
            let full = out_dir.join(&rel_path);
            if let Some(parent) = full.parent() {
                fs::create_dir_all(parent).map_err(ProoflineError::Io)?;
            }
            fs::write(&full, &bytes).map_err(ProoflineError::Io)?;
            #[cfg(unix)]
            if rel_path.ends_with(".sh") {
                use std::os::unix::fs::PermissionsExt as _;
                let mut perms = fs::metadata(&full)?.permissions();
                perms.set_mode(0o755);
                fs::set_permissions(&full, perms)?;
            }
        }
        Ok(manifest)
    }

    /// Builds a deterministic, verifiable `.tar` Evidence Bundle archive.
    pub fn package_to_tar(
        input: &EvidenceBundleInput,
        signer: &AttestationSigner,
        dest_tar: &Path,
    ) -> Result<BundleManifest> {
        let (files, manifest) = Self::build_bundle_files(input, signer)?;
        if let Some(parent) = dest_tar.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).map_err(ProoflineError::Io)?;
            }
        }
        write_deterministic_tar(&files, dest_tar)?;
        Ok(manifest)
    }

    fn build_bundle_files(
        input: &EvidenceBundleInput,
        signer: &AttestationSigner,
    ) -> Result<(BTreeMap<String, Vec<u8>>, BundleManifest)> {
        let now = Utc::now();
        let bundle_id = format!(
            "EVD-{}-{}",
            now.format("%Y"),
            Uuid::new_v4().simple().to_string().to_uppercase()
        );
        let target_repo_uri = normalize_repo_uri(&input.contract.target_repository);
        let vuln_commit = normalize_commit_sha(&input.contract.vulnerable_commit);
        let patch_commit = input
            .contract
            .candidate_patch_commit
            .as_deref()
            .map(normalize_commit_sha);

        let core_bundle = EvidenceBundle::new(
            &input.contract,
            input.epistemic_tier,
            input.reproduction_witness.clone(),
            input.differential_result.clone(),
        );

        let sarif = SarifExporter::from_verification_summary(
            &core_bundle,
            input.differential_report.as_ref(),
            &input.reachability_traces,
        );

        let mut files: BTreeMap<String, Vec<u8>> = BTreeMap::new();
        files.insert(
            "verification-contract.json".to_string(),
            serde_json::to_vec_pretty(&input.contract)?,
        );
        files.insert(
            "sarif.json".to_string(),
            serde_json::to_vec_pretty(&sarif)?,
        );
        files.insert(
            "harness/build.sh".to_string(),
            input.build_script.as_bytes().to_vec(),
        );
        files.insert(
            "harness/run.sh".to_string(),
            input.run_script.as_bytes().to_vec(),
        );
        files.insert(
            "harness/reproducer.bin".to_string(),
            input.reproducer_bytes.clone(),
        );
        files.insert(
            "traces/execution.log".to_string(),
            sanitize_terminal_trace(&input.execution_log).into_bytes(),
        );
        files.insert(
            "traces/sanitizer.log".to_string(),
            sanitize_terminal_trace(&input.sanitizer_log).into_bytes(),
        );

        // Compute SHA-256 tree before finalizing CAS artifact entries
        let mut sha256_map = BTreeMap::new();
        for (path, data) in &files {
            sha256_map.insert(path.clone(), hex_encode(&Sha256::digest(data)));
        }
        files.insert(
            "cas/blake3/sha256_tree.json".to_string(),
            serde_json::to_vec_pretty(&sha256_map)?,
        );

        let mut cas_artifacts: Vec<CasArtifactEntry> = files
            .iter()
            .map(|(path, data)| CasArtifactEntry {
                path: path.clone(),
                digest: blake3::hash(data).to_hex().to_string(),
                size_bytes: data.len() as u64,
            })
            .collect();
        cas_artifacts.sort_by(|a, b| a.path.cmp(&b.path));

        files.insert(
            "cas/blake3/artifact_digests.json".to_string(),
            serde_json::to_vec_pretty(&cas_artifacts)?,
        );

        // Recompute cas_artifacts including artifact_digests.json? No: artifact_digests.json lists
        // all non-digest-index files, while sha256_tree.json is included in cas_artifacts.
        // We compute merkle_root_hash over all entries in cas_artifacts.
        let merkle_root_hash = compute_cas_merkle_root(&cas_artifacts);

        let witness_manifest = match &input.reproduction_witness {
            Some(w) => ReproductionWitnessManifest {
                deterministic: w.deterministic,
                successful_runs: w.successful_runs,
                total_attempted_runs: w.total_attempted_runs,
                input_artifact_hash: w.input_artifact_blake3.clone(),
                fault_signal_or_oracle: w.fault_signal_or_oracle.clone(),
                stack_trace_hash: Some(w.execution_trace_blake3.clone()),
            },
            None => ReproductionWitnessManifest {
                deterministic: false,
                successful_runs: 0,
                total_attempted_runs: 0,
                input_artifact_hash: blake3::hash(&input.reproducer_bytes).to_hex().to_string(),
                fault_signal_or_oracle: "NONE".to_string(),
                stack_trace_hash: None,
            },
        };

        let diff_manifest = match &input.differential_result {
            Some(d) => DifferentialVerificationManifest {
                original_reproducer_on_patch: if d.original_reproducer_on_patch_mitigated {
                    "PASSED_MITIGATED".to_string()
                } else {
                    "FAILED_STILL_VULNERABLE".to_string()
                },
                regression_suite_status: if d.regression_tests_passed {
                    "ALL_PASSED".to_string()
                } else {
                    "REGRESSIONS_DETECTED".to_string()
                },
                mutation_fuzzing_bypasses_found: d.bypasses_discovered,
                mutation_iterations_completed: d.bypass_mutations_evaluated,
            },
            None => DifferentialVerificationManifest {
                original_reproducer_on_patch: "SKIPPED".to_string(),
                regression_suite_status: "SKIPPED".to_string(),
                mutation_fuzzing_bypasses_found: 0,
                mutation_iterations_completed: 0,
            },
        };

        let target_commits = TargetCommitsManifest {
            vulnerable: vuln_commit.clone(),
            candidate_patch: patch_commit.clone(),
        };
        let cas_hashes = CasHashesManifest {
            hash_algorithm: "BLAKE3".to_string(),
            merkle_root_hash: merkle_root_hash.clone(),
            artifacts: cas_artifacts,
        };

        let signable = ManifestSignableView {
            schema_version: "1.0.0",
            bundle_id: &bundle_id,
            timestamp: &now,
            target_repository: &target_repo_uri,
            target_commits: &target_commits,
            epistemic_tier: input.epistemic_tier,
            reproduction_witness: &witness_manifest,
            differential_verification: &diff_manifest,
            cas_hashes: &cas_hashes,
            signature_algorithm: "Ed25519",
            key_id: signer.key_id(),
        };
        let canonical_manifest = serde_jcs::to_vec(&signable).map_err(|e| {
            ProoflineError::CryptoError(format!("Manifest JCS serialization failed: {}", e))
        })?;
        let manifest_sig_b64 = signer.sign_bytes_b64(&canonical_manifest);
        let manifest_sha256 = hex_encode(&Sha256::digest(&canonical_manifest));

        let manifest = BundleManifest {
            schema_version: "1.0.0".to_string(),
            bundle_id: bundle_id.clone(),
            timestamp: now,
            target_repository: target_repo_uri.clone(),
            target_commits,
            epistemic_tier: input.epistemic_tier,
            reproduction_witness: witness_manifest,
            differential_verification: diff_manifest,
            cas_hashes,
            attestation: ManifestAttestation {
                signature_algorithm: "Ed25519".to_string(),
                key_id: signer.key_id().to_string(),
                signature: manifest_sig_b64,
            },
        };

        let mut subject_digest = BTreeMap::new();
        subject_digest.insert("blake3".to_string(), merkle_root_hash.clone());
        subject_digest.insert("sha256".to_string(), manifest_sha256);

        let statement = InTotoStatement {
            statement_type: IN_TOTO_STATEMENT_TYPE_V1.to_string(),
            subject: vec![InTotoSubject {
                name: format!("proofline:evidence-bundle:{}", bundle_id),
                digest: subject_digest,
            }],
            predicate_type: PROOFLINE_PREDICATE_TYPE_V1.to_string(),
            predicate: ProoflineVerificationPredicate {
                bundle_id,
                contract_id: input.contract.contract_id.clone(),
                target_repository: target_repo_uri,
                vulnerable_commit: vuln_commit,
                candidate_patch_commit: patch_commit,
                epistemic_tier: input.epistemic_tier,
                cas_merkle_root_blake3: merkle_root_hash,
                reproduction_witness: input.reproduction_witness.clone(),
                differential_result: input.differential_result.clone(),
                verified_at: now,
                builder_id: format!("https://proofline.dev/cli/v{}", env!("CARGO_PKG_VERSION")),
            },
        };

        let dsse = signer.sign_in_toto_statement(&statement)?;
        files.insert("manifest.json".to_string(), serde_json::to_vec_pretty(&manifest)?);
        files.insert(
            "attestation.in-toto.json".to_string(),
            serde_json::to_vec_pretty(&dsse)?,
        );

        Ok((files, manifest))
    }
}

pub struct EvidenceBundleVerifier;

impl EvidenceBundleVerifier {
    /// Independently verifies an Evidence Bundle directory against a trusted public key.
    pub fn verify_bundle_dir(
        bundle_dir: &Path,
        verifier: &AttestationVerifier,
    ) -> Result<VerifiedBundleReport> {
        let canonical_root = bundle_dir.canonicalize().map_err(ProoflineError::Io)?;
        let mut entries: BTreeMap<String, Vec<u8>> = BTreeMap::new();

        for entry in WalkDir::new(&canonical_root)
            .follow_links(false)
            .sort_by_file_name()
        {
            let entry = entry.map_err(|e| ProoflineError::ParseFailure(e.to_string()))?;
            if entry.path_is_symlink() {
                return Err(ProoflineError::IsolationViolation(format!(
                    "Symlink disallowed inside Evidence Bundle: {:?}",
                    entry.path()
                )));
            }
            if entry.file_type().is_file() {
                let rel = entry
                    .path()
                    .strip_prefix(&canonical_root)
                    .map_err(|e| ProoflineError::ParseFailure(e.to_string()))?
                    .to_string_lossy()
                    .replace('\\', "/");
                validate_archive_rel_path(&rel)?;
                let data = fs::read(entry.path()).map_err(ProoflineError::Io)?;
                entries.insert(rel, data);
            }
        }

        Self::verify_entries(&entries, verifier)
    }

    /// Independently verifies a `.tar` Evidence Bundle archive in memory without executing anything.
    pub fn verify_bundle_tar(
        tar_path: &Path,
        verifier: &AttestationVerifier,
    ) -> Result<VerifiedBundleReport> {
        let entries = read_deterministic_tar(tar_path)?;
        Self::verify_entries(&entries, verifier)
    }

    pub fn verify_entries(
        entries: &BTreeMap<String, Vec<u8>>,
        verifier: &AttestationVerifier,
    ) -> Result<VerifiedBundleReport> {
        let manifest_bytes = entries.get("manifest.json").ok_or_else(|| {
            ProoflineError::CryptoError("Evidence Bundle missing manifest.json".to_string())
        })?;
        let manifest: BundleManifest = serde_json::from_slice(manifest_bytes)?;

        if manifest.schema_version != "1.0.0" {
            return Err(ProoflineError::CryptoError(format!(
                "Unsupported Evidence Bundle schema version: {}",
                manifest.schema_version
            )));
        }
        if manifest.attestation.signature_algorithm != "Ed25519" {
            return Err(ProoflineError::CryptoError(format!(
                "Unsupported signature algorithm: {}",
                manifest.attestation.signature_algorithm
            )));
        }
        if manifest.attestation.key_id != verifier.key_id() {
            return Err(ProoflineError::CryptoError(format!(
                "Key ID mismatch: manifest signed by {}, verifier holds {}",
                manifest.attestation.key_id,
                verifier.key_id()
            )));
        }
        if manifest.cas_hashes.hash_algorithm != "BLAKE3" {
            return Err(ProoflineError::CryptoError(format!(
                "Unsupported CAS hash algorithm: {}",
                manifest.cas_hashes.hash_algorithm
            )));
        }

        // 1. Verify manifest Ed25519 signature
        let signable = ManifestSignableView {
            schema_version: &manifest.schema_version,
            bundle_id: &manifest.bundle_id,
            timestamp: &manifest.timestamp,
            target_repository: &manifest.target_repository,
            target_commits: &manifest.target_commits,
            epistemic_tier: manifest.epistemic_tier,
            reproduction_witness: &manifest.reproduction_witness,
            differential_verification: &manifest.differential_verification,
            cas_hashes: &manifest.cas_hashes,
            signature_algorithm: &manifest.attestation.signature_algorithm,
            key_id: &manifest.attestation.key_id,
        };
        let canonical_manifest = serde_jcs::to_vec(&signable).map_err(|e| {
            ProoflineError::CryptoError(format!("Manifest JCS serialization failed: {}", e))
        })?;
        verifier.verify_bytes_b64(&canonical_manifest, &manifest.attestation.signature)?;

        // 2. Verify completeness & exact CAS artifact digests (reject missing or rogue files)
        let mut expected_paths: BTreeSet<String> = BTreeSet::new();
        for artifact in &manifest.cas_hashes.artifacts {
            validate_archive_rel_path(&artifact.path)?;
            if !expected_paths.insert(artifact.path.clone()) {
                return Err(ProoflineError::CryptoError(format!(
                    "Duplicate CAS artifact entry: {}",
                    artifact.path
                )));
            }
            let data = entries.get(&artifact.path).ok_or_else(|| {
                ProoflineError::CryptoError(format!(
                    "Missing attested bundle artifact: {}",
                    artifact.path
                ))
            })?;
            if data.len() as u64 != artifact.size_bytes {
                return Err(ProoflineError::CryptoError(format!(
                    "Size mismatch for {}: expected {}, got {}",
                    artifact.path,
                    artifact.size_bytes,
                    data.len()
                )));
            }
            let actual_blake3 = blake3::hash(data).to_hex().to_string();
            if actual_blake3 != artifact.digest {
                return Err(ProoflineError::CryptoError(format!(
                    "BLAKE3 digest mismatch for {}: expected {}, got {}",
                    artifact.path, artifact.digest, actual_blake3
                )));
            }
        }

        for path in entries.keys() {
            if path == "manifest.json"
                || path == "attestation.in-toto.json"
                || path == "cas/blake3/artifact_digests.json"
            {
                continue;
            }
            if !expected_paths.contains(path) {
                return Err(ProoflineError::CryptoError(format!(
                    "Unattested rogue file found in Evidence Bundle: {}",
                    path
                )));
            }
        }

        // Verify cas/blake3/artifact_digests.json and sha256_tree.json match
        let digest_index_bytes = entries.get("cas/blake3/artifact_digests.json").ok_or_else(|| {
            ProoflineError::CryptoError("Missing cas/blake3/artifact_digests.json".to_string())
        })?;
        let indexed_artifacts: Vec<CasArtifactEntry> = serde_json::from_slice(digest_index_bytes)?;
        if indexed_artifacts != manifest.cas_hashes.artifacts {
            return Err(ProoflineError::CryptoError(
                "cas/blake3/artifact_digests.json diverges from manifest CAS entries".to_string(),
            ));
        }

        let sha256_tree_bytes = entries.get("cas/blake3/sha256_tree.json").ok_or_else(|| {
            ProoflineError::CryptoError("Missing cas/blake3/sha256_tree.json".to_string())
        })?;
        let sha256_tree: BTreeMap<String, String> = serde_json::from_slice(sha256_tree_bytes)?;
        for (path, expected_sha256) in &sha256_tree {
            let data = entries.get(path).ok_or_else(|| {
                ProoflineError::CryptoError(format!("sha256_tree references missing file {}", path))
            })?;
            let actual_sha256 = hex_encode(&Sha256::digest(data));
            if &actual_sha256 != expected_sha256 {
                return Err(ProoflineError::CryptoError(format!(
                    "SHA-256 mismatch for {}: expected {}, got {}",
                    path, expected_sha256, actual_sha256
                )));
            }
        }

        // 3. Verify Merkle root
        let computed_root = compute_cas_merkle_root(&manifest.cas_hashes.artifacts);
        if computed_root != manifest.cas_hashes.merkle_root_hash {
            return Err(ProoflineError::CryptoError(format!(
                "CAS Merkle root mismatch: expected {}, got {}",
                computed_root, manifest.cas_hashes.merkle_root_hash
            )));
        }

        // 4. Verify in-toto DSSE attestation & cross-bind it to manifest
        let dsse_bytes = entries.get("attestation.in-toto.json").ok_or_else(|| {
            ProoflineError::CryptoError(
                "Evidence Bundle missing attestation.in-toto.json".to_string(),
            )
        })?;
        let dsse: DsseEnvelope = serde_json::from_slice(dsse_bytes)?;
        let statement = verifier.verify_in_toto_envelope(&dsse)?;

        let expected_manifest_sha256 = hex_encode(&Sha256::digest(&canonical_manifest));
        let subj = &statement.subject[0];
        if subj.digest.get("blake3") != Some(&manifest.cas_hashes.merkle_root_hash)
            || subj.digest.get("sha256") != Some(&expected_manifest_sha256)
        {
            return Err(ProoflineError::CryptoError(
                "in-toto subject digest does not match verified manifest/CAS root".to_string(),
            ));
        }
        if statement.predicate.bundle_id != manifest.bundle_id
            || statement.predicate.epistemic_tier != manifest.epistemic_tier
            || statement.predicate.cas_merkle_root_blake3 != manifest.cas_hashes.merkle_root_hash
        {
            return Err(ProoflineError::CryptoError(
                "in-toto predicate metadata disagrees with manifest".to_string(),
            ));
        }

        Ok(VerifiedBundleReport {
            verified_artifact_count: manifest.cas_hashes.artifacts.len(),
            manifest,
            statement,
        })
    }

    /// Verifies cryptographic integrity of a `.tar` or directory bundle and replays
    /// the attested `harness/run.sh` + `harness/reproducer.bin` inside an isolated `SandboxRunner`.
    pub fn verify_and_replay<R: SandboxRunner>(
        bundle_path: &Path,
        verifier: &AttestationVerifier,
        runner: &R,
        command_override: Option<&[String]>,
    ) -> Result<(VerifiedBundleReport, ReplayVerificationReport)> {
        let entries = if bundle_path.is_dir() {
            let report = Self::verify_bundle_dir(bundle_path, verifier)?;
            let mut map = BTreeMap::new();
            for art in &report.manifest.cas_hashes.artifacts {
                let data = fs::read(bundle_path.join(&art.path)).map_err(ProoflineError::Io)?;
                map.insert(art.path.clone(), data);
            }
            (report, map)
        } else {
            let map = read_deterministic_tar(bundle_path)?;
            let report = Self::verify_entries(&map, verifier)?;
            (report, map)
        };

        let (verified, bundle_entries) = entries;
        let reproducer = bundle_entries
            .get("harness/reproducer.bin")
            .ok_or_else(|| {
                ProoflineError::CryptoError("Missing harness/reproducer.bin".to_string())
            })?;

        let temp_dir = tempfile::tempdir().map_err(ProoflineError::Io)?;
        extract_entries_safely(&bundle_entries, temp_dir.path())?;

        let mut config = ExecutionConfig::default();
        config.working_dir = temp_dir.path().to_path_buf();
        config.network_policy = NetworkPolicy::Denied;
        config.command = match command_override {
            Some(cmd) if !cmd.is_empty() => cmd.to_vec(),
            _ => vec!["/bin/sh".to_string(), "harness/run.sh".to_string()],
        };
        attach_input_payload(&mut config, reproducer);

        let output = runner.execute(&config)?;
        let observed_sig = CrashOracle::evaluate_trace(output.exit_code, &output.stderr, &output.stdout);
        let observed_fault_type = observed_sig.as_ref().map(|s| s.fault_type.clone());

        let replay_matches_attestation = match verified.manifest.epistemic_tier {
            EpistemicTier::ConfirmedReproduced => {
                observed_fault_type.as_deref()
                    == Some(verified.manifest.reproduction_witness.fault_signal_or_oracle.as_str())
            }
            EpistemicTier::VerifiedMitigation => observed_fault_type.is_none() && output.exit_code == 0,
            _ => true,
        };

        let replay_report = ReplayVerificationReport {
            bundle_id: verified.manifest.bundle_id.clone(),
            attested_tier: verified.manifest.epistemic_tier,
            observed_exit_code: output.exit_code,
            observed_fault_type,
            replay_matches_attestation,
        };

        Ok((verified, replay_report))
    }

    /// Distinguishes cryptographic signature validity from whether the signing key_id and builder_id
    /// satisfy the verifier's explicit trust policy.
    pub fn evaluate_trust_policy(
        verified: &VerifiedBundleReport,
        policy: &TrustedIdentityPolicy,
    ) -> SignerTrustVerdict {
        let key_id = &verified.manifest.attestation.key_id;
        let builder_id = &verified.statement.predicate.builder_id;

        let key_trusted = policy.trusted_key_ids.iter().any(|k| k == key_id);
        let builder_trusted = policy
            .trusted_builder_ids
            .iter()
            .any(|b| builder_id.starts_with(b));

        if key_trusted && builder_trusted {
            SignerTrustVerdict::TrustedIdentityAndBuilder {
                key_id: key_id.clone(),
                builder_id: builder_id.clone(),
            }
        } else {
            let mut reasons = Vec::new();
            if !key_trusted {
                reasons.push(format!("key_id '{}' is not in trusted_key_ids", key_id));
            }
            if !builder_trusted {
                reasons.push(format!(
                    "builder_id '{}' is not in trusted_builder_ids",
                    builder_id
                ));
            }
            SignerTrustVerdict::ValidSignatureUntrustedSigner {
                key_id: key_id.clone(),
                builder_id: builder_id.clone(),
                reason: reasons.join("; "),
            }
        }
    }
}

fn normalize_repo_uri(raw: &str) -> String {
    if raw.contains("://") {
        raw.to_string()
    } else if raw.is_empty() {
        "file:///unknown".to_string()
    } else if raw.starts_with('/') {
        format!("file://{}", raw)
    } else {
        format!("file:///{}", raw)
    }
}

fn normalize_commit_sha(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.len() == 40 && trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        trimmed.to_ascii_lowercase()
    } else {
        // Derive deterministic 40-hex placeholder from non-SHA refs when running ad-hoc local verification
        let digest = Sha256::digest(trimmed.as_bytes());
        hex_encode(&digest)[..40].to_string()
    }
}
