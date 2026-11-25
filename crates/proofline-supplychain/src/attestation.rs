//! Ed25519 key management, DSSE signing envelopes, and in-toto v1.0 attestations.

use crate::hex_encode;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use proofline_core::{
    DifferentialVerificationResult, EpistemicTier, ProoflineError, ReproductionWitness, Result,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

pub const IN_TOTO_STATEMENT_TYPE_V1: &str = "https://in-toto.io/Statement/v1";
pub const PROOFLINE_PREDICATE_TYPE_V1: &str = "https://proofline.dev/attestation/verification/v1";
pub const SLSA_PROVENANCE_PREDICATE_TYPE_V1: &str = "https://slsa.dev/provenance/v1";
pub const DSSE_PAYLOAD_TYPE_IN_TOTO: &str = "application/vnd.in-toto+json";

/// Policy separating cryptographic signature validity from trusted signer/builder identity.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TrustedIdentityPolicy {
    pub trusted_key_ids: Vec<String>,
    pub trusted_builder_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SignerTrustVerdict {
    TrustedIdentityAndBuilder {
        key_id: String,
        builder_id: String,
    },
    ValidSignatureUntrustedSigner {
        key_id: String,
        builder_id: String,
        reason: String,
    },
}

/// SLSA v1.0 Provenance predicate representation for build-source correspondence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlsaProvenancePredicate {
    #[serde(rename = "buildType")]
    pub build_type: String,
    #[serde(rename = "builderId")]
    pub builder_id: String,
    pub source_repository: String,
    pub source_commit: String,
    pub reproducible_digest_blake3: String,
}

/// Offline transparency-log inclusion metadata (Sigstore Rekor compatible).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RekorInclusionMetadata {
    pub log_id: String,
    pub log_index: u64,
    pub integrated_time: i64,
    pub artifact_sha256: String,
    pub set_signature_b64: String,
}

impl RekorInclusionMetadata {
    /// Verifies structural validity and subject SHA-256 binding against a signed bundle digest.
    /// Does not make network calls or replace full inclusion-proof Merkle verification against a trusted log root.
    pub fn validate_binding(&self, expected_sha256: &str) -> Result<()> {
        if self.log_id.len() != 64 || !self.log_id.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(ProoflineError::CryptoError(
                "Invalid Rekor log_id: expected 64 hex chars".to_string(),
            ));
        }
        if self.integrated_time <= 0 {
            return Err(ProoflineError::CryptoError(
                "Invalid Rekor integrated_time timestamp".to_string(),
            ));
        }
        if self.artifact_sha256 != expected_sha256 {
            return Err(ProoflineError::CryptoError(format!(
                "Rekor artifact_sha256 mismatch: expected {}, got {}",
                expected_sha256, self.artifact_sha256
            )));
        }
        STANDARD.decode(self.set_signature_b64.trim()).map_err(|e| {
            ProoflineError::CryptoError(format!("Invalid Rekor SET base64: {}", e))
        })?;
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InTotoSubject {
    pub name: String,
    pub digest: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProoflineVerificationPredicate {
    pub bundle_id: String,
    pub contract_id: String,
    pub target_repository: String,
    pub vulnerable_commit: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub candidate_patch_commit: Option<String>,
    pub epistemic_tier: EpistemicTier,
    pub cas_merkle_root_blake3: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reproduction_witness: Option<ReproductionWitness>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub differential_result: Option<DifferentialVerificationResult>,
    pub verified_at: DateTime<Utc>,
    pub builder_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InTotoStatement {
    #[serde(rename = "_type")]
    pub statement_type: String,
    pub subject: Vec<InTotoSubject>,
    #[serde(rename = "predicateType")]
    pub predicate_type: String,
    pub predicate: ProoflineVerificationPredicate,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DsseSignature {
    pub keyid: String,
    pub sig: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DsseEnvelope {
    #[serde(rename = "payloadType")]
    pub payload_type: String,
    pub payload: String,
    pub signatures: Vec<DsseSignature>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct KeyFileFormat {
    algorithm: String,
    key_id: String,
    key_b64: String,
}

/// Computes the DSSE v1 Pre-Authentication Encoding (PAE).
pub fn dsse_pae(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let header = format!(
        "DSSEv1 {} {} {} ",
        payload_type.len(),
        payload_type,
        payload.len()
    );
    let mut out = Vec::with_capacity(header.len() + payload.len());
    out.extend_from_slice(header.as_bytes());
    out.extend_from_slice(payload);
    out
}

/// Computes canonical key identifier from an Ed25519 verifying key.
pub fn derive_key_id(verifying_key: &VerifyingKey) -> String {
    let digest = Sha256::digest(verifying_key.as_bytes());
    format!("ed25519:{}", &hex_encode(&digest)[..16])
}

/// Ed25519 signer for Proofline manifests and in-toto DSSE statements.
#[derive(Clone)]
pub struct AttestationSigner {
    signing_key: SigningKey,
    key_id: String,
}

impl AttestationSigner {
    /// Generates a fresh Ed25519 keypair from OS CSPRNG.
    pub fn generate() -> Result<Self> {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).map_err(|e| {
            ProoflineError::CryptoError(format!("Failed to obtain CSPRNG entropy: {}", e))
        })?;
        Ok(Self::from_seed_bytes(&seed))
    }

    /// Constructs a signer from a 32-byte Ed25519 seed.
    pub fn from_seed_bytes(seed: &[u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(seed);
        let key_id = derive_key_id(&signing_key.verifying_key());
        Self {
            signing_key,
            key_id,
        }
    }

    /// Loads a private signing key JSON file written by `save_keypair_files`.
    pub fn from_key_file(path: &Path) -> Result<Self> {
        let content = fs::read_to_string(path).map_err(ProoflineError::Io)?;
        let parsed: KeyFileFormat = serde_json::from_str(&content)?;
        if parsed.algorithm != "Ed25519-PrivateSeed" {
            return Err(ProoflineError::CryptoError(format!(
                "Unsupported private key algorithm: {}",
                parsed.algorithm
            )));
        }
        let raw = STANDARD
            .decode(parsed.key_b64.trim())
            .map_err(|e| ProoflineError::CryptoError(format!("Invalid key base64: {}", e)))?;
        let seed: [u8; 32] = raw.try_into().map_err(|_| {
            ProoflineError::CryptoError("Ed25519 private seed must be 32 bytes".to_string())
        })?;
        let signer = Self::from_seed_bytes(&seed);
        if signer.key_id != parsed.key_id {
            return Err(ProoflineError::CryptoError(
                "Key file key_id does not match derived public key".to_string(),
            ));
        }
        Ok(signer)
    }

    /// Writes private key (`proofline.key.json`, 0600 on Unix) and public key (`proofline.pub.json`).
    pub fn save_keypair_files(&self, out_dir: &Path) -> Result<(std::path::PathBuf, std::path::PathBuf)> {
        fs::create_dir_all(out_dir).map_err(ProoflineError::Io)?;
        let priv_path = out_dir.join("proofline.key.json");
        let pub_path = out_dir.join("proofline.pub.json");

        let priv_json = serde_json::to_string_pretty(&KeyFileFormat {
            algorithm: "Ed25519-PrivateSeed".to_string(),
            key_id: self.key_id.clone(),
            key_b64: STANDARD.encode(self.signing_key.to_bytes()),
        })?;

        #[cfg(unix)]
        {
            use std::io::Write as _;
            use std::os::unix::fs::OpenOptionsExt as _;
            let mut f = fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&priv_path)
                .map_err(ProoflineError::Io)?;
            f.write_all(priv_json.as_bytes()).map_err(ProoflineError::Io)?;
        }
        #[cfg(not(unix))]
        {
            fs::write(&priv_path, priv_json).map_err(ProoflineError::Io)?;
        }

        let pub_json = serde_json::to_string_pretty(&KeyFileFormat {
            algorithm: "Ed25519-PublicKey".to_string(),
            key_id: self.key_id.clone(),
            key_b64: self.verifying_key_b64(),
        })?;
        fs::write(&pub_path, pub_json).map_err(ProoflineError::Io)?;

        Ok((priv_path, pub_path))
    }

    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    pub fn verifying_key_b64(&self) -> String {
        STANDARD.encode(self.signing_key.verifying_key().to_bytes())
    }

    pub fn verifier(&self) -> AttestationVerifier {
        AttestationVerifier::from_verifying_key(self.verifying_key())
    }

    /// Signs arbitrary bytes with Ed25519 and returns base64 signature.
    pub fn sign_bytes_b64(&self, message: &[u8]) -> String {
        let sig: Signature = self.signing_key.sign(message);
        STANDARD.encode(sig.to_bytes())
    }

    /// Canonicalizes an in-toto v1.0 statement via RFC 8785 JCS and wraps it in a signed DSSE envelope.
    pub fn sign_in_toto_statement(&self, statement: &InTotoStatement) -> Result<DsseEnvelope> {
        let canonical_payload = serde_jcs::to_vec(statement)
            .map_err(|e| ProoflineError::CryptoError(format!("JCS canonicalization failed: {}", e)))?;
        let pae = dsse_pae(DSSE_PAYLOAD_TYPE_IN_TOTO, &canonical_payload);
        let sig_b64 = self.sign_bytes_b64(&pae);

        Ok(DsseEnvelope {
            payload_type: DSSE_PAYLOAD_TYPE_IN_TOTO.to_string(),
            payload: STANDARD.encode(&canonical_payload),
            signatures: vec![DsseSignature {
                keyid: self.key_id.clone(),
                sig: sig_b64,
            }],
        })
    }
}

/// Independent public-key verifier for Proofline Evidence Bundles and DSSE envelopes.
#[derive(Clone)]
pub struct AttestationVerifier {
    verifying_key: VerifyingKey,
    key_id: String,
}

impl AttestationVerifier {
    pub fn from_verifying_key(verifying_key: VerifyingKey) -> Self {
        let key_id = derive_key_id(&verifying_key);
        Self {
            verifying_key,
            key_id,
        }
    }

    pub fn from_base64(pub_b64: &str) -> Result<Self> {
        let raw = STANDARD
            .decode(pub_b64.trim())
            .map_err(|e| ProoflineError::CryptoError(format!("Invalid public key base64: {}", e)))?;
        let bytes: [u8; 32] = raw.try_into().map_err(|_| {
            ProoflineError::CryptoError("Ed25519 public key must be 32 bytes".to_string())
        })?;
        let vk = VerifyingKey::from_bytes(&bytes)
            .map_err(|e| ProoflineError::CryptoError(format!("Invalid Ed25519 public key: {}", e)))?;
        Ok(Self::from_verifying_key(vk))
    }

    pub fn from_key_file(path: &Path) -> Result<Self> {
        let content = fs::read_to_string(path).map_err(ProoflineError::Io)?;
        let parsed: KeyFileFormat = serde_json::from_str(&content)?;
        if parsed.algorithm != "Ed25519-PublicKey" {
            return Err(ProoflineError::CryptoError(format!(
                "Expected Ed25519-PublicKey, got {}",
                parsed.algorithm
            )));
        }
        let verifier = Self::from_base64(&parsed.key_b64)?;
        if verifier.key_id != parsed.key_id {
            return Err(ProoflineError::CryptoError(
                "Public key file key_id does not match verifying key fingerprint".to_string(),
            ));
        }
        Ok(verifier)
    }

    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// Strict RFC 8032 / ZIP-215 verification rejecting malleable signatures.
    pub fn verify_bytes_b64(&self, message: &[u8], signature_b64: &str) -> Result<()> {
        let sig_bytes = STANDARD
            .decode(signature_b64.trim())
            .map_err(|e| ProoflineError::CryptoError(format!("Invalid signature base64: {}", e)))?;
        let sig_arr: [u8; 64] = sig_bytes.try_into().map_err(|_| {
            ProoflineError::CryptoError("Ed25519 signature must be 64 bytes".to_string())
        })?;
        let sig = Signature::from_bytes(&sig_arr);
        self.verifying_key
            .verify_strict(message, &sig)
            .map_err(|e| ProoflineError::CryptoError(format!("Ed25519 verification failed: {}", e)))
    }

    /// Verifies a DSSE envelope signature and decodes its in-toto v1.0 statement.
    pub fn verify_in_toto_envelope(&self, envelope: &DsseEnvelope) -> Result<InTotoStatement> {
        if envelope.payload_type != DSSE_PAYLOAD_TYPE_IN_TOTO {
            return Err(ProoflineError::CryptoError(format!(
                "Unexpected DSSE payloadType: {}",
                envelope.payload_type
            )));
        }
        if envelope.signatures.is_empty() {
            return Err(ProoflineError::CryptoError(
                "DSSE envelope contains zero signatures".to_string(),
            ));
        }

        let payload_bytes = STANDARD
            .decode(envelope.payload.trim())
            .map_err(|e| ProoflineError::CryptoError(format!("Invalid DSSE payload base64: {}", e)))?;
        let pae = dsse_pae(&envelope.payload_type, &payload_bytes);

        let matching_sig = envelope
            .signatures
            .iter()
            .find(|s| s.keyid == self.key_id)
            .ok_or_else(|| {
                ProoflineError::CryptoError(format!(
                    "No DSSE signature matches trusted key_id {}",
                    self.key_id
                ))
            })?;

        self.verify_bytes_b64(&pae, &matching_sig.sig)?;

        let statement: InTotoStatement = serde_json::from_slice(&payload_bytes)?;
        if statement.statement_type != IN_TOTO_STATEMENT_TYPE_V1 {
            return Err(ProoflineError::CryptoError(format!(
                "Unexpected in-toto statement type: {}",
                statement.statement_type
            )));
        }
        if statement.predicate_type != PROOFLINE_PREDICATE_TYPE_V1 {
            return Err(ProoflineError::CryptoError(format!(
                "Unexpected predicateType: {}",
                statement.predicate_type
            )));
        }
        if statement.subject.is_empty() {
            return Err(ProoflineError::CryptoError(
                "in-toto statement contains empty subject list".to_string(),
            ));
        }

        Ok(statement)
    }
}
