//! Core domain models, epistemic confidence tiers, verification contracts,
//! and error definitions for Project Proofline.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

#[derive(Error, Debug)]
pub enum ProoflineError {
    #[error("Sandbox isolation violation: {0}")]
    IsolationViolation(String),

    #[error("Parse failure in target source: {0}")]
    ParseFailure(String),

    #[error("Resource exhausted during analysis: {0}")]
    ResourceExhausted(String),

    #[error("Deterministic reproduction failed: {0}")]
    ReproductionFailed(String),

    #[error("Verification contract requirement unmet: {0}")]
    ContractUnmet(String),

    #[error("Cryptographic verification failure: {0}")]
    CryptoError(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, ProoflineError>;

/// Epistemic Confidence Tiers defined in RFC-001 Section 14.
/// Strict evidence requirements govern each tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EpistemicTier {
    /// Concrete reproducer input triggered deterministic crash / oracle violation in clean microVM.
    ConfirmedReproduced = 1,
    /// Path conditions verified satisfiable by SMT solver with satisfying input model.
    SymbolicallySatisfiable = 2,
    /// Interprocedural CPG identifies dataflow from ingress to sink; runtime execution unverified.
    StaticallyTainted = 3,
    /// Syntactic AST rule, heuristic pattern, or AI hypothesis. Explicitly unverified.
    HeuristicHypothesis = 4,
    /// Original reproducer fails on patched revision; mutation fuzzing uncovers zero bypasses; regression tests pass.
    VerifiedMitigation = 5,
    /// Analysis failed to complete due to timeout, unsupported constructs, or non-determinism.
    Inconclusive = 6,
}

/// Attacker models and input entrypoints.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum IngressBoundary {
    UntrustedNetworkInput,
    AuthenticatedNetworkInput,
    LocalFileInput,
    CliArgumentInput,
    EnvironmentVariable,
    InterProcessCommunication,
}

/// Dangerous operations and security-sensitive sinks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SinkKind {
    CommandExecution,
    SqlExecution,
    UnsafeMemoryAccess,
    Deserialization,
    PathTraversal,
    CryptographicOperation,
    NetworkSocketWrite,
}

/// Declarative specification of verification criteria and bounds.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationContract {
    pub contract_id: String,
    pub target_repository: String,
    pub vulnerable_commit: String,
    pub candidate_patch_commit: Option<String>,
    pub ingress_boundary: IngressBoundary,
    pub required_reproduction_runs: u32,
    pub reproduction_threshold: f64,
    pub patch_bypass_fuzz_seconds: u32,
    pub regression_pass_threshold: f64,
    pub min_acceptable_tier: EpistemicTier,
}

/// Sanitizes untrusted terminal/process output against ANSI/CSI/OSC escape
/// sequence injection and dangerous C0 control bytes while preserving newlines and tabs.
pub fn sanitize_terminal_trace(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut chars = raw.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            match chars.peek().copied() {
                Some('[') => {
                    // CSI sequence: ESC [ ... final byte in 0x40..=0x7E
                    chars.next();
                    while let Some(next_c) = chars.next() {
                        if ('@'..='~').contains(&next_c) {
                            break;
                        }
                    }
                }
                Some(']') => {
                    // OSC sequence: ESC ] ... BEL or ST (ESC \)
                    chars.next();
                    while let Some(next_c) = chars.next() {
                        if next_c == '\x07' {
                            break;
                        }
                        if next_c == '\x1b' && chars.peek() == Some(&'\\') {
                            chars.next();
                            break;
                        }
                    }
                }
                Some(_) => {
                    // 2-byte ESC sequence
                    chars.next();
                }
                None => {}
            }
            continue;
        }
        if c == '\n' || c == '\r' || c == '\t' || (!c.is_control()) {
            out.push(c);
        }
    }
    out
}

impl Default for VerificationContract {
    fn default() -> Self {
        Self {
            contract_id: format!(
                "PVC-{}-{}",
                Utc::now().format("%Y"),
                Uuid::new_v4().simple().to_string().to_uppercase()
            ),
            target_repository: String::new(),
            vulnerable_commit: String::new(),
            candidate_patch_commit: None,
            ingress_boundary: IngressBoundary::UntrustedNetworkInput,
            required_reproduction_runs: 5,
            reproduction_threshold: 1.0,
            patch_bypass_fuzz_seconds: 300,
            regression_pass_threshold: 1.0,
            min_acceptable_tier: EpistemicTier::ConfirmedReproduced,
        }
    }
}

/// Summary of an independently replayable execution witness.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReproductionWitness {
    pub deterministic: bool,
    pub successful_runs: u32,
    pub total_attempted_runs: u32,
    pub input_artifact_blake3: String,
    pub fault_signal_or_oracle: String,
    pub execution_trace_blake3: String,
    pub execution_duration_ms: u64,
}

/// Differential verification results comparing V_vuln vs V_patch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DifferentialVerificationResult {
    pub original_reproducer_on_patch_mitigated: bool,
    pub regression_tests_passed: bool,
    pub bypass_mutations_evaluated: u64,
    pub bypasses_discovered: u64,
    pub execution_divergence_notes: Vec<String>,
}

/// Immutable, cryptographically verifiable Evidence Bundle manifest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceBundle {
    pub schema_version: String,
    pub bundle_id: String,
    pub timestamp: DateTime<Utc>,
    pub contract_id: String,
    pub target_repository: String,
    pub vulnerable_commit: String,
    pub candidate_patch_commit: Option<String>,
    pub epistemic_tier: EpistemicTier,
    pub reproduction_witness: Option<ReproductionWitness>,
    pub differential_result: Option<DifferentialVerificationResult>,
    pub merkle_root_blake3: String,
}

impl EvidenceBundle {
    pub fn new(
        contract: &VerificationContract,
        tier: EpistemicTier,
        witness: Option<ReproductionWitness>,
        differential: Option<DifferentialVerificationResult>,
    ) -> Self {
        let now = Utc::now();
        let bundle_id = format!(
            "EVD-{}-{}",
            now.format("%Y"),
            Uuid::new_v4().simple().to_string().to_uppercase()
        );

        let mut bundle = Self {
            schema_version: "1.0.0".to_string(),
            bundle_id,
            timestamp: now,
            contract_id: contract.contract_id.clone(),
            target_repository: contract.target_repository.clone(),
            vulnerable_commit: contract.vulnerable_commit.clone(),
            candidate_patch_commit: contract.candidate_patch_commit.clone(),
            epistemic_tier: tier,
            reproduction_witness: witness,
            differential_result: differential,
            merkle_root_blake3: String::new(),
        };
        bundle.merkle_root_blake3 = bundle.compute_merkle_root();
        bundle
    }

    /// Computes a domain-separated BLAKE3 commitment over all evidence fields.
    pub fn compute_merkle_root(&self) -> String {
        #[derive(Serialize)]
        struct CanonicalBody<'a> {
            schema_version: &'a str,
            bundle_id: &'a str,
            timestamp: String,
            contract_id: &'a str,
            target_repository: &'a str,
            vulnerable_commit: &'a str,
            candidate_patch_commit: &'a Option<String>,
            epistemic_tier: EpistemicTier,
            reproduction_witness: &'a Option<ReproductionWitness>,
            differential_result: &'a Option<DifferentialVerificationResult>,
        }

        let body = CanonicalBody {
            schema_version: &self.schema_version,
            bundle_id: &self.bundle_id,
            timestamp: self.timestamp.to_rfc3339(),
            contract_id: &self.contract_id,
            target_repository: &self.target_repository,
            vulnerable_commit: &self.vulnerable_commit,
            candidate_patch_commit: &self.candidate_patch_commit,
            epistemic_tier: self.epistemic_tier,
            reproduction_witness: &self.reproduction_witness,
            differential_result: &self.differential_result,
        };

        let bytes = serde_json::to_vec(&body).unwrap_or_default();
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"proofline.evidence_bundle.v1:");
        hasher.update(&bytes);
        hasher.finalize().to_hex().to_string()
    }

    /// Verifies that `merkle_root_blake3` matches the canonical contents of this bundle.
    pub fn verify_integrity(&self) -> Result<()> {
        let expected = self.compute_merkle_root();
        if self.merkle_root_blake3 != expected {
            return Err(ProoflineError::CryptoError(format!(
                "EvidenceBundle integrity check failed: expected {}, got {}",
                expected, self.merkle_root_blake3
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_evidence_bundle_tamper_detection() {
        let contract = VerificationContract::default();
        assert!(contract.contract_id.starts_with("PVC-"));

        let mut bundle = EvidenceBundle::new(
            &contract,
            EpistemicTier::ConfirmedReproduced,
            None,
            None,
        );
        assert!(bundle.bundle_id.starts_with("EVD-"));
        assert!(bundle.verify_integrity().is_ok());

        // Tamper with epistemic tier after creation
        bundle.epistemic_tier = EpistemicTier::VerifiedMitigation;
        assert!(matches!(
            bundle.verify_integrity(),
            Err(ProoflineError::CryptoError(_))
        ));
    }

    #[test]
    fn test_terminal_trace_sanitization() {
        let hostile = "ok\x1b[31mRED\x1b[0m\x1b]0;pwned\x07\x00next\nline\t!";
        assert_eq!(sanitize_terminal_trace(hostile), "okREDnext\nline\t!");
    }
}
