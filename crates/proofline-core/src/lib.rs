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

impl Default for VerificationContract {
    fn default() -> Self {
        Self {
            contract_id: format!("PVC-{}", Uuid::new_v4().simple()),
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
        let bundle_id = format!("EVD-{}", Uuid::new_v4().simple());
        let mut hasher = blake3::Hasher::new();
        hasher.update(bundle_id.as_bytes());
        hasher.update(contract.contract_id.as_bytes());
        hasher.update(contract.vulnerable_commit.as_bytes());
        let merkle_root = hasher.finalize().to_hex().to_string();

        Self {
            schema_version: "1.0.0".to_string(),
            bundle_id,
            timestamp: Utc::now(),
            contract_id: contract.contract_id.clone(),
            target_repository: contract.target_repository.clone(),
            vulnerable_commit: contract.vulnerable_commit.clone(),
            candidate_patch_commit: contract.candidate_patch_commit.clone(),
            epistemic_tier: tier,
            reproduction_witness: witness,
            differential_result: differential,
            merkle_root_blake3: merkle_root,
        }
    }
}
