//! Supply-Chain Verification, Cryptographic Attestation, SARIF Export,
//! and Replayable Evidence Bundle Packaging for Project Proofline.

pub mod archive;
pub mod attestation;
pub mod bundle;
pub mod reproducible;
pub mod sarif;
pub mod sbom;

pub use archive::{read_deterministic_tar, write_deterministic_tar};
pub use attestation::{
    dsse_pae, AttestationSigner, AttestationVerifier, DsseEnvelope, DsseSignature, InTotoStatement,
    InTotoSubject, ProoflineVerificationPredicate, RekorInclusionMetadata, SignerTrustVerdict,
    SlsaProvenancePredicate, TrustedIdentityPolicy, SLSA_PROVENANCE_PREDICATE_TYPE_V1,
};
pub use bundle::{
    compute_cas_merkle_root, BundleManifest, CasArtifactEntry, CasHashesManifest,
    DifferentialVerificationManifest, EvidenceBundleInput, EvidenceBundlePackager,
    EvidenceBundleVerifier, ManifestAttestation, ReplayVerificationReport, ReproductionWitnessManifest,
    TargetCommitsManifest, VerifiedBundleReport,
};
pub use reproducible::{
    ReproducibleBuildReport, ReproducibleBuildVerifier, VerificationMarkdownRenderer,
};
pub use sarif::{SarifExporter, SarifLog};
pub use sbom::{CycloneDxBom, CycloneDxComponent, SbomGenerator};

/// Encodes a byte slice as lowercase hexadecimal.
pub fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write as _;
        let _ = write!(out, "{:02x}", b);
    }
    out
}
