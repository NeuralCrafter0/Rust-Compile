//! Reusable CLI orchestration pipelines for Project Proofline.

use proofline_analysis::{ReachabilityTrace, TaintAnalysisEngine};
use proofline_core::{
    EpistemicTier, ProoflineError, Result, VerificationContract,
};
use proofline_cpg::{
    CSourceParser, GoSourceParser, JavaSourceParser, JsTsSourceParser, ProjectCpgBuilder,
    PythonSourceParser, RustSourceParser,
};
use proofline_differential::{DifferentialPatchReport, DifferentialVerificationEngine};
use proofline_fuzzer::{MutationFuzzResult, MutationFuzzer, ReproducerSynthesizer};
use proofline_intelligence::{IngestionEngine, ProjectInspection};
use proofline_sandbox::SandboxRunner;
use proofline_supplychain::{
    AttestationSigner, AttestationVerifier, BundleManifest, CycloneDxBom,
    EvidenceBundleInput, EvidenceBundlePackager, EvidenceBundleVerifier,
    ReplayVerificationReport, ReproducibleBuildReport, ReproducibleBuildVerifier, SarifExporter,
    SarifLog, SbomGenerator, VerificationMarkdownRenderer, VerifiedBundleReport,
};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceLang {
    C,
    Python,
    Rust,
    JavaScript,
    Go,
    Java,
}

pub fn validate_verification_contract(contract: &VerificationContract) -> Result<()> {
    if !contract.contract_id.starts_with("PVC-") {
        return Err(ProoflineError::ContractUnmet(format!(
            "contract_id '{}' must start with 'PVC-'",
            contract.contract_id
        )));
    }
    if contract.target_repository.trim().is_empty() {
        return Err(ProoflineError::ContractUnmet(
            "target_repository must not be empty".to_string(),
        ));
    }
    if contract.vulnerable_commit.len() != 40
        || !contract
            .vulnerable_commit
            .chars()
            .all(|c| c.is_ascii_hexdigit())
    {
        return Err(ProoflineError::ContractUnmet(format!(
            "vulnerable_commit '{}' must be a 40-character hex SHA",
            contract.vulnerable_commit
        )));
    }
    if let Some(ref patch) = contract.candidate_patch_commit {
        if patch.len() != 40 || !patch.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(ProoflineError::ContractUnmet(format!(
                "candidate_patch_commit '{}' must be a 40-character hex SHA",
                patch
            )));
        }
    }
    if contract.required_reproduction_runs < 1 {
        return Err(ProoflineError::ContractUnmet(
            "required_reproduction_runs must be >= 1".to_string(),
        ));
    }
    if !(0.0..=1.0).contains(&contract.reproduction_threshold)
        || !(0.0..=1.0).contains(&contract.regression_pass_threshold)
    {
        return Err(ProoflineError::ContractUnmet(
            "thresholds must be within [0.0, 1.0]".to_string(),
        ));
    }
    Ok(())
}

pub fn inspect_repo(
    repo_dir: &Path,
    project_name: Option<&str>,
) -> Result<(ProjectInspection, CycloneDxBom)> {
    let inspection = IngestionEngine::default().inspect_repository(repo_dir)?;
    let name = project_name.unwrap_or_else(|| {
        repo_dir
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("proofline-target")
    });
    let sbom = SbomGenerator::to_cyclonedx(name, &inspection);
    Ok((inspection, sbom))
}

pub fn analyze_source_file(
    file_path: &Path,
    lang: Option<SourceLang>,
) -> Result<(Vec<ReachabilityTrace>, SarifLog)> {
    let source = fs::read_to_string(file_path).map_err(ProoflineError::Io)?;
    let detected = match lang {
        Some(l) => l,
        None => match file_path.extension().and_then(|e| e.to_str()) {
            Some("py") => SourceLang::Python,
            Some("rs") => SourceLang::Rust,
            Some("js" | "ts" | "mjs" | "cjs" | "tsx") => SourceLang::JavaScript,
            Some("go") => SourceLang::Go,
            Some("java") => SourceLang::Java,
            _ => SourceLang::C,
        },
    };
    let file_name = file_path.to_string_lossy();
    let cpg = match detected {
        SourceLang::C => CSourceParser::parse_snippet(&source, &file_name)?,
        SourceLang::Python => PythonSourceParser::parse_snippet(&source, &file_name)?,
        SourceLang::Rust => RustSourceParser::parse_snippet(&source, &file_name)?,
        SourceLang::JavaScript => JsTsSourceParser::parse_snippet(&source, &file_name)?,
        SourceLang::Go => GoSourceParser::parse_snippet(&source, &file_name)?,
        SourceLang::Java => JavaSourceParser::parse_snippet(&source, &file_name)?,
    };
    let traces = TaintAnalysisEngine::analyze(&cpg);
    let sarif = SarifExporter::from_reachability_traces(&file_name, &traces);
    Ok((traces, sarif))
}

pub fn analyze_repository(repo_dir: &Path) -> Result<(Vec<ReachabilityTrace>, SarifLog)> {
    let cpg = ProjectCpgBuilder::build_from_directory(repo_dir)?;
    let traces = TaintAnalysisEngine::analyze(&cpg);
    let uri = format!("file://{}", repo_dir.display());
    let sarif = SarifExporter::from_reachability_traces(&uri, &traces);
    Ok((traces, sarif))
}

pub struct PatchVerificationArgs<'a> {
    pub contract: VerificationContract,
    pub working_dir: &'a Path,
    pub vuln_command: &'a [String],
    pub patch_command: &'a [String],
    pub reproducer_bytes: &'a [u8],
    pub regression_inputs: &'a [Vec<u8>],
    pub reproduction_runs: u32,
    pub reachability_traces: Vec<ReachabilityTrace>,
}

pub struct PatchVerificationOutcome {
    pub report: DifferentialPatchReport,
    pub manifest: Option<BundleManifest>,
    pub sarif: SarifLog,
    pub markdown_summary: String,
}

/// Runs deterministic reproduction on V_vuln, differential verification & bypass fuzzing
/// against V_patch, and optionally packages a signed Evidence Bundle (directory or `.tar`).
pub fn verify_patch_pipeline<RV: SandboxRunner, RP: SandboxRunner>(
    vuln_runner: &RV,
    patch_runner: &RP,
    args: PatchVerificationArgs<'_>,
    signer: Option<&AttestationSigner>,
    bundle_out: Option<&Path>,
) -> Result<PatchVerificationOutcome> {
    let (witness, crash_sig, tier_vuln) = ReproducerSynthesizer::verify_deterministic_reproduction(
        vuln_runner,
        args.working_dir,
        args.vuln_command,
        args.reproducer_bytes,
        args.reproduction_runs,
    )?;

    if tier_vuln != EpistemicTier::ConfirmedReproduced {
        return Err(ProoflineError::ReproductionFailed(format!(
            "Vulnerability reproducer failed N-run determinism check ({}/{})",
            witness.successful_runs, witness.total_attempted_runs
        )));
    }

    // Run differential verification using V_vuln and V_patch runners; note: in CLI if vuln_command
    // differs from patch_command, DifferentialVerificationEngine uses `command`. Here we wrap
    // V_patch command override when needed via a thin adapter.
    let mut patch_adapter = CommandOverrideRunner {
        inner: patch_runner,
        command_override: args.patch_command.to_vec(),
    };

    let (report, diff_result) = DifferentialVerificationEngine::verify_patch(
        vuln_runner,
        &patch_adapter,
        args.working_dir,
        args.vuln_command,
        args.reproducer_bytes,
        args.regression_inputs,
    )?;
    let _ = &mut patch_adapter;

    let bundle_input = EvidenceBundleInput {
        contract: args.contract.clone(),
        epistemic_tier: report.final_epistemic_tier,
        reproduction_witness: Some(witness.clone()),
        differential_result: Some(diff_result.clone()),
        differential_report: Some(report.clone()),
        reachability_traces: args.reachability_traces.clone(),
        reproducer_bytes: args.reproducer_bytes.to_vec(),
        build_script: "#!/bin/sh\nset -eu\n# Hermetic build recorded by Proofline CLI\n"
            .to_string(),
        run_script: format!("#!/bin/sh\nset -eu\nexec {}\n", args.vuln_command.join(" ")),
        execution_log: format!(
            "V_vuln fault={} deterministic={}/{}; V_patch mitigated={} bypasses={} regressions={}\n",
            crash_sig.fault_type,
            witness.successful_runs,
            witness.total_attempted_runs,
            report.original_reproducer_on_patch_mitigated,
            report.bypasses.len(),
            report.regressions_detected
        ),
        sanitizer_log: format!(
            "fault_type={} exit_code={} trace_blake3={}\n",
            crash_sig.fault_type, crash_sig.exit_code, crash_sig.sanitized_trace_blake3
        ),
    };

    let core_bundle = proofline_core::EvidenceBundle::new(
        &args.contract,
        report.final_epistemic_tier,
        Some(witness),
        Some(diff_result),
    );
    let sarif = SarifExporter::from_verification_summary(
        &core_bundle,
        Some(&report),
        &args.reachability_traces,
    );

    let manifest = match (bundle_out, signer) {
        (Some(out_path), Some(s)) => {
            let m = if out_path.extension().and_then(|e| e.to_str()) == Some("tar") {
                EvidenceBundlePackager::package_to_tar(&bundle_input, s, out_path)?
            } else {
                EvidenceBundlePackager::package_to_dir(&bundle_input, s, out_path)?
            };
            Some(m)
        }
        (Some(_), None) => {
            return Err(ProoflineError::CryptoError(
                "Writing an Evidence Bundle requires an AttestationSigner".to_string(),
            ));
        }
        _ => None,
    };

    let markdown_summary = VerificationMarkdownRenderer::render_summary(
        manifest.as_ref(),
        &report,
        &args.reachability_traces,
    );

    Ok(PatchVerificationOutcome {
        report,
        manifest,
        sarif,
        markdown_summary,
    })
}

pub fn reproduce_with_fuzzer<R: SandboxRunner>(
    runner: &R,
    working_dir: &Path,
    command: &[String],
    seeds: &[Vec<u8>],
    max_iterations: usize,
    required_runs: u32,
) -> Result<MutationFuzzResult> {
    MutationFuzzer::fuzz_until_reproduced(
        runner,
        working_dir,
        command,
        seeds,
        max_iterations,
        required_runs,
    )
}

pub fn compare_reproducible_builds(
    artifact_a: &Path,
    artifact_b: &Path,
) -> Result<ReproducibleBuildReport> {
    ReproducibleBuildVerifier::compare_files(artifact_a, artifact_b)
}

struct CommandOverrideRunner<'a, R: SandboxRunner> {
    inner: &'a R,
    command_override: Vec<String>,
}

impl<'a, R: SandboxRunner> SandboxRunner for CommandOverrideRunner<'a, R> {
    fn execute(&self, config: &proofline_sandbox::ExecutionConfig) -> Result<proofline_sandbox::ExecutionOutput> {
        let mut cloned = config.clone();
        if !self.command_override.is_empty() {
            cloned.command = self.command_override.clone();
        }
        self.inner.execute(&cloned)
    }
}

pub fn generate_keypair(out_dir: &Path) -> Result<(PathBuf, PathBuf, String)> {
    let signer = AttestationSigner::generate()?;
    let (priv_path, pub_path) = signer.save_keypair_files(out_dir)?;
    Ok((priv_path, pub_path, signer.key_id().to_string()))
}

pub fn verify_bundle(
    bundle_path: &Path,
    pubkey_path: &Path,
) -> Result<VerifiedBundleReport> {
    let verifier = AttestationVerifier::from_key_file(pubkey_path)?;
    if bundle_path.is_dir() {
        EvidenceBundleVerifier::verify_bundle_dir(bundle_path, &verifier)
    } else {
        EvidenceBundleVerifier::verify_bundle_tar(bundle_path, &verifier)
    }
}

pub fn verify_and_replay_bundle<R: SandboxRunner>(
    bundle_path: &Path,
    pubkey_path: &Path,
    runner: &R,
    command_override: Option<&[String]>,
) -> Result<(VerifiedBundleReport, ReplayVerificationReport)> {
    let verifier = AttestationVerifier::from_key_file(pubkey_path)?;
    EvidenceBundleVerifier::verify_and_replay(bundle_path, &verifier, runner, command_override)
}
