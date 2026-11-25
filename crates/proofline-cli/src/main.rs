use clap::{Parser, Subcommand, ValueEnum};
use proofline_cli::{
    analyze_repository, analyze_source_file, compare_reproducible_builds, generate_keypair,
    inspect_repo, reproduce_with_fuzzer, validate_verification_contract, verify_and_replay_bundle,
    verify_bundle, verify_patch_pipeline, PatchVerificationArgs, SourceLang,
};
use proofline_core::{EpistemicTier, VerificationContract};
use proofline_sandbox::PodmanSandboxRunner;
use proofline_supplychain::{
    AttestationSigner, EvidenceBundleVerifier, SignerTrustVerdict, TrustedIdentityPolicy,
};
use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser)]
#[command(
    name = "proofline",
    version,
    about = "Evidence-grounded security verification, differential patch checking, and cryptographic attestation"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Clone, Copy, ValueEnum)]
enum CliLang {
    C,
    Python,
    Rust,
    Js,
    Go,
    Java,
}

impl From<CliLang> for SourceLang {
    fn from(value: CliLang) -> Self {
        match value {
            CliLang::C => SourceLang::C,
            CliLang::Python => SourceLang::Python,
            CliLang::Rust => SourceLang::Rust,
            CliLang::Js => SourceLang::JavaScript,
            CliLang::Go => SourceLang::Go,
            CliLang::Java => SourceLang::Java,
        }
    }
}

#[derive(Subcommand)]
enum Commands {
    /// Safely inspect a repository without executing build scripts and optionally export CycloneDX SBOM
    Inspect {
        /// Path to repository directory
        path: PathBuf,
        /// Optional CycloneDX 1.5 SBOM output path
        #[arg(long)]
        sbom: Option<PathBuf>,
        /// Emit machine-readable JSON inspection summary
        #[arg(long)]
        json: bool,
    },
    /// Construct a Code Property Graph, trace taint reachability, and synthesize SMT-LIB2 constraints
    Analyze {
        /// Source file to analyze
        file: PathBuf,
        /// Force source language (defaults to file extension)
        #[arg(long, value_enum)]
        lang: Option<CliLang>,
        /// Optional OASIS SARIF v2.1.0 output path
        #[arg(long)]
        sarif: Option<PathBuf>,
        /// Emit JSON reachability traces
        #[arg(long)]
        json: bool,
    },
    /// Build a multi-file interprocedural CPG across an entire repository without executing build scripts
    AnalyzeRepo {
        /// Path to repository directory
        path: PathBuf,
        /// Optional OASIS SARIF v2.1.0 output path
        #[arg(long)]
        sarif: Option<PathBuf>,
        /// Emit JSON reachability traces
        #[arg(long)]
        json: bool,
    },
    /// Generate an Ed25519 signing/verifying keypair for Evidence Bundle attestations
    Keygen {
        /// Output directory for proofline.key.json and proofline.pub.json
        #[arg(long)]
        out_dir: PathBuf,
    },
    /// Run isolated sandboxed reproduction and differential patch verification against V_vuln and V_patch
    VerifyPatch {
        /// Target working directory mounted into the isolated sandbox
        #[arg(long)]
        workdir: PathBuf,
        /// Command executed inside sandbox for unpatched revision V_vuln
        #[arg(long, num_args = 1.., required = true)]
        vuln_cmd: Vec<String>,
        /// Command executed inside sandbox for patched revision V_patch
        #[arg(long, num_args = 1.., required = true)]
        patch_cmd: Vec<String>,
        /// Reproducer payload file path
        #[arg(long)]
        reproducer: PathBuf,
        /// Golden regression test payload files (repeatable)
        #[arg(long)]
        regression: Vec<PathBuf>,
        /// OCI image used by rootless Podman sandbox
        #[arg(long, default_value = "docker.io/library/alpine:latest")]
        image: String,
        /// Optional VerificationContract JSON file
        #[arg(long)]
        contract: Option<PathBuf>,
        /// Optional source repository URI
        #[arg(long, default_value = "https://proofline.dev/local-repo")]
        repo: String,
        /// Vulnerable commit SHA
        #[arg(long, default_value = "0000000000000000000000000000000000000000")]
        vuln_commit: String,
        /// Candidate patch commit SHA
        #[arg(long)]
        patch_commit: Option<String>,
        /// Number of consecutive deterministic reproduction runs
        #[arg(long, default_value_t = 3)]
        runs: u32,
        /// Optional Ed25519 private key file (proofline.key.json); generates ephemeral key if omitted
        #[arg(long)]
        signing_key: Option<PathBuf>,
        /// Output Evidence Bundle directory or `.tar` archive path
        #[arg(long)]
        bundle_out: Option<PathBuf>,
        /// Optional OASIS SARIF v2.1.0 output file
        #[arg(long)]
        sarif_out: Option<PathBuf>,
        /// Optional source file to analyze and embed reachability traces into the Evidence Bundle
        #[arg(long)]
        source: Option<PathBuf>,
        /// Optional human-readable Markdown summary report path
        #[arg(long)]
        markdown_out: Option<PathBuf>,
    },
    /// Validate a declarative VerificationContract JSON specification
    VerifyContract {
        /// Path to verification contract JSON file
        #[arg(long)]
        contract: PathBuf,
    },
    /// Fuzz and deterministically reproduce a vulnerability inside an isolated sandbox
    Reproduce {
        /// Target working directory mounted into sandbox
        #[arg(long)]
        workdir: PathBuf,
        /// Optional initial seed payload file
        #[arg(long)]
        seed: Option<PathBuf>,
        /// OCI image used by rootless Podman sandbox
        #[arg(long, default_value = "docker.io/library/alpine:latest")]
        image: String,
        /// Maximum fuzzing iterations
        #[arg(long, default_value_t = 64)]
        budget: usize,
        /// Determinism verification runs after crash discovery
        #[arg(long, default_value_t = 3)]
        runs: u32,
        /// Optional output file for discovered crashing reproducer bytes
        #[arg(long)]
        out_poc: Option<PathBuf>,
        /// Target command inside sandbox after `--`
        #[arg(last = true, allow_hyphen_values = true, required = true)]
        cmd: Vec<String>,
    },
    /// Compare two build artifacts bit-for-bit for reproducible-build verification
    VerifyBuilds {
        /// First build artifact path
        artifact_a: PathBuf,
        /// Second build artifact path
        artifact_b: PathBuf,
        /// Emit machine-readable JSON report
        #[arg(long)]
        json: bool,
    },
    /// Independently verify a Proofline Evidence Bundle (and optionally replay inside sandbox)
    VerifyBundle {
        /// Path to Evidence Bundle directory or `.tar` archive
        #[arg(long)]
        bundle: PathBuf,
        /// Trusted Ed25519 public key file (`proofline.pub.json`)
        #[arg(long)]
        pubkey: PathBuf,
        /// Optional TrustedIdentityPolicy JSON file distinguishing valid signatures from trusted builders
        #[arg(long)]
        trust_policy: Option<PathBuf>,
        /// Replay the attested reproducer inside an isolated sandbox
        #[arg(long)]
        replay: bool,
        /// OCI image used when `--replay` is enabled
        #[arg(long, default_value = "docker.io/library/alpine:latest")]
        image: String,
        /// Optional replay command override inside sandbox
        #[arg(long, num_args = 1..)]
        cmd: Vec<String>,
        /// Optional replay command override after `--` (supports flags like `-c`)
        #[arg(last = true, allow_hyphen_values = true)]
        replay_args: Vec<String>,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(code) => code,
        Err(err) => {
            eprintln!("proofline error: {}", err);
            ExitCode::from(1)
        }
    }
}

fn run(cli: Cli) -> proofline_core::Result<ExitCode> {
    match cli.command {
        Commands::Inspect { path, sbom, json } => {
            let (inspection, bom) = inspect_repo(&path, None)?;
            if let Some(sbom_path) = sbom {
                let data = serde_json::to_string_pretty(&bom)?;
                fs::write(&sbom_path, data)?;
                eprintln!("Wrote CycloneDX 1.5 SBOM to {}", sbom_path.display());
            }
            if json {
                println!("{}", serde_json::to_string_pretty(&inspection)?);
            } else {
                println!(
                    "Primary language: {:?}\nFiles: {} ({} bytes)\nBuild systems: {:?}\nDependencies: {}\nRoot BLAKE3: {}",
                    inspection.primary_language,
                    inspection.total_source_files,
                    inspection.total_size_bytes,
                    inspection.build_systems,
                    inspection.manifest_dependencies.len(),
                    inspection.root_hash_blake3
                );
            }
            Ok(ExitCode::SUCCESS)
        }
        Commands::Analyze {
            file,
            lang,
            sarif,
            json,
        } => {
            let (traces, sarif_log) = analyze_source_file(&file, lang.map(Into::into))?;
            if let Some(sarif_path) = sarif {
                fs::write(&sarif_path, serde_json::to_string_pretty(&sarif_log)?)?;
                eprintln!("Wrote SARIF v2.1.0 report to {}", sarif_path.display());
            }
            if json {
                println!("{}", serde_json::to_string_pretty(&traces)?);
            } else if traces.is_empty() {
                println!("No tainted ingress-to-sink paths detected in {}", file.display());
            } else {
                for trace in &traces {
                    println!(
                        "Trace node {} -> {} | sink={} | status={:?} | tier={:?}",
                        trace.ingress_node_id,
                        trace.sink_node_id,
                        trace.sink_type,
                        trace.status,
                        trace.recommended_epistemic_tier
                    );
                }
            }
            Ok(ExitCode::SUCCESS)
        }
        Commands::AnalyzeRepo { path, sarif, json } => {
            let (traces, sarif_log) = analyze_repository(&path)?;
            if let Some(sarif_path) = sarif {
                fs::write(&sarif_path, serde_json::to_string_pretty(&sarif_log)?)?;
                eprintln!("Wrote repository SARIF v2.1.0 report to {}", sarif_path.display());
            }
            if json {
                println!("{}", serde_json::to_string_pretty(&traces)?);
            } else if traces.is_empty() {
                println!("No tainted interprocedural paths detected in {}", path.display());
            } else {
                for trace in &traces {
                    println!(
                        "Trace node {} -> {} | sink={} | status={:?} | tier={:?}",
                        trace.ingress_node_id,
                        trace.sink_node_id,
                        trace.sink_type,
                        trace.status,
                        trace.recommended_epistemic_tier
                    );
                }
            }
            Ok(ExitCode::SUCCESS)
        }
        Commands::Keygen { out_dir } => {
            let (priv_path, pub_path, key_id) = generate_keypair(&out_dir)?;
            println!(
                "Generated Ed25519 keypair ({})\n  private: {}\n  public:  {}",
                key_id,
                priv_path.display(),
                pub_path.display()
            );
            Ok(ExitCode::SUCCESS)
        }
        Commands::VerifyPatch {
            workdir,
            vuln_cmd,
            patch_cmd,
            reproducer,
            regression,
            image,
            contract,
            repo,
            vuln_commit,
            patch_commit,
            runs,
            signing_key,
            bundle_out,
            sarif_out,
            source,
            markdown_out,
        } => {
            let contract_obj = if let Some(contract_path) = contract {
                let raw = fs::read_to_string(&contract_path)?;
                let parsed = serde_json::from_str::<VerificationContract>(&raw)?;
                validate_verification_contract(&parsed)?;
                parsed
            } else {
                let mut c = VerificationContract::default();
                c.target_repository = repo;
                c.vulnerable_commit = vuln_commit;
                c.candidate_patch_commit = patch_commit;
                c.required_reproduction_runs = runs;
                c
            };

            let reachability_traces = if let Some(ref src_path) = source {
                analyze_source_file(src_path, None)?.0
            } else {
                Vec::new()
            };

            let reproducer_bytes = fs::read(&reproducer)?;
            let mut regression_inputs = Vec::with_capacity(regression.len());
            for reg_path in &regression {
                regression_inputs.push(fs::read(reg_path)?);
            }

            let signer = match signing_key {
                Some(ref key_path) => Some(AttestationSigner::from_key_file(key_path)?),
                None if bundle_out.is_some() => Some(AttestationSigner::generate()?),
                None => None,
            };

            let runner = PodmanSandboxRunner::new(&image);
            let outcome = verify_patch_pipeline(
                &runner,
                &runner,
                PatchVerificationArgs {
                    contract: contract_obj,
                    working_dir: &workdir,
                    vuln_command: &vuln_cmd,
                    patch_command: &patch_cmd,
                    reproducer_bytes: &reproducer_bytes,
                    regression_inputs: &regression_inputs,
                    reproduction_runs: runs,
                    reachability_traces,
                },
                signer.as_ref(),
                bundle_out.as_deref(),
            )?;

            if let Some(sarif_path) = sarif_out {
                fs::write(&sarif_path, serde_json::to_string_pretty(&outcome.sarif)?)?;
            }
            if let Some(md_path) = markdown_out {
                fs::write(&md_path, &outcome.markdown_summary)?;
            }

            println!(
                "Epistemic Tier: {:?}\nPatch mitigated original reproducer: {}\nBypass mutations evaluated: {} (bypasses found: {})\nRegressions detected: {}",
                outcome.report.final_epistemic_tier,
                outcome.report.original_reproducer_on_patch_mitigated,
                outcome.report.total_mutations_evaluated,
                outcome.report.bypasses.len(),
                outcome.report.regressions_detected
            );
            if let Some(m) = outcome.manifest {
                println!(
                    "Evidence Bundle {} signed by {} (Merkle root: {})",
                    m.bundle_id, m.attestation.key_id, m.cas_hashes.merkle_root_hash
                );
            }

            if outcome.report.final_epistemic_tier == EpistemicTier::VerifiedMitigation {
                Ok(ExitCode::SUCCESS)
            } else {
                Ok(ExitCode::from(2))
            }
        }
        Commands::VerifyContract { contract } => {
            let raw = fs::read_to_string(&contract)?;
            let parsed: VerificationContract = serde_json::from_str(&raw)?;
            validate_verification_contract(&parsed)?;
            println!(
                "Contract {} valid (repo: {}, runs: {}, min_tier: {:?})",
                parsed.contract_id,
                parsed.target_repository,
                parsed.required_reproduction_runs,
                parsed.min_acceptable_tier
            );
            Ok(ExitCode::SUCCESS)
        }
        Commands::Reproduce {
            workdir,
            seed,
            image,
            budget,
            runs,
            out_poc,
            cmd,
        } => {
            let seeds = match seed {
                Some(p) => vec![fs::read(&p)?],
                None => Vec::new(),
            };
            let runner = PodmanSandboxRunner::new(&image);
            let res = reproduce_with_fuzzer(&runner, &workdir, &cmd, &seeds, budget, runs)?;
            println!(
                "Iterations: {} | Epistemic Tier: {:?}",
                res.iterations_executed, res.epistemic_tier
            );
            if let Some(payload) = res.discovered_payload {
                if let Some(poc_path) = out_poc {
                    fs::write(&poc_path, &payload)?;
                    println!("Wrote discovered reproducer ({} bytes) to {}", payload.len(), poc_path.display());
                }
            }
            if res.epistemic_tier == EpistemicTier::ConfirmedReproduced {
                Ok(ExitCode::SUCCESS)
            } else {
                Ok(ExitCode::from(2))
            }
        }
        Commands::VerifyBuilds {
            artifact_a,
            artifact_b,
            json,
        } => {
            let report = compare_reproducible_builds(&artifact_a, &artifact_b)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!(
                    "Bit-for-bit identical: {}\n  A: {} bytes (BLAKE3 {})\n  B: {} bytes (BLAKE3 {})",
                    report.identical_bit_for_bit,
                    report.build_a_size_bytes,
                    report.build_a_blake3,
                    report.build_b_size_bytes,
                    report.build_b_blake3
                );
            }
            if report.identical_bit_for_bit {
                Ok(ExitCode::SUCCESS)
            } else {
                Ok(ExitCode::from(2))
            }
        }
        Commands::VerifyBundle {
            bundle,
            pubkey,
            trust_policy,
            replay,
            image,
            cmd,
            replay_args,
        } => {
            if replay {
                let runner = PodmanSandboxRunner::new(&image);
                let override_vec = if !replay_args.is_empty() {
                    replay_args
                } else {
                    cmd
                };
                let cmd_opt = if override_vec.is_empty() {
                    None
                } else {
                    Some(override_vec.as_slice())
                };
                let (verified, replay_report) =
                    verify_and_replay_bundle(&bundle, &pubkey, &runner, cmd_opt)?;
                println!(
                    "Verified bundle {} ({} CAS artifacts, tier: {:?}, key: {})\nReplay exit_code={}, fault={:?}, matches_attestation={}",
                    verified.manifest.bundle_id,
                    verified.verified_artifact_count,
                    verified.manifest.epistemic_tier,
                    verified.manifest.attestation.key_id,
                    replay_report.observed_exit_code,
                    replay_report.observed_fault_type,
                    replay_report.replay_matches_attestation
                );
                if let Some(policy_path) = trust_policy {
                    let policy: TrustedIdentityPolicy =
                        serde_json::from_str(&fs::read_to_string(&policy_path)?)?;
                    match EvidenceBundleVerifier::evaluate_trust_policy(&verified, &policy) {
                        SignerTrustVerdict::TrustedIdentityAndBuilder { key_id, builder_id } => {
                            println!("Trust policy: TRUSTED ({} / {})", key_id, builder_id);
                        }
                        SignerTrustVerdict::ValidSignatureUntrustedSigner { reason, .. } => {
                            eprintln!("Trust policy rejected: {}", reason);
                            return Ok(ExitCode::from(2));
                        }
                    }
                }
                if replay_report.replay_matches_attestation {
                    Ok(ExitCode::SUCCESS)
                } else {
                    Ok(ExitCode::from(2))
                }
            } else {
                let verified = verify_bundle(&bundle, &pubkey)?;
                println!(
                    "Verified bundle {} ({} CAS artifacts, tier: {:?}, key: {}, Merkle root: {})",
                    verified.manifest.bundle_id,
                    verified.verified_artifact_count,
                    verified.manifest.epistemic_tier,
                    verified.manifest.attestation.key_id,
                    verified.manifest.cas_hashes.merkle_root_hash
                );
                if let Some(policy_path) = trust_policy {
                    let policy: TrustedIdentityPolicy =
                        serde_json::from_str(&fs::read_to_string(&policy_path)?)?;
                    match EvidenceBundleVerifier::evaluate_trust_policy(&verified, &policy) {
                        SignerTrustVerdict::TrustedIdentityAndBuilder { key_id, builder_id } => {
                            println!("Trust policy: TRUSTED ({} / {})", key_id, builder_id);
                        }
                        SignerTrustVerdict::ValidSignatureUntrustedSigner { reason, .. } => {
                            eprintln!("Trust policy rejected: {}", reason);
                            return Ok(ExitCode::from(2));
                        }
                    }
                }
                Ok(ExitCode::SUCCESS)
            }
        }
    }
}
