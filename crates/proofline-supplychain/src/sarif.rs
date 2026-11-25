//! OASIS SARIF v2.1.0 exporter for Proofline reachability traces and verification results.

use proofline_analysis::{PathVerificationStatus, ReachabilityTrace};
use proofline_core::{sanitize_terminal_trace, EpistemicTier, EvidenceBundle};
use proofline_differential::DifferentialPatchReport;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

pub const SARIF_SCHEMA_URL: &str = "https://json.schemastore.org/sarif-2.1.0.json";
pub const SARIF_VERSION: &str = "2.1.0";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifLog {
    #[serde(rename = "$schema")]
    pub schema: String,
    pub version: String,
    pub runs: Vec<SarifRun>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifRun {
    pub tool: SarifTool,
    pub results: Vec<SarifResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifTool {
    pub driver: SarifDriver,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifDriver {
    pub name: String,
    pub version: String,
    #[serde(rename = "informationUri")]
    pub information_uri: String,
    pub rules: Vec<SarifRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifRule {
    pub id: String,
    pub name: String,
    #[serde(rename = "shortDescription")]
    pub short_description: SarifMessage,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifMessage {
    pub text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifResult {
    #[serde(rename = "ruleId")]
    pub rule_id: String,
    pub level: String,
    pub message: SarifMessage,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub locations: Vec<SarifLocation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifLocation {
    #[serde(rename = "physicalLocation")]
    pub physical_location: SarifPhysicalLocation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifPhysicalLocation {
    #[serde(rename = "artifactLocation")]
    pub artifact_location: SarifArtifactLocation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifArtifactLocation {
    pub uri: String,
}

pub struct SarifExporter;

impl SarifExporter {
    pub fn from_reachability_traces(
        artifact_uri: &str,
        traces: &[ReachabilityTrace],
    ) -> SarifLog {
        let mut rules = Vec::new();
        let mut results = Vec::new();

        for trace in traces {
            let rule_id = format!("PROOFLINE-{}", sanitize_terminal_trace(&trace.sink_type));
            if !rules.iter().any(|r: &SarifRule| r.id == rule_id) {
                rules.push(SarifRule {
                    id: rule_id.clone(),
                    name: sanitize_terminal_trace(&trace.sink_type),
                    short_description: SarifMessage {
                        text: format!(
                            "Interprocedural reachability check for {}",
                            sanitize_terminal_trace(&trace.sink_type)
                        ),
                    },
                });
            }

            let level = match trace.status {
                PathVerificationStatus::UnguardedExploitableTaint => "warning",
                PathVerificationStatus::SanitizedOrGuarded => "note",
                PathVerificationStatus::ProvenUnreachable => "none",
            };

            results.push(SarifResult {
                rule_id,
                level: level.to_string(),
                message: SarifMessage {
                    text: format!(
                        "Reachability status {:?} (epistemic tier {:?}) from node {} to sink node {}",
                        trace.status,
                        trace.recommended_epistemic_tier,
                        trace.ingress_node_id,
                        trace.sink_node_id
                    ),
                },
                locations: vec![SarifLocation {
                    physical_location: SarifPhysicalLocation {
                        artifact_location: SarifArtifactLocation {
                            uri: sanitize_terminal_trace(artifact_uri),
                        },
                    },
                }],
                properties: Some(json!({
                    "epistemic_tier": trace.recommended_epistemic_tier,
                    "path_node_ids": trace.path_node_ids,
                    "smt_constraint_formula": trace.smt_constraint_formula,
                })),
            });
        }

        SarifLog {
            schema: SARIF_SCHEMA_URL.to_string(),
            version: SARIF_VERSION.to_string(),
            runs: vec![SarifRun {
                tool: SarifTool {
                    driver: SarifDriver {
                        name: "Proofline".to_string(),
                        version: env!("CARGO_PKG_VERSION").to_string(),
                        information_uri: "https://proofline.dev".to_string(),
                        rules,
                    },
                },
                results,
            }],
        }
    }

    pub fn from_verification_summary(
        bundle: &EvidenceBundle,
        diff_report: Option<&DifferentialPatchReport>,
        traces: &[ReachabilityTrace],
    ) -> SarifLog {
        let mut log = Self::from_reachability_traces(&bundle.target_repository, traces);
        let run = &mut log.runs[0];

        let summary_rule_id = "PROOFLINE-VERIFICATION-SUMMARY".to_string();
        run.tool.driver.rules.push(SarifRule {
            id: summary_rule_id.clone(),
            name: "ProoflineVerificationOutcome".to_string(),
            short_description: SarifMessage {
                text: "Evidence-grounded reproduction and differential patch verification verdict"
                    .to_string(),
            },
        });

        let level = match bundle.epistemic_tier {
            EpistemicTier::ConfirmedReproduced => "error",
            EpistemicTier::VerifiedMitigation => "note",
            _ => "warning",
        };

        run.results.push(SarifResult {
            rule_id: summary_rule_id,
            level: level.to_string(),
            message: SarifMessage {
                text: format!(
                    "Bundle {} classified as {:?} for vulnerable commit {}",
                    sanitize_terminal_trace(&bundle.bundle_id),
                    bundle.epistemic_tier,
                    sanitize_terminal_trace(&bundle.vulnerable_commit),
                ),
            },
            locations: vec![SarifLocation {
                physical_location: SarifPhysicalLocation {
                    artifact_location: SarifArtifactLocation {
                        uri: sanitize_terminal_trace(&bundle.target_repository),
                    },
                },
            }],
            properties: Some(json!({
                "bundle_id": bundle.bundle_id,
                "contract_id": bundle.contract_id,
                "epistemic_tier": bundle.epistemic_tier,
                "reproduction_witness": bundle.reproduction_witness,
                "differential_result": bundle.differential_result,
            })),
        });

        if let Some(report) = diff_report {
            if !report.bypasses.is_empty() {
                let bypass_rule_id = "PROOFLINE-PATCH-BYPASS".to_string();
                run.tool.driver.rules.push(SarifRule {
                    id: bypass_rule_id.clone(),
                    name: "AdversarialPatchBypassDetected".to_string(),
                    short_description: SarifMessage {
                        text: "Differential mutation fuzzing discovered a variant bypassing V_patch"
                            .to_string(),
                    },
                });
                for bypass in &report.bypasses {
                    run.results.push(SarifResult {
                        rule_id: bypass_rule_id.clone(),
                        level: "error".to_string(),
                        message: SarifMessage {
                            text: format!(
                                "Patch bypass '{}' triggered fault {} (payload blake3: {})",
                                sanitize_terminal_trace(&bypass.mutation_name),
                                sanitize_terminal_trace(&bypass.crash_signature.fault_type),
                                bypass.payload_bytes_blake3,
                            ),
                        },
                        locations: vec![SarifLocation {
                            physical_location: SarifPhysicalLocation {
                                artifact_location: SarifArtifactLocation {
                                    uri: sanitize_terminal_trace(&bundle.target_repository),
                                },
                            },
                        }],
                        properties: Some(json!(bypass)),
                    });
                }
            }
        }

        log
    }
}
