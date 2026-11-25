//! CycloneDX 1.5 SBOM generator backed by safe static repository inspection.

use chrono::Utc;
use proofline_core::sanitize_terminal_trace;
use proofline_intelligence::ProjectInspection;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CycloneDxBom {
    #[serde(rename = "bomFormat")]
    pub bom_format: String,
    #[serde(rename = "specVersion")]
    pub spec_version: String,
    #[serde(rename = "serialNumber")]
    pub serial_number: String,
    pub version: u32,
    pub metadata: CycloneDxMetadata,
    pub components: Vec<CycloneDxComponent>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CycloneDxMetadata {
    pub timestamp: String,
    pub component: CycloneDxRootComponent,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CycloneDxRootComponent {
    #[serde(rename = "type")]
    pub component_type: String,
    pub name: String,
    pub hashes: Vec<CycloneDxHash>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CycloneDxHash {
    pub alg: String,
    pub content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CycloneDxComponent {
    #[serde(rename = "type")]
    pub component_type: String,
    pub name: String,
    pub version: String,
}

pub struct SbomGenerator;

impl SbomGenerator {
    pub fn to_cyclonedx(project_name: &str, inspection: &ProjectInspection) -> CycloneDxBom {
        let components = inspection
            .manifest_dependencies
            .iter()
            .map(|(name, version)| CycloneDxComponent {
                component_type: "library".to_string(),
                name: sanitize_terminal_trace(name),
                version: sanitize_terminal_trace(version),
            })
            .collect();

        CycloneDxBom {
            bom_format: "CycloneDX".to_string(),
            spec_version: "1.5".to_string(),
            serial_number: format!("urn:uuid:{}", Uuid::new_v4()),
            version: 1,
            metadata: CycloneDxMetadata {
                timestamp: Utc::now().to_rfc3339(),
                component: CycloneDxRootComponent {
                    component_type: "application".to_string(),
                    name: sanitize_terminal_trace(project_name),
                    hashes: vec![CycloneDxHash {
                        alg: "BLAKE3".to_string(),
                        content: inspection.root_hash_blake3.clone(),
                    }],
                },
            },
            components,
        }
    }
}
