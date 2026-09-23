//! Deterministic CycloneDX 1.6 CBOM serialization with LATTICE risk extensions.

use lattice_core::{CryptoAsset, CBOM_SCHEMA_VERSION, KNOWLEDGE_VERSION};
use lattice_risk::RiskAssessment;
use serde::{Deserialize, Serialize};

pub mod signing;

#[derive(Debug, Clone)]
pub struct AssessedAsset {
    pub asset: CryptoAsset,
    pub risk: RiskAssessment,
    pub context: AssetContext,
}

#[derive(Debug, Clone, Default)]
pub struct AssetContext {
    pub protected_data_ids: Vec<String>,
    pub classifications: Vec<String>,
    pub business_criticality: String,
    pub reachable_from: Vec<String>,
    pub classifier_rule: String,
    pub classifier_confidence: f64,
    pub classifier_explanation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Bom {
    pub bom_format: String,
    pub spec_version: String,
    pub serial_number: String,
    pub version: u32,
    pub metadata: Metadata,
    pub components: Vec<CryptoComponent>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<signing::CbomSignature>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Metadata {
    pub tools: Tools,
    pub properties: Vec<Property>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tools {
    pub components: Vec<ToolComponent>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolComponent {
    #[serde(rename = "type")]
    pub component_type: String,
    pub group: String,
    pub name: String,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Property {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CryptoComponent {
    #[serde(rename = "type")]
    pub component_type: String,
    #[serde(rename = "bom-ref")]
    pub bom_ref: String,
    pub name: String,
    pub version: String,
    pub crypto_properties: CryptoProperties,
    pub evidence: ComponentEvidence,
    pub properties: Vec<Property>,
    pub lattice: LatticeExtension,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CryptoProperties {
    pub asset_type: String,
    pub algorithm_properties: AlgorithmProperties,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AlgorithmProperties {
    pub primitive: String,
    pub parameter_set_identifier: String,
    pub nist_quantum_security_level: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentEvidence {
    pub occurrences: Vec<Occurrence>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Occurrence {
    pub location: String,
    pub line: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub byte_offset: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LatticeExtension {
    pub liveness: lattice_core::Liveness,
    pub evidence_grade: lattice_core::EvidenceGrade,
    pub surfaces: Vec<lattice_core::Surface>,
    pub rule_ids: Vec<String>,
    pub quantum_breakability: f64,
    pub broken_now: bool,
    pub protects_data: Vec<String>,
    pub data_classifications: Vec<String>,
    pub data_secrecy_lifetime_years: f64,
    pub business_criticality: String,
    pub reachable_from: Vec<String>,
    pub external_exposure: f64,
    pub classifier_rule: String,
    pub classifier_confidence: f64,
    pub classifier_explanation: String,
    pub crypto_agility_score: u8,
    pub mosca_urgent: bool,
    pub mosca_urgency_years: f64,
    pub hndl_index: f64,
    pub hndl_terms: Vec<lattice_risk::ScoreTerm>,
    pub recommendation: lattice_risk::Recommendation,
}

pub fn build_bom(mut assessed: Vec<AssessedAsset>) -> Bom {
    assessed.sort_by(|a, b| a.asset.id.cmp(&b.asset.id));
    let identity_material = assessed
        .iter()
        .map(|item| item.asset.id.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    let serial_number = deterministic_serial(identity_material.as_bytes());

    let components = assessed
        .into_iter()
        .map(|item| {
            let parameter_set_identifier = parameter_set(&item.asset);
            let nist_quantum_security_level = if item.risk.quantum_breakability == 0.0 { 3 } else { 0 };
            let occurrences = item
                .asset
                .locations
                .iter()
                .map(|location| Occurrence {
                    location: location.path.clone(),
                    line: location.line,
                    byte_offset: location.byte_offset,
                })
                .collect();
            let mut rule_ids = item
                .asset
                .evidence
                .iter()
                .map(|evidence| format!("{}@{}", evidence.rule_id, evidence.rule_version))
                .collect::<Vec<_>>();
            rule_ids.sort();
            rule_ids.dedup();
            let surfaces = item.asset.surfaces.iter().copied().collect();
            let version = item.asset.algorithm.key_size_bits.map_or_else(
                || "unspecified".to_owned(),
                |bits| format!("{bits}-bit"),
            );
            let properties = item
                .asset
                .parameters
                .iter()
                .map(|(name, value)| Property {
                    name: format!("lattice:parameter:{name}"),
                    value: value.clone(),
                })
                .collect();

            CryptoComponent {
                component_type: "cryptographic-asset".to_owned(),
                bom_ref: item.asset.id,
                name: item.asset.algorithm.family,
                version,
                crypto_properties: CryptoProperties {
                    asset_type: "algorithm".to_owned(),
                    algorithm_properties: AlgorithmProperties {
                        primitive: item.asset.algorithm.primitive,
                        parameter_set_identifier,
                        nist_quantum_security_level,
                    },
                },
                evidence: ComponentEvidence { occurrences },
                properties,
                lattice: LatticeExtension {
                    liveness: item.asset.liveness,
                    evidence_grade: item.asset.evidence_grade,
                    surfaces,
                    rule_ids,
                    quantum_breakability: item.risk.quantum_breakability,
                    broken_now: item.risk.broken_now,
                    protects_data: item.context.protected_data_ids,
                    data_classifications: item.context.classifications,
                    data_secrecy_lifetime_years: item.risk.mosca.data_lifetime_years,
                    business_criticality: item.context.business_criticality,
                    reachable_from: item.context.reachable_from,
                    external_exposure: item
                        .risk
                        .hndl_terms
                        .iter()
                        .find(|term| term.name == "externalExposure")
                        .map_or(0.0, |term| term.value),
                    classifier_rule: item.context.classifier_rule,
                    classifier_confidence: item.context.classifier_confidence,
                    classifier_explanation: item.context.classifier_explanation,
                    crypto_agility_score: item.risk.crypto_agility_score,
                    mosca_urgent: item.risk.mosca.urgent,
                    mosca_urgency_years: item.risk.mosca.urgency_years,
                    hndl_index: item.risk.hndl_index,
                    hndl_terms: item.risk.hndl_terms,
                    recommendation: item.risk.recommendation,
                },
            }
        })
        .collect();

    Bom {
        bom_format: "CycloneDX".to_owned(),
        spec_version: CBOM_SCHEMA_VERSION.to_owned(),
        serial_number,
        version: 1,
        metadata: Metadata {
            tools: Tools {
                components: vec![ToolComponent {
                    component_type: "application".to_owned(),
                    group: "org.doodlebyte".to_owned(),
                    name: "lattice".to_owned(),
                    version: env!("CARGO_PKG_VERSION").to_owned(),
                }],
            },
            properties: vec![
                Property { name: "lattice:knowledgeVersion".into(), value: KNOWLEDGE_VERSION.into() },
                Property { name: "lattice:deterministic".into(), value: "true".into() },
            ],
        },
        components,
        signature: None,
    }
}

pub fn to_pretty_json(bom: &Bom) -> Result<String, serde_json::Error> {
    let mut output = serde_json::to_string_pretty(bom)?;
    output.push('\n');
    Ok(output)
}

fn parameter_set(asset: &CryptoAsset) -> String {
    let mut parts = Vec::new();
    if let Some(bits) = asset.algorithm.key_size_bits {
        parts.push(format!("{bits}-bit"));
    }
    if let Some(mode) = &asset.algorithm.mode {
        parts.push(mode.clone());
    }
    if let Some(curve) = &asset.algorithm.curve {
        parts.push(curve.clone());
    }
    if parts.is_empty() { "unspecified".into() } else { parts.join("/") }
}

fn deterministic_serial(bytes: &[u8]) -> String {
    let digest = blake3::hash(bytes);
    let hex = digest.to_hex();
    format!(
        "urn:uuid:{}-{}-4{}-a{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[13..16],
        &hex[17..20],
        &hex[20..32]
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_bom_serialization_is_byte_stable() {
        let first = to_pretty_json(&build_bom(vec![])).unwrap();
        let second = to_pretty_json(&build_bom(vec![])).unwrap();
        assert_eq!(first, second);
        assert!(first.contains("\"specVersion\": \"1.6\""));
        assert!(!first.contains("timestamp"));
    }
}
