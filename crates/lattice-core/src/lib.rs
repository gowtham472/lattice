//! Shared, dependency-light domain types for LATTICE.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path};

pub const CBOM_SCHEMA_VERSION: &str = "1.6";
pub const KNOWLEDGE_VERSION: &str = "1.0.0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Surface {
    Source,
    Binary,
    Container,
    Config,
    Cloud,
    Runtime,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Location {
    /// Slash-normalized path relative to the scan root. Absolute host paths are never emitted.
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub column: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub byte_offset: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Algorithm {
    pub family: String,
    pub primitive: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_size_bits: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub curve: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EvidenceKind {
    Ast,
    ApiCall,
    Symbol,
    Constant,
    Configuration,
    Handshake,
    Heuristic,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Evidence {
    pub collector: String,
    pub rule_id: String,
    pub rule_version: String,
    pub kind: EvidenceKind,
    /// The matched API or symbol only. Source lines and possible secret values are never retained.
    pub matched_token: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Observation {
    pub surface: Surface,
    pub location: Location,
    pub algorithm: Algorithm,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub parameters: BTreeMap<String, String>,
    pub evidence: Evidence,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Liveness {
    Capable,
    Configured,
    Confirmed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EvidenceGrade {
    A,
    B,
    C,
    D,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CryptoAsset {
    pub id: String,
    pub algorithm: Algorithm,
    pub parameters: BTreeMap<String, String>,
    pub locations: Vec<Location>,
    pub surfaces: BTreeSet<Surface>,
    pub evidence: Vec<Evidence>,
    pub liveness: Liveness,
    pub evidence_grade: EvidenceGrade,
}

/// Converts a path to a stable report-safe representation without `..`, roots, or host separators.
pub fn report_path(root: &Path, path: &Path) -> String {
    let relative = path.strip_prefix(root).unwrap_or(path);
    let parts: Vec<_> = relative
        .components()
        .filter_map(|component| match component {
            Component::Normal(value) => Some(value.to_string_lossy().into_owned()),
            Component::ParentDir => Some("_parent_".to_owned()),
            _ => None,
        })
        .collect();
    if parts.is_empty() { ".".to_owned() } else { parts.join("/") }
}

/// Normalizes observations into deterministically ordered assets.
///
/// Findings across independent surfaces collapse when they identify the same algorithm and
/// cryptographic parameter set. Collector-specific metadata, evidence, and locations remain
/// attached for auditability.
pub fn normalize(mut observations: Vec<Observation>) -> Vec<CryptoAsset> {
    observations.sort_by(|a, b| {
        (&a.location, &a.algorithm, &a.parameters, &a.evidence)
            .cmp(&(&b.location, &b.algorithm, &b.parameters, &b.evidence))
    });

    let mut grouped: BTreeMap<String, Vec<Observation>> = BTreeMap::new();
    for observation in observations {
        let key = asset_key(&observation);
        grouped.entry(key).or_default().push(observation);
    }

    grouped
        .into_values()
        .map(|items| {
            let first = &items[0];
            let id = canonical_asset_id(first);
            let surfaces: BTreeSet<_> = items.iter().map(|item| item.surface).collect();
            let mut locations: Vec<_> = items.iter().map(|item| item.location.clone()).collect();
            locations.sort();
            locations.dedup();
            let mut evidence: Vec<_> = items.iter().map(|item| item.evidence.clone()).collect();
            evidence.sort();
            evidence.dedup();
            let parameters = merge_parameters(&items);
            let liveness = resolve_liveness(&surfaces);
            let evidence_grade = grade_evidence(&surfaces, &evidence);

            CryptoAsset {
                id,
                algorithm: first.algorithm.clone(),
                parameters,
                locations,
                surfaces,
                evidence,
                liveness,
                evidence_grade,
            }
        })
        .collect()
}

fn asset_key(observation: &Observation) -> String {
    format!(
        "{}|{}|{:?}|{:?}|{:?}",
        observation.algorithm.family.to_ascii_uppercase(),
        observation.algorithm.primitive,
        observation.algorithm.key_size_bits,
        observation.algorithm.mode.as_deref().map(str::to_ascii_uppercase),
        observation.algorithm.curve.as_deref().map(str::to_ascii_uppercase),
    )
}

fn merge_parameters(items: &[Observation]) -> BTreeMap<String, String> {
    let mut values: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for item in items {
        for (name, value) in &item.parameters {
            values.entry(name.clone()).or_default().insert(value.clone());
        }
    }
    values
        .into_iter()
        .map(|(name, values)| (name, values.into_iter().collect::<Vec<_>>().join(",")))
        .collect()
}

pub fn canonical_asset_id(observation: &Observation) -> String {
    let digest = blake3::hash(asset_key(observation).as_bytes()).to_hex();
    format!(
        "crypto/{}/{}",
        observation.algorithm.family.to_ascii_lowercase().replace(' ', "-"),
        &digest[..16]
    )
}

fn resolve_liveness(surfaces: &BTreeSet<Surface>) -> Liveness {
    if surfaces.contains(&Surface::Runtime) {
        Liveness::Confirmed
    } else if surfaces.contains(&Surface::Config) || surfaces.contains(&Surface::Cloud) {
        Liveness::Configured
    } else {
        Liveness::Capable
    }
}

fn grade_evidence(surfaces: &BTreeSet<Surface>, evidence: &[Evidence]) -> EvidenceGrade {
    if evidence.iter().all(|item| item.kind == EvidenceKind::Heuristic) {
        return EvidenceGrade::D;
    }
    match surfaces.len() {
        3.. => EvidenceGrade::A,
        2 => EvidenceGrade::B,
        _ => EvidenceGrade::C,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn observation(line: u64) -> Observation {
        Observation {
            surface: Surface::Source,
            location: Location {
                path: "src/main.c".into(),
                line: Some(line),
                column: Some(1),
                byte_offset: None,
            },
            algorithm: Algorithm {
                family: "RSA".into(),
                primitive: "public-key".into(),
                key_size_bits: Some(2048),
                mode: None,
                curve: None,
            },
            parameters: BTreeMap::new(),
            evidence: Evidence {
                collector: "source".into(),
                rule_id: "rsa".into(),
                rule_version: "1".into(),
                kind: EvidenceKind::ApiCall,
                matched_token: "RSA_new".into(),
            },
        }
    }

    #[test]
    fn normalization_is_stable_and_deduplicates_assets() {
        let assets = normalize(vec![observation(4), observation(2)]);
        assert_eq!(assets.len(), 1);
        assert_eq!(assets[0].locations.len(), 2);
        assert_eq!(assets[0].evidence_grade, EvidenceGrade::C);
        assert_eq!(assets[0].id.len(), "crypto/rsa/".len() + 16);
    }

    #[test]
    fn normalization_correlates_independent_surfaces() {
        let mut source = observation(2);
        source.parameters.insert("language".into(), "c".into());
        let mut binary = observation(0);
        binary.surface = Surface::Binary;
        binary.location = Location {
            path: "build/app".into(),
            line: None,
            column: None,
            byte_offset: Some(128),
        };
        binary.parameters.insert("binaryFormat".into(), "ELF".into());
        binary.evidence.kind = EvidenceKind::Symbol;

        let assets = normalize(vec![source, binary]);
        assert_eq!(assets.len(), 1);
        assert_eq!(assets[0].evidence_grade, EvidenceGrade::B);
        assert_eq!(assets[0].surfaces, BTreeSet::from([Surface::Source, Surface::Binary]));
        assert_eq!(assets[0].parameters.get("language").map(String::as_str), Some("c"));
        assert_eq!(assets[0].parameters.get("binaryFormat").map(String::as_str), Some("ELF"));
    }

    #[test]
    fn report_paths_do_not_leak_root() {
        let root = Path::new("/secret/project");
        let path = Path::new("/secret/project/src/main.rs");
        assert_eq!(report_path(root, path), "src/main.rs");
    }
}
