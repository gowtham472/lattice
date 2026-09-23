//! Transparent, offline data classification for graph enrichment.

use lattice_core::CryptoAsset;
use serde::{Deserialize, Serialize};
use thiserror::Error;

const EMBEDDED_POLICY: &str = include_str!("../../../knowledge/policy.yaml");

#[derive(Debug, Error)]
pub enum ClassifierError {
    #[error("embedded classification policy is invalid: {0}")]
    InvalidPolicy(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DataClassification {
    Financial,
    Health,
    Identity,
    Credential,
    Public,
    Sensitive,
}

impl DataClassification {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Financial => "financial",
            Self::Health => "health",
            Self::Identity => "identity",
            Self::Credential => "credential",
            Self::Public => "public",
            Self::Sensitive => "sensitive",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BusinessCriticality {
    Low,
    Medium,
    High,
    Critical,
}

impl BusinessCriticality {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DataClassificationResult {
    pub data_asset_id: String,
    pub classification: DataClassification,
    pub secrecy_lifetime_years: f64,
    pub business_criticality: BusinessCriticality,
    pub rule_id: String,
    pub confidence: f64,
    pub explanation: String,
}

#[derive(Debug, Deserialize)]
struct Policy {
    version: String,
    defaults: Defaults,
    secrecy_lifetimes: SecrecyLifetimes,
}

#[derive(Debug, Deserialize)]
struct Defaults {
    data_secrecy_lifetime_years: f64,
    business_criticality: String,
}

#[derive(Debug, Deserialize)]
struct SecrecyLifetimes {
    payment_card: f64,
    health: f64,
    identity: f64,
    credential: f64,
    session: f64,
}

#[derive(Debug)]
pub struct DataClassifier {
    policy: Policy,
}

impl DataClassifier {
    pub fn from_embedded_policy() -> Result<Self, ClassifierError> {
        let policy = serde_yaml::from_str(EMBEDDED_POLICY)
            .map_err(|error| ClassifierError::InvalidPolicy(error.to_string()))?;
        Ok(Self { policy })
    }

    /// Classifies only metadata already present in findings. Source contents are not retained or
    /// copied into this layer. Every result identifies the rule and explanation used.
    pub fn classify(
        &self,
        asset: &CryptoAsset,
        fallback_lifetime_years: Option<f64>,
    ) -> DataClassificationResult {
        let haystack = classification_haystack(asset);
        let matched = if contains_any(
            &haystack,
            &["payment", "card", "pan", "upi", "iban", "account", "transaction"],
        ) {
            (
                DataClassification::Financial,
                self.policy.secrecy_lifetimes.payment_card,
                BusinessCriticality::Critical,
                "data.financial",
                0.85,
                "Path or API metadata indicates payment or financial data.",
            )
        } else if contains_any(&haystack, &["health", "patient", "medical", "diagnosis", "clinical"]) {
            (
                DataClassification::Health,
                self.policy.secrecy_lifetimes.health,
                BusinessCriticality::Critical,
                "data.health",
                0.85,
                "Path or API metadata indicates health data.",
            )
        } else if contains_any(&haystack, &["aadhaar", "passport", "identity", "biometric", "kyc"]) {
            (
                DataClassification::Identity,
                self.policy.secrecy_lifetimes.identity,
                BusinessCriticality::Critical,
                "data.identity",
                0.85,
                "Path or API metadata indicates long-lived identity data.",
            )
        } else if contains_any(
            &haystack,
            &["password", "credential", "secret", "auth", "login", "private_key"],
        ) {
            (
                DataClassification::Credential,
                self.policy.secrecy_lifetimes.credential,
                BusinessCriticality::High,
                "data.credential",
                0.8,
                "Path or API metadata indicates authentication or credential data.",
            )
        } else if contains_any(&haystack, &["public", "example", "fixture", "testdata"]) {
            (
                DataClassification::Public,
                self.policy.secrecy_lifetimes.session,
                BusinessCriticality::Low,
                "data.public",
                0.65,
                "Path metadata indicates public or non-production fixture data.",
            )
        } else {
            (
                DataClassification::Sensitive,
                fallback_lifetime_years.unwrap_or(self.policy.defaults.data_secrecy_lifetime_years),
                parse_criticality(&self.policy.defaults.business_criticality),
                "data.default-sensitive",
                0.25,
                "No specific data class matched; conservative sensitive-data policy applied.",
            )
        };

        let location_class = asset
            .locations
            .first()
            .map_or("unknown", |location| location.path.as_str());
        let identity = format!("{}|{}|{}", asset.id, matched.0.as_str(), location_class);
        let digest = blake3::hash(identity.as_bytes()).to_hex();

        DataClassificationResult {
            data_asset_id: format!("data/{}/{}", matched.0.as_str(), &digest[..16]),
            classification: matched.0,
            secrecy_lifetime_years: matched.1,
            business_criticality: matched.2,
            rule_id: format!("{}@{}", matched.3, self.policy.version),
            confidence: matched.4,
            explanation: matched.5.into(),
        }
    }
}

fn classification_haystack(asset: &CryptoAsset) -> String {
    let mut terms = asset
        .locations
        .iter()
        .map(|location| location.path.as_str())
        .chain(asset.evidence.iter().map(|evidence| evidence.matched_token.as_str()))
        .collect::<Vec<_>>();
    terms.sort_unstable();
    terms.join(" ").to_ascii_lowercase()
}

fn contains_any(haystack: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| haystack.contains(needle))
}

fn parse_criticality(value: &str) -> BusinessCriticality {
    match value.to_ascii_lowercase().as_str() {
        "low" => BusinessCriticality::Low,
        "high" => BusinessCriticality::High,
        "critical" => BusinessCriticality::Critical,
        _ => BusinessCriticality::Medium,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lattice_core::{Algorithm, Evidence, EvidenceGrade, EvidenceKind, Liveness, Location, Surface};
    use std::collections::{BTreeMap, BTreeSet};

    fn asset(path: &str) -> CryptoAsset {
        CryptoAsset {
            id: "crypto/rsa/test".into(),
            algorithm: Algorithm {
                family: "RSA".into(),
                primitive: "public-key".into(),
                key_size_bits: Some(2048),
                mode: None,
                curve: None,
            },
            parameters: BTreeMap::new(),
            locations: vec![Location {
                path: path.into(),
                line: Some(1),
                column: Some(1),
                byte_offset: Some(0),
            }],
            surfaces: BTreeSet::from([Surface::Source]),
            evidence: vec![Evidence {
                collector: "source".into(),
                rule_id: "rsa".into(),
                rule_version: "1".into(),
                kind: EvidenceKind::Ast,
                matched_token: "RSA_new".into(),
            }],
            liveness: Liveness::Capable,
            evidence_grade: EvidenceGrade::C,
        }
    }

    #[test]
    fn financial_paths_receive_long_lived_critical_policy() {
        let classifier = DataClassifier::from_embedded_policy().unwrap();
        let result = classifier.classify(&asset("payments/card_vault.py"), None);
        assert_eq!(result.classification, DataClassification::Financial);
        assert_eq!(result.secrecy_lifetime_years, 10.0);
        assert_eq!(result.business_criticality, BusinessCriticality::Critical);
        assert!(result.rule_id.starts_with("data.financial@"));
    }

    #[test]
    fn fallback_is_explicit_and_low_confidence() {
        let classifier = DataClassifier::from_embedded_policy().unwrap();
        let result = classifier.classify(&asset("src/crypto.c"), Some(7.0));
        assert_eq!(result.classification, DataClassification::Sensitive);
        assert_eq!(result.secrecy_lifetime_years, 7.0);
        assert!(result.confidence < 0.5);
    }
}
