//! Risk policy: every weight, default and data class the scoring uses, loaded from
//! `knowledge/policy.toml` (embedded, versioned, overridable by the operator).

use serde::{Deserialize, Serialize};
use std::sync::OnceLock;

const EMBEDDED_POLICY: &str = include_str!("../../../knowledge/policy.toml");

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Criticality {
    Low,
    Medium,
    High,
    Critical,
}

impl Criticality {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QDay {
    pub earliest_year: u16,
    pub latest_year: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ExposureWeights {
    pub http_route: f64,
    pub listener: f64,
    pub library_export: f64,
    pub main: f64,
    pub unreached: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LivenessWeights {
    pub confirmed: f64,
    pub configured: f64,
    pub capable: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HndlPolicy {
    pub lifetime_cap_years: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgilityWeights {
    pub provider_interface: u8,
    pub config_driven: u8,
    pub negotiation: u8,
    pub centralized: u8,
    pub dependency_pqc_ready: u8,
    pub base_years: f64,
    pub years_per_point: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Defaults {
    pub secrecy_lifetime_years: f64,
    pub criticality: Criticality,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataClass {
    pub id: String,
    pub lifetime_years: f64,
    pub criticality: Criticality,
    pub terms: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    pub version: String,
    pub q_day: QDay,
    pub exposure: ExposureWeights,
    pub liveness_weight: LivenessWeights,
    pub hndl: HndlPolicy,
    pub agility: AgilityWeights,
    pub defaults: Defaults,
    pub data_class: Vec<DataClass>,
}

#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    #[error("policy is not valid TOML: {0}")]
    Parse(String),
    #[error("policy is inconsistent: {0}")]
    Inconsistent(String),
}

impl Policy {
    pub fn embedded() -> &'static Policy {
        static POLICY: OnceLock<Policy> = OnceLock::new();
        POLICY.get_or_init(|| {
            Policy::from_toml(EMBEDDED_POLICY)
                .unwrap_or_else(|error| panic!("embedded policy is invalid: {error}"))
        })
    }

    pub fn from_toml(source: &str) -> Result<Self, PolicyError> {
        let policy: Policy =
            toml::from_str(source).map_err(|error| PolicyError::Parse(error.to_string()))?;
        policy.validate()?;
        Ok(policy)
    }

    fn validate(&self) -> Result<(), PolicyError> {
        let a = &self.agility;
        let total = u32::from(a.provider_interface)
            + u32::from(a.config_driven)
            + u32::from(a.negotiation)
            + u32::from(a.centralized)
            + u32::from(a.dependency_pqc_ready);
        if total != 100 {
            return Err(PolicyError::Inconsistent(format!(
                "agility weights sum to {total}, not 100"
            )));
        }
        if self.q_day.latest_year < self.q_day.earliest_year {
            return Err(PolicyError::Inconsistent(
                "q_day.latest_year is before earliest_year".into(),
            ));
        }
        for weight in [
            self.exposure.http_route,
            self.exposure.listener,
            self.exposure.library_export,
            self.exposure.main,
            self.exposure.unreached,
            self.liveness_weight.confirmed,
            self.liveness_weight.configured,
            self.liveness_weight.capable,
        ] {
            if !(0.0..=1.0).contains(&weight) {
                return Err(PolicyError::Inconsistent(format!(
                    "weight {weight} is outside 0..=1"
                )));
            }
        }
        if self.hndl.lifetime_cap_years <= 0.0 {
            return Err(PolicyError::Inconsistent(
                "hndl.lifetime_cap_years must be positive".into(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_policy_is_valid() {
        let policy = Policy::embedded();
        assert!(
            policy
                .data_class
                .iter()
                .any(|class| class.id == "financial")
        );
        assert!(policy.q_day.earliest_year <= policy.q_day.latest_year);
    }

    #[test]
    fn agility_weights_must_total_one_hundred() {
        let broken = EMBEDDED_POLICY.replace("provider_interface = 40", "provider_interface = 41");
        assert!(Policy::from_toml(&broken).is_err());
    }
}
