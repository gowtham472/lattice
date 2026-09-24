//! Risk policy: every weight, default and data class the scoring uses, loaded from
//! `knowledge/policy.toml` (embedded, versioned, overridable by the operator).

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
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

/// Person-week weights for migration effort estimates.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EffortPolicy {
    /// Base person-weeks by recommended action.
    pub action: BTreeMap<String, f64>,
    /// Multiplier by surface (`source`, `binary`, ...); the largest present applies.
    pub surface: BTreeMap<String, f64>,
    pub agility_penalty: f64,
    pub spread: f64,
    pub criticality: BTreeMap<String, f64>,
    /// Multiplier for keys held in hardware or a key service, by custody kind.
    #[serde(default = "default_custody")]
    pub custody: BTreeMap<String, f64>,
}

fn default_custody() -> BTreeMap<String, f64> {
    [
        ("pkcs11-token", 1.5),
        ("tpm", 1.5),
        ("cloud-hsm", 1.2),
        ("cloud-kms", 0.8),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_owned(), v))
    .collect()
}

impl Default for EffortPolicy {
    fn default() -> Self {
        let map =
            |pairs: &[(&str, f64)]| pairs.iter().map(|(k, v)| ((*k).to_owned(), *v)).collect();
        Self {
            action: map(&[
                ("rotate", 0.5),
                ("enable", 0.5),
                ("remove", 0.5),
                ("review", 0.5),
                ("upgrade", 1.0),
                ("replace", 2.0),
            ]),
            surface: map(&[
                ("source", 1.5),
                ("binary", 2.0),
                ("container", 1.2),
                ("certificate", 1.0),
                ("config", 0.6),
                ("cloud", 0.8),
            ]),
            agility_penalty: 2.0,
            spread: 0.5,
            criticality: map(&[
                ("low", 1.0),
                ("medium", 1.0),
                ("high", 1.25),
                ("critical", 1.5),
            ]),
            custody: default_custody(),
        }
    }
}

/// The deadline schedule the roadmap is measured against.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Timeline {
    pub name: String,
    pub reference: String,
    /// Year by which roadmap wave `i + 1` must be complete. Later waves have no deadline.
    pub wave_due: Vec<u16>,
    pub working_weeks_per_year: f64,
}

impl Default for Timeline {
    fn default() -> Self {
        Self {
            name: "India DST critical-infrastructure migration, 2027–2029".into(),
            reference:
                "DST Task Force, Implementation of a Quantum Safe Ecosystem in India (Feb 2026)"
                    .into(),
            wave_due: vec![2027, 2028, 2029],
            working_weeks_per_year: 46.0,
        }
    }
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
    /// Absent in policies written before effort estimates existed; the defaults apply.
    #[serde(default)]
    pub effort: EffortPolicy,
    #[serde(default)]
    pub timeline: Timeline,
    pub data_class: Vec<DataClass>,
}

#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    #[error("policy is not valid TOML: {0}")]
    Parse(String),
    #[error("policy is inconsistent: {0}")]
    Inconsistent(String),
}

/// The default policy: a verified knowledge bundle's, activated at startup, or the compiled-in
/// one. A `--policy` file still overrides it per run.
static ACTIVE: OnceLock<Policy> = OnceLock::new();

impl Policy {
    /// The active default policy.
    pub fn active() -> &'static Policy {
        ACTIVE.get_or_init(Policy::compiled)
    }

    /// The policy compiled into this binary.
    pub fn compiled() -> Policy {
        Policy::from_toml(EMBEDDED_POLICY)
            .unwrap_or_else(|error| panic!("embedded policy is invalid: {error}"))
    }

    /// Makes `policy` the default. Only possible before it is first used.
    pub fn activate(policy: Policy) -> Result<(), PolicyError> {
        ACTIVE.set(policy).map_err(|_| {
            PolicyError::Inconsistent("the policy was already in use before activation".into())
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
        let e = &self.effort;
        let factors = e
            .action
            .values()
            .chain(e.surface.values())
            .chain(e.criticality.values())
            .chain(e.custody.values())
            .chain([&e.agility_penalty, &e.spread]);
        for factor in factors {
            if !factor.is_finite() || *factor < 0.0 || *factor > 1000.0 {
                return Err(PolicyError::Inconsistent(format!(
                    "effort factor {factor} is outside 0..=1000"
                )));
            }
        }
        let t = &self.timeline;
        if !(1.0..=52.0).contains(&t.working_weeks_per_year) {
            return Err(PolicyError::Inconsistent(
                "timeline.working_weeks_per_year must be between 1 and 52".into(),
            ));
        }
        if t.wave_due.windows(2).any(|w| w[1] < w[0]) {
            return Err(PolicyError::Inconsistent(
                "timeline.wave_due must not decrease from one wave to the next".into(),
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
        let policy = Policy::active();
        assert!(
            policy
                .data_class
                .iter()
                .any(|class| class.id == "financial")
        );
        assert!(policy.q_day.earliest_year <= policy.q_day.latest_year);
    }

    #[test]
    fn effort_and_timeline_default_when_absent_and_are_checked_when_present() {
        let start = EMBEDDED_POLICY.find("[effort]").unwrap();
        let end = EMBEDDED_POLICY.find("# Data classes.").unwrap();
        let older = format!("{}{}", &EMBEDDED_POLICY[..start], &EMBEDDED_POLICY[end..]);
        let policy = Policy::from_toml(&older).expect("a policy without the sections still loads");
        assert_eq!(policy.timeline.wave_due, vec![2027, 2028, 2029]);
        assert_eq!(policy.effort.action["replace"], 2.0);

        let embedded = Policy::active();
        assert_eq!(embedded.effort.surface, EffortPolicy::default().surface);
        assert_eq!(embedded.timeline.wave_due, Timeline::default().wave_due);

        let reversed = EMBEDDED_POLICY.replace("[2027, 2028, 2029]", "[2029, 2028]");
        assert!(Policy::from_toml(&reversed).is_err());
        let negative = EMBEDDED_POLICY.replace("spread = 0.5", "spread = -1.0");
        assert!(Policy::from_toml(&negative).is_err());
    }

    #[test]
    fn agility_weights_must_total_one_hundred() {
        let broken = EMBEDDED_POLICY.replace("provider_interface = 40", "provider_interface = 41");
        assert!(Policy::from_toml(&broken).is_err());
    }
}
