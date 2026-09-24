//! Deterministic, explainable quantum and classical risk for each cryptographic asset.
//!
//! Every number comes with the terms that produced it:
//! * **Quantum Breakability** (0–1): how completely a quantum adversary defeats the asset.
//! * **Classical status**: whether it is already weak today, independent of Q-day.
//! * **Threat**: *harvest* (confidentiality: record now, decrypt later), *forge* (authenticity:
//!   forge signatures after Q-day while they are still trusted) or *integrity* (hashes, MACs).
//! * **Exposure index** (0–100): HNDL for harvest assets, TNFL (trust-now-forge-later) for forge
//!   assets: `100 · exposure · min(X / cap, 1) · QB · liveness`.
//! * **Crypto-Agility Score** (0–100): measured from how the code actually uses the algorithm.
//! * **Mosca's inequality**: X (secrecy or trust lifetime) + Y (migration time from agility)
//!   against Z (years to Q-day), for both ends of the policy's Q-day range.
//! * **Priority** (0–100) and tier, with every contributing reason listed.
//!
//! The migration advisor (`advisor`) turns assessments into recommendations and a roadmap.

pub mod advisor;

use lattice_core::policy::{Criticality, Policy};
use lattice_core::{
    AlgorithmRef, AlgorithmSource, ApiStyle, ClassicalStatus, CryptoAsset, Finding, Liveness,
    Primitive, ProtocolKind, QuantumClass, Registry, Surface,
};
use lattice_graph::AssetContext;
use serde::Serialize;
use std::collections::BTreeSet;

/// Quantum breakability at or above which a cryptographically relevant quantum computer is taken
/// to break the asset: Shor-broken (1.0) or Grover leaving too little margin (0.5). Below it
/// (SHA-256, AES-256) quantum search only erodes a margin that remains adequate, so Mosca's
/// inequality does not apply and nothing counts as quantum-vulnerable.
pub const QUANTUM_VULNERABLE: f64 = 0.5;

pub fn is_quantum_vulnerable(quantum_breakability: f64) -> bool {
    quantum_breakability >= QUANTUM_VULNERABLE
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Threat {
    /// Confidentiality: traffic or data recorded today is decrypted after Q-day.
    Harvest,
    /// Authenticity: signatures forged after Q-day while they are still trusted.
    Forge,
    /// Hashes, MACs, KDFs: quantum search weakens them; broken ones are broken today.
    Integrity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Tier {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Tier {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        [
            Self::Info,
            Self::Low,
            Self::Medium,
            Self::High,
            Self::Critical,
        ]
        .into_iter()
        .find(|tier| tier.as_str().eq_ignore_ascii_case(value.trim()))
    }

    fn from_priority(priority: u8) -> Self {
        match priority {
            80.. => Self::Critical,
            60.. => Self::High,
            35.. => Self::Medium,
            10.. => Self::Low,
            _ => Self::Info,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Term {
    pub name: String,
    pub value: f64,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AgilityFactor {
    pub name: String,
    pub points: u8,
    pub max: u8,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Agility {
    pub score: u8,
    pub factors: Vec<AgilityFactor>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Mosca {
    pub applicable: bool,
    /// X: how long the protected data must stay secret (or the signature stay trusted).
    pub x_years: f64,
    pub x_reason: String,
    /// Y: estimated migration time, from the crypto-agility score.
    pub y_years: f64,
    /// Z at the pessimistic and optimistic ends of the policy's Q-day range.
    pub z_earliest_years: f64,
    pub z_latest_years: f64,
    /// X + Y > Z(earliest): urgent if a quantum computer arrives as early as policy fears.
    pub urgent: bool,
    /// X + Y > Z(latest): urgent even under the optimistic Q-day.
    pub urgent_even_if_late: bool,
    /// (X + Y) − Z(earliest), in years; positive means already late.
    pub urgency_years: f64,
    pub verdict: String,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Assessment {
    pub quantum_breakability: f64,
    pub quantum_reason: String,
    pub classical_status: ClassicalStatus,
    pub classical_reasons: Vec<String>,
    pub broken_now: bool,
    pub threat: Threat,
    /// `hndl`, `tnfl` or `integrity`.
    pub index_kind: String,
    pub exposure_index: f64,
    pub index_terms: Vec<Term>,
    pub agility: Agility,
    pub mosca: Mosca,
    pub priority: u8,
    pub tier: Tier,
    pub priority_reasons: Vec<String>,
}

#[derive(Debug, Clone, Copy)]
pub struct Assessor<'p> {
    pub policy: &'p Policy,
    /// Fixed so results are reproducible; never read from the clock.
    pub assessment_year: u16,
}

impl Assessor<'_> {
    pub fn assess(&self, asset: &CryptoAsset, context: &AssetContext) -> Assessment {
        let policy = self.policy;
        let (quantum_breakability, quantum_reason) = quantum_breakability(asset);
        let (classical_status, classical_reasons) = self.classical(asset);
        let broken_now = classical_status == ClassicalStatus::Broken;
        let threat = threat_of(asset);
        let agility = agility(asset, context, policy);
        let mosca = self.mosca(asset, context, &agility, quantum_breakability);

        let liveness_weight = match asset.liveness {
            Liveness::Confirmed => policy.liveness_weight.confirmed,
            Liveness::Configured => policy.liveness_weight.configured,
            Liveness::Capable => policy.liveness_weight.capable,
        };
        let lifetime_factor = (mosca.x_years / policy.hndl.lifetime_cap_years).clamp(0.0, 1.0);
        let exposure_index = round2(
            100.0 * context.exposure * lifetime_factor * quantum_breakability * liveness_weight,
        );
        let index_kind = match threat {
            Threat::Harvest => "hndl",
            Threat::Forge => "tnfl",
            Threat::Integrity => "integrity",
        };
        let index_terms = vec![
            Term {
                name: "exposure".into(),
                value: context.exposure,
                reason: context.exposure_reason.clone(),
            },
            Term {
                name: "lifetime".into(),
                value: round2(lifetime_factor),
                reason: format!(
                    "{} of a {}-year cap: {}",
                    mosca.x_years, policy.hndl.lifetime_cap_years, mosca.x_reason
                ),
            },
            Term {
                name: "quantumBreakability".into(),
                value: quantum_breakability,
                reason: quantum_reason.clone(),
            },
            Term {
                name: "liveness".into(),
                value: liveness_weight,
                reason: asset.liveness_reason.clone(),
            },
        ];

        let (priority, priority_reasons) = priority(
            exposure_index,
            index_kind,
            broken_now,
            classical_status,
            &classical_reasons,
            &mosca,
            context,
            quantum_breakability,
        );
        Assessment {
            quantum_breakability,
            quantum_reason,
            classical_status,
            classical_reasons,
            broken_now,
            threat,
            index_kind: index_kind.into(),
            exposure_index,
            index_terms,
            agility,
            mosca,
            priority,
            tier: Tier::from_priority(priority),
            priority_reasons,
        }
    }

    fn classical(&self, asset: &CryptoAsset) -> (ClassicalStatus, Vec<String>) {
        let registry = Registry::active();
        let strength = |algorithm: &AlgorithmRef| {
            registry
                .strength(algorithm)
                .map_or((ClassicalStatus::Acceptable, Vec::new()), |s| {
                    (s.classical_status, s.reasons)
                })
        };
        match &asset.finding {
            Finding::Algorithm(finding) => strength(&finding.algorithm),
            Finding::Certificate(certificate) => {
                let (key_status, mut reasons) = strength(&certificate.public_key);
                let (signature_status, signature_reasons) = strength(&certificate.signature);
                reasons.extend(signature_reasons);
                let mut status = key_status.max(signature_status);
                if let Some(year) = year_of(&certificate.not_after)
                    && year < i32::from(self.assessment_year)
                {
                    status = status.max(ClassicalStatus::Disallowed);
                    reasons.push(format!("certificate expired {}", certificate.not_after));
                }
                if let (Some(from), Some(to)) = (
                    year_of(&certificate.not_before),
                    year_of(&certificate.not_after),
                ) && to - from > 2
                    && !certificate.is_ca
                {
                    status = status.max(ClassicalStatus::Legacy);
                    reasons.push(format!(
                        "leaf certificate valid for {} years; public CAs cap leaf validity at 398 days",
                        to - from
                    ));
                }
                (status, reasons)
            }
            Finding::Protocol(protocol) => {
                let mut reasons = Vec::new();
                let status = match protocol.version.as_deref() {
                    Some(version) if version.starts_with("ssl") => {
                        reasons.push(format!(
                            "SSL {} is broken (POODLE, DROWN) and prohibited by RFC 7568",
                            version.trim_start_matches("ssl")
                        ));
                        ClassicalStatus::Broken
                    }
                    Some("1.0" | "1.1") if protocol.protocol != ProtocolKind::Ssh => {
                        reasons.push(format!(
                            "TLS {} is deprecated by RFC 8996",
                            protocol.version.as_deref().unwrap_or("")
                        ));
                        ClassicalStatus::Disallowed
                    }
                    _ => ClassicalStatus::Acceptable,
                };
                let mut status = status;
                for suite in &protocol.cipher_suites {
                    if let Some(parsed) = lattice_core::names::parse_cipher_suite(suite)
                        && !parsed.weaknesses.is_empty()
                    {
                        status = status.max(ClassicalStatus::Broken);
                        reasons.extend(parsed.weaknesses.iter().map(|w| format!("{suite}: {w}")));
                    }
                }
                (status, reasons)
            }
            Finding::RelatedCryptoMaterial(material) => {
                let (mut status, mut reasons) = material
                    .algorithm
                    .as_ref()
                    .map_or((ClassicalStatus::Acceptable, Vec::new()), strength);
                if material.material_type == lattice_core::MaterialType::PrivateKey
                    && !material.encrypted
                    && material.custody.is_none()
                {
                    status = status.max(ClassicalStatus::Disallowed);
                    reasons.push(
                        "unencrypted private key stored at rest in a scanned artefact".into(),
                    );
                }
                (status, reasons)
            }
        }
    }

    fn mosca(
        &self,
        asset: &CryptoAsset,
        context: &AssetContext,
        agility: &Agility,
        quantum_breakability: f64,
    ) -> Mosca {
        let policy = self.policy;
        let (x_years, x_reason) = match &asset.finding {
            Finding::Certificate(certificate) => {
                let remaining = year_of(&certificate.not_after).map_or(0.0, |year| {
                    (f64::from(year) - f64::from(self.assessment_year)).max(0.0)
                });
                (
                    remaining,
                    format!(
                        "the certificate stays trusted until {}",
                        certificate.not_after
                    ),
                )
            }
            _ => (
                context.data.secrecy_lifetime_years,
                context.data.explanation.clone(),
            ),
        };
        let y_years = round2(
            policy.agility.base_years
                + f64::from(100 - agility.score) * policy.agility.years_per_point,
        );
        let z_earliest_years = f64::from(
            policy
                .q_day
                .earliest_year
                .saturating_sub(self.assessment_year),
        );
        let z_latest_years = f64::from(
            policy
                .q_day
                .latest_year
                .saturating_sub(self.assessment_year),
        );
        let applicable = is_quantum_vulnerable(quantum_breakability);
        let total = x_years + y_years;
        let urgent = applicable && total > z_earliest_years;
        let urgent_even_if_late = applicable && total > z_latest_years;
        let urgency_years = round2(total - z_earliest_years);
        let verdict = if !applicable {
            "quantum-safe at its current parameters: the inequality does not apply".to_owned()
        } else if urgent_even_if_late {
            format!(
                "X + Y = {total:.2} years exceeds even the latest Q-day ({z_latest_years} years away): already late"
            )
        } else if urgent {
            format!(
                "X + Y = {total:.2} years exceeds the earliest Q-day ({z_earliest_years} years away): migrate now"
            )
        } else {
            format!(
                "X + Y = {total:.2} years fits before the earliest Q-day ({z_earliest_years} years away): plan, do not panic"
            )
        };
        Mosca {
            applicable,
            x_years,
            x_reason,
            y_years,
            z_earliest_years,
            z_latest_years,
            urgent,
            urgent_even_if_late,
            urgency_years,
            verdict,
        }
    }
}

/// Quantum breakability with its reason (architecture.md §6.1).
pub fn quantum_breakability(asset: &CryptoAsset) -> (f64, String) {
    let registry = Registry::active();
    let for_algorithm = |algorithm: &AlgorithmRef| -> (f64, String) {
        let Some(spec) = registry.get(&algorithm.id) else {
            return (
                0.5,
                format!(
                    "`{}` is not in the knowledge base; assumed partially exposed",
                    algorithm.id
                ),
            );
        };
        let strength = registry.strength(algorithm);
        if strength
            .as_ref()
            .is_some_and(|s| s.classical_status == ClassicalStatus::Broken)
            && spec.quantum != QuantumClass::PostQuantum
        {
            return (1.0, format!("{} is already broken classically", spec.name));
        }
        match spec.quantum {
            QuantumClass::Shor => (
                1.0,
                format!(
                    "Shor's algorithm breaks {} outright (factoring / discrete logarithm)",
                    spec.name
                ),
            ),
            QuantumClass::PostQuantum => (
                0.0,
                format!(
                    "{} is a post-quantum standard ({})",
                    spec.name,
                    spec.standard.as_deref().unwrap_or("NIST PQC")
                ),
            ),
            QuantumClass::Grover => {
                let bits = strength.as_ref().and_then(|s| s.classical_bits);
                match spec.primitive {
                    // an XOF's output is as long as asked for: its security strength is the measure
                    Primitive::Hash | Primitive::Xof => match spec.output_bits.or(spec.strength) {
                        Some(384..) => (
                            0.1,
                            format!(
                                "{}: Grover leaves a comfortable margin at {} output bits",
                                spec.name,
                                spec.output_bits.unwrap_or(0)
                            ),
                        ),
                        Some(256..) => (
                            0.2,
                            format!(
                                "{}: quantum search halves preimage security to 128 bits; collision margin stays adequate",
                                spec.name
                            ),
                        ),
                        _ => (
                            0.5,
                            format!(
                                "{}: short output leaves little margin under quantum search",
                                spec.name
                            ),
                        ),
                    },
                    _ => match bits {
                        Some(bits) if bits >= 256 => (
                            0.1,
                            format!(
                                "{}: Grover leaves {}-bit effective security",
                                spec.name,
                                bits / 2
                            ),
                        ),
                        Some(bits) => (
                            0.5,
                            format!(
                                "{}: Grover leaves only {}-bit effective security; use 256-bit keys",
                                spec.name,
                                bits / 2
                            ),
                        ),
                        None => (
                            0.5,
                            format!(
                                "{}: key size unknown, assumed below 256 bits (Grover halves it)",
                                spec.name
                            ),
                        ),
                    },
                }
            }
        }
    };
    match &asset.finding {
        Finding::Algorithm(finding) => for_algorithm(&finding.algorithm),
        Finding::Certificate(certificate) => {
            let (qb, reason) = for_algorithm(&certificate.public_key);
            (qb, format!("certificate key: {reason}"))
        }
        Finding::RelatedCryptoMaterial(material) => match &material.algorithm {
            Some(algorithm) => for_algorithm(algorithm),
            None => (
                0.5,
                "key container of unknown algorithm; assumed partially exposed".into(),
            ),
        },
        Finding::Protocol(protocol) => {
            let post_quantum_group = protocol
                .groups
                .iter()
                .chain(&protocol.cipher_suites)
                .filter_map(|name| {
                    lattice_core::names::resolve_group(name)
                        .or_else(|| lattice_core::names::resolve(name))
                })
                .any(|algorithm| {
                    registry
                        .get(&algorithm.id)
                        .is_some_and(|spec| spec.quantum == QuantumClass::PostQuantum)
                });
            if post_quantum_group {
                (
                    0.0,
                    format!(
                        "{} offers a post-quantum key exchange",
                        protocol.protocol.as_str().to_ascii_uppercase()
                    ),
                )
            } else {
                (
                    1.0,
                    format!(
                        "{} key exchange without a post-quantum group can be recorded today and decrypted after Q-day",
                        protocol.protocol.as_str().to_ascii_uppercase()
                    ),
                )
            }
        }
    }
}

fn threat_of(asset: &CryptoAsset) -> Threat {
    let registry = Registry::active();
    match &asset.finding {
        Finding::Certificate(_) => Threat::Forge,
        Finding::Protocol(_) => Threat::Harvest,
        Finding::RelatedCryptoMaterial(material) => material
            .algorithm
            .as_ref()
            .and_then(|a| registry.get(&a.id))
            .map_or(Threat::Harvest, |spec| {
                if spec.primitive == Primitive::Signature {
                    Threat::Forge
                } else {
                    Threat::Harvest
                }
            }),
        Finding::Algorithm(finding) => {
            let primitive = finding.primitive.or_else(|| {
                registry
                    .get(&finding.algorithm.id)
                    .map(|spec| spec.primitive)
            });
            match primitive {
                Some(Primitive::Signature) => Threat::Forge,
                Some(
                    Primitive::Hash
                    | Primitive::Xof
                    | Primitive::Mac
                    | Primitive::Kdf
                    | Primitive::Drbg,
                ) => Threat::Integrity,
                _ => Threat::Harvest,
            }
        }
    }
}

/// Crypto-Agility Score, measured from the asset's actual uses (architecture.md §6.5).
pub fn agility(asset: &CryptoAsset, context: &AssetContext, policy: &Policy) -> Agility {
    let weights = &policy.agility;
    let usages: Vec<_> = asset.usages().collect();
    let configured = asset
        .occurrences
        .iter()
        .any(|o| matches!(o.surface, Surface::Config | Surface::Cloud));
    let mut factors = Vec::new();

    // provider interface
    let provider = if !usages.is_empty() {
        let via_provider = usages
            .iter()
            .filter(|u| matches!(u.api_style, ApiStyle::Provider | ApiStyle::Protocol))
            .count();
        let share = via_provider as f64 / usages.len() as f64;
        let points = (f64::from(weights.provider_interface) * share).round() as u8;
        (
            points,
            format!(
                "{via_provider} of {} code uses go through a provider interface that selects the algorithm by name",
                usages.len()
            ),
        )
    } else if configured || matches!(asset.finding, Finding::Protocol(_)) {
        (
            weights.provider_interface,
            "selected in configuration, not hard-coded in a call".into(),
        )
    } else {
        (
            0,
            "no source-level use seen: compiled in or stored, not selectable".into(),
        )
    };
    factors.push(AgilityFactor {
        name: "providerInterface".into(),
        points: provider.0,
        max: weights.provider_interface,
        reason: provider.1,
    });

    // configuration-driven choice
    let sources: BTreeSet<AlgorithmSource> = usages.iter().map(|u| u.algorithm_source).collect();
    let config = if configured || sources.contains(&AlgorithmSource::Dynamic) {
        (weights.config_driven, "the algorithm comes from configuration or a runtime value: changing it needs no code change".to_owned())
    } else if sources.contains(&AlgorithmSource::Constant) {
        (
            weights.config_driven / 2,
            "the algorithm is a named constant: one edit changes every use".to_owned(),
        )
    } else {
        (0, "the algorithm is written at each call site".to_owned())
    };
    factors.push(AgilityFactor {
        name: "configDriven".into(),
        points: config.0,
        max: weights.config_driven,
        reason: config.1,
    });

    // negotiation
    let negotiated = matches!(asset.finding, Finding::Protocol(_))
        || usages.iter().any(|u| u.api_style == ApiStyle::Protocol)
        || asset.occurrences.iter().any(|o| {
            let rule = o.evidence.rule_id.as_str();
            rule.contains("cipher")
                || rule.contains("group")
                || rule.contains("ssl")
                || rule.contains("tls")
                || rule.contains("ssh")
        });
    factors.push(AgilityFactor {
        name: "negotiation".into(),
        points: if negotiated { weights.negotiation } else { 0 },
        max: weights.negotiation,
        reason: if negotiated {
            "chosen by protocol negotiation: peers can move to a new algorithm without a flag day"
                .into()
        } else {
            "not negotiated: both ends must change together".into()
        },
    });

    // centralisation
    let places: BTreeSet<&str> = asset
        .occurrences
        .iter()
        .map(|o| {
            o.usage
                .as_ref()
                .and_then(|u| u.function.as_deref())
                .unwrap_or(o.location.path.as_str())
        })
        .collect();
    let centralised = match places.len() {
        0 | 1 => weights.centralized,
        2 => weights.centralized * 2 / 3,
        3..=5 => weights.centralized / 3,
        _ => 0,
    };
    factors.push(AgilityFactor {
        name: "centralized".into(),
        points: centralised,
        max: weights.centralized,
        reason: format!(
            "used in {} place{}",
            places.len(),
            if places.len() == 1 { "" } else { "s" }
        ),
    });

    // dependency readiness
    let already_pqc = quantum_breakability(asset).0 == 0.0;
    let dependency = if already_pqc {
        (
            weights.dependency_pqc_ready,
            "already post-quantum".to_owned(),
        )
    } else if let Some(library) = &context.pqc_ready_library {
        (
            weights.dependency_pqc_ready,
            format!("the component already links a PQC-capable library: {library}"),
        )
    } else {
        (
            0,
            "no PQC-capable cryptographic library identified in this component".to_owned(),
        )
    };
    factors.push(AgilityFactor {
        name: "dependencyPqcReady".into(),
        points: dependency.0,
        max: weights.dependency_pqc_ready,
        reason: dependency.1,
    });

    let score = factors
        .iter()
        .map(|f| u32::from(f.points))
        .sum::<u32>()
        .min(100) as u8;
    Agility { score, factors }
}

#[allow(clippy::too_many_arguments)]
fn priority(
    exposure_index: f64,
    index_kind: &str,
    broken_now: bool,
    classical: ClassicalStatus,
    classical_reasons: &[String],
    mosca: &Mosca,
    context: &AssetContext,
    quantum_breakability: f64,
) -> (u8, Vec<String>) {
    let mut reasons = vec![format!(
        "{} exposure index {exposure_index:.1}",
        index_kind.to_ascii_uppercase()
    )];
    let mut score = exposure_index;
    if broken_now {
        score = score.max(90.0);
        reasons.push(format!(
            "broken today, independent of Q-day: {}",
            classical_reasons.first().map_or("", String::as_str)
        ));
    } else if classical == ClassicalStatus::Disallowed {
        score = score.max(70.0);
        reasons.push(format!(
            "disallowed today: {}",
            classical_reasons.first().map_or("", String::as_str)
        ));
    } else if classical == ClassicalStatus::Legacy {
        score = score.max(35.0);
        reasons.push(format!(
            "legacy: {}",
            classical_reasons.first().map_or("", String::as_str)
        ));
    }
    if mosca.urgent {
        score += 15.0;
        reasons.push(format!("Mosca: {}", mosca.verdict));
    }
    if mosca.urgent_even_if_late {
        score += 10.0;
    }
    if context.data.criticality == Criticality::Critical
        && is_quantum_vulnerable(quantum_breakability)
    {
        score += 5.0;
        reasons.push(format!("protects critical {} data", context.data.class));
    }
    if quantum_breakability == 0.0 && classical == ClassicalStatus::Acceptable {
        score = score.min(5.0);
        reasons.push("quantum-safe and classically sound: no action needed".into());
    }
    (score.clamp(0.0, 100.0).round() as u8, reasons)
}

/// Year from an RFC 3339 timestamp.
fn year_of(timestamp: &str) -> Option<i32> {
    timestamp.get(..4)?.parse().ok()
}

fn round2(value: f64) -> f64 {
    (value * 100.0).round() / 100.0
}

#[cfg(test)]
mod tests;
