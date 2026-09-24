//! Migration advice: what to replace each asset with, what it costs in bytes and person-weeks,
//! in what order, and whether the plan fits the regulatory timeline.
//!
//! Recommendations follow the asset's *role* (key exchange, signature, bulk encryption, hashing,
//! protocol policy, stored keys) rather than just its algorithm, because the right replacement
//! for RSA depends on whether it signs or transports keys. Size deltas are computed from the
//! parameter sets in the knowledge base (FIPS 203/204 sizes), not quoted from memory.

use crate::{Assessment, Tier};
use lattice_core::policy::{Criticality, Policy};
use lattice_core::{
    CryptoAsset, Finding, MaterialType, Primitive, ProtocolKind, QuantumClass, Registry, Surface,
};
use serde::Serialize;
use std::collections::BTreeSet;

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SizeDelta {
    pub before_bytes: u32,
    pub after_bytes: u32,
    /// What the bytes are counted over, e.g. `key share + ciphertext per handshake`.
    pub basis: String,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Recommendation {
    /// `replace`, `upgrade`, `enable`, `remove`, `rotate`, `retain`.
    pub action: String,
    pub target: String,
    pub rationale: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size_delta: Option<SizeDelta>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RoadmapItem {
    pub wave: u8,
    pub wave_name: String,
    pub asset_id: String,
    pub name: String,
    pub component: String,
    pub tier: Tier,
    pub priority: u8,
    pub agility: u8,
    pub migration_years: f64,
    pub action: String,
    pub target: String,
    pub effort_person_weeks: f64,
    /// Year the item's wave is due under the policy's timeline; absent for undated waves.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub due_year: Option<u16>,
}

/// Estimated person-weeks for one recommended change, with every factor that produced it.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Effort {
    pub person_weeks: f64,
    pub factors: Vec<EffortFactor>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EffortFactor {
    /// `action`, `surface`, `agility`, `spread`, `criticality`, and `custody` for keys held in
    /// hardware or a key service.
    pub name: String,
    /// Person-weeks for `action`, a multiplier for the rest.
    pub value: f64,
    pub reason: String,
}

/// One wave of the plan measured against the timeline.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WavePlan {
    pub wave: u8,
    pub name: String,
    pub items: usize,
    pub person_weeks: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub due_year: Option<u16>,
    /// Person-weeks of this wave and every earlier one: the work that must be done by `due_year`.
    pub cumulative_person_weeks: f64,
    /// Working weeks from the start of the assessment year to the end of `due_year`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub weeks_available: Option<f64>,
    /// Full-time engineers needed to finish the cumulative work in the weeks available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub engineers_needed: Option<f64>,
    /// The due year has already passed and work remains.
    pub overdue: bool,
}

/// The roadmap's cost and schedule against the policy's timeline.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MigrationPlan {
    pub timeline: String,
    pub reference: String,
    pub assessment_year: u16,
    pub total_person_weeks: f64,
    pub waves: Vec<WavePlan>,
    /// The team that meets every dated wave: the largest `engineers_needed`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub engineers_needed: Option<f64>,
    pub overdue: bool,
}

const WAVE_NAMES: [&str; 4] = [
    "Wave 1 · urgent quick wins",
    "Wave 2 · urgent re-engineering",
    "Wave 3 · planned migration",
    "Wave 4 · opportunistic hygiene",
];

/// Rounds to `places` decimals, so reports stay readable and stable.
fn round(value: f64, places: i32) -> f64 {
    let scale = 10f64.powi(places);
    (value * scale).round() / scale
}

/// Estimates the person-weeks of carrying out `recommendation` on `asset`: `None` when nothing
/// is to be done. Deterministic: every input is in the asset, its assessment and the policy.
pub fn estimate(
    asset: &CryptoAsset,
    assessment: &Assessment,
    recommendation: &Recommendation,
    criticality: Criticality,
    policy: &Policy,
) -> Option<Effort> {
    if recommendation.action == "retain" {
        return None;
    }
    let weights = &policy.effort;
    let base = weights
        .action
        .get(&recommendation.action)
        .copied()
        .unwrap_or(1.0);

    let surface = asset
        .surfaces
        .iter()
        .filter(|surface| **surface != Surface::Runtime)
        .filter_map(|surface| {
            weights
                .surface
                .get(surface.as_str())
                .map(|weight| (*weight, surface.as_str()))
        })
        .max_by(|a, b| a.0.total_cmp(&b.0).then_with(|| b.1.cmp(a.1)));
    let (surface_factor, surface_reason) = match surface {
        Some((weight, name)) => (weight, format!("changed in {name}")),
        None => (
            1.0,
            "seen only at runtime; changed where it is configured".into(),
        ),
    };

    let agility = assessment.agility.score.min(100);
    let agility_factor = 1.0 + f64::from(100 - agility) / 100.0 * weights.agility_penalty;

    let files: BTreeSet<&str> = asset
        .occurrences
        .iter()
        .filter(|occurrence| occurrence.surface != Surface::Runtime)
        .map(|occurrence| occurrence.location.path.as_str())
        .collect();
    let file_count = files.len().max(1);
    let spread_factor = 1.0 + weights.spread * (file_count as f64).ln();

    let criticality_factor = weights
        .criticality
        .get(criticality.as_str())
        .copied()
        .unwrap_or(1.0);

    let custody = match &asset.finding {
        Finding::RelatedCryptoMaterial(material) => material.custody.as_ref(),
        _ => None,
    };
    let custody_factor = custody.map(|custody| {
        (
            weights
                .custody
                .get(custody.kind.as_str())
                .copied()
                .unwrap_or(1.0),
            format!("held in a {}", custody.kind.mechanism()),
        )
    });

    let person_weeks = base
        * surface_factor
        * agility_factor
        * spread_factor
        * criticality_factor
        * custody_factor.as_ref().map_or(1.0, |(factor, _)| *factor);
    let factor = |name: &str, value: f64, reason: String| EffortFactor {
        name: name.into(),
        value: round(value, 2),
        reason,
    };
    Some(Effort {
        person_weeks: round(person_weeks, 1).max(0.1),
        factors: vec![
            factor(
                "action",
                base,
                format!("{} one asset", recommendation.action),
            ),
            factor("surface", surface_factor, surface_reason),
            factor(
                "agility",
                agility_factor,
                format!("crypto-agility {agility}/100"),
            ),
            factor(
                "spread",
                spread_factor,
                format!(
                    "{file_count} file{}",
                    if file_count == 1 { "" } else { "s" }
                ),
            ),
            factor(
                "criticality",
                criticality_factor,
                format!("protects {} data", criticality.as_str()),
            ),
        ]
        .into_iter()
        .chain(custody_factor.map(|(value, reason)| factor("custody", value, reason)))
        .collect(),
    })
}

/// Public key + ciphertext / key-share bytes of classical key establishment, for size deltas.
fn classical_key_exchange_bytes(id: &str, curve: Option<&str>, bits: Option<u32>) -> u32 {
    match id {
        "x25519" => 32 + 32,
        "x448" => 56 + 56,
        "ecdh" => match curve {
            Some("P-384") => 97 * 2,
            Some("P-521") => 133 * 2,
            _ => 65 * 2,
        },
        "dh" => bits.unwrap_or(2048) / 8 * 2,
        "rsa" => bits.unwrap_or(2048) / 8 * 2,
        _ => 64,
    }
}

/// Public key + signature bytes of classical signatures.
fn classical_signature_bytes(id: &str, curve: Option<&str>, bits: Option<u32>) -> u32 {
    match id {
        "ed25519" => 32 + 64,
        "ed448" => 57 + 114,
        "ecdsa" => match curve {
            Some("P-384") => 97 + 104,
            Some("P-521") => 133 + 139,
            _ => 65 + 72,
        },
        "rsa" | "dsa" => bits.unwrap_or(2048) / 8 * 2,
        _ => 128,
    }
}

fn hybrid_kem_bytes() -> u32 {
    let registry = Registry::active();
    registry.get("x25519-mlkem768").map_or(2336, |spec| {
        spec.public_key_bytes.unwrap_or(1216) + spec.ciphertext_bytes.unwrap_or(1120)
    })
}

fn ml_dsa_bytes(set: &str) -> u32 {
    Registry::active()
        .get("ml-dsa")
        .and_then(|spec| spec.parameter_set(set))
        .map_or(5261, |set| {
            set.public_key_bytes.unwrap_or(0) + set.signature_bytes.unwrap_or(0)
        })
}

/// The recommendation for one assessed asset.
pub fn recommend(
    asset: &CryptoAsset,
    assessment: &Assessment,
    data_lifetime_years: f64,
) -> Recommendation {
    let registry = Registry::active();
    // Data that must stay secret for decades gets the strongest parameter set.
    let signature_set = if data_lifetime_years >= 25.0 {
        "87"
    } else {
        "65"
    };
    match &asset.finding {
        Finding::RelatedCryptoMaterial(material) if material.custody.is_some() => {
            let custody = material.custody.as_ref().expect("guarded");
            custody_recommendation(material, custody, assessment, signature_set)
        }
        Finding::RelatedCryptoMaterial(material) if material.material_type == MaterialType::PrivateKey && !material.encrypted => Recommendation {
            action: "rotate".into(),
            target: "a new key held in an HSM or cloud KMS".into(),
            rationale: "An unencrypted private key sits in a scanned artefact: treat it as disclosed, rotate it, and remove it from the repository and its history.".into(),
            size_delta: None,
        },
        Finding::Certificate(certificate) => {
            let classical = classical_signature_bytes(&certificate.public_key.id, certificate.public_key.params.curve.as_deref(), certificate.public_key.params.key_bits);
            Recommendation {
                action: "replace".into(),
                target: format!("ML-DSA-{signature_set} certificate (composite ML-DSA + ECDSA during transition)"),
                rationale: "Certificate signatures can be forged after Q-day for as long as the certificate is trusted; reissue with ML-DSA once the CA and relying parties support it, and shorten validity meanwhile.".into(),
                size_delta: Some(SizeDelta {
                    before_bytes: classical,
                    after_bytes: ml_dsa_bytes(signature_set),
                    basis: "public key + signature per certificate".into(),
                }),
            }
        }
        Finding::Protocol(protocol) => {
            let delta = Some(SizeDelta { before_bytes: 64, after_bytes: hybrid_kem_bytes(), basis: "X25519 → X25519MLKEM768 key shares per handshake".into() });
            match protocol.protocol {
                ProtocolKind::Ssh => Recommendation {
                    action: "enable".into(),
                    target: "mlkem768x25519-sha256 key exchange (OpenSSH 9.9+)".into(),
                    rationale: "Put the hybrid ML-KEM key exchange first in KexAlgorithms so recorded sessions stay confidential after Q-day.".into(),
                    size_delta: delta,
                },
                _ if matches!(protocol.version.as_deref(), Some(v) if v.starts_with("ssl") || v == "1.0" || v == "1.1") => Recommendation {
                    action: "upgrade".into(),
                    target: "TLS 1.3 with the X25519MLKEM768 group".into(),
                    rationale: "Remove deprecated protocol versions (RFC 8996) and move to TLS 1.3, which also carries the hybrid post-quantum group.".into(),
                    size_delta: delta,
                },
                _ if assessment.quantum_breakability == 0.0 => Recommendation {
                    action: "retain".into(),
                    target: "current configuration".into(),
                    rationale: "A post-quantum key-exchange group is already offered; keep it first in the preference list.".into(),
                    size_delta: None,
                },
                _ => Recommendation {
                    action: "enable".into(),
                    target: "X25519MLKEM768 group (OpenSSL 3.5+, BoringSSL, Go 1.24+)".into(),
                    rationale: "Add the hybrid group ahead of classical groups: traffic stays confidential after Q-day and classical security is never lower than today.".into(),
                    size_delta: delta,
                },
            }
        }
        Finding::Algorithm(_) | Finding::RelatedCryptoMaterial(_) => {
            let algorithm = match &asset.finding {
                Finding::Algorithm(finding) => Some(finding.algorithm.clone()),
                Finding::RelatedCryptoMaterial(material) => material.algorithm.clone(),
                _ => None,
            };
            let Some(algorithm) = algorithm else {
                return Recommendation {
                    action: "review".into(),
                    target: "identify the key type inside the container".into(),
                    rationale: "The container is password-protected; LATTICE does not open it.".into(),
                    size_delta: None,
                };
            };
            let Some(spec) = registry.get(&algorithm.id) else {
                return Recommendation { action: "review".into(), target: "manual review".into(), rationale: "Algorithm outside the knowledge base.".into(), size_delta: None };
            };
            let primitive = match &asset.finding {
                Finding::Algorithm(finding) => finding.primitive.unwrap_or(spec.primitive),
                _ => spec.primitive,
            };
            let params = &algorithm.params;
            if spec.quantum == QuantumClass::PostQuantum {
                let weak_set = matches!(params.parameter_set.as_deref(), Some("512" | "44"));
                return Recommendation {
                    action: "retain".into(),
                    target: if weak_set { format!("{} at NIST level 3 or higher", spec.name) } else { format!("{} (verify implementation)", spec.name) },
                    rationale: if weak_set {
                        "Already post-quantum; the level-1/2 parameter set is fine for short-lived data, level 3+ for long-lived secrets.".into()
                    } else {
                        "Already post-quantum; confirm the implementation is FIPS-validated and constant-time.".into()
                    },
                    size_delta: None,
                };
            }
            match primitive {
                Primitive::KeyAgree | Primitive::Kem | Primitive::Pke if spec.quantum == QuantumClass::Shor => Recommendation {
                    action: "replace".into(),
                    target: "hybrid X25519 + ML-KEM-768 (FIPS 203)".into(),
                    rationale: "Key establishment broken by Shor's algorithm is the harvest-now-decrypt-later target; a hybrid keeps classical security while adding ML-KEM.".into(),
                    size_delta: Some(SizeDelta {
                        before_bytes: classical_key_exchange_bytes(&spec.id, params.curve.as_deref(), params.key_bits),
                        after_bytes: hybrid_kem_bytes(),
                        basis: "key share + ciphertext per key establishment".into(),
                    }),
                },
                Primitive::Signature if spec.quantum == QuantumClass::Shor => Recommendation {
                    action: "replace".into(),
                    target: format!("ML-DSA-{signature_set} (FIPS 204), or SLH-DSA for long-term roots"),
                    rationale: "Signatures broken by Shor's algorithm can be forged after Q-day; ML-DSA is the general-purpose replacement, SLH-DSA the conservative one for roots of trust.".into(),
                    size_delta: Some(SizeDelta {
                        before_bytes: classical_signature_bytes(&spec.id, params.curve.as_deref(), params.key_bits),
                        after_bytes: ml_dsa_bytes(signature_set),
                        basis: "public key + signature".into(),
                    }),
                },
                Primitive::Hash | Primitive::Xof if assessment.broken_now => Recommendation {
                    action: "replace".into(),
                    target: "SHA-384 (or SHA3-384)".into(),
                    rationale: format!("{} has practical collisions today; the quantum question is secondary.", spec.name),
                    size_delta: None,
                },
                Primitive::Mac | Primitive::Kdf if params.digest.as_deref().is_some_and(|d| d == "sha-1" || d == "md5") => Recommendation {
                    action: "upgrade".into(),
                    target: if spec.id == "pbkdf2" { "Argon2id, or PBKDF2-HMAC-SHA-256 at ≥600,000 iterations".into() } else { format!("{}-SHA-256", spec.name) },
                    rationale: "The underlying digest is legacy; move to SHA-256 or stronger.".into(),
                    size_delta: None,
                },
                Primitive::BlockCipher | Primitive::StreamCipher | Primitive::Ae => {
                    let weak_mode = params.mode.as_deref() == Some("ecb");
                    let needs_change = weak_mode || assessment.broken_now || crate::is_quantum_vulnerable(assessment.quantum_breakability) || assessment.classical_status > lattice_core::ClassicalStatus::Acceptable;
                    if needs_change {
                        Recommendation {
                            action: "replace".into(),
                            target: "AES-256-GCM".into(),
                            rationale: if weak_mode {
                                "ECB encrypts identical blocks identically and leaks structure; use an authenticated mode with a 256-bit key.".into()
                            } else if assessment.broken_now || assessment.classical_status > lattice_core::ClassicalStatus::Acceptable {
                                format!("{} is weak today; AES-256-GCM is secure classically and keeps a 128-bit margin under Grover.", spec.name)
                            } else {
                                "A 256-bit key keeps a 128-bit margin under Grover's algorithm.".into()
                            },
                            size_delta: None,
                        }
                    } else {
                        Recommendation { action: "retain".into(), target: algorithm.to_string(), rationale: "Adequate classically and against quantum search.".into(), size_delta: None }
                    }
                }
                _ if assessment.quantum_breakability <= 0.2 && !assessment.broken_now => Recommendation {
                    action: "retain".into(),
                    target: algorithm.to_string(),
                    rationale: "Adequate classically and against quantum search.".into(),
                    size_delta: None,
                },
                _ => {
                    let target = spec.replacement.values().next().cloned().unwrap_or_else(|| "a NIST-approved replacement".into());
                    Recommendation {
                        action: "replace".into(),
                        target,
                        rationale: spec.note.clone().unwrap_or_else(|| format!("{} should be replaced.", spec.name)),
                        size_delta: None,
                    }
                }
            }
        }
    }
}

/// One assessed asset as the roadmap sees it: the asset, its assessment, the recommendation and
/// the effort of carrying it out.
pub type PlanInput<'a> = (
    &'a CryptoAsset,
    &'a Assessment,
    &'a Recommendation,
    Option<&'a Effort>,
);

/// Advice for a key held in hardware or a key service: the replacement has to be generated
/// where the key lives, so the device or service must support the post-quantum algorithms.
fn custody_recommendation(
    material: &lattice_core::MaterialFinding,
    custody: &lattice_core::Custody,
    assessment: &Assessment,
    signature_set: &str,
) -> Recommendation {
    use lattice_core::CustodyKind;
    let place = custody.kind.mechanism();
    let Some(algorithm) = &material.algorithm else {
        return Recommendation {
            action: "review".into(),
            target: format!(
                "the key's algorithm in the {place}, and the {place}'s post-quantum support"
            ),
            rationale: format!(
                "The key is referenced here but held in a {place}, so LATTICE cannot see its type. \
                 Inventory it on the device, and confirm the firmware or service supports ML-KEM \
                 and ML-DSA (FIPS 203/204) before its replacement is due."
            ),
            size_delta: None,
        };
    };
    if assessment.quantum_breakability <= 0.2 && !assessment.broken_now {
        return Recommendation {
            action: "retain".into(),
            target: format!("{algorithm} in the {place}"),
            rationale: "Held in hardware or a key service and adequate against quantum attack."
                .into(),
            size_delta: None,
        };
    }
    let signing = format!("ML-DSA-{signature_set} (FIPS 204)");
    let encrypting = "ML-KEM-768 (FIPS 203)";
    let replacement = match custody.usage {
        Some(lattice_core::KeyUsage::Sign) => signing,
        Some(lattice_core::KeyUsage::Encrypt) => encrypting.into(),
        None => match Registry::active()
            .get(&algorithm.id)
            .map(|spec| spec.primitive)
        {
            Some(Primitive::Signature) => signing,
            Some(Primitive::KeyAgree | Primitive::Kem) => encrypting.into(),
            // RSA signs or decrypts; nothing here says which
            _ => format!("{signing} signing or {encrypting} decryption"),
        },
    };
    let where_ = match custody.kind {
        CustodyKind::CloudKms | CustodyKind::CloudHsm => {
            "when the provider offers it as a key spec; plan the switch and the re-signing or re-wrapping of what the key protects"
        }
        CustodyKind::Pkcs11Token | CustodyKind::Tpm => {
            "which needs device firmware that supports it: confirm the vendor roadmap now, hardware refresh cycles are long"
        }
    };
    Recommendation {
        action: "replace".into(),
        target: format!("{replacement} key generated inside the {place}"),
        rationale: format!(
            "{algorithm} is broken by a quantum computer and the key never leaves the {place}, so its \
             replacement must be generated there too, {where_}."
        ),
        size_delta: None,
    }
}

/// Orders assessed assets into migration waves: urgent quick wins first (high priority, easy to
/// change), then urgent hard changes, then the rest by priority. Retained assets are excluded.
///
/// Each item carries its effort and the year its wave is due under the policy's timeline.
pub fn roadmap(items: &[PlanInput<'_>], policy: &Policy) -> Vec<RoadmapItem> {
    let mut roadmap: Vec<RoadmapItem> = items
        .iter()
        .filter(|(_, _, recommendation, _)| recommendation.action != "retain")
        .map(|(asset, assessment, recommendation, effort)| {
            let urgent = assessment.tier >= Tier::High;
            let wave: u8 = match (urgent, assessment.agility.score >= 60) {
                (true, true) => 1,
                (true, false) => 2,
                (false, _) if assessment.tier == Tier::Medium => 3,
                _ => 4,
            };
            RoadmapItem {
                wave,
                wave_name: WAVE_NAMES[usize::from(wave - 1)].into(),
                asset_id: asset.id.clone(),
                name: asset.finding.display_name(),
                component: asset.component.clone(),
                tier: assessment.tier,
                priority: assessment.priority,
                agility: assessment.agility.score,
                migration_years: assessment.mosca.y_years,
                action: recommendation.action.clone(),
                target: recommendation.target.clone(),
                effort_person_weeks: effort.map_or(0.0, |effort| effort.person_weeks),
                due_year: policy.timeline.wave_due.get(usize::from(wave - 1)).copied(),
            }
        })
        .collect();
    roadmap.sort_by(|a, b| {
        a.wave
            .cmp(&b.wave)
            .then_with(|| b.priority.cmp(&a.priority))
            .then_with(|| b.agility.cmp(&a.agility))
            .then_with(|| a.asset_id.cmp(&b.asset_id))
    });
    roadmap
}

/// Measures the roadmap against the policy's timeline: effort per wave, and the team needed to
/// finish each dated wave, together with everything before it, by its due year.
pub fn plan(roadmap: &[RoadmapItem], policy: &Policy, assessment_year: u16) -> MigrationPlan {
    let timeline = &policy.timeline;
    let mut cumulative = 0.0;
    let waves: Vec<WavePlan> = (1..=4u8)
        .map(|wave| {
            let items: Vec<&RoadmapItem> = roadmap.iter().filter(|i| i.wave == wave).collect();
            let person_weeks: f64 = items.iter().map(|i| i.effort_person_weeks).sum();
            cumulative += person_weeks;
            let due_year = timeline.wave_due.get(usize::from(wave - 1)).copied();
            let overdue = due_year.is_some_and(|due| due < assessment_year) && cumulative > 0.0;
            let weeks_available = due_year
                .filter(|due| *due >= assessment_year)
                .map(|due| f64::from(due - assessment_year + 1) * timeline.working_weeks_per_year);
            WavePlan {
                wave,
                name: WAVE_NAMES[usize::from(wave - 1)].into(),
                items: items.len(),
                person_weeks: round(person_weeks, 1),
                due_year,
                cumulative_person_weeks: round(cumulative, 1),
                weeks_available,
                engineers_needed: weeks_available.map(|weeks| round(cumulative / weeks, 1)),
                overdue,
            }
        })
        .collect();
    let engineers_needed = waves
        .iter()
        .filter_map(|wave| wave.engineers_needed)
        .max_by(f64::total_cmp);
    MigrationPlan {
        timeline: timeline.name.clone(),
        reference: timeline.reference.clone(),
        assessment_year,
        total_person_weeks: round(cumulative, 1),
        overdue: waves.iter().any(|wave| wave.overdue),
        waves,
        engineers_needed,
    }
}
