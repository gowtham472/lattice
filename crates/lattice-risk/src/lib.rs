//! Deterministic and explainable quantum-risk scoring.

use lattice_core::{CryptoAsset, Liveness};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Exposure {
    Internet,
    Partner,
    Internal,
    DeadCode,
}

impl Exposure {
    pub fn weight(self) -> f64 {
        match self {
            Self::Internet => 1.0,
            Self::Partner => 0.6,
            Self::Internal => 0.3,
            Self::DeadCode => 0.0,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgilityFactors {
    pub provider_interface: bool,
    pub config_driven: bool,
    pub negotiation_layer: bool,
    pub centralized: bool,
    pub dependency_pqc_ready: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct RiskContext {
    pub data_secrecy_lifetime_years: f64,
    pub exposure: Exposure,
    pub assessment_year: u16,
    pub q_day_year: u16,
    pub agility: AgilityFactors,
}

impl Default for RiskContext {
    fn default() -> Self {
        Self {
            data_secrecy_lifetime_years: 5.0,
            exposure: Exposure::Internal,
            assessment_year: 2026,
            q_day_year: 2035,
            agility: AgilityFactors::default(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScoreTerm {
    pub name: String,
    pub value: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MoscaAssessment {
    pub data_lifetime_years: f64,
    pub migration_time_years: f64,
    pub years_until_q_day: f64,
    pub urgent: bool,
    pub urgency_years: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Recommendation {
    pub target: String,
    pub rationale: String,
    pub handshake_bytes_delta: i32,
    pub latency_ms_delta: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RiskAssessment {
    pub quantum_breakability: f64,
    pub broken_now: bool,
    pub crypto_agility_score: u8,
    pub mosca: MoscaAssessment,
    pub hndl_index: f64,
    pub hndl_terms: Vec<ScoreTerm>,
    pub recommendation: Recommendation,
}

pub fn assess(asset: &CryptoAsset, context: RiskContext) -> RiskAssessment {
    let (quantum_breakability, broken_now) = quantum_breakability(
        &asset.algorithm.family,
        asset.algorithm.key_size_bits,
    );
    let crypto_agility_score = agility_score(context.agility);
    let migration_time_years = round2(0.25 + f64::from(100 - crypto_agility_score) / 25.0);
    let years_until_q_day = f64::from(context.q_day_year.saturating_sub(context.assessment_year));
    let urgency_years = round2(
        context.data_secrecy_lifetime_years + migration_time_years - years_until_q_day,
    );
    let mosca = MoscaAssessment {
        data_lifetime_years: context.data_secrecy_lifetime_years,
        migration_time_years,
        years_until_q_day,
        urgent: urgency_years > 0.0,
        urgency_years,
    };

    let liveness_weight = match asset.liveness {
        Liveness::Confirmed => 1.0,
        Liveness::Configured => 0.7,
        Liveness::Capable => 0.4,
    };
    let lifetime_weight = (context.data_secrecy_lifetime_years / 25.0).clamp(0.0, 1.0);
    let hndl_index = round2(
        100.0
            * context.exposure.weight()
            * lifetime_weight
            * quantum_breakability
            * liveness_weight,
    );
    let hndl_terms = vec![
        ScoreTerm { name: "externalExposure".into(), value: context.exposure.weight() },
        ScoreTerm { name: "normalizedDataLifetime".into(), value: lifetime_weight },
        ScoreTerm { name: "quantumBreakability".into(), value: quantum_breakability },
        ScoreTerm { name: "livenessWeight".into(), value: liveness_weight },
    ];

    RiskAssessment {
        quantum_breakability,
        broken_now,
        crypto_agility_score,
        mosca,
        hndl_index,
        hndl_terms,
        recommendation: recommendation(&asset.algorithm.family, asset.algorithm.key_size_bits),
    }
}

pub fn quantum_breakability(family: &str, key_size_bits: Option<u32>) -> (f64, bool) {
    let normalized = family.to_ascii_uppercase().replace('_', "-");
    match normalized.as_str() {
        "RSA" | "DH" | "ECDH" | "ECDHE" | "ECDSA" | "DSA" | "ELGAMAL" => (1.0, false),
        "MD5" | "SHA-1" | "SHA1" | "DES" | "3DES" | "TRIPLEDES" | "RC4" => (1.0, true),
        "AES" if key_size_bits.unwrap_or(128) < 256 => (0.5, false),
        "AES" => (0.1, false),
        "SHA-256" | "SHA256" => (0.2, false),
        "SHA-384" | "SHA384" | "SHA-512" | "SHA512" | "CHACHA20" => (0.1, false),
        "ML-KEM" | "MLKEM" | "KYBER" | "ML-DSA" | "MLDSA" | "DILITHIUM" | "SLH-DSA" => {
            (0.0, false)
        }
        _ => (0.5, false),
    }
}

pub fn agility_score(factors: AgilityFactors) -> u8 {
    u8::from(factors.provider_interface) * 40
        + u8::from(factors.config_driven) * 20
        + u8::from(factors.negotiation_layer) * 15
        + u8::from(factors.centralized) * 15
        + u8::from(factors.dependency_pqc_ready) * 10
}

fn recommendation(family: &str, key_size_bits: Option<u32>) -> Recommendation {
    let normalized = family.to_ascii_uppercase().replace('_', "-");
    match normalized.as_str() {
        "RSA" | "ECDSA" | "DSA" => Recommendation {
            target: "ML-DSA-65 (FIPS 204), or hybrid during transition".into(),
            rationale: "Replace Shor-vulnerable public-key signatures with a standardized post-quantum signature.".into(),
            handshake_bytes_delta: 3200,
            latency_ms_delta: 0.6,
        },
        "DH" | "ECDH" | "ECDHE" | "ELGAMAL" => Recommendation {
            target: "Hybrid X25519 + ML-KEM-768 (FIPS 203)".into(),
            rationale: "Use hybrid key establishment until the ecosystem permits a PQC-only transition.".into(),
            handshake_bytes_delta: 1184,
            latency_ms_delta: 0.4,
        },
        "MD5" | "SHA-1" | "SHA1" => Recommendation {
            target: "SHA-384 or SHA-512".into(),
            rationale: "The current hash is broken classically and should be removed independently of Q-day.".into(),
            handshake_bytes_delta: 0,
            latency_ms_delta: 0.0,
        },
        "AES" if key_size_bits.unwrap_or(128) < 256 => Recommendation {
            target: "AES-256-GCM".into(),
            rationale: "Increase symmetric key strength to retain an adequate margin under Grover's algorithm.".into(),
            handshake_bytes_delta: 0,
            latency_ms_delta: 0.0,
        },
        "ML-KEM" | "MLKEM" | "KYBER" | "ML-DSA" | "MLDSA" | "DILITHIUM" | "SLH-DSA" => Recommendation {
            target: "Retain standardized PQC; verify parameter set and implementation".into(),
            rationale: "The algorithm family is post-quantum; operational and implementation review still applies.".into(),
            handshake_bytes_delta: 0,
            latency_ms_delta: 0.0,
        },
        _ => Recommendation {
            target: "Review against current organizational cryptographic policy".into(),
            rationale: "No automatic migration target is safe without protocol and usage context.".into(),
            handshake_bytes_delta: 0,
            latency_ms_delta: 0.0,
        },
    }
}

fn round2(value: f64) -> f64 {
    (value * 100.0).round() / 100.0
}

#[cfg(test)]
mod tests {
    use super::*;
    use lattice_core::{Algorithm, EvidenceGrade, Surface};
    use std::collections::{BTreeMap, BTreeSet};

    fn asset(family: &str, bits: Option<u32>, liveness: Liveness) -> CryptoAsset {
        CryptoAsset {
            id: "crypto/test".into(),
            algorithm: Algorithm {
                family: family.into(),
                primitive: "test".into(),
                key_size_bits: bits,
                mode: None,
                curve: None,
            },
            parameters: BTreeMap::new(),
            locations: vec![],
            surfaces: BTreeSet::from([Surface::Source]),
            evidence: vec![],
            liveness,
            evidence_grade: EvidenceGrade::C,
        }
    }

    #[test]
    fn classifies_quantum_and_classical_risk() {
        assert_eq!(quantum_breakability("RSA", Some(4096)), (1.0, false));
        assert_eq!(quantum_breakability("SHA-1", None), (1.0, true));
        assert_eq!(quantum_breakability("AES", Some(256)), (0.1, false));
        assert_eq!(quantum_breakability("ML-KEM", None), (0.0, false));
    }

    #[test]
    fn hndl_increases_with_liveness() {
        let context = RiskContext {
            data_secrecy_lifetime_years: 25.0,
            exposure: Exposure::Internet,
            ..RiskContext::default()
        };
        let capable = assess(&asset("RSA", Some(2048), Liveness::Capable), context);
        let confirmed = assess(&asset("RSA", Some(2048), Liveness::Confirmed), context);
        assert!(confirmed.hndl_index > capable.hndl_index);
        assert_eq!(confirmed.hndl_index, 100.0);
    }

    #[test]
    fn agility_weights_total_one_hundred() {
        assert_eq!(agility_score(AgilityFactors {
            provider_interface: true,
            config_driven: true,
            negotiation_layer: true,
            centralized: true,
            dependency_pqc_ready: true,
        }), 100);
    }
}
