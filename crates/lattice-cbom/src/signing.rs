//! BLAKE3 hash-chain and ML-DSA (FIPS 204) signing for tamper-evident CBOMs.
//!
//! The chain commits to every component in report order: altering, removing, or reordering a
//! finding changes the chain from that point forward. The signature binds the document identity
//! (serial number, spec version, component count) to the final chain root, so a valid signature
//! proves both authorship and that the chain itself has not been re-derived by an attacker who
//! does not hold the private key. Verification always takes the trusted public key as an explicit
//! argument; the public key embedded in the document is informational only and is never trusted
//! on its own, since an attacker who can rewrite the document could also replace it.

use crate::{Bom, CryptoComponent};
use fips204::ml_dsa_65;
use fips204::traits::{SerDes, Signer, Verifier};
use serde::{Deserialize, Serialize};
use thiserror::Error;

const SIGNING_CONTEXT: &[u8] = b"lattice-cbom-v1";
pub const ALGORITHM_NAME: &str = "ML-DSA-65";
pub const HASH_ALGORITHM_NAME: &str = "BLAKE3";

#[derive(Debug, Error)]
pub enum SigningError {
    #[error("failed to generate an ML-DSA-65 keypair")]
    KeyGeneration,
    #[error("public key has an invalid length for ML-DSA-65")]
    InvalidPublicKey,
    #[error("private key has an invalid length for ML-DSA-65")]
    InvalidPrivateKey,
    #[error("failed to produce an ML-DSA-65 signature")]
    SigningFailed,
    #[error("signature is not valid hexadecimal")]
    MalformedSignatureEncoding,
    #[error("the CBOM carries no signature block")]
    MissingSignature,
    #[error("hash chain mismatch at component index {0}: the CBOM has been altered since signing")]
    ChainBroken(usize),
    #[error("ML-DSA-65 signature does not verify against the supplied trusted public key")]
    SignatureInvalid,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChainEntry {
    pub bom_ref: String,
    pub digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CbomSignature {
    pub algorithm: String,
    pub hash_algorithm: String,
    pub chain: Vec<ChainEntry>,
    pub chain_root: String,
    /// Informational only. Verification always requires a separately supplied trusted key.
    pub signer_public_key: String,
    pub signature: String,
}

/// Generates a fresh ML-DSA-65 keypair using the operating system's random number generator.
/// This never touches the network; the OS RNG is a local syscall.
pub fn generate_keypair() -> Result<(Vec<u8>, Vec<u8>), SigningError> {
    let (public_key, private_key) =
        ml_dsa_65::try_keygen().map_err(|_| SigningError::KeyGeneration)?;
    Ok((public_key.into_bytes().to_vec(), private_key.into_bytes().to_vec()))
}

/// Computes the hash chain over components in their current (already deterministic) order.
pub fn compute_chain(components: &[CryptoComponent]) -> (Vec<ChainEntry>, String) {
    let mut previous = blake3::Hash::from_bytes([0u8; 32]);
    let mut entries = Vec::with_capacity(components.len());
    for component in components {
        let bytes = serde_json::to_vec(component).expect("CryptoComponent always serializes");
        let mut hasher = blake3::Hasher::new();
        hasher.update(previous.as_bytes());
        hasher.update(&bytes);
        let digest = hasher.finalize();
        entries.push(ChainEntry { bom_ref: component.bom_ref.clone(), digest: digest.to_hex().to_string() });
        previous = digest;
    }
    (entries, previous.to_hex().to_string())
}

fn signing_message(bom: &Bom, chain_root: &str) -> Vec<u8> {
    let mut message = Vec::new();
    message.extend_from_slice(SIGNING_CONTEXT);
    message.push(b'|');
    message.extend_from_slice(bom.serial_number.as_bytes());
    message.push(b'|');
    message.extend_from_slice(bom.spec_version.as_bytes());
    message.push(b'|');
    message.extend_from_slice(bom.components.len().to_string().as_bytes());
    message.push(b'|');
    message.extend_from_slice(chain_root.as_bytes());
    message
}

/// Hash-chains and signs the CBOM in place, replacing any prior signature block.
pub fn sign_bom(bom: &mut Bom, private_key: &[u8], public_key: &[u8]) -> Result<(), SigningError> {
    let (chain, chain_root) = compute_chain(&bom.components);
    let message = signing_message(bom, &chain_root);

    let key_array: [u8; ml_dsa_65::SK_LEN] =
        private_key.try_into().map_err(|_| SigningError::InvalidPrivateKey)?;
    let signer =
        ml_dsa_65::PrivateKey::try_from_bytes(key_array).map_err(|_| SigningError::InvalidPrivateKey)?;
    let signature = signer.try_sign(&message, SIGNING_CONTEXT).map_err(|_| SigningError::SigningFailed)?;

    bom.signature = Some(CbomSignature {
        algorithm: ALGORITHM_NAME.to_owned(),
        hash_algorithm: HASH_ALGORITHM_NAME.to_owned(),
        chain,
        chain_root,
        signer_public_key: hex::encode(public_key),
        signature: hex::encode(signature),
    });
    Ok(())
}

/// Verifies the hash chain and the ML-DSA-65 signature against a caller-supplied trusted public
/// key. The public key embedded in the document is never used for trust decisions.
pub fn verify_bom(bom: &Bom, trusted_public_key: &[u8]) -> Result<(), SigningError> {
    let signature_block = bom.signature.as_ref().ok_or(SigningError::MissingSignature)?;
    let (recomputed_chain, recomputed_root) = compute_chain(&bom.components);

    if recomputed_chain.len() != signature_block.chain.len() {
        return Err(SigningError::ChainBroken(recomputed_chain.len().min(signature_block.chain.len())));
    }
    for (index, (recomputed, recorded)) in
        recomputed_chain.iter().zip(signature_block.chain.iter()).enumerate()
    {
        if recomputed != recorded {
            return Err(SigningError::ChainBroken(index));
        }
    }
    if recomputed_root != signature_block.chain_root {
        return Err(SigningError::ChainBroken(recomputed_chain.len()));
    }

    let message = signing_message(bom, &recomputed_root);
    let pk_array: [u8; ml_dsa_65::PK_LEN] =
        trusted_public_key.try_into().map_err(|_| SigningError::InvalidPublicKey)?;
    let public_key =
        ml_dsa_65::PublicKey::try_from_bytes(pk_array).map_err(|_| SigningError::InvalidPublicKey)?;
    let signature_bytes =
        hex::decode(&signature_block.signature).map_err(|_| SigningError::MalformedSignatureEncoding)?;
    let sig_array: [u8; ml_dsa_65::SIG_LEN] =
        signature_bytes.try_into().map_err(|_| SigningError::SignatureInvalid)?;

    if public_key.verify(&message, &sig_array, SIGNING_CONTEXT) {
        Ok(())
    } else {
        Err(SigningError::SignatureInvalid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{build_bom, AssessedAsset, AssetContext};
    use lattice_core::{Algorithm, EvidenceGrade, Liveness};
    use lattice_risk::{MoscaAssessment, Recommendation, RiskAssessment};
    use std::collections::BTreeSet;

    fn sample_bom() -> Bom {
        let asset = lattice_core::CryptoAsset {
            id: "crypto/rsa/test".into(),
            algorithm: Algorithm {
                family: "RSA".into(),
                primitive: "public-key".into(),
                key_size_bits: Some(2048),
                mode: None,
                curve: None,
            },
            parameters: Default::default(),
            locations: vec![],
            surfaces: BTreeSet::new(),
            evidence: vec![],
            liveness: Liveness::Capable,
            evidence_grade: EvidenceGrade::C,
        };
        let risk = RiskAssessment {
            quantum_breakability: 1.0,
            broken_now: false,
            crypto_agility_score: 40,
            mosca: MoscaAssessment {
                data_lifetime_years: 10.0,
                migration_time_years: 1.0,
                years_until_q_day: 9.0,
                urgent: true,
                urgency_years: 2.0,
            },
            hndl_index: 80.0,
            hndl_terms: vec![],
            recommendation: Recommendation {
                target: "ML-DSA-65".into(),
                rationale: "test".into(),
                handshake_bytes_delta: 0,
                latency_ms_delta: 0.0,
            },
        };
        build_bom(vec![AssessedAsset { asset, risk, context: AssetContext::default() }])
    }

    #[test]
    fn signed_bom_verifies_with_the_matching_public_key() {
        let (public_key, private_key) = generate_keypair().unwrap();
        let mut bom = sample_bom();
        sign_bom(&mut bom, &private_key, &public_key).unwrap();
        verify_bom(&bom, &public_key).unwrap();
    }

    #[test]
    fn tampering_with_a_component_breaks_the_chain() {
        let (public_key, private_key) = generate_keypair().unwrap();
        let mut bom = sample_bom();
        sign_bom(&mut bom, &private_key, &public_key).unwrap();
        bom.components[0].name = "TAMPERED".into();
        let error = verify_bom(&bom, &public_key).unwrap_err();
        assert!(matches!(error, SigningError::ChainBroken(0)));
    }

    #[test]
    fn verification_rejects_an_untrusted_public_key() {
        let (_, private_key) = generate_keypair().unwrap();
        let (other_public_key, _) = generate_keypair().unwrap();
        let mut bom = sample_bom();
        let (public_key, _) = generate_keypair().unwrap();
        sign_bom(&mut bom, &private_key, &public_key).unwrap();
        let error = verify_bom(&bom, &other_public_key).unwrap_err();
        assert!(matches!(error, SigningError::SignatureInvalid));
    }

    #[test]
    fn unsigned_bom_fails_with_missing_signature() {
        let bom = sample_bom();
        let (public_key, _) = generate_keypair().unwrap();
        let error = verify_bom(&bom, &public_key).unwrap_err();
        assert!(matches!(error, SigningError::MissingSignature));
    }
}
