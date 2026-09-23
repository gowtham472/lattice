//! Detached ML-DSA-65 (FIPS 204) signatures for CBOM files.
//!
//! The CBOM stays a pristine CycloneDX document; the signature lives next to it in
//! `<cbom>.sig.json`. What is signed:
//!
//! * the SHA-256 and BLAKE3 digests of the exact CBOM bytes, so any change at all is detected;
//! * a BLAKE3 hash chain over the components in document order (each link hashes the previous
//!   link and the component's canonical JSON), so verification can say *which* component was
//!   altered, removed or reordered rather than only "the file changed";
//! * the document's serial number and component count, binding the signature to one document.
//!
//! Verification always takes the trusted public key as an explicit argument. The key fingerprint
//! recorded in the signature file only helps pick the right key; it is never trusted on its own,
//! because whoever can rewrite the CBOM can rewrite the signature file too.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use fips204::ml_dsa_65;
use fips204::traits::{KeyGen, SerDes, Signer, Verifier};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const FORMAT: &str = "lattice-cbom-signature/1";
pub const ALGORITHM: &str = "ML-DSA-65";
/// FIPS 204 context string: separates these signatures from any other use of the same key.
pub const CONTEXT: &[u8] = b"lattice-cbom-v1";
const PUBLIC_KEY_LABEL: &str = "LATTICE ML-DSA-65 PUBLIC KEY";
const PRIVATE_KEY_LABEL: &str = "LATTICE ML-DSA-65 PRIVATE KEY";

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SigningError {
    #[error("failed to generate an ML-DSA-65 key pair")]
    KeyGeneration,
    #[error("not a LATTICE ML-DSA-65 {0} key file")]
    KeyFormat(&'static str),
    #[error("failed to produce an ML-DSA-65 signature")]
    SigningFailed,
    #[error("the CBOM is not valid JSON or has no components array: {0}")]
    Document(String),
    #[error("the signature file is malformed: {0}")]
    SignatureFormat(String),
    #[error("signature was made by key {signed_by}, not the trusted key {trusted}")]
    WrongKey { signed_by: String, trusted: String },
    #[error("the ML-DSA-65 signature does not verify against the trusted public key")]
    SignatureInvalid,
    #[error("component {index} ({bom_ref}) was altered, removed or reordered after signing")]
    ComponentAltered { index: usize, bom_ref: String },
    #[error("the CBOM has {actual} components but {signed} were signed")]
    ComponentCount { signed: usize, actual: usize },
    #[error("the CBOM was altered after signing outside its components (metadata or dependencies)")]
    DocumentAltered,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChainLink {
    pub bom_ref: String,
    pub digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DocumentDigest {
    pub serial_number: String,
    pub bytes: u64,
    pub sha256: String,
    pub blake3: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignatureFile {
    pub format: String,
    pub algorithm: String,
    pub context: String,
    /// BLAKE3 of the signer's public key, first 16 bytes, hex.
    pub key_id: String,
    pub document: DocumentDigest,
    pub chain: Vec<ChainLink>,
    pub chain_root: String,
    pub signature: String,
}

pub struct KeyPair {
    pub public_key: Vec<u8>,
    pub private_key: Vec<u8>,
}

/// Generates a key pair from the operating system's random source. No network is involved.
pub fn generate_keypair() -> Result<KeyPair, SigningError> {
    let (public_key, private_key) =
        ml_dsa_65::KG::try_keygen().map_err(|_| SigningError::KeyGeneration)?;
    Ok(KeyPair {
        public_key: public_key.into_bytes().to_vec(),
        private_key: private_key.into_bytes().to_vec(),
    })
}

pub fn key_id(public_key: &[u8]) -> String {
    hex::encode(&blake3::hash(public_key).as_bytes()[..16])
}

/// Armoured text form of a key: a labelled base64 block, safe to paste and diff.
pub fn encode_public_key(key: &[u8]) -> String {
    armour(PUBLIC_KEY_LABEL, key)
}

pub fn encode_private_key(key: &[u8]) -> String {
    armour(PRIVATE_KEY_LABEL, key)
}

pub fn decode_public_key(text: &str) -> Result<Vec<u8>, SigningError> {
    let key = unarmour(PUBLIC_KEY_LABEL, text).ok_or(SigningError::KeyFormat("public"))?;
    (key.len() == ml_dsa_65::PK_LEN)
        .then_some(key)
        .ok_or(SigningError::KeyFormat("public"))
}

pub fn decode_private_key(text: &str) -> Result<Vec<u8>, SigningError> {
    let key = unarmour(PRIVATE_KEY_LABEL, text).ok_or(SigningError::KeyFormat("private"))?;
    (key.len() == ml_dsa_65::SK_LEN)
        .then_some(key)
        .ok_or(SigningError::KeyFormat("private"))
}

fn armour(label: &str, bytes: &[u8]) -> String {
    let encoded = STANDARD.encode(bytes);
    let mut out = format!("-----BEGIN {label}-----\n");
    for line in encoded.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(line).expect("base64 is ASCII"));
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out
}

fn unarmour(label: &str, text: &str) -> Option<Vec<u8>> {
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let body = text.split_once(&begin)?.1.split_once(&end)?.0;
    let joined: String = body.chars().filter(|c| !c.is_whitespace()).collect();
    STANDARD.decode(joined).ok()
}

/// The hash chain over a parsed CBOM's components.
pub fn chain(document: &Value) -> Result<(Vec<ChainLink>, String), SigningError> {
    let components = document
        .get("components")
        .and_then(Value::as_array)
        .ok_or_else(|| SigningError::Document("no components array".into()))?;
    let mut previous = [0u8; 32];
    let mut links = Vec::with_capacity(components.len());
    for component in components {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&previous);
        hasher.update(crate::canonical_json(component).as_bytes());
        previous = *hasher.finalize().as_bytes();
        links.push(ChainLink {
            bom_ref: component
                .get("bom-ref")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
            digest: hex::encode(previous),
        });
    }
    Ok((links, hex::encode(previous)))
}

fn parse(document: &[u8]) -> Result<Value, SigningError> {
    serde_json::from_slice(document).map_err(|e| SigningError::Document(e.to_string()))
}

fn digest(document: &[u8], serial_number: String) -> DocumentDigest {
    DocumentDigest {
        serial_number,
        bytes: document.len() as u64,
        sha256: hex::encode(Sha256::digest(document)),
        blake3: blake3::hash(document).to_hex().to_string(),
    }
}

/// The exact bytes ML-DSA signs. Length-prefixed fields, so no two inputs share an encoding.
fn message(file: &SignatureFile) -> Vec<u8> {
    let fields: [&[u8]; 8] = [
        file.format.as_bytes(),
        file.algorithm.as_bytes(),
        file.key_id.as_bytes(),
        file.document.serial_number.as_bytes(),
        &file.document.bytes.to_be_bytes(),
        file.document.sha256.as_bytes(),
        file.document.blake3.as_bytes(),
        file.chain_root.as_bytes(),
    ];
    let mut message = Vec::new();
    for field in fields {
        message.extend_from_slice(&(field.len() as u64).to_be_bytes());
        message.extend_from_slice(field);
    }
    message.extend_from_slice(&(file.chain.len() as u64).to_be_bytes());
    message
}

/// Signs the exact CBOM bytes and returns the detached signature.
pub fn sign(
    document: &[u8],
    private_key: &[u8],
    public_key: &[u8],
) -> Result<SignatureFile, SigningError> {
    let parsed = parse(document)?;
    let serial_number = parsed
        .get("serialNumber")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let (links, root) = chain(&parsed)?;
    let mut file = SignatureFile {
        format: FORMAT.into(),
        algorithm: ALGORITHM.into(),
        context: String::from_utf8_lossy(CONTEXT).into_owned(),
        key_id: key_id(public_key),
        document: digest(document, serial_number),
        chain: links,
        chain_root: root,
        signature: String::new(),
    };
    let key: [u8; ml_dsa_65::SK_LEN] = private_key
        .try_into()
        .map_err(|_| SigningError::KeyFormat("private"))?;
    let signer = ml_dsa_65::PrivateKey::try_from_bytes(key)
        .map_err(|_| SigningError::KeyFormat("private"))?;
    let signature = signer
        .try_sign(&message(&file), CONTEXT)
        .map_err(|_| SigningError::SigningFailed)?;
    file.signature = STANDARD.encode(signature);
    Ok(file)
}

/// Verifies a CBOM against its detached signature and a trusted public key. On success the
/// document is byte-for-byte what was signed; on failure the error names what changed.
pub fn verify(
    document: &[u8],
    signature: &SignatureFile,
    trusted_public_key: &[u8],
) -> Result<(), SigningError> {
    if signature.format != FORMAT || signature.algorithm != ALGORITHM {
        return Err(SigningError::SignatureFormat(format!(
            "unsupported {} / {}",
            signature.format, signature.algorithm
        )));
    }
    let trusted = key_id(trusted_public_key);
    if signature.key_id != trusted {
        return Err(SigningError::WrongKey {
            signed_by: signature.key_id.clone(),
            trusted,
        });
    }

    // 1. The signature file itself is authentic.
    let key: [u8; ml_dsa_65::PK_LEN] = trusted_public_key
        .try_into()
        .map_err(|_| SigningError::KeyFormat("public"))?;
    let public_key =
        ml_dsa_65::PublicKey::try_from_bytes(key).map_err(|_| SigningError::KeyFormat("public"))?;
    let bytes = STANDARD
        .decode(&signature.signature)
        .map_err(|e| SigningError::SignatureFormat(e.to_string()))?;
    let bytes: [u8; ml_dsa_65::SIG_LEN] = bytes
        .try_into()
        .map_err(|_| SigningError::SignatureInvalid)?;
    if !public_key.verify(&message(signature), &bytes, CONTEXT) {
        return Err(SigningError::SignatureInvalid);
    }

    // 2. The document is the one it describes.
    let actual = digest(document, signature.document.serial_number.clone());
    if actual == signature.document {
        return Ok(());
    }

    // 3. It is not: find the first component that differs to say what changed.
    let parsed = parse(document)?;
    let (links, _) = chain(&parsed)?;
    for (index, signed) in signature.chain.iter().enumerate() {
        match links.get(index) {
            Some(link) if link == signed => {}
            _ => {
                return Err(SigningError::ComponentAltered {
                    index,
                    bom_ref: signed.bom_ref.clone(),
                });
            }
        }
    }
    if links.len() != signature.chain.len() {
        return Err(SigningError::ComponentCount {
            signed: signature.chain.len(),
            actual: links.len(),
        });
    }
    Err(SigningError::DocumentAltered)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::OnceLock;

    fn keys() -> &'static KeyPair {
        static KEYS: OnceLock<KeyPair> = OnceLock::new();
        KEYS.get_or_init(|| generate_keypair().unwrap())
    }

    fn document() -> Vec<u8> {
        let value = json!({
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
            "version": 1,
            "metadata": {"timestamp": "2026-09-23T00:00:00Z"},
            "components": [
                {"type": "cryptographic-asset", "bom-ref": "a", "name": "RSA-2048"},
                {"type": "cryptographic-asset", "bom-ref": "b", "name": "AES-256-GCM"},
            ],
        });
        serde_json::to_vec_pretty(&value).unwrap()
    }

    fn edit(document: &[u8], change: impl FnOnce(&mut Value)) -> Vec<u8> {
        let mut value: Value = serde_json::from_slice(document).unwrap();
        change(&mut value);
        serde_json::to_vec_pretty(&value).unwrap()
    }

    #[test]
    fn a_signed_cbom_verifies_with_the_signing_key() {
        let keys = keys();
        let document = document();
        let signature = sign(&document, &keys.private_key, &keys.public_key).unwrap();
        assert_eq!(signature.chain.len(), 2);
        verify(&document, &signature, &keys.public_key).unwrap();
        // the signature file round-trips through JSON
        let text = serde_json::to_string(&signature).unwrap();
        verify(
            &document,
            &serde_json::from_str(&text).unwrap(),
            &keys.public_key,
        )
        .unwrap();
    }

    #[test]
    fn verification_names_the_altered_component() {
        let keys = keys();
        let document = document();
        let signature = sign(&document, &keys.private_key, &keys.public_key).unwrap();
        let tampered = edit(&document, |v| {
            v["components"][1]["name"] = json!("AES-128-GCM")
        });
        assert_eq!(
            verify(&tampered, &signature, &keys.public_key),
            Err(SigningError::ComponentAltered {
                index: 1,
                bom_ref: "b".into()
            })
        );
        let removed = edit(&document, |v| {
            v["components"].as_array_mut().unwrap().remove(0);
        });
        assert_eq!(
            verify(&removed, &signature, &keys.public_key),
            Err(SigningError::ComponentAltered {
                index: 0,
                bom_ref: "a".into()
            })
        );
        let appended = edit(&document, |v| {
            v["components"]
                .as_array_mut()
                .unwrap()
                .push(json!({"bom-ref": "c"}))
        });
        assert_eq!(
            verify(&appended, &signature, &keys.public_key),
            Err(SigningError::ComponentCount {
                signed: 2,
                actual: 3
            })
        );
        let metadata = edit(&document, |v| {
            v["metadata"]["timestamp"] = json!("2020-01-01T00:00:00Z")
        });
        assert_eq!(
            verify(&metadata, &signature, &keys.public_key),
            Err(SigningError::DocumentAltered)
        );
    }

    #[test]
    fn formatting_changes_are_still_tampering() {
        let keys = keys();
        let document = document();
        let signature = sign(&document, &keys.private_key, &keys.public_key).unwrap();
        let mut reformatted =
            serde_json::to_vec(&serde_json::from_slice::<Value>(&document).unwrap()).unwrap();
        reformatted.push(b'\n');
        assert_eq!(
            verify(&reformatted, &signature, &keys.public_key),
            Err(SigningError::DocumentAltered)
        );
    }

    #[test]
    fn a_forged_signature_file_is_rejected() {
        let keys = keys();
        let document = document();
        let mut signature = sign(&document, &keys.private_key, &keys.public_key).unwrap();
        // an attacker edits the CBOM and recomputes digests, but cannot re-sign
        let tampered = edit(&document, |v| {
            v["components"][0]["name"] = json!("ML-KEM-768")
        });
        let (links, root) = chain(&serde_json::from_slice(&tampered).unwrap()).unwrap();
        signature.document = digest(&tampered, signature.document.serial_number.clone());
        signature.chain = links;
        signature.chain_root = root;
        assert_eq!(
            verify(&tampered, &signature, &keys.public_key),
            Err(SigningError::SignatureInvalid)
        );
    }

    #[test]
    fn an_untrusted_key_is_rejected_before_anything_else() {
        let keys = keys();
        let other = generate_keypair().unwrap();
        let document = document();
        let signature = sign(&document, &other.private_key, &other.public_key).unwrap();
        assert!(matches!(
            verify(&document, &signature, &keys.public_key),
            Err(SigningError::WrongKey { .. })
        ));
        // claiming the trusted key's id does not help: the signature itself fails
        let mut claimed = signature;
        claimed.key_id = key_id(&keys.public_key);
        assert_eq!(
            verify(&document, &claimed, &keys.public_key),
            Err(SigningError::SignatureInvalid)
        );
    }

    #[test]
    fn keys_round_trip_through_their_armoured_form() {
        let keys = keys();
        let public = encode_public_key(&keys.public_key);
        let private = encode_private_key(&keys.private_key);
        assert!(public.starts_with("-----BEGIN LATTICE ML-DSA-65 PUBLIC KEY-----\n"));
        assert_eq!(decode_public_key(&public).unwrap(), keys.public_key);
        assert_eq!(decode_private_key(&private).unwrap(), keys.private_key);
        assert_eq!(
            decode_public_key(&private),
            Err(SigningError::KeyFormat("public"))
        );
        assert_eq!(
            decode_private_key("garbage"),
            Err(SigningError::KeyFormat("private"))
        );
    }
}
