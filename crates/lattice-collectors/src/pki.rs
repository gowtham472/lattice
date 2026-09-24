//! PKI collector: X.509 certificates and key material at rest.
//!
//! Certificates are parsed with `x509-parser`. Keys are read with a minimal, bounds-checked DER
//! reader that extracts only algorithm, size and curve. What is recorded about a key is its type,
//! size, algorithm, whether it is encrypted at rest, and a one-way BLAKE3 identity so the same
//! key in two files is one asset. Key bytes are never copied into a finding, a log line or a
//! report (security.md §4).

use crate::sandbox::Deadline;
use crate::{Artifact, Collector, Findings};
use base64::Engine;
use lattice_core::{
    AlgorithmRef, CertificateFinding, Evidence, EvidenceKind, Finding, Location, MaterialFinding,
    MaterialType, Observation, Params, Registry, Surface,
};
use sha2::{Digest, Sha256};

const COLLECTOR: &str = "pki";
const RULE_VERSION: &str = "2026.09.1";
const MAX_PEM_BLOCKS: usize = 512;

#[derive(Debug, Default)]
pub struct PkiCollector;

impl PkiCollector {
    pub fn new() -> Self {
        Self
    }
}

const EXTENSIONS: &[&str] = &[
    "pem",
    "crt",
    "cer",
    "der",
    "key",
    "pub",
    "p8",
    "pk8",
    "csr",
    "p12",
    "pfx",
    "jks",
    "keystore",
    "bks",
    "p7b",
    "ca-bundle",
];
const NAMES: &[&str] = &[
    "id_rsa",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    "authorized_keys",
    "known_hosts",
    "ssh_host_rsa_key",
    "ssh_host_ecdsa_key",
    "ssh_host_ed25519_key",
];

impl Collector for PkiCollector {
    fn name(&self) -> &'static str {
        COLLECTOR
    }

    fn accepts(&self, path: &str, head: &[u8]) -> bool {
        let file = path.rsplit('/').next().unwrap_or(path);
        let extension = file
            .rsplit_once('.')
            .map(|(_, ext)| ext.to_ascii_lowercase());
        extension
            .as_deref()
            .is_some_and(|ext| EXTENSIONS.contains(&ext))
            || NAMES
                .iter()
                .any(|name| file == *name || file.starts_with(&format!("{name}.")))
            || contains(head, b"-----BEGIN ")
            || head.starts_with(b"ssh-rsa ")
            || head.starts_with(b"ssh-ed25519 ")
            || head.starts_with(b"ecdsa-sha2-")
    }

    fn collect(
        &self,
        artifact: &Artifact<'_>,
        deadline: &Deadline,
        findings: &mut Findings,
    ) -> Result<(), String> {
        let mut out = Out { artifact, findings };
        let extension = artifact
            .path
            .rsplit_once('.')
            .map(|(_, ext)| ext.to_ascii_lowercase())
            .unwrap_or_default();

        if matches!(
            extension.as_str(),
            "p12" | "pfx" | "jks" | "keystore" | "bks"
        ) && !contains(artifact.bytes, b"-----BEGIN ")
        {
            // Password-protected containers: LATTICE never tries passwords. Presence is the finding.
            let format = if matches!(extension.as_str(), "p12" | "pfx") {
                "PKCS12"
            } else {
                "JKS"
            };
            out.material(
                MaterialType::Key,
                None,
                None,
                format,
                true,
                identity(artifact.bytes),
                0,
                "pki.keystore",
            );
            return Ok(());
        }

        if contains(artifact.bytes, b"-----BEGIN ") {
            for (index, block) in pem_blocks(artifact.bytes)
                .into_iter()
                .take(MAX_PEM_BLOCKS)
                .enumerate()
            {
                if index % 32 == 0 {
                    deadline.check()?;
                }
                out.pem_block(&block);
            }
        } else if artifact.bytes.first() == Some(&0x30) {
            // DER: try a certificate first, then a bare key structure
            if !out.certificate(artifact.bytes, 0) {
                out.der_key(artifact.bytes, "DER", 0);
            }
        }

        // SSH public keys, one per line (`*.pub`, `authorized_keys`, `known_hosts`)
        let text = String::from_utf8_lossy(artifact.bytes);
        for (line_index, line) in text.lines().enumerate().take(10_000) {
            out.ssh_public_key_line(line, line_index as u64 + 1);
        }
        Ok(())
    }
}

struct PemBlock {
    label: String,
    contents: Vec<u8>,
    encrypted_headers: bool,
    offset: usize,
}

/// Minimal PEM splitter: tolerant of CRLF, headers (`Proc-Type: 4,ENCRYPTED`) and junk between
/// blocks; bounded by the input size.
fn pem_blocks(bytes: &[u8]) -> Vec<PemBlock> {
    let text = String::from_utf8_lossy(bytes);
    let mut blocks = Vec::new();
    let mut rest: &str = &text;
    let mut consumed = 0usize;
    while let Some(start) = rest.find("-----BEGIN ") {
        let after = &rest[start + 11..];
        let Some(label_end) = after.find("-----") else {
            break;
        };
        let label = after[..label_end].trim().to_owned();
        let body_start = start + 11 + label_end + 5;
        let end_marker = format!("-----END {label}-----");
        let Some(end) = rest[body_start..].find(&end_marker) else {
            break;
        };
        let body = &rest[body_start..body_start + end];
        let encrypted_headers = body.contains("ENCRYPTED");
        let base64_body: String = body
            .lines()
            .filter(|line| !line.contains(':'))
            .flat_map(|line| line.chars().filter(|c| !c.is_whitespace()))
            .collect();
        if let Ok(contents) =
            base64::engine::general_purpose::STANDARD.decode(base64_body.as_bytes())
        {
            blocks.push(PemBlock {
                label,
                contents,
                encrypted_headers,
                offset: consumed + start,
            });
        }
        let advance = body_start + end + end_marker.len();
        consumed += advance;
        rest = &rest[advance..];
    }
    blocks
}

struct Out<'a, 'f> {
    artifact: &'a Artifact<'a>,
    findings: &'f mut Findings,
}

impl Out<'_, '_> {
    fn pem_block(&mut self, block: &PemBlock) {
        let offset = block.offset;
        match block.label.as_str() {
            "CERTIFICATE" | "TRUSTED CERTIFICATE" | "X509 CERTIFICATE" => {
                self.certificate(&block.contents, offset);
            }
            "PRIVATE KEY" | "RSA PRIVATE KEY" | "EC PRIVATE KEY" | "DSA PRIVATE KEY"
            | "PUBLIC KEY" | "RSA PUBLIC KEY" => {
                let encrypted = block.encrypted_headers;
                if encrypted {
                    self.material(
                        MaterialType::PrivateKey,
                        None,
                        None,
                        "PEM",
                        true,
                        identity(&block.contents),
                        offset,
                        "pki.pem.encrypted-legacy",
                    );
                } else {
                    self.pem_key(&block.label, &block.contents, offset);
                }
            }
            "ENCRYPTED PRIVATE KEY" => {
                self.material(
                    MaterialType::PrivateKey,
                    None,
                    None,
                    "PEM",
                    true,
                    identity(&block.contents),
                    offset,
                    "pki.pem.pkcs8-encrypted",
                );
            }
            "OPENSSH PRIVATE KEY" => self.openssh_private_key(&block.contents, offset),
            _ => {}
        }
    }

    fn pem_key(&mut self, label: &str, der: &[u8], offset: usize) {
        match label {
            "RSA PRIVATE KEY" => {
                let bits = der::rsa_pkcs1_private_bits(der);
                self.material(
                    MaterialType::PrivateKey,
                    Some(AlgorithmRef::with_params(
                        "rsa",
                        Params {
                            key_bits: bits,
                            ..Params::default()
                        },
                    )),
                    bits,
                    "PEM",
                    false,
                    identity(der),
                    offset,
                    "pki.pem.pkcs1",
                );
            }
            "RSA PUBLIC KEY" => {
                let bits = der::rsa_public_bits(der);
                self.material(
                    MaterialType::PublicKey,
                    Some(AlgorithmRef::with_params(
                        "rsa",
                        Params {
                            key_bits: bits,
                            ..Params::default()
                        },
                    )),
                    bits,
                    "PEM",
                    false,
                    identity(der),
                    offset,
                    "pki.pem.pkcs1-public",
                );
            }
            "EC PRIVATE KEY" => {
                let curve = der::sec1_curve(der).and_then(|oid| {
                    Registry::active()
                        .curve_by_oid(&oid)
                        .map(|curve| curve.name.clone())
                });
                self.material(
                    MaterialType::PrivateKey,
                    Some(AlgorithmRef::with_params(
                        "ecdsa",
                        Params {
                            curve,
                            ..Params::default()
                        },
                    )),
                    None,
                    "PEM",
                    false,
                    identity(der),
                    offset,
                    "pki.pem.sec1",
                );
            }
            _ => {
                self.der_key(der, "PEM", offset);
            }
        }
    }

    /// PKCS#8 private key or SubjectPublicKeyInfo.
    fn der_key(&mut self, der: &[u8], format: &str, offset: usize) -> bool {
        if let Some((algorithm, bits)) = der::spki(der) {
            self.material(
                MaterialType::PublicKey,
                Some(algorithm),
                bits,
                format,
                false,
                identity(der),
                offset,
                "pki.spki",
            );
            return true;
        }
        if let Some((algorithm, bits)) = der::pkcs8(der) {
            self.material(
                MaterialType::PrivateKey,
                Some(algorithm),
                bits,
                format,
                false,
                identity(der),
                offset,
                "pki.pkcs8",
            );
            return true;
        }
        false
    }

    fn certificate(&mut self, der: &[u8], offset: usize) -> bool {
        use x509_parser::prelude::*;
        let Ok((_, certificate)) = X509Certificate::from_der(der) else {
            return false;
        };
        let registry = Registry::active();
        let spki = certificate.public_key();
        let key_oid = spki.algorithm.algorithm.to_id_string();
        let mut public_key = registry
            .by_oid(&key_oid)
            .unwrap_or_else(|| AlgorithmRef::new(unknown_oid(&key_oid)));
        if let Ok(x509_parser::public_key::PublicKey::RSA(rsa)) = spki.parsed() {
            public_key.params.key_bits = Some(rsa.key_size() as u32);
        }
        if let Some(parameters) = &spki.algorithm.parameters
            && let Some(oid) = der::oid_from_content(parameters.data)
            && let Some(curve) = registry.curve_by_oid(&oid)
        {
            public_key.params.curve = Some(curve.name.clone());
        }
        let signature_oid = certificate.signature_algorithm.algorithm.to_id_string();
        let signature = registry
            .by_oid(&signature_oid)
            .unwrap_or_else(|| AlgorithmRef::new(unknown_oid(&signature_oid)));
        if registry.get(&public_key.id).is_none() || registry.get(&signature.id).is_none() {
            // An algorithm outside the knowledge base: report the certificate honestly as a
            // heuristic rather than inventing an algorithm.
            return self.unknown_certificate(&certificate, der, offset, &key_oid, &signature_oid);
        }
        let is_ca = certificate
            .basic_constraints()
            .ok()
            .flatten()
            .is_some_and(|constraint| constraint.value.ca);
        let finding = CertificateFinding {
            subject: certificate.subject().to_string(),
            issuer: certificate.issuer().to_string(),
            not_before: lattice_core::rfc3339(certificate.validity().not_before.timestamp()),
            not_after: lattice_core::rfc3339(certificate.validity().not_after.timestamp()),
            serial: hex::encode(certificate.raw_serial()),
            public_key,
            signature,
            self_signed: certificate.subject() == certificate.issuer(),
            is_ca,
            fingerprint_sha256: hex::encode(Sha256::digest(der)),
        };
        self.push(
            Finding::Certificate(finding),
            EvidenceKind::Certificate,
            "pki.x509",
            "X.509 certificate",
            offset,
        );
        true
    }

    fn unknown_certificate(
        &mut self,
        certificate: &x509_parser::certificate::X509Certificate<'_>,
        der: &[u8],
        offset: usize,
        key_oid: &str,
        signature_oid: &str,
    ) -> bool {
        let _ = (certificate, der);
        self.push(
            Finding::RelatedCryptoMaterial(MaterialFinding {
                material_type: MaterialType::Other,
                algorithm: None,
                size_bits: None,
                format: "X.509".into(),
                encrypted: false,
                identity: identity(der),
            }),
            EvidenceKind::Heuristic,
            "pki.x509.unknown-algorithm",
            &format!("key {key_oid}, signature {signature_oid}"),
            offset,
        );
        true
    }

    fn openssh_private_key(&mut self, blob: &[u8], offset: usize) {
        let Some(key) = ssh::parse_private(blob) else {
            return;
        };
        let (algorithm, bits) = key.algorithm;
        self.material(
            MaterialType::PrivateKey,
            algorithm,
            bits,
            "OpenSSH",
            key.encrypted,
            identity(&key.public_blob),
            offset,
            "pki.openssh",
        );
    }

    fn ssh_public_key_line(&mut self, line: &str, line_number: u64) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        // authorized_keys lines may start with options; known_hosts with a host list
        let Some(position) = fields.iter().position(|field| ssh::is_key_type(field)) else {
            return;
        };
        let Some(encoded) = fields.get(position + 1) else {
            return;
        };
        let Ok(blob) = base64::engine::general_purpose::STANDARD.decode(encoded) else {
            return;
        };
        let Some((algorithm, bits)) = ssh::parse_public_blob(&blob) else {
            return;
        };
        let location = Location::at_line(self.artifact.path, line_number, 1);
        let finding = Finding::RelatedCryptoMaterial(MaterialFinding {
            material_type: MaterialType::PublicKey,
            algorithm,
            size_bits: bits,
            format: "OpenSSH".into(),
            encrypted: false,
            identity: identity(&blob),
        });
        self.push_at(
            finding,
            EvidenceKind::Certificate,
            "pki.ssh-public-key",
            fields[position],
            location,
        );
    }

    #[allow(clippy::too_many_arguments)]
    fn material(
        &mut self,
        material_type: MaterialType,
        algorithm: Option<AlgorithmRef>,
        size_bits: Option<u32>,
        format: &str,
        encrypted: bool,
        identity: String,
        offset: usize,
        rule: &str,
    ) {
        let finding = Finding::RelatedCryptoMaterial(MaterialFinding {
            material_type,
            algorithm,
            size_bits,
            format: format.into(),
            encrypted,
            identity,
        });
        let token = match material_type {
            MaterialType::PrivateKey if !encrypted => "unencrypted private key",
            MaterialType::PrivateKey => "encrypted private key",
            MaterialType::PublicKey => "public key",
            _ => "key container",
        };
        self.push(finding, EvidenceKind::Certificate, rule, token, offset);
    }

    fn push(
        &mut self,
        finding: Finding,
        kind: EvidenceKind,
        rule: &str,
        token: &str,
        offset: usize,
    ) {
        let location = Location::at_offset(self.artifact.path, offset as u64);
        self.push_at(finding, kind, rule, token, location);
    }

    fn push_at(
        &mut self,
        finding: Finding,
        kind: EvidenceKind,
        rule: &str,
        token: &str,
        location: Location,
    ) {
        self.findings.observations.push(Observation {
            surface: Surface::Certificate,
            component: self.artifact.component.to_owned(),
            location,
            finding,
            evidence: Evidence {
                collector: COLLECTOR.into(),
                rule_id: rule.into(),
                rule_version: RULE_VERSION.into(),
                kind,
                matched_token: token.chars().take(96).collect(),
            },
            usage: None,
        });
    }
}

fn unknown_oid(oid: &str) -> String {
    format!("oid:{oid}")
}

/// One-way identity for key material: BLAKE3 truncated to 128 bits. Never the key.
fn identity(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex()[..32].to_owned()
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

/// Unix seconds → RFC 3339 UTC (civil-from-days, Howard Hinnant).
/// Just enough DER to read key algorithms and sizes. Every read is bounds-checked; malformed
/// input yields `None`, never a panic.
pub(crate) mod der {
    use lattice_core::{AlgorithmRef, Params, Registry};

    pub struct Tlv<'a> {
        pub tag: u8,
        pub content: &'a [u8],
        pub rest: &'a [u8],
    }

    pub fn read(input: &[u8]) -> Option<Tlv<'_>> {
        let (&tag, rest) = input.split_first()?;
        let (&first, mut rest) = rest.split_first()?;
        let length = if first & 0x80 == 0 {
            usize::from(first)
        } else {
            let count = usize::from(first & 0x7f);
            if count == 0 || count > 4 || rest.len() < count {
                return None;
            }
            let mut length = 0usize;
            for &byte in &rest[..count] {
                length = (length << 8) | usize::from(byte);
            }
            rest = &rest[count..];
            length
        };
        if rest.len() < length {
            return None;
        }
        Some(Tlv {
            tag,
            content: &rest[..length],
            rest: &rest[length..],
        })
    }

    pub fn children(content: &[u8]) -> Vec<Tlv<'_>> {
        let mut out = Vec::new();
        let mut rest = content;
        while !rest.is_empty() && out.len() < 64 {
            let Some(tlv) = read(rest) else { break };
            rest = tlv.rest;
            out.push(tlv);
        }
        out
    }

    pub fn oid_from_content(content: &[u8]) -> Option<String> {
        // accept either a full TLV (06 len ..) or bare content
        let content = match read(content) {
            Some(tlv) if tlv.tag == 0x06 && tlv.rest.is_empty() => tlv.content,
            _ => content,
        };
        let (&first, rest) = content.split_first()?;
        let mut arcs = vec![
            u64::from(first / 40).min(2),
            u64::from(first) - 40 * u64::from(first / 40).min(2),
        ];
        let mut value: u64 = 0;
        for &byte in rest {
            value = value.checked_shl(7)? | u64::from(byte & 0x7f);
            if byte & 0x80 == 0 {
                arcs.push(value);
                value = 0;
            }
        }
        Some(
            arcs.iter()
                .map(u64::to_string)
                .collect::<Vec<_>>()
                .join("."),
        )
    }

    /// Bit length of a positive DER INTEGER.
    pub fn integer_bits(content: &[u8]) -> Option<u32> {
        let trimmed: &[u8] = {
            let mut slice = content;
            while slice.len() > 1 && slice[0] == 0 {
                slice = &slice[1..];
            }
            slice
        };
        let first = *trimmed.first()?;
        Some((trimmed.len() as u32 - 1) * 8 + (8 - first.leading_zeros()))
    }

    /// Algorithm and key size from an AlgorithmIdentifier + key payload.
    fn algorithm(
        algorithm_identifier: &[u8],
        key_payload: Option<&[u8]>,
    ) -> Option<(AlgorithmRef, Option<u32>)> {
        let parts = children(algorithm_identifier);
        let oid = oid_from_content(parts.first().filter(|p| p.tag == 0x06)?.content)?;
        let registry = Registry::active();
        let mut reference = registry.by_oid(&oid)?;
        let mut bits = None;
        if let Some(parameter) = parts.get(1).filter(|p| p.tag == 0x06)
            && let Some(curve_oid) = oid_from_content(parameter.content)
            && let Some(curve) = registry.curve_by_oid(&curve_oid)
        {
            reference.params = Params {
                curve: Some(curve.name.clone()),
                ..reference.params
            };
        }
        if reference.id == "rsa"
            && let Some(payload) = key_payload
        {
            bits = rsa_public_bits(payload).or_else(|| rsa_pkcs1_private_bits(payload));
            reference.params.key_bits = bits;
        }
        Some((reference, bits))
    }

    /// SubjectPublicKeyInfo: SEQ { AlgorithmIdentifier, BIT STRING }.
    pub fn spki(der: &[u8]) -> Option<(AlgorithmRef, Option<u32>)> {
        let outer = read(der).filter(|t| t.tag == 0x30)?;
        let parts = children(outer.content);
        if parts.len() != 2 || parts[0].tag != 0x30 || parts[1].tag != 0x03 {
            return None;
        }
        let key = parts[1].content.get(1..);
        algorithm(parts[0].content, key)
    }

    /// PKCS#8 PrivateKeyInfo: SEQ { INTEGER version, AlgorithmIdentifier, OCTET STRING key }.
    pub fn pkcs8(der: &[u8]) -> Option<(AlgorithmRef, Option<u32>)> {
        let outer = read(der).filter(|t| t.tag == 0x30)?;
        let parts = children(outer.content);
        if parts.len() < 3 || parts[0].tag != 0x02 || parts[1].tag != 0x30 || parts[2].tag != 0x04 {
            return None;
        }
        algorithm(parts[1].content, Some(parts[2].content))
    }

    /// RSAPublicKey: SEQ { INTEGER modulus, INTEGER exponent }.
    pub fn rsa_public_bits(der: &[u8]) -> Option<u32> {
        let outer = read(der).filter(|t| t.tag == 0x30)?;
        let parts = children(outer.content);
        (parts.len() == 2 && parts[0].tag == 0x02)
            .then(|| integer_bits(parts[0].content))
            .flatten()
    }

    /// RSAPrivateKey (PKCS#1): SEQ { INTEGER 0, INTEGER modulus, ... }.
    pub fn rsa_pkcs1_private_bits(der: &[u8]) -> Option<u32> {
        let outer = read(der).filter(|t| t.tag == 0x30)?;
        let parts = children(outer.content);
        (parts.len() >= 3 && parts[1].tag == 0x02)
            .then(|| integer_bits(parts[1].content))
            .flatten()
    }

    /// ECPrivateKey (SEC 1): SEQ { INTEGER 1, OCTET STRING, [0] OID curve, [1] pubkey }.
    pub fn sec1_curve(der: &[u8]) -> Option<String> {
        let outer = read(der).filter(|t| t.tag == 0x30)?;
        children(outer.content)
            .into_iter()
            .find(|part| part.tag == 0xa0)
            .and_then(|parameters| oid_from_content(parameters.content))
    }
}

/// OpenSSH key formats (RFC 4253 §6.6 public blobs, PROTOCOL.key private keys).
pub(crate) mod ssh {
    use lattice_core::{AlgorithmRef, Params};

    pub struct PrivateKey {
        pub algorithm: (Option<AlgorithmRef>, Option<u32>),
        pub encrypted: bool,
        pub public_blob: Vec<u8>,
    }

    pub fn is_key_type(field: &str) -> bool {
        field.starts_with("ssh-") || field.starts_with("ecdsa-sha2-") || field.starts_with("sk-")
    }

    fn string(input: &[u8]) -> Option<(&[u8], &[u8])> {
        let length = u32::from_be_bytes(input.get(..4)?.try_into().ok()?) as usize;
        let data = input.get(4..4 + length)?;
        Some((data, &input[4 + length..]))
    }

    pub fn parse_public_blob(blob: &[u8]) -> Option<(Option<AlgorithmRef>, Option<u32>)> {
        let (key_type, rest) = string(blob)?;
        let key_type = std::str::from_utf8(key_type).ok()?;
        Some(match key_type {
            "ssh-rsa" => {
                let (_exponent, rest) = string(rest)?;
                let (modulus, _) = string(rest)?;
                let bits = super::der::integer_bits(modulus);
                (
                    Some(AlgorithmRef::with_params(
                        "rsa",
                        Params {
                            key_bits: bits,
                            ..Params::default()
                        },
                    )),
                    bits,
                )
            }
            "ssh-dss" => (Some(AlgorithmRef::new("dsa")), Some(1024)),
            "ssh-ed25519" | "sk-ssh-ed25519@openssh.com" => {
                (Some(AlgorithmRef::new("ed25519")), Some(256))
            }
            "ssh-ed448" => (Some(AlgorithmRef::new("ed448")), Some(456)),
            other if other.starts_with("ecdsa-sha2-") || other.starts_with("sk-ecdsa-sha2-") => {
                let curve = lattice_core::names::resolve_curve(
                    other
                        .trim_start_matches("sk-")
                        .trim_start_matches("ecdsa-sha2-")
                        .split('@')
                        .next()
                        .unwrap_or(""),
                );
                (
                    Some(AlgorithmRef::with_params(
                        "ecdsa",
                        Params {
                            curve,
                            ..Params::default()
                        },
                    )),
                    None,
                )
            }
            _ => (None, None),
        })
    }

    pub fn parse_private(blob: &[u8]) -> Option<PrivateKey> {
        let rest = blob.strip_prefix(b"openssh-key-v1\0")?;
        let (cipher, rest) = string(rest)?;
        let (_kdf, rest) = string(rest)?;
        let (_kdf_options, rest) = string(rest)?;
        let count = u32::from_be_bytes(rest.get(..4)?.try_into().ok()?);
        if count == 0 {
            return None;
        }
        let (public_blob, _) = string(&rest[4..])?;
        Some(PrivateKey {
            algorithm: parse_public_blob(public_blob)?,
            encrypted: cipher != b"none",
            public_blob: public_blob.to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    // A real self-signed RSA-2048 / SHA-256 certificate (CN=lattice-test, 2025-01-01..2035-01-01).
    const CERT_PEM: &str = include_str!("../tests/fixtures/rsa2048-sha256.pem");
    const EC_KEY_PEM: &str = include_str!("../tests/fixtures/ec-p384-key.pem");
    const RSA1024_KEY_PEM: &str = include_str!("../tests/fixtures/rsa1024-key.pem");
    const SSH_ED25519: &str = include_str!("../tests/fixtures/id_ed25519.pub");

    fn run(path: &str, bytes: &[u8]) -> Findings {
        let artifact = Artifact {
            path,
            component: ".",
            bytes,
        };
        let collector = PkiCollector::new();
        assert!(collector.accepts(path, &bytes[..bytes.len().min(512)]));
        let mut findings = Findings::default();
        collector
            .collect(
                &artifact,
                &Deadline::after(Duration::from_secs(5)),
                &mut findings,
            )
            .unwrap();
        findings
    }

    #[test]
    fn certificates_yield_key_and_signature_algorithms() {
        let findings = run("tls/server.crt", CERT_PEM.as_bytes());
        let certificate = findings
            .observations
            .iter()
            .find_map(|o| match &o.finding {
                Finding::Certificate(c) => Some(c.clone()),
                _ => None,
            })
            .expect("certificate parsed");
        assert_eq!(certificate.public_key.id, "rsa");
        assert_eq!(certificate.public_key.params.key_bits, Some(2048));
        assert_eq!(certificate.signature.id, "rsa");
        assert_eq!(
            certificate.signature.params.digest.as_deref(),
            Some("sha-256")
        );
        assert!(certificate.self_signed);
        assert!(certificate.subject.contains("lattice-test"));
        assert_eq!(certificate.fingerprint_sha256.len(), 64);
        assert!(certificate.not_after.starts_with("2035-"));
    }

    #[test]
    fn private_keys_record_type_and_size_never_bytes() {
        let findings = run("keys/server.key", RSA1024_KEY_PEM.as_bytes());
        let Finding::RelatedCryptoMaterial(material) = &findings.observations[0].finding else {
            panic!()
        };
        assert_eq!(material.material_type, MaterialType::PrivateKey);
        assert_eq!(material.size_bits, Some(1024));
        assert!(!material.encrypted);
        let serialized = serde_json::to_string(&findings.observations).unwrap();
        let body: String = RSA1024_KEY_PEM
            .lines()
            .filter(|l| !l.starts_with("-----"))
            .collect();
        assert!(
            !serialized.contains(&body[..40]),
            "key material must never appear in findings"
        );
    }

    #[test]
    fn ec_keys_resolve_their_curve() {
        let findings = run("keys/signing.pem", EC_KEY_PEM.as_bytes());
        let Finding::RelatedCryptoMaterial(material) = &findings.observations[0].finding else {
            panic!()
        };
        assert_eq!(
            material.algorithm.as_ref().unwrap().params.curve.as_deref(),
            Some("P-384")
        );
    }

    #[test]
    fn ssh_public_keys() {
        let findings = run("home/.ssh/id_ed25519.pub", SSH_ED25519.as_bytes());
        let Finding::RelatedCryptoMaterial(material) = &findings.observations[0].finding else {
            panic!()
        };
        assert_eq!(material.algorithm.as_ref().unwrap().id, "ed25519");
    }

    #[test]
    fn keystores_are_reported_without_opening_them() {
        let findings = run("conf/app.p12", &[0x30, 0x82, 0x01, 0x00, 1, 2, 3]);
        let Finding::RelatedCryptoMaterial(material) = &findings.observations[0].finding else {
            panic!()
        };
        assert!(material.encrypted);
        assert_eq!(material.format, "PKCS12");
    }

    #[test]
    fn garbage_in_pem_armour_is_ignored() {
        let findings = run(
            "x.pem",
            b"-----BEGIN CERTIFICATE-----\nnot base64 at all!!\n-----END CERTIFICATE-----\n",
        );
        assert!(findings.observations.is_empty());
    }
}
