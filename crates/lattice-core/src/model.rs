//! What collectors report and what normalisation turns it into.
//!
//! Collectors emit [`Observation`]s: one sighting of cryptography at one location, with the
//! evidence for it. Normalisation groups observations into [`CryptoAsset`]s: one asset per
//! distinct cryptographic thing in one component, carrying every place it was seen. Everything
//! downstream (graph, risk, CBOM) works on assets.

use crate::knowledge::{AlgorithmRef, CryptoFunction, Primitive, Registry};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Where an observation came from. Determines which evidence layer it counts towards.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Surface {
    Source,
    Binary,
    Container,
    Certificate,
    Config,
    Cloud,
    Runtime,
}

impl Surface {
    /// Independent layers of evidence. Agreement between layers is what the grade measures:
    /// two artefact collectors seeing the same file is one layer, not two.
    pub fn layer(self) -> EvidenceLayer {
        match self {
            Self::Source => EvidenceLayer::SourceCode,
            Self::Binary | Self::Container | Self::Certificate | Self::Config | Self::Cloud => {
                EvidenceLayer::Artifact
            }
            Self::Runtime => EvidenceLayer::Runtime,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Source => "source",
            Self::Binary => "binary",
            Self::Container => "container",
            Self::Certificate => "certificate",
            Self::Config => "config",
            Self::Cloud => "cloud",
            Self::Runtime => "runtime",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EvidenceLayer {
    SourceCode,
    Artifact,
    Runtime,
}

impl EvidenceLayer {
    pub fn describe(self) -> &'static str {
        match self {
            Self::SourceCode => "source code",
            Self::Artifact => "a built or deployed artefact",
            Self::Runtime => "live runtime",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Location {
    /// Slash-normalised path relative to the scan root; never an absolute host path. Paths
    /// inside archives and images use `outer!/inner`, e.g. `app.jar!/com/x/Crypto.class`.
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub column: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub byte_offset: Option<u64>,
}

impl Location {
    pub fn file(path: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            line: None,
            column: None,
            byte_offset: None,
        }
    }

    pub fn at_line(path: impl Into<String>, line: u64, column: u64) -> Self {
        Self {
            path: path.into(),
            line: Some(line),
            column: Some(column),
            byte_offset: None,
        }
    }

    pub fn at_offset(path: impl Into<String>, offset: u64) -> Self {
        Self {
            path: path.into(),
            line: None,
            column: None,
            byte_offset: Some(offset),
        }
    }

    /// `path:line` or `path@0xoffset`, for human-readable reasons.
    pub fn short(&self) -> String {
        match (self.line, self.byte_offset) {
            (Some(line), _) => format!("{}:{line}", self.path),
            (None, Some(offset)) => format!("{}@{offset:#x}", self.path),
            _ => self.path.clone(),
        }
    }
}

/// How a collector knows what it reports, strongest first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EvidenceKind {
    /// Observed in a live protocol exchange or runtime hook.
    Handshake,
    /// A call to a cryptographic API, confirmed on the syntax tree.
    ApiCall,
    /// Parsed from an X.509 certificate or key structure.
    Certificate,
    /// A setting in a configuration file that selects the algorithm.
    Configuration,
    /// A resource attribute in infrastructure-as-code.
    Infrastructure,
    /// An imported or exported symbol in a compiled binary's symbol tables.
    Symbol,
    /// An algorithm OID found encoded in data.
    Oid,
    /// A known constant table (S-box, round constants) in binary data.
    ByteSignature,
    /// An import of a cryptographic module or package with no call observed.
    Import,
    /// A textual match that could not be confirmed structurally.
    Heuristic,
    /// A call into a cryptographic library observed on a running system (`lattice trace`).
    Trace,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Evidence {
    pub collector: String,
    pub rule_id: String,
    pub rule_version: String,
    pub kind: EvidenceKind,
    /// The matched API, symbol or directive only. Source lines and values that could be
    /// secrets are never retained (security.md §4).
    pub matched_token: String,
}

/// Where the algorithm choice in a source-level call comes from. Drives crypto-agility.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AlgorithmSource {
    /// Written as a literal at the call site: `Cipher.getInstance("AES/GCM/NoPadding")`.
    Literal,
    /// Taken from a named constant in the same file: `getInstance(CIPHER_NAME)`.
    Constant,
    /// Implied by the API itself: `EVP_aes_256_gcm()`, `hashlib.sha1(...)`.
    Implicit,
    /// Supplied at runtime (a variable, parameter or configuration lookup): swappable without
    /// a code change.
    Dynamic,
}

/// The shape of the API through which cryptography is used. Drives crypto-agility.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ApiStyle {
    /// A provider interface that selects the algorithm by name (JCA, OpenSSL EVP, Go `crypto`
    /// interfaces, WebCrypto): swapping algorithms is a parameter change.
    Provider,
    /// A primitive-specific API (`RSA_public_encrypt`, `AES_encrypt`, `hashlib.sha1`): swapping
    /// algorithms means rewriting the call.
    Primitive,
    /// A protocol stack that negotiates algorithms (TLS, SSH, JOSE libraries).
    Protocol,
}

/// Source-level context around a cryptographic call, used by the classifier (what data does
/// it touch), the graph (which function is it in) and crypto-agility (how hard to change).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Usage {
    pub language: String,
    /// The call as written, e.g. `Cipher.getInstance`.
    pub api: String,
    /// Graph id of the enclosing function, when the call is inside one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub function: Option<String>,
    /// Identifier names passed to the call or bound to its result. Names only, never values.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub identifiers: Vec<String>,
    pub algorithm_source: AlgorithmSource,
    pub api_style: ApiStyle,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AlgorithmFinding {
    pub algorithm: AlgorithmRef,
    /// Primitive when the use pins one (RSA used for signing rather than encryption).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub primitive: Option<Primitive>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub function: Option<CryptoFunction>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificateFinding {
    pub subject: String,
    pub issuer: String,
    /// RFC 3339 timestamps.
    pub not_before: String,
    pub not_after: String,
    pub serial: String,
    pub public_key: AlgorithmRef,
    pub signature: AlgorithmRef,
    pub self_signed: bool,
    pub is_ca: bool,
    /// Lowercase hex SHA-256 of the DER encoding: identifies the certificate across files.
    pub fingerprint_sha256: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProtocolKind {
    Tls,
    Dtls,
    Ssh,
    Ipsec,
    Other,
}

impl ProtocolKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tls => "tls",
            Self::Dtls => "dtls",
            Self::Ssh => "ssh",
            Self::Ipsec => "ipsec",
            Self::Other => "other",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProtocolFinding {
    pub protocol: ProtocolKind,
    /// `1.2`, `1.3`, `2.0`; `None` when only algorithms were configured.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Suite names as configured or negotiated (IANA naming where known).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cipher_suites: Vec<String>,
    /// Key-exchange groups offered or selected (`x25519`, `X25519MLKEM768`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub groups: Vec<String>,
}

/// CycloneDX `relatedCryptoMaterialProperties.type`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MaterialType {
    PrivateKey,
    PublicKey,
    SecretKey,
    Key,
    Password,
    Credential,
    Token,
    Other,
}

/// Where a key is held when it is not a file LATTICE can read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CustodyKind {
    /// A PKCS#11 token: a hardware security module, a smart card, or a software token such as
    /// SoftHSM. A reference alone does not say which.
    Pkcs11Token,
    /// A Trusted Platform Module: the key is wrapped by, or sealed to, the TPM.
    Tpm,
    /// A cloud provider's HSM-backed key service.
    CloudHsm,
    /// A cloud provider's software-protected key management service.
    CloudKms,
}

impl CustodyKind {
    /// CycloneDX `securedBy.mechanism`.
    pub fn mechanism(self) -> &'static str {
        match self {
            Self::Pkcs11Token => "PKCS#11 token",
            Self::Tpm => "TPM",
            Self::CloudHsm => "cloud HSM",
            Self::CloudKms => "cloud KMS",
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pkcs11Token => "pkcs11-token",
            Self::Tpm => "tpm",
            Self::CloudHsm => "cloud-hsm",
            Self::CloudKms => "cloud-kms",
        }
    }
}

/// What a held key is permitted to do, when the device or service records it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum KeyUsage {
    Sign,
    Encrypt,
}

/// A key held in hardware or a key service, and what identifies it there.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Custody {
    pub kind: CustodyKind,
    /// e.g. `PKCS#11 token "prod-ca", object "tls"`. Never a PIN or secret.
    pub detail: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usage: Option<KeyUsage>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MaterialFinding {
    pub material_type: MaterialType,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub algorithm: Option<AlgorithmRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size_bits: Option<u32>,
    /// `PEM`, `DER`, `OpenSSH`, `PKCS12`, `JKS`.
    pub format: String,
    /// Whether the material is protected at rest (an encrypted PEM or keystore).
    pub encrypted: bool,
    /// Stable, non-reversible identity of the material (BLAKE3 over the public part or the
    /// container), so the same key in two files is one asset. Never the key itself.
    pub identity: String,
    /// Set when the key lives in an HSM, a TPM or a key service and is only referenced here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custody: Option<Custody>,
}

/// What an observation saw. Variants map one-to-one onto CycloneDX `assetType`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(tag = "assetType", rename_all = "kebab-case")]
#[expect(
    clippy::large_enum_variant,
    reason = "certificates are rare next to algorithms and a few hundred bytes each; boxing would               complicate every constructor and pattern for no measurable gain"
)]
pub enum Finding {
    Algorithm(AlgorithmFinding),
    Certificate(CertificateFinding),
    Protocol(ProtocolFinding),
    RelatedCryptoMaterial(MaterialFinding),
}

impl Finding {
    pub fn algorithm(algorithm: AlgorithmRef) -> Self {
        Self::Algorithm(AlgorithmFinding {
            algorithm,
            primitive: None,
            function: None,
        })
    }

    pub fn asset_type(&self) -> &'static str {
        match self {
            Self::Algorithm(_) => "algorithm",
            Self::Certificate(_) => "certificate",
            Self::Protocol(_) => "protocol",
            Self::RelatedCryptoMaterial(_) => "related-crypto-material",
        }
    }

    /// Algorithms this finding depends on (a certificate's key and signature, a material's key
    /// type). Normalisation turns each into its own asset so nothing is inventoried twice.
    pub fn dependencies(&self) -> Vec<AlgorithmRef> {
        match self {
            // A signature's digest is a hash use in its own right (collisions forge signatures).
            // Inside HMAC, HKDF or PBKDF2 it is part of the construction, where collision attacks
            // do not apply, so it is a parameter, not a separate asset.
            Self::Algorithm(finding) => {
                let primitive = finding.primitive.or_else(|| {
                    crate::Registry::active()
                        .get(&finding.algorithm.id)
                        .map(|spec| spec.primitive)
                });
                if matches!(
                    primitive,
                    Some(crate::Primitive::Mac | crate::Primitive::Kdf | crate::Primitive::Drbg)
                ) {
                    return Vec::new();
                }
                finding
                    .algorithm
                    .params
                    .digest
                    .iter()
                    .map(|digest| AlgorithmRef::new(digest.clone()))
                    .collect()
            }
            Self::Certificate(certificate) => {
                let mut algorithms = vec![
                    certificate.public_key.clone(),
                    certificate.signature.clone(),
                ];
                if let Some(digest) = &certificate.signature.params.digest {
                    algorithms.push(AlgorithmRef::new(digest.clone()));
                }
                algorithms
            }
            Self::Protocol(_) => Vec::new(),
            Self::RelatedCryptoMaterial(material) => material.algorithm.iter().cloned().collect(),
        }
    }

    /// Human-readable name for inventories and reasons.
    pub fn display_name(&self) -> String {
        match self {
            Self::Algorithm(finding) => finding.algorithm.to_string(),
            Self::Certificate(certificate) => format!("X.509 {}", certificate.subject),
            Self::Protocol(protocol) => match &protocol.version {
                Some(version) => format!(
                    "{} {version}",
                    protocol.protocol.as_str().to_ascii_uppercase()
                ),
                None => protocol.protocol.as_str().to_ascii_uppercase(),
            },
            Self::RelatedCryptoMaterial(material) => {
                let kind = serde_json::to_value(material.material_type)
                    .ok()
                    .and_then(|value| value.as_str().map(str::to_owned))
                    .unwrap_or_else(|| "key".into());
                match &material.algorithm {
                    Some(algorithm) => format!("{algorithm} {kind}"),
                    None => kind,
                }
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Observation {
    pub surface: Surface,
    /// Logical owner: the directory of the nearest build manifest, or the image name. Assets
    /// are per component, because each component migrates separately.
    pub component: String,
    pub location: Location,
    pub finding: Finding,
    pub evidence: Evidence,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usage: Option<Usage>,
}

/// How entry points are reached from outside the component.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EntryKind {
    /// An HTTP/RPC handler bound by a web framework.
    HttpRoute,
    /// A process entry point (`main`).
    Main,
    /// A function exported from a library for other components to call.
    LibraryExport,
    /// A network listener configured outside code (a TLS server block, an sshd).
    Listener,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EntryPoint {
    pub kind: EntryKind,
    /// What made this an entry point, e.g. `@app.route("/pay", methods=["POST"])`.
    pub detail: String,
}

/// A function definition seen by a source collector.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FunctionFact {
    /// `component::path::Qualified.name`, unique within a scan.
    pub id: String,
    pub component: String,
    pub name: String,
    pub location: Location,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entry: Option<EntryPoint>,
    /// Parameter names, used by the classifier alongside argument identifiers.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub parameters: Vec<String>,
    /// File names this entry point presents to clients: the certificates and keys a TLS
    /// listener's configuration references (`ssl_certificate`, `SSLCertificateKeyFile`, ...).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub serves: Vec<String>,
    /// Host names a TLS listener answers to (`server_name`, `ServerName`, `ServerAlias`), so
    /// handshakes observed in traffic can be attributed to it.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hosts: Vec<String>,
}

/// A framework registration that makes a named function an entry point, e.g.
/// `http.HandleFunc("/pay", pay)` or `.route("/pay", post(pay))`. The handler is a name; the
/// graph resolves it to a [`FunctionFact`].
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EntryBinding {
    pub component: String,
    /// File the registration appears in; handlers resolve preferentially within it.
    pub file: String,
    pub handler: String,
    pub entry: EntryPoint,
    pub location: Location,
}

/// A cryptographic library identified in an artefact (by version string or soname), and whether
/// that version can do post-quantum cryptography. Feeds the crypto-agility score: migrating is
/// cheap when the library already in use ships the replacement.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LibraryFact {
    pub component: String,
    pub location: Location,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Whether this version ships standardised PQC (ML-KEM / ML-DSA), per `knowledge/libraries.toml`.
    pub pqc_capable: bool,
    /// Where the judgement comes from, e.g. `OpenSSL >= 3.5.0 ships ML-KEM, ML-DSA, SLH-DSA`.
    pub basis: String,
}

/// A call from one function to another, by name. The graph resolves names to definitions.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CallFact {
    pub caller: String,
    /// The callee as written, final segment only (`encrypt_card`, `cardCipher`).
    pub callee: String,
    pub location: Location,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Liveness {
    /// A present library or binary could perform it.
    Capable,
    /// Code or configuration explicitly selects it.
    Configured,
    /// It is exercised: observed at runtime, or reachable from an entry point.
    Confirmed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum EvidenceGrade {
    A,
    B,
    C,
    D,
}

/// One place an asset was seen.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Occurrence {
    pub surface: Surface,
    pub location: Location,
    pub evidence: Evidence,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usage: Option<Usage>,
    /// Set when this occurrence saw less than the asset records and was attributed to it,
    /// e.g. a bare `AES` in source attributed to the only concrete AES in the component.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refined_from: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CryptoAsset {
    /// Stable CycloneDX `bom-ref`.
    pub id: String,
    pub component: String,
    pub finding: Finding,
    pub occurrences: Vec<Occurrence>,
    pub surfaces: BTreeSet<Surface>,
    pub liveness: Liveness,
    pub liveness_reason: String,
    pub evidence_grade: EvidenceGrade,
    pub grade_reason: String,
    /// bom-refs of the algorithm assets this asset depends on.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub depends_on: Vec<String>,
}

impl CryptoAsset {
    pub fn algorithm(&self) -> Option<&AlgorithmRef> {
        match &self.finding {
            Finding::Algorithm(finding) => Some(&finding.algorithm),
            _ => None,
        }
    }

    pub fn usages(&self) -> impl Iterator<Item = &Usage> {
        self.occurrences
            .iter()
            .filter_map(|occurrence| occurrence.usage.as_ref())
    }

    /// Raises liveness to `Confirmed` with the reason, used when the graph proves reachability.
    pub fn confirm(&mut self, reason: impl Into<String>) {
        if self.liveness < Liveness::Confirmed {
            self.liveness = Liveness::Confirmed;
            self.liveness_reason = reason.into();
        }
    }
}

/// Resolves an algorithm's display name through the registry.
pub fn algorithm_name(id: &str) -> String {
    Registry::active()
        .get(id)
        .map_or_else(|| id.to_owned(), |spec| spec.name.clone())
}
