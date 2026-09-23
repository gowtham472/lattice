//! The algorithm knowledge base: what every algorithm is, how strong it is classically, and how
//! a quantum adversary affects it.
//!
//! The catalogue is data (`knowledge/algorithms.toml`), embedded at build time and versioned so
//! every report records exactly which knowledge produced it. Code here only interprets the data;
//! no algorithm judgement is hard-coded outside the catalogue.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::sync::OnceLock;

const EMBEDDED_ALGORITHMS: &str = include_str!("../../../knowledge/algorithms.toml");

/// CycloneDX 1.6 `algorithmProperties.primitive`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Primitive {
    Drbg,
    Mac,
    BlockCipher,
    StreamCipher,
    Signature,
    Hash,
    Pke,
    Xof,
    Kdf,
    KeyAgree,
    Kem,
    Ae,
    Combiner,
    Other,
    Unknown,
}

impl Primitive {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Drbg => "drbg",
            Self::Mac => "mac",
            Self::BlockCipher => "block-cipher",
            Self::StreamCipher => "stream-cipher",
            Self::Signature => "signature",
            Self::Hash => "hash",
            Self::Pke => "pke",
            Self::Xof => "xof",
            Self::Kdf => "kdf",
            Self::KeyAgree => "key-agree",
            Self::Kem => "kem",
            Self::Ae => "ae",
            Self::Combiner => "combiner",
            Self::Other => "other",
            Self::Unknown => "unknown",
        }
    }
}

/// CycloneDX 1.6 `algorithmProperties.cryptoFunctions`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CryptoFunction {
    Generate,
    Keygen,
    Encrypt,
    Decrypt,
    Digest,
    Tag,
    Keyderive,
    Sign,
    Verify,
    Encapsulate,
    Decapsulate,
    Other,
    Unknown,
}

/// How a quantum adversary affects an algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum QuantumClass {
    /// Broken outright by Shor's algorithm (integer factoring and discrete logarithms).
    Shor,
    /// Generic quantum search: effective security roughly halves; larger keys restore margin.
    Grover,
    /// Designed and standardised to resist known quantum attacks.
    PostQuantum,
}

/// Classical standing today, independent of any quantum computer. Ordered by severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ClassicalStatus {
    Acceptable,
    Legacy,
    Disallowed,
    Broken,
}

impl ClassicalStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Acceptable => "acceptable",
            Self::Legacy => "legacy",
            Self::Disallowed => "disallowed",
            Self::Broken => "broken",
        }
    }
}

/// How classical security strength is derived for an algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SecurityModel {
    KeyBits,
    IntegerFactoring,
    Curve,
    Fixed,
    HashOutput,
    ParameterSet,
    Digest,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParameterSetSpec {
    pub name: String,
    #[serde(default)]
    pub aliases: Vec<String>,
    pub nist_level: u8,
    pub strength: u32,
    #[serde(default)]
    pub public_key_bytes: Option<u32>,
    #[serde(default)]
    pub ciphertext_bytes: Option<u32>,
    #[serde(default)]
    pub signature_bytes: Option<u32>,
    #[serde(default)]
    pub oid: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidMapping {
    pub oid: String,
    #[serde(default)]
    pub key_bits: Option<u32>,
    #[serde(default)]
    pub mode: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlgorithmSpec {
    pub id: String,
    pub name: String,
    pub family: String,
    pub primitive: Primitive,
    #[serde(default)]
    pub functions: Vec<CryptoFunction>,
    pub quantum: QuantumClass,
    pub classical: ClassicalStatus,
    pub security: SecurityModel,
    #[serde(default)]
    pub strength: Option<u32>,
    #[serde(default)]
    pub output_bits: Option<u32>,
    #[serde(default)]
    pub min_key_bits: Option<u32>,
    #[serde(default)]
    pub key_bits: Vec<u32>,
    #[serde(default)]
    pub modes: Vec<String>,
    #[serde(default)]
    pub weak_modes: Vec<String>,
    #[serde(default)]
    pub curve: Option<String>,
    #[serde(default)]
    pub nist_level: Option<u8>,
    #[serde(default)]
    pub public_key_bytes: Option<u32>,
    #[serde(default)]
    pub ciphertext_bytes: Option<u32>,
    #[serde(default)]
    pub aliases: Vec<String>,
    #[serde(default)]
    pub oids: Vec<String>,
    #[serde(default)]
    pub oid_map: Vec<OidMapping>,
    #[serde(default)]
    pub parameter_set: Vec<ParameterSetSpec>,
    /// Recommended replacement per usage role (`signature`, `encryption`, `key-agreement`, `digest`).
    #[serde(default)]
    pub replacement: BTreeMap<String, String>,
    #[serde(default)]
    pub standard: Option<String>,
    #[serde(default)]
    pub note: Option<String>,
}

impl AlgorithmSpec {
    pub fn parameter_set(&self, name: &str) -> Option<&ParameterSetSpec> {
        let wanted = normalize_token(name);
        self.parameter_set.iter().find(|set| {
            normalize_token(&set.name) == wanted
                || set
                    .aliases
                    .iter()
                    .any(|alias| normalize_token(alias) == wanted)
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CurveSpec {
    pub name: String,
    #[serde(default)]
    pub aliases: Vec<String>,
    pub strength: u32,
    #[serde(default)]
    pub oid: Option<String>,
    pub classical: ClassicalStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CompositeOid {
    oid: String,
    algorithm: String,
    digest: String,
}

#[derive(Debug, Deserialize)]
struct Catalogue {
    version: String,
    algorithm: Vec<AlgorithmSpec>,
    #[serde(default)]
    curve: Vec<CurveSpec>,
    #[serde(default)]
    composite_oid: Vec<CompositeOid>,
}

/// Cryptographic parameters observed alongside an algorithm. Every field is optional because
/// collectors frequently see only part of the picture (an API name without a key size, say).
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Params {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_bits: Option<u32>,
    /// PQC parameter set (`768`, `65`, `sha2-128s`) or a named DH group.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parameter_set: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub curve: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub padding: Option<String>,
    /// Digest bound into a composite algorithm (RSA-PSS with SHA-256, HMAC-SHA256).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
}

impl Params {
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }

    /// Fills unset fields from `other` without overwriting what is already known.
    pub fn fill_from(&mut self, other: &Params) {
        self.key_bits = self.key_bits.or(other.key_bits);
        if self.parameter_set.is_none() {
            self.parameter_set.clone_from(&other.parameter_set);
        }
        if self.curve.is_none() {
            self.curve.clone_from(&other.curve);
        }
        if self.mode.is_none() {
            self.mode.clone_from(&other.mode);
        }
        if self.padding.is_none() {
            self.padding.clone_from(&other.padding);
        }
        if self.digest.is_none() {
            self.digest.clone_from(&other.digest);
        }
    }
}

/// An algorithm identified in the catalogue together with what is known about its parameters.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct AlgorithmRef {
    pub id: String,
    #[serde(default, skip_serializing_if = "Params::is_empty")]
    pub params: Params,
}

impl AlgorithmRef {
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            params: Params::default(),
        }
    }

    pub fn with_params(id: impl Into<String>, params: Params) -> Self {
        Self {
            id: id.into(),
            params,
        }
    }
}

impl fmt::Display for AlgorithmRef {
    /// CycloneDX-style names: parameters joined by hyphens (`AES-256-GCM`, `RSA-2048`,
    /// `ML-KEM-768`, `ECDSA-P-256`), then padding and digest in parentheses
    /// (`RSA-2048 (OAEP, SHA-256)`).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let registry = Registry::active();
        let display = |id: &str| {
            registry
                .get(id)
                .map_or_else(|| id.to_owned(), |spec| spec.name.clone())
        };
        let params = &self.params;
        let mut name = display(&self.id);
        let bits = params.key_bits.map(|bits| bits.to_string());
        let mode = params.mode.as_ref().map(|mode| mode.to_ascii_uppercase());
        for part in [&bits, &params.parameter_set, &params.curve, &mode]
            .into_iter()
            .flatten()
        {
            // a parameter set spelled `ML-KEM-768` already carries the algorithm name
            if part
                .to_ascii_lowercase()
                .starts_with(&name.to_ascii_lowercase())
            {
                name.clone_from(part);
            } else {
                name.push('-');
                name.push_str(part);
            }
        }
        let extras: Vec<String> = [
            params.padding.as_deref().and_then(padding_name),
            params.digest.as_deref().map(display),
        ]
        .into_iter()
        .flatten()
        .collect();
        if extras.is_empty() {
            f.write_str(&name)
        } else {
            write!(f, "{name} ({})", extras.join(", "))
        }
    }
}

/// Conventional spelling of a padding scheme; `None` for "no padding", which is not worth naming.
fn padding_name(padding: &str) -> Option<String> {
    let key = padding.to_ascii_lowercase().replace(['-', '_', ' '], "");
    let key = key.strip_suffix("padding").unwrap_or(&key);
    Some(
        match key {
            "" | "no" | "none" | "raw" => return None,
            "pkcs5" => "PKCS5",
            "pkcs7" => "PKCS7",
            "pkcs1" | "pkcs1v15" | "pkcs1v1.5" => "PKCS1v15",
            "oaep" => "OAEP",
            "pss" => "PSS",
            "iso10126" => "ISO10126",
            _ => return Some(padding.to_owned()),
        }
        .to_owned(),
    )
}

/// Classical and quantum standing of one concrete algorithm use, with the reason for each call.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Strength {
    /// Classical security strength in bits, when it can be derived from what was observed.
    pub classical_bits: Option<u32>,
    pub classical_status: ClassicalStatus,
    /// NIST PQC security category 0-5 (CycloneDX `nistQuantumSecurityLevel`).
    pub nist_quantum_level: u8,
    pub quantum: QuantumClass,
    /// Why `classical_status` is what it is, in words an auditor can check.
    pub reasons: Vec<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum KnowledgeError {
    #[error("algorithm catalogue is not valid TOML: {0}")]
    Parse(String),
    #[error("algorithm catalogue is inconsistent: {0}")]
    Inconsistent(String),
    #[error("the knowledge in use was already fixed before a bundle could be activated")]
    AlreadyActive,
}

/// One way a name can begin: an algorithm alias, or an alphabetic parameter-set alias such as
/// `kyber768` that names an algorithm and its parameters at once.
#[derive(Debug, Clone)]
struct PrefixEntry {
    alias: String,
    algorithm: usize,
    parameter_set: Option<usize>,
}

/// Indexed, read-only view of the catalogue.
#[derive(Debug)]
pub struct Registry {
    version: String,
    algorithms: Vec<AlgorithmSpec>,
    curves: Vec<CurveSpec>,
    by_id: HashMap<String, usize>,
    by_alias: HashMap<String, usize>,
    by_oid: HashMap<String, (usize, Params)>,
    curve_by_alias: HashMap<String, usize>,
    curve_by_oid: HashMap<String, usize>,
    /// Every normalised alias, longest first, for prefix parsing of compound names.
    prefixes: Vec<PrefixEntry>,
    /// Normalised hash/XOF aliases, longest first.
    digests: Vec<(String, usize)>,
}

/// The catalogue every lookup uses: a verified knowledge bundle activated at startup, or the
/// catalogue compiled into this binary.
static ACTIVE: OnceLock<Registry> = OnceLock::new();

impl Registry {
    /// The active catalogue. Loaded and validated once; compiled in unless [`Registry::activate`]
    /// installed a bundle's catalogue first.
    pub fn active() -> &'static Registry {
        ACTIVE.get_or_init(Registry::compiled)
    }

    /// The catalogue compiled into this binary.
    pub fn compiled() -> Registry {
        Registry::from_toml(EMBEDDED_ALGORITHMS)
            .unwrap_or_else(|error| panic!("embedded algorithm catalogue is invalid: {error}"))
    }

    /// Makes `registry` the active catalogue. Only possible before the first lookup, so one
    /// process never mixes two catalogues.
    pub fn activate(registry: Registry) -> Result<(), KnowledgeError> {
        ACTIVE
            .set(registry)
            .map_err(|_| KnowledgeError::AlreadyActive)
    }

    pub fn from_toml(source: &str) -> Result<Self, KnowledgeError> {
        let catalogue: Catalogue =
            toml::from_str(source).map_err(|error| KnowledgeError::Parse(error.to_string()))?;
        Self::index(catalogue)
    }

    fn index(catalogue: Catalogue) -> Result<Self, KnowledgeError> {
        let mut by_id = HashMap::new();
        let mut by_alias = HashMap::new();
        let mut by_oid = HashMap::new();
        for (index, spec) in catalogue.algorithm.iter().enumerate() {
            if by_id.insert(spec.id.clone(), index).is_some() {
                return Err(KnowledgeError::Inconsistent(format!(
                    "duplicate id `{}`",
                    spec.id
                )));
            }
            for alias in spec.aliases.iter().chain([&spec.id, &spec.name]) {
                let key = normalize_token(alias);
                if let Some(previous) = by_alias.insert(key.clone(), index)
                    && previous != index
                {
                    return Err(KnowledgeError::Inconsistent(format!(
                        "alias `{alias}` names both `{}` and `{}`",
                        catalogue.algorithm[previous].id, spec.id
                    )));
                }
            }
            for oid in &spec.oids {
                by_oid.insert(oid.clone(), (index, Params::default()));
            }
            for mapping in &spec.oid_map {
                let params = Params {
                    key_bits: mapping.key_bits,
                    mode: mapping.mode.clone(),
                    ..Params::default()
                };
                by_oid.insert(mapping.oid.clone(), (index, params));
            }
            for set in &spec.parameter_set {
                if let Some(oid) = &set.oid {
                    let params = Params {
                        parameter_set: Some(set.name.clone()),
                        ..Params::default()
                    };
                    by_oid.insert(oid.clone(), (index, params));
                }
            }
        }
        for composite in &catalogue.composite_oid {
            let &index = by_id.get(&composite.algorithm).ok_or_else(|| {
                KnowledgeError::Inconsistent(format!(
                    "composite OID {} names unknown algorithm `{}`",
                    composite.oid, composite.algorithm
                ))
            })?;
            if !by_id.contains_key(&composite.digest) {
                return Err(KnowledgeError::Inconsistent(format!(
                    "composite OID {} names unknown digest `{}`",
                    composite.oid, composite.digest
                )));
            }
            let params = Params {
                digest: Some(composite.digest.clone()),
                ..Params::default()
            };
            by_oid.insert(composite.oid.clone(), (index, params));
        }
        for spec in &catalogue.algorithm {
            for target in spec.replacement.values() {
                // A target is either an id (`sha-384`) or an id followed by parameters
                // (`ml-dsa-65`, `aes-256-gcm`).
                let known = catalogue.algorithm.iter().any(|candidate| {
                    target == &candidate.id || target.starts_with(&format!("{}-", candidate.id))
                });
                if !known {
                    return Err(KnowledgeError::Inconsistent(format!(
                        "`{}` recommends unknown replacement `{target}`",
                        spec.id
                    )));
                }
            }
        }

        let mut curve_by_alias = HashMap::new();
        let mut curve_by_oid = HashMap::new();
        for (index, curve) in catalogue.curve.iter().enumerate() {
            for alias in curve.aliases.iter().chain([&curve.name]) {
                curve_by_alias.insert(normalize_token(alias), index);
            }
            if let Some(oid) = &curve.oid {
                curve_by_oid.insert(oid.clone(), index);
            }
        }

        let mut prefixes: Vec<PrefixEntry> = by_alias
            .iter()
            .map(|(alias, &algorithm)| PrefixEntry {
                alias: alias.clone(),
                algorithm,
                parameter_set: None,
            })
            .collect();
        for (algorithm, spec) in catalogue.algorithm.iter().enumerate() {
            for (set_index, set) in spec.parameter_set.iter().enumerate() {
                for alias in &set.aliases {
                    let alias = normalize_token(alias);
                    // `768` or `128s` alone name nothing; `kyber768` names algorithm + set.
                    if alias.starts_with(|c: char| c.is_ascii_alphabetic()) {
                        prefixes.push(PrefixEntry {
                            alias,
                            algorithm,
                            parameter_set: Some(set_index),
                        });
                    }
                }
            }
        }
        prefixes.sort_by(|a, b| {
            b.alias
                .len()
                .cmp(&a.alias.len())
                .then_with(|| a.alias.cmp(&b.alias))
        });
        let mut digests: Vec<(String, usize)> = prefixes
            .iter()
            .filter(|entry| {
                entry.parameter_set.is_none()
                    && matches!(
                        catalogue.algorithm[entry.algorithm].primitive,
                        Primitive::Hash | Primitive::Xof
                    )
            })
            .map(|entry| (entry.alias.clone(), entry.algorithm))
            .collect();
        digests.dedup();

        Ok(Self {
            version: catalogue.version,
            algorithms: catalogue.algorithm,
            curves: catalogue.curve,
            by_id,
            by_alias,
            by_oid,
            curve_by_alias,
            curve_by_oid,
            prefixes,
            digests,
        })
    }

    /// Every way `normalized` can begin with a known algorithm name, longest first. Callers try
    /// each in turn, because the longest prefix is not always the right reading:
    /// `ecdsasha256` begins with alias `ecdsasha2` but parses only as `ecdsa` + `sha256`.
    pub fn prefix_candidates<'a>(
        &'a self,
        normalized: &'a str,
    ) -> impl Iterator<Item = (&'a AlgorithmSpec, Option<&'a ParameterSetSpec>, usize)> + 'a {
        self.prefixes
            .iter()
            .filter(move |entry| normalized.starts_with(&entry.alias))
            .map(|entry| {
                let spec = &self.algorithms[entry.algorithm];
                (
                    spec,
                    entry.parameter_set.map(|index| &spec.parameter_set[index]),
                    entry.alias.len(),
                )
            })
    }

    /// Longest hash or XOF name at the start of `rest`, with the number of bytes it spans.
    pub fn digest_prefix(&self, rest: &str) -> Option<(&AlgorithmSpec, usize)> {
        self.digests
            .iter()
            .find(|(alias, _)| rest.starts_with(alias.as_str()))
            .map(|(alias, index)| (&self.algorithms[*index], alias.len()))
    }

    pub fn version(&self) -> &str {
        &self.version
    }

    pub fn algorithms(&self) -> &[AlgorithmSpec] {
        &self.algorithms
    }

    pub fn get(&self, id: &str) -> Option<&AlgorithmSpec> {
        self.by_id.get(id).map(|&index| &self.algorithms[index])
    }

    /// Resolves a single algorithm name or alias (`sha256`, `Rijndael`, `ML-KEM`).
    pub fn by_alias(&self, name: &str) -> Option<&AlgorithmSpec> {
        self.by_alias
            .get(&normalize_token(name))
            .map(|&index| &self.algorithms[index])
    }

    /// Every OID the knowledge base can resolve, including composite signature OIDs.
    pub fn oids(&self) -> impl Iterator<Item = &str> {
        let mut oids: Vec<&str> = self.by_oid.keys().map(String::as_str).collect();
        oids.sort_unstable();
        oids.into_iter()
    }

    /// Resolves a dotted OID to an algorithm and whatever parameters the OID itself encodes.
    pub fn by_oid(&self, oid: &str) -> Option<AlgorithmRef> {
        self.by_oid.get(oid).map(|(index, params)| {
            AlgorithmRef::with_params(self.algorithms[*index].id.clone(), params.clone())
        })
    }

    pub fn curve(&self, name: &str) -> Option<&CurveSpec> {
        self.curve_by_alias
            .get(&normalize_token(name))
            .map(|&index| &self.curves[index])
    }

    pub fn curve_by_oid(&self, oid: &str) -> Option<&CurveSpec> {
        self.curve_by_oid.get(oid).map(|&index| &self.curves[index])
    }

    /// Canonicalises a curve name (`prime256v1` → `P-256`); unknown names pass through unchanged.
    pub fn canonical_curve(&self, name: &str) -> String {
        self.curve(name)
            .map_or_else(|| name.to_owned(), |curve| curve.name.clone())
    }

    /// Derives classical strength, classical status and NIST quantum category for a use.
    pub fn strength(&self, algorithm: &AlgorithmRef) -> Option<Strength> {
        let spec = self.get(&algorithm.id)?;
        let params = &algorithm.params;
        let mut reasons = Vec::new();
        let mut status = spec.classical;
        if status != ClassicalStatus::Acceptable {
            reasons.push(spec.note.clone().unwrap_or_else(|| {
                format!(
                    "{} is classified `{}` in the knowledge base",
                    spec.name,
                    status.as_str()
                )
            }));
        }

        let classical_bits = match spec.security {
            SecurityModel::Fixed => spec.strength,
            SecurityModel::KeyBits => params.key_bits.or_else(|| single(&spec.key_bits)),
            SecurityModel::IntegerFactoring => params.key_bits.map(integer_factoring_strength),
            SecurityModel::HashOutput => spec.output_bits.map(|bits| bits / 2),
            SecurityModel::ParameterSet => params
                .parameter_set
                .as_deref()
                .and_then(|set| spec.parameter_set(set))
                .map(|set| set.strength),
            SecurityModel::Curve => {
                let curve = params.curve.as_deref().or(spec.curve.as_deref());
                match curve.and_then(|name| self.curve(name)) {
                    Some(curve) => {
                        if curve.classical > status {
                            status = curve.classical;
                            reasons.push(format!(
                                "curve {} is `{}` (NIST SP 800-186)",
                                curve.name,
                                curve.classical.as_str()
                            ));
                        }
                        Some(curve.strength)
                    }
                    None => None,
                }
            }
            SecurityModel::Digest => params
                .digest
                .as_deref()
                .and_then(|digest| self.get(digest))
                .and_then(|digest| digest.output_bits),
        };

        if let (Some(minimum), Some(bits)) = (spec.min_key_bits, params.key_bits)
            && bits < minimum
            && status < ClassicalStatus::Disallowed
        {
            status = ClassicalStatus::Disallowed;
            reasons.push(format!(
                "{} with a {bits}-bit key is below the {minimum}-bit minimum (NIST SP 800-131A Rev2)",
                spec.name
            ));
        }
        if let Some(mode) = &params.mode
            && spec
                .weak_modes
                .iter()
                .any(|weak| weak.eq_ignore_ascii_case(mode))
            && status < ClassicalStatus::Legacy
        {
            status = ClassicalStatus::Legacy;
            reasons.push(format!(
                "{} in {} mode leaks plaintext structure: identical blocks encrypt identically",
                spec.name,
                mode.to_ascii_uppercase()
            ));
        }
        if let Some(digest_id) = &params.digest
            && let Some(digest) = self.get(digest_id)
            && digest.classical > status
            && matches!(spec.primitive, Primitive::Signature | Primitive::Pke)
        {
            status = digest.classical;
            reasons.push(format!(
                "signature digest {} is `{}`",
                digest.name,
                digest.classical.as_str()
            ));
        }

        let nist_quantum_level = match spec.quantum {
            QuantumClass::Shor => 0,
            QuantumClass::PostQuantum => params
                .parameter_set
                .as_deref()
                .and_then(|set| spec.parameter_set(set))
                .map(|set| set.nist_level)
                .or(spec.nist_level)
                .unwrap_or(1),
            QuantumClass::Grover => grover_level(spec, classical_bits),
        };

        Some(Strength {
            classical_bits,
            classical_status: status,
            nist_quantum_level,
            quantum: spec.quantum,
            reasons,
        })
    }
}

/// NIST SP 800-57 Part 1 Rev 5, Table 2: comparable strength of integer-factoring and
/// finite-field discrete-log keys. Values between table rows take the lower strength.
pub fn integer_factoring_strength(modulus_bits: u32) -> u32 {
    match modulus_bits {
        0..=1023 => 0,
        1024..=2047 => 80,
        2048..=3071 => 112,
        3072..=7679 => 128,
        7680..=15359 => 192,
        _ => 256,
    }
}

/// NIST PQC security categories for symmetric primitives: 1 = AES-128 key search,
/// 2 = SHA-256 collision, 3 = AES-192, 4 = SHA-384 collision, 5 = AES-256.
fn grover_level(spec: &AlgorithmSpec, classical_bits: Option<u32>) -> u8 {
    if spec.classical == ClassicalStatus::Broken {
        return 0;
    }
    let Some(bits) = classical_bits else { return 0 };
    match spec.primitive {
        Primitive::Hash => match spec.output_bits.unwrap_or(0) {
            512.. => 5,
            384.. => 4,
            256.. => 2,
            _ => 0,
        },
        _ => match bits {
            256.. => 5,
            192.. => 3,
            128.. => 1,
            _ => 0,
        },
    }
}

fn single(values: &[u32]) -> Option<u32> {
    match values {
        [only] => Some(*only),
        _ => None,
    }
}

/// Lower-cases and strips separators so `SHA-256`, `sha_256` and `SHA256` compare equal.
pub fn normalize_token(value: &str) -> String {
    value
        .chars()
        .filter(|c| !matches!(c, '-' | '_' | ' ' | '/' | '.'))
        .flat_map(char::to_lowercase)
        .collect()
}

#[cfg(test)]
mod tests {
    #[test]
    fn algorithm_names_follow_cyclonedx_conventions() {
        let name = |id: &str, params: Params| AlgorithmRef::with_params(id, params).to_string();
        assert_eq!(
            name(
                "aes",
                Params {
                    key_bits: Some(256),
                    mode: Some("gcm".into()),
                    padding: Some("NoPadding".into()),
                    ..Params::default()
                }
            ),
            "AES-256-GCM"
        );
        assert_eq!(
            name(
                "aes",
                Params {
                    key_bits: Some(128),
                    mode: Some("ecb".into()),
                    padding: Some("PKCS5Padding".into()),
                    ..Params::default()
                }
            ),
            "AES-128-ECB (PKCS5)"
        );
        assert_eq!(
            name(
                "rsa",
                Params {
                    key_bits: Some(2048),
                    padding: Some("pkcs1v15".into()),
                    digest: Some("sha-256".into()),
                    ..Params::default()
                }
            ),
            "RSA-2048 (PKCS1v15, SHA-256)"
        );
        assert_eq!(
            name(
                "ml-kem",
                Params {
                    parameter_set: Some("768".into()),
                    ..Params::default()
                }
            ),
            "ML-KEM-768"
        );
        assert_eq!(
            name(
                "ml-kem",
                Params {
                    parameter_set: Some("ML-KEM-768".into()),
                    ..Params::default()
                }
            ),
            "ML-KEM-768"
        );
        assert_eq!(
            name(
                "ecdsa",
                Params {
                    curve: Some("P-256".into()),
                    ..Params::default()
                }
            ),
            "ECDSA-P-256"
        );
        assert_eq!(name("sha-1", Params::default()), "SHA-1");
    }

    use super::*;

    fn registry() -> &'static Registry {
        Registry::active()
    }

    fn strength(id: &str, params: Params) -> Strength {
        registry()
            .strength(&AlgorithmRef::with_params(id, params))
            .expect("known algorithm")
    }

    #[test]
    fn embedded_catalogue_loads_and_is_consistent() {
        let registry = registry();
        assert!(registry.algorithms().len() > 60);
        assert!(!registry.version().is_empty());
        for spec in registry.algorithms() {
            assert_eq!(spec.id, spec.id.to_ascii_lowercase(), "ids are lowercase");
        }
    }

    #[test]
    fn aliases_resolve_regardless_of_separator_and_case() {
        let registry = registry();
        assert_eq!(registry.by_alias("SHA256").unwrap().id, "sha-256");
        assert_eq!(registry.by_alias("sha_256").unwrap().id, "sha-256");
        assert_eq!(registry.by_alias("Rijndael").unwrap().id, "aes");
        assert_eq!(registry.by_alias("Kyber").unwrap().id, "ml-kem");
        assert_eq!(
            registry.by_alias("X25519MLKEM768").unwrap().id,
            "x25519-mlkem768"
        );
    }

    #[test]
    fn oids_resolve_with_encoded_parameters() {
        let registry = registry();
        let aes = registry.by_oid("2.16.840.1.101.3.4.1.46").unwrap();
        assert_eq!(aes.id, "aes");
        assert_eq!(aes.params.key_bits, Some(256));
        assert_eq!(aes.params.mode.as_deref(), Some("gcm"));
        let sig = registry.by_oid("1.2.840.113549.1.1.11").unwrap();
        assert_eq!(sig.id, "rsa");
        assert_eq!(sig.params.digest.as_deref(), Some("sha-256"));
        let kem = registry.by_oid("2.16.840.1.101.3.4.4.2").unwrap();
        assert_eq!(kem.params.parameter_set.as_deref(), Some("768"));
        assert_eq!(
            registry.curve_by_oid("1.2.840.10045.3.1.7").unwrap().name,
            "P-256"
        );
    }

    #[test]
    fn rsa_strength_follows_sp800_57_and_small_keys_are_disallowed() {
        let rsa2048 = strength(
            "rsa",
            Params {
                key_bits: Some(2048),
                ..Params::default()
            },
        );
        assert_eq!(rsa2048.classical_bits, Some(112));
        assert_eq!(rsa2048.classical_status, ClassicalStatus::Acceptable);
        assert_eq!(rsa2048.nist_quantum_level, 0);
        assert_eq!(rsa2048.quantum, QuantumClass::Shor);

        let rsa1024 = strength(
            "rsa",
            Params {
                key_bits: Some(1024),
                ..Params::default()
            },
        );
        assert_eq!(rsa1024.classical_status, ClassicalStatus::Disallowed);
        assert!(
            rsa1024
                .reasons
                .iter()
                .any(|reason| reason.contains("SP 800-131A"))
        );
    }

    #[test]
    fn symmetric_levels_follow_nist_categories() {
        let aes = |bits| {
            strength(
                "aes",
                Params {
                    key_bits: Some(bits),
                    ..Params::default()
                },
            )
        };
        assert_eq!(aes(128).nist_quantum_level, 1);
        assert_eq!(aes(192).nist_quantum_level, 3);
        assert_eq!(aes(256).nist_quantum_level, 5);
        assert_eq!(strength("sha-256", Params::default()).nist_quantum_level, 2);
        assert_eq!(strength("sha-384", Params::default()).nist_quantum_level, 4);
        assert_eq!(
            strength("sha-1", Params::default()).classical_status,
            ClassicalStatus::Broken
        );
    }

    #[test]
    fn ecb_mode_downgrades_an_otherwise_strong_cipher() {
        let ecb = strength(
            "aes",
            Params {
                key_bits: Some(256),
                mode: Some("ecb".into()),
                ..Params::default()
            },
        );
        assert_eq!(ecb.classical_status, ClassicalStatus::Legacy);
        assert!(ecb.reasons.iter().any(|reason| reason.contains("ECB")));
    }

    #[test]
    fn pqc_parameter_sets_carry_their_nist_category() {
        let kem = strength(
            "ml-kem",
            Params {
                parameter_set: Some("768".into()),
                ..Params::default()
            },
        );
        assert_eq!(kem.nist_quantum_level, 3);
        assert_eq!(kem.classical_bits, Some(192));
        let sig = strength(
            "ml-dsa",
            Params {
                parameter_set: Some("dilithium5".into()),
                ..Params::default()
            },
        );
        assert_eq!(sig.nist_quantum_level, 5);
    }

    #[test]
    fn curve_strength_and_weak_curves() {
        let p256 = strength(
            "ecdsa",
            Params {
                curve: Some("prime256v1".into()),
                ..Params::default()
            },
        );
        assert_eq!(p256.classical_bits, Some(128));
        let p192 = strength(
            "ecdsa",
            Params {
                curve: Some("secp192r1".into()),
                ..Params::default()
            },
        );
        assert_eq!(p192.classical_status, ClassicalStatus::Disallowed);
    }

    #[test]
    fn weak_signature_digest_is_reported() {
        let sha1_rsa = strength(
            "rsa",
            Params {
                key_bits: Some(2048),
                digest: Some("sha-1".into()),
                ..Params::default()
            },
        );
        assert_eq!(sha1_rsa.classical_status, ClassicalStatus::Broken);
    }

    #[test]
    fn hmac_strength_follows_its_digest() {
        let hmac = strength(
            "hmac",
            Params {
                digest: Some("sha-256".into()),
                ..Params::default()
            },
        );
        assert_eq!(hmac.classical_bits, Some(256));
    }
}
