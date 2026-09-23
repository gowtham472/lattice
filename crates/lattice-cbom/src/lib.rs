//! CycloneDX 1.6 CBOM emission.
//!
//! The document is strict CycloneDX: every standard field is filled from the inventory, and
//! everything CycloneDX has no field for (liveness, risk, Mosca, the recommendation) goes into
//! `properties` under the `lattice:` namespace, so any CycloneDX tool can read the file and
//! LATTICE loses nothing. Output is deterministic for a given inventory and timestamp: components
//! are ordered by `bom-ref`, properties by insertion, and nothing depends on hash-map order.

pub mod signing;
#[cfg(feature = "validate")]
pub mod validate;

use lattice_core::{
    AlgorithmRef, CryptoAsset, CryptoFunction, Finding, LibraryFact, MaterialType, Primitive,
    Registry, Surface,
};
use lattice_graph::AssetContext;
use lattice_risk::Assessment;
use lattice_risk::advisor::Recommendation;
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const BOM_FORMAT: &str = "CycloneDX";
pub const PROPERTY_NAMESPACE: &str = "lattice:";

/// Everything known about one asset at report time.
pub struct AssessedAsset<'a> {
    pub asset: &'a CryptoAsset,
    pub context: &'a AssetContext,
    pub assessment: &'a Assessment,
    pub recommendation: &'a Recommendation,
}

/// Provenance of the inputs that produced the scores, so a report can be recomputed exactly.
pub struct Provenance<'a> {
    pub tool_version: &'a str,
    pub knowledge_version: &'a str,
    pub rules_version: &'a str,
    pub policy_version: &'a str,
    pub assessment_year: u16,
    pub q_day: (u16, u16),
    pub knowledge_sequence: u64,
    /// Key id of the signed knowledge bundle in use, if one was activated.
    pub knowledge_signer: Option<&'a str>,
}

pub struct BomInput<'a> {
    /// Name of the scanned system (the directory name unless the caller overrides it).
    pub subject: &'a str,
    pub subject_version: Option<&'a str>,
    /// Unix seconds; the caller decides, so reproducible builds can pin it.
    pub timestamp: i64,
    pub provenance: Provenance<'a>,
    pub assets: &'a [AssessedAsset<'a>],
    pub libraries: &'a [LibraryFact],
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Bom {
    pub bom_format: String,
    pub spec_version: String,
    pub serial_number: String,
    pub version: u32,
    pub metadata: Metadata,
    #[serde(default)]
    pub components: Vec<Component>,
    #[serde(default)]
    pub dependencies: Vec<Dependency>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Metadata {
    pub timestamp: String,
    pub tools: Tools,
    pub component: Component,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub properties: Vec<Property>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Tools {
    pub components: Vec<Component>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Component {
    #[serde(rename = "type")]
    pub component_type: String,
    #[serde(rename = "bom-ref", default, skip_serializing_if = "Option::is_none")]
    pub bom_ref: Option<String>,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub crypto_properties: Option<CryptoProperties>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence: Option<ComponentEvidence>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub properties: Vec<Property>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CryptoProperties {
    pub asset_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub algorithm_properties: Option<AlgorithmProperties>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificate_properties: Option<CertificateProperties>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub related_crypto_material_properties: Option<RelatedCryptoMaterialProperties>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol_properties: Option<ProtocolProperties>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oid: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AlgorithmProperties {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub primitive: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parameter_set_identifier: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub curve: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub padding: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub crypto_functions: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub classical_security_level: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nist_quantum_security_level: Option<u8>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificateProperties {
    pub subject_name: String,
    pub issuer_name: String,
    pub not_valid_before: String,
    pub not_valid_after: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature_algorithm_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject_public_key_ref: Option<String>,
    pub certificate_format: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificate_extension: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelatedCryptoMaterialProperties {
    #[serde(rename = "type")]
    pub material_type: String,
    /// A fingerprint, never key bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub algorithm_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secured_by: Option<SecuredBy>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SecuredBy {
    pub mechanism: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProtocolProperties {
    #[serde(rename = "type")]
    pub protocol_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cipher_suites: Vec<CipherSuite>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CipherSuite {
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ComponentEvidence {
    pub occurrences: Vec<EvidenceOccurrence>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceOccurrence {
    pub location: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offset: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub symbol: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub additional_context: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Property {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Dependency {
    #[serde(rename = "ref")]
    pub reference: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub depends_on: Vec<String>,
}

/// Collects `lattice:` properties in the order they are added.
#[derive(Default)]
struct Properties(Vec<Property>);

impl Properties {
    fn add(&mut self, name: &str, value: impl ToString) -> &mut Self {
        self.0.push(Property {
            name: format!("{PROPERTY_NAMESPACE}{name}"),
            value: value.to_string(),
        });
        self
    }

    fn add_opt(&mut self, name: &str, value: Option<impl ToString>) -> &mut Self {
        if let Some(value) = value {
            self.add(name, value);
        }
        self
    }
}

pub const SUBJECT_REF: &str = "subject";

/// Builds the CBOM for an assessed inventory.
pub fn build(input: &BomInput<'_>) -> Bom {
    let mut components: Vec<Component> = input
        .assets
        .iter()
        .map(|assessed| asset_component(assessed, input.assets))
        .collect();
    components.sort_by(|a, b| a.bom_ref.cmp(&b.bom_ref));

    let mut libraries: Vec<Component> = Vec::new();
    for library in input.libraries {
        let component = library_component(library);
        if !libraries
            .iter()
            .any(|existing| existing.bom_ref == component.bom_ref)
        {
            libraries.push(component);
        }
    }
    libraries.sort_by(|a, b| a.bom_ref.cmp(&b.bom_ref));

    let mut dependencies: Vec<Dependency> = Vec::new();
    let mut subject_depends: Vec<String> =
        libraries.iter().filter_map(|c| c.bom_ref.clone()).collect();
    subject_depends.extend(
        input
            .assets
            .iter()
            .filter(|a| !is_referenced(a.asset, input.assets))
            .map(|a| a.asset.id.clone()),
    );
    subject_depends.sort();
    dependencies.push(Dependency {
        reference: SUBJECT_REF.into(),
        depends_on: subject_depends,
    });
    let mut asset_dependencies: Vec<Dependency> = input
        .assets
        .iter()
        .filter(|a| !a.asset.depends_on.is_empty())
        .map(|a| Dependency {
            reference: a.asset.id.clone(),
            depends_on: a.asset.depends_on.clone(),
        })
        .collect();
    asset_dependencies.sort_by(|a, b| a.reference.cmp(&b.reference));
    dependencies.extend(asset_dependencies);

    components.extend(libraries);
    let timestamp = lattice_core::rfc3339(input.timestamp);
    let serial_number = serial_number(input.subject, &timestamp, &components);

    let provenance = &input.provenance;
    let mut metadata_properties = Properties::default();
    metadata_properties
        .add("knowledge-version", provenance.knowledge_version)
        .add("knowledge-sequence", provenance.knowledge_sequence)
        .add_opt("knowledge-signer", provenance.knowledge_signer)
        .add("rules-version", provenance.rules_version)
        .add("policy-version", provenance.policy_version)
        .add("assessment-year", provenance.assessment_year)
        .add(
            "q-day",
            format!("{}..{}", provenance.q_day.0, provenance.q_day.1),
        );
    let summary = Summary::of(input.assets);
    metadata_properties
        .add("summary:assets", summary.assets)
        .add("summary:quantum-vulnerable", summary.quantum_vulnerable)
        .add("summary:broken-now", summary.broken_now)
        .add("summary:mosca-urgent", summary.mosca_urgent)
        .add("summary:critical", summary.critical)
        .add("summary:high", summary.high);

    Bom {
        bom_format: BOM_FORMAT.into(),
        spec_version: lattice_core::CBOM_SPEC_VERSION.into(),
        serial_number,
        version: 1,
        metadata: Metadata {
            timestamp,
            tools: Tools {
                components: vec![Component {
                    component_type: "application".into(),
                    bom_ref: Some("tool/lattice".into()),
                    name: "lattice".into(),
                    version: Some(provenance.tool_version.into()),
                    description: Some(
                        "LATTICE cryptographic discovery and quantum-risk assessment".into(),
                    ),
                    crypto_properties: None,
                    evidence: None,
                    properties: Vec::new(),
                }],
            },
            component: Component {
                component_type: "application".into(),
                bom_ref: Some(SUBJECT_REF.into()),
                name: input.subject.into(),
                version: input.subject_version.map(str::to_owned),
                description: None,
                crypto_properties: None,
                evidence: None,
                properties: Vec::new(),
            },
            properties: metadata_properties.0,
        },
        components,
        dependencies,
    }
}

/// Serialises a CBOM as pretty JSON with a trailing newline: the exact bytes that get signed.
pub fn render(bom: &Bom) -> Vec<u8> {
    let mut bytes = serde_json::to_vec_pretty(bom).expect("the CBOM model always serialises");
    bytes.push(b'\n');
    bytes
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Summary {
    pub assets: usize,
    pub quantum_vulnerable: usize,
    pub broken_now: usize,
    pub mosca_urgent: usize,
    pub critical: usize,
    pub high: usize,
}

impl Summary {
    pub fn of(assets: &[AssessedAsset<'_>]) -> Self {
        let mut summary = Self {
            assets: assets.len(),
            ..Self::default()
        };
        for assessed in assets {
            let assessment = assessed.assessment;
            summary.quantum_vulnerable += usize::from(lattice_risk::is_quantum_vulnerable(
                assessment.quantum_breakability,
            ));
            summary.broken_now += usize::from(assessment.broken_now);
            summary.mosca_urgent += usize::from(assessment.mosca.urgent);
            summary.critical += usize::from(assessment.tier == lattice_risk::Tier::Critical);
            summary.high += usize::from(assessment.tier == lattice_risk::Tier::High);
        }
        summary
    }
}

/// Assets another asset depends on (a certificate's signature algorithm) hang off that asset in
/// the dependency graph; the subject depends directly only on the roots.
fn is_referenced(asset: &CryptoAsset, all: &[AssessedAsset<'_>]) -> bool {
    all.iter()
        .any(|other| other.asset.depends_on.contains(&asset.id))
}

/// RFC 4122 layout (version 4 bits) over a BLAKE3 digest of the subject, time and content, so the
/// serial is unique per document without needing a random source in the report path.
fn serial_number(subject: &str, timestamp: &str, components: &[Component]) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"lattice-serial|");
    hasher.update(subject.as_bytes());
    hasher.update(b"|");
    hasher.update(timestamp.as_bytes());
    for component in components {
        hasher.update(b"|");
        hasher.update(component.bom_ref.as_deref().unwrap_or_default().as_bytes());
    }
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&hasher.finalize().as_bytes()[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex = hex::encode(bytes);
    format!(
        "urn:uuid:{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

fn library_component(library: &LibraryFact) -> Component {
    let bom_ref = match &library.version {
        Some(version) => format!(
            "library/{}/{}@{version}",
            library.component,
            slug(&library.name)
        ),
        None => format!("library/{}/{}", library.component, slug(&library.name)),
    };
    let mut properties = Properties::default();
    properties
        .add("component", &library.component)
        .add("pqc-capable", library.pqc_capable)
        .add("pqc-basis", &library.basis)
        .add("detected-at", library.location.short());
    Component {
        component_type: "library".into(),
        bom_ref: Some(bom_ref),
        name: library.name.clone(),
        version: library.version.clone(),
        description: None,
        crypto_properties: None,
        evidence: None,
        properties: properties.0,
    }
}

fn slug(value: &str) -> String {
    value
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '-' {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect()
}

fn asset_component(assessed: &AssessedAsset<'_>, all: &[AssessedAsset<'_>]) -> Component {
    let asset = assessed.asset;
    let crypto_properties = match &asset.finding {
        Finding::Algorithm(finding) => {
            let primitive = finding.primitive;
            let function = finding.function;
            CryptoProperties {
                asset_type: "algorithm".into(),
                algorithm_properties: Some(algorithm_properties(
                    &finding.algorithm,
                    primitive,
                    function,
                )),
                oid: algorithm_oid(&finding.algorithm),
                ..CryptoProperties::empty("algorithm")
            }
        }
        Finding::Certificate(certificate) => {
            let dependency = |wanted: &AlgorithmRef| dependency_ref(asset, wanted, all);
            let extension = asset
                .occurrences
                .first()
                .and_then(|o| {
                    o.location
                        .path
                        .rsplit_once('.')
                        .map(|(_, ext)| ext.to_ascii_lowercase())
                })
                .filter(|ext| ext.len() <= 8);
            CryptoProperties {
                certificate_properties: Some(CertificateProperties {
                    subject_name: certificate.subject.clone(),
                    issuer_name: certificate.issuer.clone(),
                    not_valid_before: certificate.not_before.clone(),
                    not_valid_after: certificate.not_after.clone(),
                    signature_algorithm_ref: dependency(&certificate.signature),
                    subject_public_key_ref: dependency(&certificate.public_key),
                    certificate_format: "X.509".into(),
                    certificate_extension: extension,
                }),
                ..CryptoProperties::empty("certificate")
            }
        }
        Finding::Protocol(protocol) => CryptoProperties {
            protocol_properties: Some(ProtocolProperties {
                protocol_type: match protocol.protocol.as_str() {
                    kind @ ("tls" | "ssh" | "ipsec" | "ike") => kind.into(),
                    _ => "other".into(),
                },
                version: protocol.version.clone(),
                cipher_suites: protocol
                    .cipher_suites
                    .iter()
                    .map(|name| CipherSuite { name: name.clone() })
                    .collect(),
            }),
            ..CryptoProperties::empty("protocol")
        },
        Finding::RelatedCryptoMaterial(material) => CryptoProperties {
            related_crypto_material_properties: Some(RelatedCryptoMaterialProperties {
                material_type: match material.material_type {
                    MaterialType::PrivateKey => "private-key",
                    MaterialType::PublicKey => "public-key",
                    MaterialType::SecretKey => "secret-key",
                    MaterialType::Key => "key",
                    MaterialType::Password => "password",
                    MaterialType::Credential => "credential",
                    MaterialType::Token => "token",
                    MaterialType::Other => "other",
                }
                .into(),
                id: (!material.identity.is_empty()).then(|| material.identity.clone()),
                algorithm_ref: material
                    .algorithm
                    .as_ref()
                    .and_then(|algorithm| dependency_ref(asset, algorithm, all)),
                size: material.size_bits,
                format: (!material.format.is_empty()).then(|| material.format.clone()),
                secured_by: material.encrypted.then(|| SecuredBy {
                    mechanism: "encrypted container".into(),
                }),
            }),
            ..CryptoProperties::empty("related-crypto-material")
        },
    };

    Component {
        component_type: "cryptographic-asset".into(),
        bom_ref: Some(asset.id.clone()),
        name: asset.finding.display_name(),
        version: None,
        description: None,
        crypto_properties: Some(crypto_properties),
        evidence: Some(ComponentEvidence {
            occurrences: asset.occurrences.iter().map(occurrence).collect(),
        }),
        properties: asset_properties(assessed),
    }
}

impl CryptoProperties {
    fn empty(asset_type: &str) -> Self {
        Self {
            asset_type: asset_type.into(),
            algorithm_properties: None,
            certificate_properties: None,
            related_crypto_material_properties: None,
            protocol_properties: None,
            oid: None,
        }
    }
}

/// Finds which of an asset's dependencies is a given algorithm: exact match first, then the
/// same algorithm with different (refined) parameters.
fn dependency_ref(
    asset: &CryptoAsset,
    wanted: &AlgorithmRef,
    all: &[AssessedAsset<'_>],
) -> Option<String> {
    let dependencies: Vec<(&str, &AlgorithmRef)> = asset
        .depends_on
        .iter()
        .filter_map(|id| all.iter().find(|a| &a.asset.id == id))
        .filter_map(|a| {
            a.asset
                .algorithm()
                .map(|algorithm| (a.asset.id.as_str(), algorithm))
        })
        .collect();
    dependencies
        .iter()
        .find(|(_, algorithm)| *algorithm == wanted)
        .or_else(|| {
            dependencies
                .iter()
                .find(|(_, algorithm)| algorithm.id == wanted.id)
        })
        .map(|(id, _)| (*id).to_owned())
}

fn algorithm_properties(
    algorithm: &AlgorithmRef,
    primitive: Option<Primitive>,
    function: Option<CryptoFunction>,
) -> AlgorithmProperties {
    let registry = Registry::active();
    let spec = registry.get(&algorithm.id);
    let params = &algorithm.params;
    let strength = registry.strength(algorithm);
    let functions: Vec<CryptoFunction> = match function {
        Some(function) => vec![function],
        None => spec.map(|s| s.functions.clone()).unwrap_or_default(),
    };
    AlgorithmProperties {
        primitive: primitive
            .or_else(|| spec.map(|s| s.primitive))
            .map(|p| p.as_str().to_owned()),
        parameter_set_identifier: params
            .parameter_set
            .clone()
            .or_else(|| params.key_bits.map(|bits| bits.to_string())),
        curve: params
            .curve
            .as_deref()
            .map(|curve| registry.canonical_curve(curve)),
        mode: params.mode.as_deref().map(|mode| {
            let mode = mode.to_ascii_lowercase();
            if matches!(
                mode.as_str(),
                "cbc" | "ecb" | "ccm" | "gcm" | "cfb" | "ofb" | "ctr"
            ) {
                mode
            } else {
                "other".into()
            }
        }),
        padding: params.padding.as_deref().map(|padding| {
            let padding = padding.to_ascii_lowercase().replace(['-', '_'], "");
            match padding.as_str() {
                "pkcs5" | "pkcs5padding" => "pkcs5".into(),
                "pkcs7" | "pkcs7padding" => "pkcs7".into(),
                "pkcs1" | "pkcs1v15" | "pkcs1padding" => "pkcs1v15".into(),
                "oaep" | "oaeppadding" => "oaep".into(),
                "none" | "nopadding" | "raw" => "raw".into(),
                _ => "other".into(),
            }
        }),
        crypto_functions: functions
            .into_iter()
            .filter_map(|f| {
                serde_json::to_value(f)
                    .ok()
                    .and_then(|v| v.as_str().map(str::to_owned))
            })
            .collect(),
        classical_security_level: strength.as_ref().and_then(|s| s.classical_bits),
        nist_quantum_security_level: strength.as_ref().map(|s| s.nist_quantum_level),
    }
}

/// The most specific OID the knowledge base has for this algorithm and its parameters.
fn algorithm_oid(algorithm: &AlgorithmRef) -> Option<String> {
    let spec = Registry::active().get(&algorithm.id)?;
    let params = &algorithm.params;
    if let Some(set) = params
        .parameter_set
        .as_deref()
        .and_then(|name| spec.parameter_set(name))
        && let Some(oid) = &set.oid
    {
        return Some(oid.clone());
    }
    spec.oid_map
        .iter()
        .find(|mapping| {
            mapping
                .key_bits
                .is_some_and(|bits| Some(bits) == params.key_bits)
                && mapping.mode.as_deref().is_none_or(|mode| {
                    params
                        .mode
                        .as_deref()
                        .is_some_and(|m| m.eq_ignore_ascii_case(mode))
                })
        })
        .map(|mapping| mapping.oid.clone())
        .or_else(|| {
            (spec.oid_map.is_empty() && spec.parameter_set.is_empty())
                .then(|| spec.oids.first().cloned())
                .flatten()
        })
}

fn occurrence(occurrence: &lattice_core::Occurrence) -> EvidenceOccurrence {
    let evidence = &occurrence.evidence;
    let kind = serde_json::to_value(evidence.kind)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_default();
    let mut context = format!(
        "{} evidence via {} rule {}@{} ({})",
        occurrence.surface.as_str(),
        evidence.collector,
        evidence.rule_id,
        evidence.rule_version,
        kind
    );
    if let Some(from) = &occurrence.refined_from {
        context.push_str(&format!("; refined from {from}"));
    }
    if let Some(usage) = &occurrence.usage
        && let Some(function) = &usage.function
    {
        context.push_str(&format!("; in {function}"));
    }
    EvidenceOccurrence {
        location: occurrence.location.path.clone(),
        line: occurrence.location.line,
        offset: occurrence.location.byte_offset,
        symbol: occurrence
            .usage
            .as_ref()
            .map(|usage| usage.api.clone())
            .or_else(|| {
                (!evidence.matched_token.is_empty()).then(|| evidence.matched_token.clone())
            }),
        additional_context: Some(context),
    }
}

fn asset_properties(assessed: &AssessedAsset<'_>) -> Vec<Property> {
    let AssessedAsset {
        asset,
        context,
        assessment,
        recommendation,
    } = assessed;
    let mut p = Properties::default();
    p.add("component", &asset.component)
        .add(
            "surfaces",
            asset
                .surfaces
                .iter()
                .map(|s: &Surface| s.as_str())
                .collect::<Vec<_>>()
                .join(","),
        )
        .add(
            "liveness",
            format!("{:?}", asset.liveness).to_ascii_lowercase(),
        )
        .add("liveness-reason", &asset.liveness_reason)
        .add("evidence-grade", format!("{:?}", asset.evidence_grade))
        .add("evidence-grade-reason", &asset.grade_reason)
        .add("reachable", context.reachable)
        .add_opt(
            "entry-point",
            context.entry.as_ref().map(|entry| entry.detail.clone()),
        )
        .add_opt(
            "call-path",
            (!context.path.is_empty()).then(|| context.path.join(" -> ")),
        )
        .add("exposure", context.exposure)
        .add("exposure-reason", &context.exposure_reason)
        .add("data-class", &context.data.class)
        .add("data-secrecy-years", context.data.secrecy_lifetime_years)
        .add("data-reason", &context.data.explanation)
        .add("quantum-breakability", assessment.quantum_breakability)
        .add("quantum-reason", &assessment.quantum_reason)
        .add("classical-status", assessment.classical_status.as_str());
    for reason in &assessment.classical_reasons {
        p.add("classical-reason", reason);
    }
    p.add("threat", serde_label(&assessment.threat))
        .add(
            &format!("{}-index", assessment.index_kind),
            assessment.exposure_index,
        )
        .add("agility-score", assessment.agility.score)
        .add("mosca-x-years", assessment.mosca.x_years)
        .add("mosca-y-years", assessment.mosca.y_years)
        .add(
            "mosca-z-years",
            format!(
                "{}..{}",
                assessment.mosca.z_earliest_years, assessment.mosca.z_latest_years
            ),
        )
        .add("mosca-urgent", assessment.mosca.urgent)
        .add("mosca-verdict", &assessment.mosca.verdict)
        .add("priority", assessment.priority)
        .add("tier", serde_label(&assessment.tier))
        .add("recommendation-action", &recommendation.action)
        .add("recommendation-target", &recommendation.target)
        .add("recommendation-rationale", &recommendation.rationale);
    if let Some(delta) = &recommendation.size_delta {
        p.add(
            "recommendation-size-delta",
            format!(
                "{} -> {} bytes ({})",
                delta.before_bytes, delta.after_bytes, delta.basis
            ),
        );
    }
    p.0
}

fn serde_label(value: &impl Serialize) -> String {
    match serde_json::to_value(value) {
        Ok(Value::String(label)) => label,
        _ => String::new(),
    }
}

/// Deterministic JSON: object keys sorted, no insignificant whitespace. Used for the per-component
/// hash chain, so it does not depend on serde_json's map ordering features.
pub fn canonical_json(value: &Value) -> String {
    let mut out = String::new();
    write_canonical(value, &mut out);
    out
}

fn write_canonical(value: &Value, out: &mut String) {
    match value {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            out.push('{');
            for (index, key) in keys.into_iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                out.push_str(&Value::String(key.clone()).to_string());
                out.push(':');
                write_canonical(&map[key], out);
            }
            out.push('}');
        }
        Value::Array(items) => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write_canonical(item, out);
            }
            out.push(']');
        }
        other => out.push_str(&other.to_string()),
    }
}

#[cfg(test)]
mod tests;
