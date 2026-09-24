use super::*;
use lattice_classify::Classifier;
use lattice_core::policy::Policy;
use lattice_core::{
    CertificateFinding, Evidence, EvidenceKind, Location, MaterialFinding, Observation, Params,
    ProtocolFinding, ProtocolKind, normalize,
};
use lattice_graph::{CryptoGraph, GraphInput};
use lattice_risk::Assessor;
use lattice_risk::advisor::recommend;
use std::collections::{BTreeMap, HashMap};

fn observe(surface: Surface, path: &str, finding: Finding) -> Observation {
    Observation {
        surface,
        component: "services/payments".into(),
        location: Location::at_line(path, 12, 5),
        finding,
        evidence: Evidence {
            collector: "test".into(),
            rule_id: "test.rule".into(),
            rule_version: "2026.09.1".into(),
            kind: match surface {
                Surface::Certificate => EvidenceKind::Certificate,
                Surface::Config => EvidenceKind::Configuration,
                _ => EvidenceKind::ApiCall,
            },
            matched_token: "token".into(),
        },
        usage: None,
    }
}

fn certificate() -> Finding {
    Finding::Certificate(CertificateFinding {
        subject: "CN=pay.example.in".into(),
        issuer: "CN=Example CA".into(),
        not_before: "2026-01-01T00:00:00Z".into(),
        not_after: "2027-01-01T00:00:00Z".into(),
        serial: "0a".into(),
        public_key: AlgorithmRef::with_params(
            "rsa",
            Params {
                key_bits: Some(2048),
                ..Params::default()
            },
        ),
        signature: AlgorithmRef::with_params(
            "rsa",
            Params {
                digest: Some("sha-256".into()),
                ..Params::default()
            },
        ),
        self_signed: false,
        is_ca: false,
        fingerprint_sha256: "cd".repeat(32),
    })
}

fn inventory() -> Vec<Observation> {
    vec![
        observe(Surface::Certificate, "deploy/tls/server.crt", certificate()),
        observe(
            Surface::Source,
            "src/Crypto.java",
            Finding::algorithm(AlgorithmRef::with_params(
                "aes",
                Params {
                    key_bits: Some(128),
                    mode: Some("ecb".into()),
                    padding: Some("PKCS5Padding".into()),
                    ..Params::default()
                },
            )),
        ),
        observe(
            Surface::Source,
            "src/Kem.java",
            Finding::algorithm(AlgorithmRef::with_params(
                "ml-kem",
                Params {
                    parameter_set: Some("768".into()),
                    ..Params::default()
                },
            )),
        ),
        observe(
            Surface::Config,
            "deploy/nginx.conf",
            Finding::Protocol(ProtocolFinding {
                protocol: ProtocolKind::Tls,
                version: Some("1.2".into()),
                cipher_suites: vec!["TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256".into()],
                groups: vec!["x25519".into()],
            }),
        ),
        observe(
            Surface::Certificate,
            "deploy/tls/server.key",
            Finding::RelatedCryptoMaterial(MaterialFinding {
                material_type: MaterialType::PrivateKey,
                algorithm: Some(AlgorithmRef::with_params(
                    "rsa",
                    Params {
                        key_bits: Some(2048),
                        ..Params::default()
                    },
                )),
                size_bits: Some(2048),
                format: "PEM".into(),
                encrypted: false,
                identity: "blake3:0123456789abcdef".into(),
            }),
        ),
    ]
}

struct Assessed {
    assets: Vec<CryptoAsset>,
    contexts: Vec<AssetContext>,
    assessments: Vec<Assessment>,
    recommendations: Vec<Recommendation>,
}

fn assess() -> Assessed {
    let policy = Policy::active();
    let assets = normalize(inventory());
    let classifier = Classifier::new(policy);
    let classifications: BTreeMap<String, _> = assets
        .iter()
        .map(|asset| {
            (
                asset.id.clone(),
                classifier.classify(asset, &HashMap::new()),
            )
        })
        .collect();
    let graph = CryptoGraph::build(&GraphInput {
        assets: &assets,
        functions: &[],
        calls: &[],
        bindings: &[],
        libraries: &[],
        classifications: &classifications,
        policy,
    });
    let assessor = Assessor {
        policy,
        assessment_year: 2026,
    };
    let contexts: Vec<AssetContext> = assets
        .iter()
        .map(|asset| graph.context(&asset.id).unwrap().clone())
        .collect();
    let assessments: Vec<Assessment> = assets
        .iter()
        .zip(&contexts)
        .map(|(asset, context)| assessor.assess(asset, context))
        .collect();
    let recommendations = assets
        .iter()
        .zip(&contexts)
        .zip(&assessments)
        .map(|((asset, context), assessment)| {
            recommend(asset, assessment, context.data.secrecy_lifetime_years)
        })
        .collect();
    Assessed {
        assets,
        contexts,
        assessments,
        recommendations,
    }
}

fn library() -> LibraryFact {
    LibraryFact {
        component: "services/payments".into(),
        location: Location::file("pom.xml"),
        name: "Bouncy Castle".into(),
        version: Some("1.78".into()),
        pqc_capable: true,
        basis: "ML-KEM and ML-DSA providers since 1.78".into(),
    }
}

fn bom(assessed: &Assessed, timestamp: i64) -> Bom {
    let items: Vec<AssessedAsset<'_>> = (0..assessed.assets.len())
        .map(|i| AssessedAsset {
            asset: &assessed.assets[i],
            context: &assessed.contexts[i],
            assessment: &assessed.assessments[i],
            recommendation: &assessed.recommendations[i],
            effort: None,
            due_year: None,
        })
        .collect();
    let libraries = [library()];
    build(&BomInput {
        subject: "payments",
        subject_version: Some("4.2.0"),
        timestamp,
        provenance: Provenance {
            tool_version: "0.1.0",
            knowledge_version: Registry::active().version(),
            rules_version: "2026.09.1",
            policy_version: &Policy::active().version,
            assessment_year: 2026,
            q_day: (2030, 2035),
            knowledge_sequence: 1,
            knowledge_signer: None,
        },
        assets: &items,
        libraries: &libraries,
        plan: None,
    })
}

fn component<'b>(bom: &'b Bom, name_prefix: &str) -> &'b Component {
    bom.components
        .iter()
        .find(|c| c.name.starts_with(name_prefix))
        .unwrap_or_else(|| panic!("no component {name_prefix}"))
}

fn property<'b>(component: &'b Component, name: &str) -> Option<&'b str> {
    component
        .properties
        .iter()
        .find(|p| p.name == format!("lattice:{name}"))
        .map(|p| p.value.as_str())
}

#[test]
fn the_cbom_validates_against_the_official_cyclonedx_schema() {
    let document = serde_json::to_value(bom(&assess(), 1_790_000_000)).unwrap();
    if let Err(violations) = validate::validate(&document) {
        panic!(
            "schema violations:\n{}",
            violations
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("\n")
        );
    }
    validate::check_references(&document).unwrap();
}

#[test]
fn the_validator_rejects_what_the_schema_forbids() {
    let mut document = serde_json::to_value(bom(&assess(), 1_790_000_000)).unwrap();
    document["components"][0]["cryptoProperties"]["assetType"] = serde_json::json!("quantum-thing");
    document["components"][0]["cryptoProperties"]["lattice"] = serde_json::json!({});
    let violations = validate::validate(&document).unwrap_err();
    assert!(
        violations
            .iter()
            .any(|v| v.path == "/components/0/cryptoProperties/assetType")
    );
    assert!(
        violations.iter().any(|v| v.message.contains("lattice")),
        "no undeclared fields: {violations:?}"
    );

    let mut dangling = serde_json::to_value(bom(&assess(), 1_790_000_000)).unwrap();
    dangling["dependencies"][0]["dependsOn"][0] = serde_json::json!("crypto/algorithm/nope/0000");
    assert!(validate::check_references(&dangling).is_err());
}

#[test]
fn certificates_point_at_their_key_and_signature_algorithms() {
    let bom = bom(&assess(), 1_790_000_000);
    let certificate = component(&bom, "X.509");
    let properties = certificate
        .crypto_properties
        .as_ref()
        .unwrap()
        .certificate_properties
        .as_ref()
        .unwrap();
    let key = properties.subject_public_key_ref.as_deref().unwrap();
    let signature = properties.signature_algorithm_ref.as_deref().unwrap();
    assert_ne!(key, signature);
    let find = |reference: &str| {
        bom.components
            .iter()
            .find(|c| c.bom_ref.as_deref() == Some(reference))
            .unwrap()
            .name
            .clone()
    };
    assert_eq!(find(key), "RSA-2048");
    assert!(find(signature).contains("SHA-256"), "{}", find(signature));
    assert_eq!(properties.certificate_extension.as_deref(), Some("crt"));
    assert_eq!(properties.not_valid_after, "2027-01-01T00:00:00Z");
    let dependency = bom
        .dependencies
        .iter()
        .find(|d| Some(d.reference.as_str()) == certificate.bom_ref.as_deref())
        .unwrap();
    assert!(dependency.depends_on.contains(&key.to_owned()));
}

#[test]
fn algorithm_properties_use_cyclonedx_vocabulary() {
    let bom = bom(&assess(), 1_790_000_000);
    let aes = component(&bom, "AES");
    let algorithm = aes
        .crypto_properties
        .as_ref()
        .unwrap()
        .algorithm_properties
        .as_ref()
        .unwrap();
    assert_eq!(algorithm.primitive.as_deref(), Some("block-cipher"));
    assert_eq!(algorithm.mode.as_deref(), Some("ecb"));
    assert_eq!(algorithm.padding.as_deref(), Some("pkcs5"));
    assert_eq!(algorithm.parameter_set_identifier.as_deref(), Some("128"));
    assert_eq!(algorithm.classical_security_level, Some(128));
    assert_eq!(
        aes.crypto_properties.as_ref().unwrap().oid.as_deref(),
        Some("2.16.840.1.101.3.4.1.1"),
        "AES-128-ECB"
    );

    let kem = component(&bom, "ML-KEM");
    let crypto = kem.crypto_properties.as_ref().unwrap();
    let algorithm = crypto.algorithm_properties.as_ref().unwrap();
    assert_eq!(algorithm.primitive.as_deref(), Some("kem"));
    assert_eq!(algorithm.nist_quantum_security_level, Some(3));
    assert_eq!(crypto.oid.as_deref(), Some("2.16.840.1.101.3.4.4.2"));
    assert_eq!(property(kem, "recommendation-action"), Some("retain"));
}

#[test]
fn risk_travels_as_namespaced_properties() {
    let bom = bom(&assess(), 1_790_000_000);
    let aes = component(&bom, "AES");
    for name in [
        "liveness",
        "evidence-grade",
        "quantum-breakability",
        "classical-status",
        "threat",
        "agility-score",
        "mosca-verdict",
        "priority",
        "tier",
        "recommendation-target",
    ] {
        assert!(property(aes, name).is_some(), "missing lattice:{name}");
    }
    assert_eq!(property(aes, "classical-status"), Some("legacy"));
    assert!(
        bom.components
            .iter()
            .flat_map(|c| &c.properties)
            .all(|p| p.name.starts_with("lattice:"))
    );
    let summary = |name: &str| {
        bom.metadata
            .properties
            .iter()
            .find(|p| p.name == format!("lattice:summary:{name}"))
            .unwrap()
            .value
            .clone()
    };
    assert_eq!(
        summary("assets"),
        bom.components
            .iter()
            .filter(|c| c.component_type == "cryptographic-asset")
            .count()
            .to_string()
    );
}

#[test]
fn private_keys_are_described_never_embedded() {
    let bom = bom(&assess(), 1_790_000_000);
    let key = component(&bom, "RSA-2048 private-key");
    let material = key
        .crypto_properties
        .as_ref()
        .unwrap()
        .related_crypto_material_properties
        .as_ref()
        .unwrap();
    assert_eq!(material.material_type, "private-key");
    assert_eq!(material.id.as_deref(), Some("blake3:0123456789abcdef"));
    assert!(material.algorithm_ref.is_some());
    assert!(material.secured_by.is_none(), "stored unencrypted");
    assert_eq!(property(key, "recommendation-action"), Some("rotate"));
    let text = String::from_utf8(render(&bom)).unwrap();
    assert!(!text.contains("BEGIN"), "no PEM material in the report");
}

#[test]
fn output_is_deterministic_and_serials_are_unique_per_document() {
    let assessed = assess();
    let first = render(&bom(&assessed, 1_790_000_000));
    let second = render(&bom(&assessed, 1_790_000_000));
    assert_eq!(first, second);
    let later = bom(&assessed, 1_790_000_001);
    assert_ne!(
        bom(&assessed, 1_790_000_000).serial_number,
        later.serial_number
    );
    assert!(later.serial_number.starts_with("urn:uuid:"));
    let refs: Vec<_> = later
        .components
        .iter()
        .filter(|c| c.component_type == "cryptographic-asset")
        .map(|c| c.bom_ref.clone())
        .collect();
    let mut sorted = refs.clone();
    sorted.sort();
    assert_eq!(refs, sorted);
}

#[test]
fn libraries_are_components_the_subject_depends_on() {
    let bom = bom(&assess(), 1_790_000_000);
    let library = bom
        .components
        .iter()
        .find(|c| c.component_type == "library")
        .unwrap();
    assert_eq!(library.version.as_deref(), Some("1.78"));
    assert_eq!(property(library, "pqc-capable"), Some("true"));
    let subject = &bom.dependencies[0];
    assert_eq!(subject.reference, SUBJECT_REF);
    assert!(
        subject
            .depends_on
            .contains(library.bom_ref.as_ref().unwrap())
    );
    // dependency-only algorithms (the certificate's) hang off the certificate, not the subject
    let certificate = component(&bom, "X.509");
    let cert_deps = &bom
        .dependencies
        .iter()
        .find(|d| Some(d.reference.as_str()) == certificate.bom_ref.as_deref())
        .unwrap()
        .depends_on;
    assert!(cert_deps.iter().all(|d| !subject.depends_on.contains(d)));
}

#[test]
fn a_rendered_cbom_signs_and_verifies() {
    let rendered = render(&bom(&assess(), 1_790_000_000));
    let keys = signing::generate_keypair().unwrap();
    let signature = signing::sign(&rendered, &keys.private_key, &keys.public_key).unwrap();
    assert_eq!(
        signature.chain.len(),
        serde_json::from_slice::<Value>(&rendered).unwrap()["components"]
            .as_array()
            .unwrap()
            .len()
    );
    signing::verify(&rendered, &signature, &keys.public_key).unwrap();
}
