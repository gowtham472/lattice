use super::advisor::{recommend, roadmap};
use super::*;
use lattice_classify::Classifier;
use lattice_core::{
    AlgorithmRef, AlgorithmSource, CertificateFinding, EntryKind, EntryPoint, Evidence,
    EvidenceKind, Location, MaterialFinding, MaterialType, Observation, Params, ProtocolFinding,
    Usage, normalize,
};

const YEAR: u16 = 2026;

fn assessor() -> Assessor<'static> {
    Assessor {
        policy: Policy::active(),
        assessment_year: YEAR,
    }
}

fn observation(surface: Surface, finding: Finding, usage: Option<Usage>) -> Observation {
    Observation {
        surface,
        component: ".".into(),
        location: Location::at_line("app/pay.py", 10, 1),
        finding,
        evidence: Evidence {
            collector: "test".into(),
            rule_id: "test.rule".into(),
            rule_version: "1".into(),
            kind: if surface == Surface::Source {
                EvidenceKind::ApiCall
            } else {
                EvidenceKind::Configuration
            },
            matched_token: "t".into(),
        },
        usage,
    }
}

fn usage(style: ApiStyle, source: AlgorithmSource) -> Usage {
    Usage {
        language: "python".into(),
        api: "api".into(),
        function: Some("f/pay".into()),
        identifiers: vec!["card_number".into()],
        algorithm_source: source,
        api_style: style,
    }
}

fn algorithm(id: &str, params: Params) -> Finding {
    Finding::algorithm(AlgorithmRef::with_params(id, params))
}

fn context(class: &str, exposure: f64) -> AssetContext {
    let classifier = Classifier::new(Policy::active());
    let data = match class {
        "financial" => classifier.classify_evidence(
            "x",
            &[(
                lattice_classify::EvidenceSource::Argument,
                "card_number".into(),
            )],
        ),
        _ => classifier.unclassified("x"),
    };
    AssetContext {
        reachable: exposure >= 1.0,
        entry: (exposure >= 1.0).then(|| EntryPoint {
            kind: EntryKind::HttpRoute,
            detail: "@app.route('/pay')".into(),
        }),
        path: vec!["pay".into()],
        exposure,
        exposure_reason: "test exposure".into(),
        data,
        data_inherited: false,
        pqc_ready_library: None,
    }
}

/// The asset the observation itself produced: normalisation also emits the algorithms it depends
/// on (a certificate's key and signature algorithm), which nothing else points back to it.
fn single(observation: Observation) -> CryptoAsset {
    let assets = normalize(vec![observation]);
    let dependencies: std::collections::HashSet<&str> = assets
        .iter()
        .flat_map(|a| a.depends_on.iter().map(String::as_str))
        .collect();
    let root = assets
        .iter()
        .position(|a| !dependencies.contains(a.id.as_str()))
        .expect("a root asset");
    assets.into_iter().nth(root).unwrap()
}

fn confirmed(mut asset: CryptoAsset) -> CryptoAsset {
    asset.confirm("reachable from @app.route('/pay')");
    asset
}

#[test]
fn internet_reachable_rsa_protecting_financial_data_is_mosca_urgent() {
    let asset = confirmed(single(observation(
        Surface::Source,
        algorithm(
            "rsa",
            Params {
                key_bits: Some(2048),
                ..Params::default()
            },
        ),
        Some(usage(ApiStyle::Provider, AlgorithmSource::Literal)),
    )));
    let assessment = assessor().assess(&asset, &context("financial", 1.0));
    assert_eq!(assessment.quantum_breakability, 1.0);
    assert_eq!(assessment.threat, Threat::Harvest);
    assert_eq!(assessment.index_kind, "hndl");
    // 100 × exposure 1.0 × lifetime 10/25 × QB 1.0 × liveness 1.0
    assert_eq!(assessment.exposure_index, 40.0);
    assert!(assessment.mosca.urgent, "X=10 + Y > Z=4");
    assert!(assessment.mosca.urgent_even_if_late, "X=10 + Y > Z=9 too");
    assert_eq!(assessment.mosca.z_earliest_years, 4.0);
    assert_eq!(assessment.tier, Tier::High);
    assert!(
        assessment
            .index_terms
            .iter()
            .all(|term| !term.reason.is_empty()),
        "every term is explained"
    );
}

#[test]
fn broken_hashes_are_critical_regardless_of_quantum() {
    let asset = single(observation(
        Surface::Source,
        algorithm("sha-1", Params::default()),
        Some(usage(ApiStyle::Primitive, AlgorithmSource::Implicit)),
    ));
    let assessment = assessor().assess(&asset, &context("unclassified", 0.3));
    assert!(assessment.broken_now);
    assert_eq!(assessment.threat, Threat::Integrity);
    assert!(assessment.priority >= 90);
    assert_eq!(assessment.tier, Tier::Critical);
    assert_eq!(
        recommend(&asset, &assessment, 5.0).target,
        "SHA-384 (or SHA3-384)"
    );
}

#[test]
fn post_quantum_assets_need_no_action() {
    let asset = single(observation(
        Surface::Source,
        algorithm(
            "ml-kem",
            Params {
                parameter_set: Some("768".into()),
                ..Params::default()
            },
        ),
        Some(usage(ApiStyle::Provider, AlgorithmSource::Literal)),
    ));
    let assessment = assessor().assess(&asset, &context("financial", 1.0));
    assert_eq!(assessment.quantum_breakability, 0.0);
    assert!(!assessment.mosca.applicable);
    assert!(assessment.priority <= 5);
    assert_eq!(recommend(&asset, &assessment, 10.0).action, "retain");
}

#[test]
fn symmetric_key_size_decides_grover_margin() {
    let aes128 = single(observation(
        Surface::Source,
        algorithm(
            "aes",
            Params {
                key_bits: Some(128),
                mode: Some("gcm".into()),
                ..Params::default()
            },
        ),
        None,
    ));
    let aes256 = single(observation(
        Surface::Source,
        algorithm(
            "aes",
            Params {
                key_bits: Some(256),
                mode: Some("gcm".into()),
                ..Params::default()
            },
        ),
        None,
    ));
    let a128 = assessor().assess(&aes128, &context("financial", 1.0));
    let a256 = assessor().assess(&aes256, &context("financial", 1.0));
    assert_eq!(a128.quantum_breakability, 0.5);
    assert_eq!(a256.quantum_breakability, 0.1);
    assert_eq!(recommend(&aes128, &a128, 10.0).target, "AES-256-GCM");
    assert_eq!(recommend(&aes256, &a256, 10.0).action, "retain");
}

#[test]
fn ecb_is_flagged_even_with_a_strong_key() {
    let asset = single(observation(
        Surface::Source,
        algorithm(
            "aes",
            Params {
                key_bits: Some(256),
                mode: Some("ecb".into()),
                ..Params::default()
            },
        ),
        None,
    ));
    let assessment = assessor().assess(&asset, &context("financial", 1.0));
    assert_eq!(assessment.classical_status, ClassicalStatus::Legacy);
    let recommendation = recommend(&asset, &assessment, 10.0);
    assert!(recommendation.rationale.contains("ECB"));
}

#[test]
fn certificates_use_their_remaining_validity_as_mosca_x() {
    let certificate = Finding::Certificate(CertificateFinding {
        subject: "CN=api".into(),
        issuer: "CN=ca".into(),
        not_before: "2025-01-01T00:00:00Z".into(),
        not_after: "2035-01-01T00:00:00Z".into(),
        serial: "01".into(),
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
        fingerprint_sha256: "ab".repeat(32),
    });
    let asset = single(observation(Surface::Certificate, certificate, None));
    let assessment = assessor().assess(&asset, &context("unclassified", 1.0));
    assert_eq!(assessment.threat, Threat::Forge);
    assert_eq!(assessment.index_kind, "tnfl");
    assert_eq!(assessment.mosca.x_years, 9.0);
    assert!(
        assessment
            .classical_reasons
            .iter()
            .any(|r| r.contains("398 days")),
        "10-year leaf validity is legacy"
    );
    let recommendation = recommend(&asset, &assessment, 9.0);
    assert!(recommendation.target.contains("ML-DSA"));
    let delta = recommendation.size_delta.unwrap();
    assert_eq!(delta.before_bytes, 512);
    assert_eq!(
        delta.after_bytes,
        1952 + 3309,
        "ML-DSA-65 sizes come from FIPS 204 via the knowledge base"
    );
}

#[test]
fn deprecated_tls_versions_are_disallowed_and_pq_groups_are_safe() {
    let old = single(observation(
        Surface::Config,
        Finding::Protocol(ProtocolFinding {
            protocol: ProtocolKind::Tls,
            version: Some("1.0".into()),
            cipher_suites: vec![],
            groups: vec![],
        }),
        None,
    ));
    let assessment = assessor().assess(&old, &context("financial", 1.0));
    assert_eq!(assessment.classical_status, ClassicalStatus::Disallowed);
    assert!(
        assessment
            .classical_reasons
            .iter()
            .any(|r| r.contains("RFC 8996"))
    );
    assert_eq!(recommend(&old, &assessment, 10.0).action, "upgrade");

    let hybrid = single(observation(
        Surface::Config,
        Finding::Protocol(ProtocolFinding {
            protocol: ProtocolKind::Tls,
            version: None,
            cipher_suites: vec![],
            groups: vec!["X25519MLKEM768".into(), "x25519".into()],
        }),
        None,
    ));
    let assessment = assessor().assess(&hybrid, &context("financial", 1.0));
    assert_eq!(assessment.quantum_breakability, 0.0);
    assert_eq!(recommend(&hybrid, &assessment, 10.0).action, "retain");
}

#[test]
fn agility_is_measured_from_how_code_uses_the_algorithm() {
    let provider = single(observation(
        Surface::Source,
        algorithm("rsa", Params::default()),
        Some(usage(ApiStyle::Provider, AlgorithmSource::Constant)),
    ));
    let primitive = single(observation(
        Surface::Source,
        algorithm("rsa", Params::default()),
        Some(usage(ApiStyle::Primitive, AlgorithmSource::Literal)),
    ));
    let a = agility(&provider, &context("financial", 1.0), Policy::active());
    let b = agility(&primitive, &context("financial", 1.0), Policy::active());
    assert_eq!(
        a.score,
        40 + 10 + 15,
        "provider + named constant + centralised"
    );
    assert_eq!(b.score, 15, "only centralised");
    assert!(a.factors.iter().all(|factor| !factor.reason.is_empty()));

    let mut ready = context("financial", 1.0);
    ready.pqc_ready_library = Some("OpenSSL 3.5.1".into());
    assert_eq!(
        agility(&primitive, &ready, Policy::active()).score,
        25,
        "a PQC-capable library adds 10"
    );

    let configured = single(observation(
        Surface::Config,
        algorithm("rsa", Params::default()),
        None,
    ));
    assert_eq!(
        agility(&configured, &context("financial", 1.0), Policy::active()).score,
        40 + 20 + 15
    );
}

#[test]
fn low_agility_lengthens_migration_and_can_flip_mosca() {
    let easy = single(observation(
        Surface::Config,
        algorithm("rsa", Params::default()),
        None,
    ));
    let hard = single(observation(
        Surface::Source,
        algorithm("rsa", Params::default()),
        Some(usage(ApiStyle::Primitive, AlgorithmSource::Literal)),
    ));
    let e = assessor().assess(&easy, &context("unclassified", 1.0));
    let h = assessor().assess(&hard, &context("unclassified", 1.0));
    assert!(h.mosca.y_years > e.mosca.y_years);
    // unclassified data: X = 5; Y hard = 0.25 + 85×0.04 = 3.65 → X+Y = 8.65 > Z earliest (4)
    assert_eq!(h.mosca.y_years, 3.65);
    assert!(h.mosca.urgent);
}

#[test]
fn unencrypted_private_keys_must_be_rotated() {
    let key = single(observation(
        Surface::Certificate,
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
            identity: "abc".into(),
        }),
        None,
    ));
    let assessment = assessor().assess(&key, &context("unclassified", 0.3));
    assert_eq!(assessment.classical_status, ClassicalStatus::Disallowed);
    assert_eq!(recommend(&key, &assessment, 5.0).action, "rotate");
}

#[test]
fn key_exchange_size_delta_is_computed_not_quoted() {
    let asset = single(observation(
        Surface::Source,
        algorithm(
            "ecdh",
            Params {
                curve: Some("P-256".into()),
                ..Params::default()
            },
        ),
        None,
    ));
    let assessment = assessor().assess(&asset, &context("financial", 1.0));
    let delta = recommend(&asset, &assessment, 10.0).size_delta.unwrap();
    assert_eq!(delta.before_bytes, 130);
    assert_eq!(delta.after_bytes, 1216 + 1120);
}

#[test]
fn roadmap_puts_urgent_quick_wins_first_and_skips_retained_assets() {
    let quick = single(observation(
        Surface::Config,
        algorithm(
            "rsa",
            Params {
                key_bits: Some(1024),
                ..Params::default()
            },
        ),
        None,
    ));
    let hard = confirmed(single(observation(
        Surface::Source,
        algorithm(
            "rsa",
            Params {
                key_bits: Some(2048),
                ..Params::default()
            },
        ),
        Some(usage(ApiStyle::Primitive, AlgorithmSource::Literal)),
    )));
    let fine = single(observation(
        Surface::Source,
        algorithm(
            "ml-kem",
            Params {
                parameter_set: Some("768".into()),
                ..Params::default()
            },
        ),
        None,
    ));
    let ctx = context("financial", 1.0);
    let assessments: Vec<(CryptoAsset, Assessment)> = [quick, hard, fine]
        .into_iter()
        .map(|asset| {
            let assessment = assessor().assess(&asset, &ctx);
            (asset, assessment)
        })
        .collect();
    let recommendations: Vec<Recommendation> = assessments
        .iter()
        .map(|(a, s)| recommend(a, s, 10.0))
        .collect();
    let items: Vec<_> = assessments
        .iter()
        .zip(&recommendations)
        .map(|((a, s), r)| (a, s, r))
        .collect();
    let plan = roadmap(&items);
    assert_eq!(plan.len(), 2, "the ML-KEM asset is retained, not planned");
    assert_eq!(
        plan[0].wave, 1,
        "configurable RSA-1024 is an urgent quick win"
    );
    assert_eq!(plan[1].wave, 2, "hard-coded RSA is urgent re-engineering");
}

use advisor::Recommendation;
