//! Observations → assets: one asset per distinct cryptographic thing per component.

use crate::knowledge::{AlgorithmRef, Params};
use crate::model::{
    AlgorithmFinding, CryptoAsset, EvidenceGrade, EvidenceKind, EvidenceLayer, Finding, Liveness,
    Observation, Occurrence, ProtocolFinding, Surface,
};
use std::collections::{BTreeMap, BTreeSet};

/// Groups observations into deterministically ordered assets with liveness, evidence grades and
/// dependency links, each with the reason it was assigned.
pub fn normalize(observations: Vec<Observation>) -> Vec<CryptoAsset> {
    let observations = expand_dependencies(observations);

    // group by identity
    let mut groups: BTreeMap<String, Group> = BTreeMap::new();
    for observation in observations {
        let mut key = identity_key(&observation.component, &observation.finding);
        // a version-less setting (a cipher list) is identified by the file that declares it
        if let Finding::Protocol(protocol) = &observation.finding
            && protocol.version.is_none()
        {
            key.push('|');
            key.push_str(&observation.location.path);
        }
        let group = groups.entry(key).or_insert_with(|| Group {
            component: observation.component.clone(),
            finding: observation.finding.clone(),
            occurrences: Vec::new(),
        });
        if let (Finding::Protocol(existing), Finding::Protocol(incoming)) =
            (&mut group.finding, &observation.finding)
        {
            merge_protocol(existing, incoming);
        }
        group.occurrences.push(Occurrence {
            surface: observation.surface,
            location: observation.location,
            evidence: observation.evidence,
            usage: observation.usage,
            refined_from: None,
        });
    }

    refine_underspecified(&mut groups);
    attach_protocol_settings(&mut groups);

    let ids: BTreeMap<String, String> = groups
        .iter()
        .map(|(key, group)| (key.clone(), asset_id(&group.finding, key)))
        .collect();

    let mut assets: Vec<CryptoAsset> = groups
        .into_iter()
        .map(|(key, mut group)| {
            group.occurrences.sort();
            group.occurrences.dedup();
            let surfaces = group.occurrences.iter().map(|o| o.surface).collect();
            let (liveness, liveness_reason) = resolve_liveness(&group.occurrences);
            let (evidence_grade, grade_reason) = grade_evidence(&group.occurrences);
            let mut depends_on: Vec<String> = group
                .finding
                .dependencies()
                .into_iter()
                .filter_map(|algorithm| {
                    let dependency = Finding::algorithm(algorithm);
                    ids.get(&identity_key(&group.component, &dependency))
                        .cloned()
                })
                .collect();
            depends_on.sort();
            depends_on.dedup();
            CryptoAsset {
                id: ids[&key].clone(),
                component: group.component,
                finding: group.finding,
                occurrences: group.occurrences,
                surfaces,
                liveness,
                liveness_reason,
                evidence_grade,
                grade_reason,
                depends_on,
            }
        })
        .collect();
    assets.sort_by(|a, b| a.id.cmp(&b.id));
    assets
}

struct Group {
    component: String,
    finding: Finding,
    occurrences: Vec<Occurrence>,
}

/// Every algorithm a finding depends on is inventoried as its own asset: the digest inside
/// `SHA256withRSA`, a certificate's key and signature algorithms, a key file's key type.
fn expand_dependencies(observations: Vec<Observation>) -> Vec<Observation> {
    let mut expanded = Vec::with_capacity(observations.len());
    for observation in observations {
        for dependency in observation.finding.dependencies() {
            let mut derived = observation.clone();
            derived.finding = Finding::Algorithm(AlgorithmFinding {
                algorithm: dependency,
                primitive: None,
                function: None,
            });
            derived.evidence.rule_id = format!("{}#dependency", derived.evidence.rule_id);
            expanded.push(derived);
        }
        expanded.push(observation);
    }
    expanded
}

fn identity_key(component: &str, finding: &Finding) -> String {
    match finding {
        Finding::Algorithm(finding) => format!(
            "{component}|algorithm|{}|{}|{}",
            finding.algorithm.id,
            finding.primitive.map_or("", |primitive| primitive.as_str()),
            params_key(&finding.algorithm.params)
        ),
        Finding::Certificate(certificate) => {
            format!("{component}|certificate|{}", certificate.fingerprint_sha256)
        }
        Finding::Protocol(protocol) => format!(
            "{component}|protocol|{}|{}",
            protocol.protocol.as_str(),
            protocol.version.as_deref().unwrap_or("")
        ),
        Finding::RelatedCryptoMaterial(material) => {
            format!("{component}|material|{}", material.identity)
        }
    }
}

fn params_key(params: &Params) -> String {
    let lower = |value: &Option<String>| value.as_deref().unwrap_or("").to_ascii_lowercase();
    format!(
        "{}|{}|{}|{}|{}|{}",
        params
            .key_bits
            .map(|bits| bits.to_string())
            .unwrap_or_default(),
        lower(&params.parameter_set),
        lower(&params.curve),
        lower(&params.mode),
        lower(&params.padding),
        lower(&params.digest),
    )
}

fn merge_protocol(existing: &mut ProtocolFinding, incoming: &ProtocolFinding) {
    let mut suites: BTreeSet<String> = existing.cipher_suites.drain(..).collect();
    suites.extend(incoming.cipher_suites.iter().cloned());
    existing.cipher_suites = suites.into_iter().collect();
    let mut groups: BTreeSet<String> = existing.groups.drain(..).collect();
    groups.extend(incoming.groups.iter().cloned());
    existing.groups = groups.into_iter().collect();
}

/// A version-less protocol observation (a cipher-suite or group list) configures the versioned
/// protocol assets declared in the same file, so it is folded into each of them: nginx's
/// `ssl_ciphers` applies to every version `ssl_protocols` enables. With no versioned sibling in
/// the file it stays an asset of its own.
fn attach_protocol_settings(groups: &mut BTreeMap<String, Group>) {
    let files = |group: &Group| -> BTreeSet<String> {
        group
            .occurrences
            .iter()
            .map(|o| o.location.path.clone())
            .collect()
    };
    let versionless: Vec<String> = groups
        .iter()
        .filter(|(_, g)| matches!(&g.finding, Finding::Protocol(p) if p.version.is_none()))
        .map(|(key, _)| key.clone())
        .collect();
    for key in versionless {
        let Some(settings) = groups.get(&key) else {
            continue;
        };
        let Finding::Protocol(setting) = &settings.finding else {
            continue;
        };
        let (component, kind, setting_files) = (
            settings.component.clone(),
            setting.protocol,
            files(settings),
        );
        let targets: Vec<String> = groups
            .iter()
            .filter(|(other, g)| {
                *other != &key
                    && g.component == component
                    && matches!(&g.finding, Finding::Protocol(p) if p.protocol == kind && p.version.is_some())
                    && !files(g).is_disjoint(&setting_files)
            })
            .map(|(other, _)| other.clone())
            .collect();
        if targets.is_empty() {
            continue;
        }
        let settings = groups.remove(&key).expect("present above");
        let Finding::Protocol(setting) = &settings.finding else {
            unreachable!()
        };
        for target in targets {
            let group = groups.get_mut(&target).expect("collected above");
            if let Finding::Protocol(protocol) = &mut group.finding {
                merge_protocol(protocol, setting);
            }
            group
                .occurrences
                .extend(settings.occurrences.iter().cloned());
        }
    }
}

/// `a` is a less specific view of `b`: every parameter `a` knows, `b` agrees with, and `b`
/// knows more.
fn refines(a: &Params, b: &Params) -> bool {
    fn agrees<T: PartialEq>(a: &Option<T>, b: &Option<T>) -> bool {
        a.is_none() || a == b
    }
    a != b
        && agrees(&a.key_bits, &b.key_bits)
        && agrees(&a.parameter_set, &b.parameter_set)
        && agrees(&a.curve, &b.curve)
        && agrees(&a.mode, &b.mode)
        && agrees(&a.padding, &b.padding)
        && agrees(&a.digest, &b.digest)
}

/// Folds an under-specified algorithm group into the single more specific group of the same
/// algorithm in the same component. Ambiguous cases (two candidates) are left alone: guessing
/// which AES a bare `AES` meant would fabricate evidence.
fn refine_underspecified(groups: &mut BTreeMap<String, Group>) {
    let algorithm_of = |group: &Group| -> Option<(String, AlgorithmFinding)> {
        match &group.finding {
            Finding::Algorithm(finding) => Some((group.component.clone(), finding.clone())),
            _ => None,
        }
    };
    let snapshot: Vec<(String, String, AlgorithmFinding)> = groups
        .iter()
        .filter_map(|(key, group)| {
            algorithm_of(group).map(|(component, finding)| (key.clone(), component, finding))
        })
        .collect();

    let mut moves: Vec<(String, String)> = Vec::new();
    for (key, component, finding) in &snapshot {
        let candidates: Vec<&(String, String, AlgorithmFinding)> = snapshot
            .iter()
            .filter(|(other_key, other_component, other)| {
                other_key != key
                    && other_component == component
                    && other.algorithm.id == finding.algorithm.id
                    && (finding.primitive.is_none() || finding.primitive == other.primitive)
                    && refines(&finding.algorithm.params, &other.algorithm.params)
            })
            .collect();
        // Only the most specific candidates count: `AES` → {`AES-256`, `AES-256-GCM`} has one
        // real target, since `AES-256` is itself a less specific view of `AES-256-GCM`.
        let maximal: Vec<&String> = candidates
            .iter()
            .filter(|(_, _, candidate)| {
                !candidates.iter().any(|(_, _, other)| {
                    refines(&candidate.algorithm.params, &other.algorithm.params)
                })
            })
            .map(|(candidate_key, _, _)| candidate_key)
            .collect();
        if let [target] = maximal.as_slice() {
            moves.push((key.clone(), (*target).clone()));
        }
    }

    for (source, target) in moves {
        let Some(group) = groups.remove(&source) else {
            continue;
        };
        let refined_from = group.finding.display_name();
        if let Some(destination) = groups.get_mut(&target) {
            destination
                .occurrences
                .extend(group.occurrences.into_iter().map(|mut occurrence| {
                    occurrence.refined_from = Some(refined_from.clone());
                    occurrence
                }));
        } else {
            groups.insert(source, group);
        }
    }
}

fn asset_id(finding: &Finding, key: &str) -> String {
    let digest = blake3::hash(key.as_bytes()).to_hex();
    let slug = match finding {
        Finding::Algorithm(finding) => finding.algorithm.id.clone(),
        Finding::Certificate(_) => "x509".to_owned(),
        Finding::Protocol(protocol) => match &protocol.version {
            Some(version) => format!("{}-{version}", protocol.protocol.as_str()),
            None => protocol.protocol.as_str().to_owned(),
        },
        Finding::RelatedCryptoMaterial(_) => "key".to_owned(),
    };
    format!("crypto/{}/{slug}/{}", finding.asset_type(), &digest[..16])
}

fn resolve_liveness(occurrences: &[Occurrence]) -> (Liveness, String) {
    if let Some(runtime) = occurrences.iter().find(|o| o.surface == Surface::Runtime) {
        return (
            Liveness::Confirmed,
            format!("observed in live traffic at {}", runtime.location.short()),
        );
    }
    if let Some(config) = occurrences.iter().find(|o| {
        matches!(
            o.surface,
            Surface::Config | Surface::Cloud | Surface::Certificate
        )
    }) {
        return (
            Liveness::Configured,
            format!(
                "selected by {} at {}",
                match config.surface {
                    Surface::Cloud => "infrastructure-as-code",
                    Surface::Certificate => "deployed key or certificate material",
                    _ => "configuration",
                },
                config.location.short()
            ),
        );
    }
    if let Some(call) = occurrences
        .iter()
        .find(|o| o.surface == Surface::Source && o.evidence.kind == EvidenceKind::ApiCall)
    {
        let api = call
            .usage
            .as_ref()
            .map_or(call.evidence.matched_token.as_str(), |usage| {
                usage.api.as_str()
            });
        return (
            Liveness::Configured,
            format!("selected in code by `{api}` at {}", call.location.short()),
        );
    }
    let first = &occurrences[0];
    (
        Liveness::Capable,
        format!(
            "present only as {} evidence at {}; no code, configuration or runtime selects it",
            describe_kind(first.evidence.kind),
            first.location.short()
        ),
    )
}

fn describe_kind(kind: EvidenceKind) -> &'static str {
    match kind {
        EvidenceKind::Handshake => "handshake",
        EvidenceKind::ApiCall => "API call",
        EvidenceKind::Certificate => "certificate",
        EvidenceKind::Configuration => "configuration",
        EvidenceKind::Infrastructure => "infrastructure",
        EvidenceKind::Symbol => "binary symbol",
        EvidenceKind::Oid => "encoded OID",
        EvidenceKind::ByteSignature => "binary constant",
        EvidenceKind::Import => "import",
        EvidenceKind::Heuristic => "textual",
    }
}

fn grade_evidence(occurrences: &[Occurrence]) -> (EvidenceGrade, String) {
    let layers: BTreeSet<EvidenceLayer> = occurrences
        .iter()
        .filter(|o| o.evidence.kind != EvidenceKind::Heuristic)
        .map(|o| o.surface.layer())
        .collect();
    let describe = || {
        layers
            .iter()
            .map(|layer| layer.describe())
            .collect::<Vec<_>>()
            .join(", ")
    };
    match layers.len() {
        0 => (
            EvidenceGrade::D,
            "only unconfirmed textual matches; not validated structurally".into(),
        ),
        1 => (
            EvidenceGrade::C,
            format!("one evidence layer: {}", describe()),
        ),
        2 => (
            EvidenceGrade::B,
            format!("corroborated by two independent layers: {}", describe()),
        ),
        _ => (
            EvidenceGrade::A,
            format!("corroborated by all three layers: {}", describe()),
        ),
    }
}

/// Convenience used by tests and collectors: the canonical reference for a single algorithm.
pub fn algorithm_ref(id: &str, params: Params) -> AlgorithmRef {
    AlgorithmRef::with_params(id, params)
}

#[cfg(test)]
mod tests {
    #[test]
    fn mac_digests_are_parameters_signature_digests_are_assets() {
        let hmac = Params {
            digest: Some("sha-1".into()),
            ..Params::default()
        };
        let assets = normalize(vec![observe(
            Surface::Config,
            EvidenceKind::Configuration,
            "hmac",
            hmac,
            1,
        )]);
        assert_eq!(
            assets.len(),
            1,
            "HMAC-SHA1 does not inventory a standalone SHA-1"
        );
        let signature = Params {
            digest: Some("sha-1".into()),
            ..Params::default()
        };
        let assets = normalize(vec![observe(
            Surface::Source,
            EvidenceKind::ApiCall,
            "rsa",
            signature,
            1,
        )]);
        assert_eq!(
            assets.len(),
            2,
            "SHA1withRSA does: collisions forge signatures"
        );
    }

    #[test]
    fn protocol_settings_fold_into_the_versions_they_configure() {
        let protocol =
            |version: Option<&str>, suites: &[&str], line: u64, file: &str| Observation {
                surface: Surface::Config,
                component: ".".into(),
                location: crate::Location::at_line(file, line, 1),
                finding: Finding::Protocol(ProtocolFinding {
                    protocol: crate::model::ProtocolKind::Tls,
                    version: version.map(str::to_owned),
                    cipher_suites: suites.iter().map(|s| (*s).to_owned()).collect(),
                    groups: Vec::new(),
                }),
                evidence: crate::Evidence {
                    collector: "config".into(),
                    rule_id: "r".into(),
                    rule_version: "1".into(),
                    kind: EvidenceKind::Configuration,
                    matched_token: "t".into(),
                },
                usage: None,
            };
        let assets = normalize(vec![
            protocol(Some("1.0"), &[], 5, "nginx.conf"),
            protocol(Some("1.2"), &[], 5, "nginx.conf"),
            protocol(None, &["DES-CBC3-SHA"], 6, "nginx.conf"),
            protocol(None, &["TLS_AES_128_GCM_SHA256"], 3, "other.yaml"),
        ]);
        let protocols: Vec<&ProtocolFinding> = assets
            .iter()
            .filter_map(|a| match &a.finding {
                Finding::Protocol(p) => Some(p),
                _ => None,
            })
            .collect();
        assert_eq!(
            protocols.len(),
            3,
            "both versions keep their assets; the other file's list stands alone"
        );
        for version in ["1.0", "1.2"] {
            let p = protocols
                .iter()
                .find(|p| p.version.as_deref() == Some(version))
                .unwrap();
            assert_eq!(p.cipher_suites, vec!["DES-CBC3-SHA".to_owned()]);
        }
        assert!(
            protocols.iter().any(|p| p.version.is_none()
                && p.cipher_suites == vec!["TLS_AES_128_GCM_SHA256".to_owned()])
        );
    }

    use super::*;
    use crate::model::{AlgorithmSource, ApiStyle, Evidence, Location, Usage};

    fn evidence(kind: EvidenceKind) -> Evidence {
        Evidence {
            collector: "test".into(),
            rule_id: "rule".into(),
            rule_version: "1".into(),
            kind,
            matched_token: "token".into(),
        }
    }

    fn observe(
        surface: Surface,
        kind: EvidenceKind,
        id: &str,
        params: Params,
        line: u64,
    ) -> Observation {
        Observation {
            surface,
            component: ".".into(),
            location: Location::at_line("src/app.c", line, 1),
            finding: Finding::algorithm(AlgorithmRef::with_params(id, params)),
            evidence: evidence(kind),
            usage: None,
        }
    }

    fn aes(bits: Option<u32>, mode: Option<&str>) -> Params {
        Params {
            key_bits: bits,
            mode: mode.map(str::to_owned),
            ..Params::default()
        }
    }

    #[test]
    fn identical_findings_collapse_with_all_locations_kept() {
        let assets = normalize(vec![
            observe(
                Surface::Source,
                EvidenceKind::ApiCall,
                "rsa",
                Params::default(),
                4,
            ),
            observe(
                Surface::Source,
                EvidenceKind::ApiCall,
                "rsa",
                Params::default(),
                2,
            ),
        ]);
        assert_eq!(assets.len(), 1);
        assert_eq!(assets[0].occurrences.len(), 2);
        assert_eq!(assets[0].evidence_grade, EvidenceGrade::C);
        assert!(assets[0].id.starts_with("crypto/algorithm/rsa/"));
    }

    #[test]
    fn independent_layers_raise_the_grade_but_duplicate_layers_do_not() {
        let two_layers = normalize(vec![
            observe(
                Surface::Source,
                EvidenceKind::ApiCall,
                "rsa",
                Params::default(),
                1,
            ),
            observe(
                Surface::Binary,
                EvidenceKind::Symbol,
                "rsa",
                Params::default(),
                1,
            ),
        ]);
        assert_eq!(two_layers[0].evidence_grade, EvidenceGrade::B);

        let same_layer = normalize(vec![
            observe(
                Surface::Binary,
                EvidenceKind::Symbol,
                "rsa",
                Params::default(),
                1,
            ),
            observe(
                Surface::Config,
                EvidenceKind::Configuration,
                "rsa",
                Params::default(),
                1,
            ),
        ]);
        assert_eq!(
            same_layer[0].evidence_grade,
            EvidenceGrade::C,
            "binary + config are one layer"
        );

        let all = normalize(vec![
            observe(
                Surface::Source,
                EvidenceKind::ApiCall,
                "rsa",
                Params::default(),
                1,
            ),
            observe(
                Surface::Binary,
                EvidenceKind::Symbol,
                "rsa",
                Params::default(),
                1,
            ),
            observe(
                Surface::Runtime,
                EvidenceKind::Handshake,
                "rsa",
                Params::default(),
                1,
            ),
        ]);
        assert_eq!(all[0].evidence_grade, EvidenceGrade::A);
        assert_eq!(all[0].liveness, Liveness::Confirmed);
    }

    #[test]
    fn heuristic_only_evidence_is_grade_d() {
        let assets = normalize(vec![observe(
            Surface::Source,
            EvidenceKind::Heuristic,
            "md5",
            Params::default(),
            1,
        )]);
        assert_eq!(assets[0].evidence_grade, EvidenceGrade::D);
    }

    #[test]
    fn liveness_follows_the_strongest_selection() {
        let capable = normalize(vec![observe(
            Surface::Binary,
            EvidenceKind::Symbol,
            "rsa",
            Params::default(),
            1,
        )]);
        assert_eq!(capable[0].liveness, Liveness::Capable);
        let configured = normalize(vec![observe(
            Surface::Source,
            EvidenceKind::ApiCall,
            "rsa",
            Params::default(),
            1,
        )]);
        assert_eq!(configured[0].liveness, Liveness::Configured);
        assert!(configured[0].liveness_reason.contains("src/app.c:1"));
    }

    #[test]
    fn distinct_parameters_are_distinct_assets() {
        let assets = normalize(vec![
            observe(
                Surface::Source,
                EvidenceKind::ApiCall,
                "aes",
                aes(Some(128), Some("cbc")),
                1,
            ),
            observe(
                Surface::Source,
                EvidenceKind::ApiCall,
                "aes",
                aes(Some(256), Some("gcm")),
                2,
            ),
        ]);
        assert_eq!(assets.len(), 2);
    }

    #[test]
    fn a_bare_algorithm_refines_into_the_only_concrete_variant() {
        let assets = normalize(vec![
            observe(
                Surface::Source,
                EvidenceKind::ApiCall,
                "aes",
                aes(None, None),
                1,
            ),
            observe(
                Surface::Binary,
                EvidenceKind::Symbol,
                "aes",
                aes(Some(256), Some("gcm")),
                2,
            ),
        ]);
        assert_eq!(assets.len(), 1);
        assert_eq!(assets[0].evidence_grade, EvidenceGrade::B);
        assert!(
            assets[0]
                .occurrences
                .iter()
                .any(|o| o.refined_from.is_some())
        );
    }

    #[test]
    fn a_bare_algorithm_is_not_guessed_between_two_variants() {
        let assets = normalize(vec![
            observe(
                Surface::Source,
                EvidenceKind::ApiCall,
                "aes",
                aes(None, None),
                1,
            ),
            observe(
                Surface::Binary,
                EvidenceKind::Symbol,
                "aes",
                aes(Some(256), Some("gcm")),
                2,
            ),
            observe(
                Surface::Binary,
                EvidenceKind::Symbol,
                "aes",
                aes(Some(128), Some("cbc")),
                3,
            ),
        ]);
        assert_eq!(assets.len(), 3);
    }

    #[test]
    fn signature_digests_become_linked_dependency_assets() {
        let params = Params {
            key_bits: Some(2048),
            digest: Some("sha-256".into()),
            ..Params::default()
        };
        let assets = normalize(vec![observe(
            Surface::Source,
            EvidenceKind::ApiCall,
            "rsa",
            params,
            1,
        )]);
        assert_eq!(assets.len(), 2);
        let rsa = assets
            .iter()
            .find(|a| a.algorithm().is_some_and(|alg| alg.id == "rsa"))
            .unwrap();
        let sha = assets
            .iter()
            .find(|a| a.algorithm().is_some_and(|alg| alg.id == "sha-256"))
            .unwrap();
        assert_eq!(rsa.depends_on, vec![sha.id.clone()]);
    }

    #[test]
    fn components_keep_the_same_algorithm_separate() {
        let mut a = observe(
            Surface::Source,
            EvidenceKind::ApiCall,
            "rsa",
            Params::default(),
            1,
        );
        a.component = "services/payments".into();
        let mut b = a.clone();
        b.component = "services/identity".into();
        assert_eq!(normalize(vec![a, b]).len(), 2);
    }

    #[test]
    fn usage_is_carried_onto_occurrences() {
        let mut observation = observe(
            Surface::Source,
            EvidenceKind::ApiCall,
            "sha-1",
            Params::default(),
            7,
        );
        observation.usage = Some(Usage {
            language: "python".into(),
            api: "hashlib.sha1".into(),
            function: Some("payment.py::legacy_receipt".into()),
            identifiers: vec!["value".into()],
            algorithm_source: AlgorithmSource::Implicit,
            api_style: ApiStyle::Primitive,
        });
        let assets = normalize(vec![observation]);
        assert_eq!(assets[0].usages().next().unwrap().api, "hashlib.sha1");
    }

    #[test]
    fn output_is_deterministic_regardless_of_input_order() {
        let first = normalize(vec![
            observe(
                Surface::Source,
                EvidenceKind::ApiCall,
                "rsa",
                Params::default(),
                1,
            ),
            observe(
                Surface::Source,
                EvidenceKind::ApiCall,
                "md5",
                Params::default(),
                2,
            ),
        ]);
        let second = normalize(vec![
            observe(
                Surface::Source,
                EvidenceKind::ApiCall,
                "md5",
                Params::default(),
                2,
            ),
            observe(
                Surface::Source,
                EvidenceKind::ApiCall,
                "rsa",
                Params::default(),
                1,
            ),
        ]);
        assert_eq!(first, second);
    }
}
