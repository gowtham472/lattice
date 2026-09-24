use super::*;
use compare::{ChangeKind, compare};
use lattice_core::{EntryKind, Finding, Liveness};
use lattice_risk::{Threat, Tier};
use std::fs;
use std::path::PathBuf;

const TIMESTAMP: i64 = 1_790_121_600; // 2026-09-23T00:00:00Z

const SERVER_PY: &str = r#"from flask import Flask, request
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

app = Flask(__name__)


@app.route("/pay", methods=["POST"])
def pay():
    card_number = request.json["card_number"]
    return encrypt_card(card_number)


def encrypt_card(card_number):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.public_key().encrypt(card_number.encode(), padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
"#;

const LEGACY_PY: &str = r#"import hashlib


def file_checksum(data):
    return hashlib.md5(data).hexdigest()
"#;

const CRYPTO_JAVA: &str = r#"import javax.crypto.Cipher;

final class LedgerCrypto {
    static Cipher ledgerCipher() throws Exception {
        return Cipher.getInstance("AES/ECB/PKCS5Padding");
    }
}
"#;

const NGINX_CONF: &str = r#"server {
    listen 443 ssl;
    server_name pay.example.in;
    ssl_certificate /etc/tls/server.crt;
    ssl_protocols TLSv1 TLSv1.2;
    ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:DES-CBC3-SHA;
}
"#;

fn project() -> tempfile::TempDir {
    let dir = tempfile::Builder::new()
        .prefix("payments")
        .tempdir()
        .unwrap();
    let write = |path: &str, contents: &[u8]| {
        let full: PathBuf = dir.path().join(path);
        fs::create_dir_all(full.parent().unwrap()).unwrap();
        fs::write(full, contents).unwrap();
    };
    write("app/server.py", SERVER_PY.as_bytes());
    write("app/legacy.py", LEGACY_PY.as_bytes());
    write("src/LedgerCrypto.java", CRYPTO_JAVA.as_bytes());
    write("deploy/nginx.conf", NGINX_CONF.as_bytes());
    write(
        "deploy/tls/server.crt",
        include_bytes!("../../lattice-collectors/tests/fixtures/rsa2048-sha256.pem"),
    );
    dir
}

fn config() -> Config {
    let mut config = Config::new(TIMESTAMP);
    config.subject = Some("payments".into());
    config
}

fn find(report: &Report, predicate: impl Fn(&AssetReport) -> bool) -> &AssetReport {
    report
        .assets
        .iter()
        .find(|a| predicate(a))
        .unwrap_or_else(|| {
            let names: Vec<String> = report
                .assets
                .iter()
                .map(|a| a.asset.finding.display_name())
                .collect();
            panic!("no matching asset among {names:?}")
        })
}

fn algorithm_is(asset: &AssetReport, id: &str) -> bool {
    asset.asset.algorithm().is_some_and(|a| a.id == id)
        && matches!(asset.asset.finding, Finding::Algorithm(_))
}

#[test]
fn assessment_year_follows_the_timestamp() {
    assert_eq!(Config::new(TIMESTAMP).assessment_year, 2026);
    let restamped = Config::new(0).stamped(TIMESTAMP);
    assert_eq!(
        (restamped.timestamp, restamped.assessment_year),
        (TIMESTAMP, 2026)
    );
    assert_eq!(lattice_core::rfc3339(TIMESTAMP), "2026-09-23T00:00:00Z");
}

#[test]
fn rsa_behind_an_http_route_protecting_card_data_is_confirmed_and_urgent() {
    let dir = project();
    let outcome = run(dir.path(), &config()).unwrap();
    let report = &outcome.report;
    let rsa = find(report, |a| {
        algorithm_is(a, "rsa")
            && a.asset
                .occurrences
                .iter()
                .any(|o| o.location.path == "app/server.py")
    });
    assert!(rsa.context.reachable, "{}", rsa.context.exposure_reason);
    assert_eq!(
        rsa.context.entry.as_ref().map(|e| e.kind),
        Some(EntryKind::HttpRoute)
    );
    assert_eq!(
        rsa.asset.liveness,
        Liveness::Confirmed,
        "{}",
        rsa.asset.liveness_reason
    );
    assert_eq!(
        rsa.context.data.class, "financial",
        "{}",
        rsa.context.data.explanation
    );
    assert_eq!(rsa.assessment.threat, Threat::Harvest);
    assert_eq!(rsa.assessment.quantum_breakability, 1.0);
    assert!(
        rsa.assessment.mosca.urgent,
        "{}",
        rsa.assessment.mosca.verdict
    );
    assert!(
        rsa.assessment.tier >= Tier::High,
        "priority {}",
        rsa.assessment.priority
    );
    assert!(
        rsa.recommendation.target.contains("ML-KEM"),
        "{}",
        rsa.recommendation.target
    );
}

#[test]
fn classically_broken_and_misconfigured_crypto_is_flagged() {
    let dir = project();
    let report = run(dir.path(), &config()).unwrap().report;
    let md5 = find(&report, |a| algorithm_is(a, "md5"));
    assert!(md5.assessment.broken_now);
    assert_eq!(md5.assessment.tier, Tier::Critical);

    let ecb = find(&report, |a| {
        algorithm_is(a, "aes") && a.asset.algorithm().unwrap().params.mode.as_deref() == Some("ecb")
    });
    assert_eq!(
        ecb.assessment.classical_status,
        lattice_core::ClassicalStatus::Legacy
    );

    let tls10 = find(
        &report,
        |a| matches!(&a.asset.finding, Finding::Protocol(p) if p.version.as_deref() == Some("1.0")),
    );
    assert_eq!(
        tls10.assessment.classical_status,
        lattice_core::ClassicalStatus::Disallowed
    );
    assert_eq!(
        tls10.context.entry.as_ref().map(|e| e.kind),
        Some(EntryKind::Listener),
        "{}",
        tls10.context.exposure_reason
    );

    let certificate = find(&report, |a| {
        matches!(a.asset.finding, Finding::Certificate(_))
    });
    assert_eq!(certificate.assessment.threat, Threat::Forge);
}

#[test]
fn reports_are_ordered_by_priority_and_explain_every_score() {
    let dir = project();
    let report = run(dir.path(), &config()).unwrap().report;
    assert!(
        report
            .assets
            .windows(2)
            .all(|w| w[0].assessment.priority >= w[1].assessment.priority)
    );
    for asset in &report.assets {
        assert!(!asset.assessment.quantum_reason.is_empty());
        assert!(!asset.assessment.mosca.verdict.is_empty());
        assert!(!asset.asset.liveness_reason.is_empty());
        assert!(
            asset
                .assessment
                .index_terms
                .iter()
                .all(|t| !t.reason.is_empty())
        );
    }
    assert!(report.failures.is_empty(), "{:?}", report.failures);
    assert_eq!(report.summary.assets, report.assets.len());
    assert!(!report.roadmap.is_empty());
    assert!(report.roadmap.windows(2).all(|w| w[0].wave <= w[1].wave));
    for asset in &report.assets {
        assert_eq!(
            asset.effort.is_some(),
            asset.recommendation.action != "retain",
            "every change, and only a change, has an effort: {}",
            asset.name
        );
    }
    let planned: f64 = report.roadmap.iter().map(|i| i.effort_person_weeks).sum();
    assert!((report.plan.total_person_weeks - planned).abs() < 0.05);
    assert!(report.plan.engineers_needed.is_some());
    assert_eq!(report.provenance.assessment_year, 2026);
    assert!(report.graph.entry_points >= 1);
}

#[test]
fn the_cbom_is_schema_valid_and_runs_are_reproducible() {
    let dir = project();
    let first = run(dir.path(), &config()).unwrap();
    let second = run(dir.path(), &config()).unwrap();
    let document = serde_json::to_value(&first.cbom).unwrap();
    if let Err(violations) = lattice_cbom::validate::validate(&document) {
        panic!(
            "{}",
            violations
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("\n")
        );
    }
    lattice_cbom::validate::check_references(&document).unwrap();
    assert_eq!(
        lattice_cbom::render(&first.cbom),
        lattice_cbom::render(&second.cbom)
    );
    assert_eq!(
        serde_json::to_string(&first.report).unwrap(),
        serde_json::to_string(&second.report).unwrap()
    );
    let text = String::from_utf8(lattice_cbom::render(&first.cbom)).unwrap();
    assert!(
        !text.contains(&dir.path().display().to_string()),
        "absolute scan paths never leak into reports"
    );
}

#[test]
fn the_gate_fails_on_new_high_risk_crypto_and_passes_on_its_removal() {
    let dir = project();
    let baseline = run(dir.path(), &config()).unwrap().cbom;
    fs::write(
        dir.path().join("app/tokens.py"),
        "from Crypto.Cipher import DES\n\n\ndef seal(token_key, data):\n    return DES.new(token_key, DES.MODE_CBC).encrypt(data)\n",
    )
    .unwrap();
    let current = run(dir.path(), &config()).unwrap().cbom;

    let comparison = compare(&baseline, &current, Tier::High);
    assert!(!comparison.passed());
    let added: Vec<_> = comparison.regressions().collect();
    assert!(added.iter().all(|c| c.kind == ChangeKind::Added));
    assert!(added.iter().any(|c| c.name.starts_with("DES")), "{added:?}");

    let reverse = compare(&current, &baseline, Tier::High);
    assert!(reverse.passed());
    assert!(
        reverse
            .changes
            .iter()
            .any(|c| c.kind == ChangeKind::Removed)
    );

    assert!(
        compare(&baseline, &baseline, Tier::Info).changes.is_empty(),
        "identical scans have no changes"
    );
}

#[test]
fn captured_traffic_confirms_the_listener_that_serves_it() {
    let dir = tempfile::Builder::new().prefix("edge").tempdir().unwrap();
    let write = |path: &str, contents: &[u8]| {
        let full = dir.path().join(path);
        fs::create_dir_all(full.parent().unwrap()).unwrap();
        fs::write(full, contents).unwrap();
    };
    write(
        "gateway/nginx.conf",
        b"server {\n    listen 443 ssl;\n    server_name pay.example.gov.in;\n    ssl_protocols TLSv1 TLSv1.2;\n}\n",
    );
    // a manifest-bearing service makes this an estate, so top-level directories are components
    write(
        "payments/requirements.txt",
        b"flask
",
    );
    // real OpenSSL handshakes recorded by scripts/make-demo-artefacts.py
    write(
        "captures/edge-traffic.pcap",
        include_bytes!("../../../examples/demo-estate/captures/edge-traffic.pcap"),
    );
    write(
        "images/payments-api-4.2.0.tar",
        include_bytes!("../../../examples/demo-estate/images/payments-api-4.2.0.tar"),
    );
    let report = run(dir.path(), &config()).unwrap().report;
    assert!(report.failures.is_empty(), "{:?}", report.failures);

    let tls10 = find(
        &report,
        |a| matches!(&a.asset.finding, Finding::Protocol(p) if p.version.as_deref() == Some("1.0")),
    );
    assert_eq!(
        tls10.asset.component, "gateway",
        "attributed through the server name to the listener's component"
    );
    let surfaces: Vec<_> = tls10.asset.surfaces.iter().map(|s| s.as_str()).collect();
    assert_eq!(
        surfaces,
        vec!["config", "runtime"],
        "configured and negotiated: one asset"
    );
    assert_eq!(tls10.asset.liveness, Liveness::Confirmed);
    assert!(
        tls10.asset.liveness_reason.contains("live traffic"),
        "{}",
        tls10.asset.liveness_reason
    );

    let served = find(
        &report,
        |a| matches!(&a.asset.finding, Finding::Certificate(c) if c.subject.contains("pay.example.gov.in")),
    );
    assert_eq!(served.asset.component, "gateway");
    assert!(
        served.context.exposure_reason.contains("live traffic"),
        "{}",
        served.context.exposure_reason
    );

    let hybrid = find(&report, |a| algorithm_is(a, "x25519-mlkem768"));
    assert_eq!(
        hybrid.asset.component, "captures",
        "no configured listener answers to the ledger's name"
    );
    assert_eq!(hybrid.assessment.quantum_breakability, 0.0);

    let image = "registry.example.gov.in/payments-api:4.2.0";
    assert!(report.assets.iter().any(|a| a.asset.component == image));
    assert!(
        !report.assets.iter().any(|a| a.asset.component == image
            && matches!(&a.asset.finding, Finding::RelatedCryptoMaterial(_))),
        "the debug key deleted by a later layer is not in the image"
    );
    let openssl = report
        .libraries
        .iter()
        .find(|l| l.component == image && l.name == "OpenSSL")
        .unwrap();
    assert_eq!(
        (openssl.version.as_deref(), openssl.pqc_capable),
        (Some("3.0.13"), false)
    );
}

#[test]
fn progress_counts_every_file_and_ends_done() {
    let dir = tempfile::tempdir().unwrap();
    fs::create_dir_all(dir.path().join("app")).unwrap();
    for i in 0..5 {
        fs::write(
            dir.path().join(format!("app/m{i}.py")),
            "import hashlib
hashlib.md5(b'x')
",
        )
        .unwrap();
    }
    let progress = std::sync::Arc::new(lattice_collectors::Progress::default());
    let mut config = config();
    config.scan.progress = Some(progress.clone());
    assert_eq!(progress.snapshot().phase, lattice_collectors::Phase::Queued);
    run(dir.path(), &config).unwrap();
    let done = progress.snapshot();
    assert_eq!(done.phase, lattice_collectors::Phase::Done);
    assert_eq!(done.files_total, 5);
    assert_eq!(done.files_done, 5);
    assert!(done.bytes_done > 0);
}
