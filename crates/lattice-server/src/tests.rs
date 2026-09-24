use super::*;
use axum::body::Body;
use axum::http::Request;
use http_body_util::BodyExt;
use serde_json::{Value, json};
use std::time::Duration;
use tower::ServiceExt;

struct Fixture {
    _dir: tempfile::TempDir,
    root: PathBuf,
    data: PathBuf,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("estate");
    let app = root.join("payments/src");
    std::fs::create_dir_all(&app).unwrap();
    std::fs::write(
        app.join("receipt.py"),
        "import hashlib\n\ndef receipt(data):\n    return hashlib.md5(data).hexdigest()\n",
    )
    .unwrap();
    std::fs::create_dir_all(root.join("identity")).unwrap();
    std::fs::write(root.join("identity/Keys.java"), "import java.security.KeyPairGenerator;\nclass Keys { Object k() throws Exception { return KeyPairGenerator.getInstance(\"RSA\"); } }\n").unwrap();
    let data = dir.path().join("data");
    Fixture {
        _dir: dir,
        root,
        data,
    }
}

fn config(fixture: &Fixture, bind: &str, token: Option<&str>) -> ServerConfig {
    ServerConfig {
        bind: bind.parse().unwrap(),
        roots: vec![("estate".into(), fixture.root.clone())],
        token: token.map(str::to_owned),
        data_dir: Some(fixture.data.clone()),
        ui_dir: None,
        // a template stamped long ago, as `lattice serve` builds it: every scan must re-stamp
        engine: Config::new(0),
        sandbox: None,
    }
}

async fn call(
    app: &Router,
    method: &str,
    uri: &str,
    body: Option<Value>,
    headers: &[(&str, &str)],
) -> (StatusCode, Value, axum::http::HeaderMap) {
    let mut request = Request::builder()
        .method(method)
        .uri(uri)
        .header("host", "localhost:7443");
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    let request = match body {
        Some(body) => request
            .header("content-type", "application/json")
            .body(Body::from(body.to_string())),
        None => request.body(Body::empty()),
    }
    .unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, value, headers)
}

async fn get(app: &Router, uri: &str) -> (StatusCode, Value) {
    let (status, value, _) = call(app, "GET", uri, None, &[]).await;
    (status, value)
}

async fn wait_done(app: &Router, id: &str) -> Value {
    for _ in 0..600 {
        let (_, meta) = get(app, &format!("/api/scans/{id}")).await;
        if meta["status"] == "done" || meta["status"] == "failed" {
            return meta;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("scan {id} did not finish");
}

#[tokio::test]
async fn non_loopback_binds_need_a_token_and_names_must_be_safe() {
    let f = fixture();
    assert!(matches!(
        app(config(&f, "0.0.0.0:7443", None)),
        Err(ServerError::TokenRequired(_))
    ));
    assert!(app(config(&f, "0.0.0.0:7443", Some("s3cret"))).is_ok());
    let mut bad = config(&f, "127.0.0.1:7443", None);
    bad.roots = vec![("../x".into(), f.root.clone())];
    assert!(matches!(app(bad), Err(ServerError::Root { .. })));
}

#[tokio::test]
async fn dns_rebinding_and_missing_tokens_are_refused() {
    let f = fixture();
    let open = app(config(&f, "127.0.0.1:7443", None)).unwrap();
    let (status, _, headers) = call(&open, "GET", "/api/health", None, &[]).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        headers
            .get("content-security-policy")
            .unwrap()
            .to_str()
            .unwrap()
            .contains("frame-ancestors 'none'")
    );
    assert_eq!(headers.get("cache-control").unwrap(), "no-store");

    let rebinding = Request::builder()
        .uri("/api/roots")
        .header("host", "attacker.example")
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        open.clone().oneshot(rebinding).await.unwrap().status(),
        StatusCode::MISDIRECTED_REQUEST
    );

    let guarded = app(config(&f, "127.0.0.1:7443", Some("s3cret"))).unwrap();
    assert_eq!(
        get(&guarded, "/api/health").await.0,
        StatusCode::OK,
        "health needs no token"
    );
    assert_eq!(
        get(&guarded, "/api/roots").await.0,
        StatusCode::UNAUTHORIZED
    );
    let (status, _, _) = call(
        &guarded,
        "GET",
        "/api/roots",
        None,
        &[("authorization", "Bearer wrong")],
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, roots, _) = call(
        &guarded,
        "GET",
        "/api/roots",
        None,
        &[("authorization", "Bearer s3cret")],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        roots,
        json!([{"name": "estate"}]),
        "roots are named, host paths never exposed"
    );
}

#[tokio::test]
async fn targets_are_confined_to_their_root() {
    let f = fixture();
    let app = app(config(&f, "127.0.0.1:7443", None)).unwrap();
    let (status, entries) = get(&app, "/api/roots/estate/entries").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(entries["directories"], json!(["identity", "payments"]));
    assert_eq!(
        get(&app, "/api/roots/estate/entries?path=payments").await.1["directories"],
        json!(["src"])
    );
    assert_eq!(
        get(&app, "/api/roots/estate/entries?path=../").await.0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        get(&app, "/api/roots/nope/entries").await.0,
        StatusCode::NOT_FOUND
    );

    let (status, _, _) = call(
        &app,
        "POST",
        "/api/scans",
        Some(json!({"root": "estate", "path": "../../etc"})),
        &[],
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _, _) = call(
        &app,
        "POST",
        "/api/scans",
        Some(json!({"root": "estate", "path": "x", "extra": 1})),
        &[],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "unknown fields are rejected"
    );
    assert_eq!(
        get(&app, "/api/scans/..%2F..%2Fetc").await.0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        get(&app, "/api/nothing-here").await.0,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn scan_lifecycle_artefacts_persistence_and_comparison() {
    let f = fixture();
    let server = app(config(&f, "127.0.0.1:7443", None)).unwrap();

    let (status, queued, _) = call(
        &server,
        "POST",
        "/api/scans",
        Some(json!({"root": "estate", "path": "payments", "subject": "payments"})),
        &[],
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let first = queued["id"].as_str().unwrap().to_owned();
    assert_eq!(queued["path"], "payments");
    let meta = wait_done(&server, &first).await;
    assert_eq!(meta["status"], "done", "{meta}");
    assert!(meta["summary"]["assets"].as_u64().unwrap() >= 1);

    let (status, report) = get(&server, &format!("/api/scans/{first}/report")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(report["format"], "lattice-report/1");
    let this_year: u64 = now().1[..4].parse().unwrap();
    assert_eq!(
        report["provenance"]["assessmentYear"], this_year,
        "scored from today, not the template's year"
    );
    assert!(
        report["assets"]
            .as_array()
            .unwrap()
            .iter()
            .any(|a| a["assessment"]["brokenNow"] == true)
    );
    let (_, cbom, headers) = call(
        &server,
        "GET",
        &format!("/api/scans/{first}/cbom?download=1"),
        None,
        &[],
    )
    .await;
    assert_eq!(cbom["specVersion"], "1.6");
    assert!(
        headers
            .get("content-disposition")
            .unwrap()
            .to_str()
            .unwrap()
            .contains(".cdx.json")
    );
    let (status, _, headers) = call(
        &server,
        "GET",
        &format!("/api/scans/{first}/report.pdf"),
        None,
        &[],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers.get("content-type").unwrap(), "application/pdf");
    assert!(
        headers
            .get("content-disposition")
            .unwrap()
            .to_str()
            .unwrap()
            .ends_with(".pdf\"")
    );
    let (_, graph) = get(&server, &format!("/api/scans/{first}/graph")).await;
    assert!(
        graph["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|n| n["type"] == "crypto")
    );

    // a second scan over the whole estate adds RSA
    let (_, queued, _) = call(
        &server,
        "POST",
        "/api/scans",
        Some(json!({"root": "estate"})),
        &[],
    )
    .await;
    let second = queued["id"].as_str().unwrap().to_owned();
    assert_eq!(wait_done(&server, &second).await["status"], "done");
    let (status, comparison) = get(
        &server,
        &format!("/api/compare?baseline={first}&current={second}&failOn=low"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        comparison["changes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["kind"] == "added"),
        "{comparison}"
    );
    assert_eq!(
        get(
            &server,
            &format!("/api/compare?baseline={first}&current={second}&failOn=bogus")
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );

    let (_, list) = get(&server, "/api/scans").await;
    assert_eq!(list.as_array().unwrap().len(), 2);

    // restart: history and artefacts come back from the data directory
    drop(server);
    let restarted = app(config(&f, "127.0.0.1:7443", None)).unwrap();
    let (_, list) = get(&restarted, "/api/scans").await;
    assert_eq!(list.as_array().unwrap().len(), 2);
    let (status, report) = get(&restarted, &format!("/api/scans/{first}/report")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(report["subject"], "payments");
}
