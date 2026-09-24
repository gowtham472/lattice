//! The `lattice` binary end to end: scan, sign, verify, tamper detection, the CI gate.

use std::fs;
use std::path::Path;
use std::process::{Command, Output};

fn lattice(args: &[&str], cwd: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_lattice"))
        .args(args)
        .current_dir(cwd)
        .env("SOURCE_DATE_EPOCH", "1790121600")
        .env_remove("LATTICE_LOG")
        .output()
        .expect("the lattice binary runs")
}

fn code(output: &Output) -> i32 {
    output.status.code().expect("exited normally")
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn project(root: &Path) {
    let app = root.join("target-app");
    fs::create_dir_all(app.join("src")).unwrap();
    fs::write(
        app.join("src/Ledger.java"),
        "import javax.crypto.Cipher;\nclass Ledger { Cipher c() throws Exception { return Cipher.getInstance(\"AES/ECB/PKCS5Padding\"); } }\n",
    )
    .unwrap();
    fs::write(
        app.join("src/receipt.py"),
        "import hashlib\n\ndef receipt(data):\n    return hashlib.sha1(data).hexdigest()\n",
    )
    .unwrap();
}

#[test]
fn scan_sign_verify_and_detect_tampering() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    project(root);

    let keygen = lattice(&["keygen", "--out-dir", "keys"], root);
    assert_eq!(code(&keygen), 0, "{}", text(&keygen.stderr));
    assert!(
        lattice(&["keygen", "--out-dir", "keys"], root)
            .status
            .code()
            == Some(2),
        "never overwrites keys"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(root.join("keys/lattice-signing.key"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o077, 0, "private key is owner-only");
    }

    let scan = lattice(
        &[
            "scan",
            "target-app",
            "-o",
            "out/app.cbom.json",
            "--report",
            "out/app.report.json",
            "--sign-with",
            "keys/lattice-signing.key",
            "--public-key",
            "keys/lattice-signing.pub",
        ],
        root,
    );
    assert_eq!(code(&scan), 0, "{}", text(&scan.stderr));
    let summary = text(&scan.stdout);
    assert!(
        summary.contains("assets:") || summary.contains(" assets"),
        "{summary}"
    );
    assert!(
        summary.contains("SHA-1") || summary.contains("SHA1"),
        "{summary}"
    );
    assert!(root.join("out/app.cbom.json.sig.json").exists());

    let validate = lattice(&["validate", "out/app.cbom.json"], root);
    assert_eq!(
        code(&validate),
        0,
        "{}{}",
        text(&validate.stdout),
        text(&validate.stderr)
    );

    let verify = lattice(
        &[
            "verify",
            "out/app.cbom.json",
            "--public-key",
            "keys/lattice-signing.pub",
        ],
        root,
    );
    assert_eq!(code(&verify), 0, "{}", text(&verify.stderr));

    // downgrade a finding in place: verification must fail with exit code 3 and say where
    let path = root.join("out/app.cbom.json");
    let original = fs::read_to_string(&path).unwrap();
    let tampered = original.replacen("\"critical\"", "\"low\"", 1);
    assert_ne!(
        original, tampered,
        "the fixture has a critical asset to tamper with"
    );
    fs::write(&path, tampered).unwrap();
    let verify = lattice(
        &[
            "verify",
            "out/app.cbom.json",
            "--public-key",
            "keys/lattice-signing.pub",
        ],
        root,
    );
    assert_eq!(code(&verify), 3);
    assert!(
        text(&verify.stderr).contains("component"),
        "{}",
        text(&verify.stderr)
    );
}

#[test]
fn scans_are_reproducible_under_source_date_epoch() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    project(root);
    for name in ["a", "b"] {
        let out = format!("{name}.cbom.json");
        let report = format!("{name}.report.json");
        let scan = lattice(
            &[
                "scan",
                "target-app",
                "-o",
                &out,
                "--report",
                &report,
                "--quiet",
            ],
            root,
        );
        assert_eq!(code(&scan), 0, "{}", text(&scan.stderr));
        assert!(scan.stdout.is_empty(), "--quiet prints nothing");
    }
    assert_eq!(
        fs::read(root.join("a.cbom.json")).unwrap(),
        fs::read(root.join("b.cbom.json")).unwrap()
    );
    assert_eq!(
        fs::read(root.join("a.report.json")).unwrap(),
        fs::read(root.join("b.report.json")).unwrap()
    );
    let report: serde_json::Value =
        serde_json::from_slice(&fs::read(root.join("a.report.json")).unwrap()).unwrap();
    assert_eq!(report["generated"], "2026-09-23T00:00:00Z");
}

#[test]
fn ci_gate_exit_codes() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    project(root);
    let scan = lattice(
        &[
            "scan",
            "target-app",
            "-o",
            "baseline.cbom.json",
            "--report",
            "baseline.report.json",
            "--quiet",
        ],
        root,
    );
    assert_eq!(code(&scan), 0, "{}", text(&scan.stderr));

    let unchanged = lattice(
        &["ci", "target-app", "--baseline", "baseline.cbom.json"],
        root,
    );
    assert_eq!(
        code(&unchanged),
        0,
        "{}{}",
        text(&unchanged.stdout),
        text(&unchanged.stderr)
    );

    fs::write(
        root.join("target-app/src/legacy.py"),
        "import hashlib\n\ndef token(data):\n    return hashlib.md5(data).hexdigest()\n",
    )
    .unwrap();
    let regressed = lattice(
        &[
            "ci",
            "target-app",
            "--baseline",
            "baseline.cbom.json",
            "--changes",
            "changes.json",
        ],
        root,
    );
    assert_eq!(code(&regressed), 1, "{}", text(&regressed.stdout));
    assert!(text(&regressed.stdout).contains("FAIL"));
    let changes: serde_json::Value =
        serde_json::from_slice(&fs::read(root.join("changes.json")).unwrap()).unwrap();
    assert!(
        changes["changes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["regression"] == true)
    );

    // an unsigned baseline is rejected when a trusted key is required
    assert_eq!(code(&lattice(&["keygen", "--out-dir", "keys"], root)), 0);
    let untrusted = lattice(
        &[
            "ci",
            "target-app",
            "--baseline",
            "baseline.cbom.json",
            "--trusted-key",
            "keys/lattice-signing.pub",
        ],
        root,
    );
    assert_eq!(code(&untrusted), 3, "{}", text(&untrusted.stderr));

    let missing = lattice(&["scan", "does-not-exist"], root);
    assert_eq!(code(&missing), 2);
}

fn sandbox_status(root: &Path) -> serde_json::Value {
    let check = lattice(&["sandbox-check", "--json"], root);
    assert_eq!(
        code(&check),
        0,
        "every probe matches what the sandbox reports: {}{}",
        text(&check.stdout),
        text(&check.stderr)
    );
    serde_json::from_slice(&check.stdout).unwrap()
}

#[test]
fn the_sandbox_denies_what_it_claims_to() {
    let dir = tempfile::tempdir().unwrap();
    let status = sandbox_status(dir.path());
    let probes = status["probes"].as_array().unwrap();
    assert_eq!(probes.len(), 6);
    assert!(probes.iter().all(|p| p["expected"] == p["observed"]));
    #[cfg(target_os = "linux")]
    {
        // seccomp is available on every supported Linux kernel; Landlock depends on the kernel
        assert_eq!(status["sandbox"]["syscalls"]["state"], "enforced");
        for name in ["open a network connection", "run another program"] {
            let probe = probes.iter().find(|p| p["name"] == name).unwrap();
            assert_eq!(probe["observed"], "denied", "{name}");
        }
    }
}

#[test]
fn required_sandbox_scans_or_refuses_honestly() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    project(root);
    let status = sandbox_status(root);
    let both = ["filesystem", "syscalls"].iter().all(|layer| {
        matches!(
            status["sandbox"][layer]["state"].as_str(),
            Some("enforced" | "partial")
        )
    });
    let scan = lattice(
        &[
            "--sandbox",
            "required",
            "scan",
            "target-app",
            "-o",
            "out/a.cbom.json",
            "--report",
            "out/a.report.json",
        ],
        root,
    );
    if both {
        assert_eq!(code(&scan), 0, "{}", text(&scan.stderr));
        assert!(
            text(&scan.stdout).contains("sandbox filesystem enforced"),
            "{}",
            text(&scan.stdout)
        );
        assert!(root.join("out/a.cbom.json").exists());
    } else {
        assert_eq!(
            code(&scan),
            2,
            "required confinement that is unavailable is an error"
        );
        assert!(text(&scan.stderr).contains("sandbox required"));
    }
}

#[test]
fn the_server_serves_after_confinement() {
    use std::io::{BufRead, BufReader, Read as _, Write as _};
    use std::net::TcpStream;
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    project(root);
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let mut child = Command::new(env!("CARGO_BIN_EXE_lattice"))
        .args([
            "serve",
            "--bind",
            &format!("127.0.0.1:{port}"),
            "--root",
            "app=target-app",
            "--data-dir",
            "data",
        ])
        .current_dir(root)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let mut banner = String::new();
    BufReader::new(child.stdout.take().unwrap())
        .read_line(&mut banner)
        .unwrap();
    assert!(banner.contains("sandbox:"), "{banner}");
    let mut body = String::new();
    for _ in 0..50 {
        if let Ok(mut stream) = TcpStream::connect(("127.0.0.1", port)) {
            stream
                .write_all(
                    b"GET /api/health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
                )
                .unwrap();
            stream.read_to_string(&mut body).unwrap();
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    child.kill().unwrap();
    let _ = child.wait();
    assert!(body.starts_with("HTTP/1.1 200"), "{body}");
    #[cfg(target_os = "linux")]
    assert!(
        body.contains(r#""syscalls":{"state":"enforced"}"#),
        "{body}"
    );
}

#[test]
fn signed_knowledge_bundles_update_scans_and_refuse_tampering_and_rollback() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    project(root);
    let repository = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    // a publisher's next knowledge release: new catalogue version, an earlier Q-day window
    let source = root.join("knowledge-src");
    fs::create_dir_all(&source).unwrap();
    for file in ["algorithms.toml", "libraries.toml", "policy.toml"] {
        let text = fs::read_to_string(repository.join("knowledge").join(file)).unwrap();
        let text = match file {
            "algorithms.toml" => {
                text.replacen("version = \"2026.09.1\"", "version = \"2026.10.1\"", 1)
            }
            "policy.toml" => text.replace("earliest_year = 2030", "earliest_year = 2028"),
            _ => text,
        };
        fs::write(source.join(file), text).unwrap();
    }
    fs::copy(
        repository.join("rules/source.toml"),
        root.join("source-rules.toml"),
    )
    .unwrap();
    assert_eq!(
        code(&lattice(&["keygen", "--out-dir", "publisher"], root)),
        0
    );
    let pack = |sequence: &str, output: &str| {
        lattice(
            &[
                "knowledge",
                "pack",
                "--source",
                "knowledge-src",
                "--rules",
                "source-rules.toml",
                "--sequence",
                sequence,
                "--key",
                "publisher/lattice-signing.key",
                "--public-key",
                "publisher/lattice-signing.pub",
                "-o",
                output,
            ],
            root,
        )
    };
    let packed = pack("2", "k2.bundle.json");
    assert_eq!(code(&packed), 0, "{}", text(&packed.stderr));
    let trust = [
        "--knowledge-dir",
        "kdir",
        "--knowledge-key",
        "publisher/lattice-signing.pub",
    ];

    let install = lattice(
        &[&trust[..], &["knowledge", "install", "k2.bundle.json"]].concat(),
        root,
    );
    assert_eq!(code(&install), 0, "{}", text(&install.stderr));
    assert!(text(&install.stdout).contains("2026.10.1 #2"));

    let scan = lattice(
        &[
            &trust[..],
            &[
                "scan",
                "target-app",
                "-o",
                "k.cbom.json",
                "--report",
                "k.report.json",
            ],
        ]
        .concat(),
        root,
    );
    assert_eq!(code(&scan), 0, "{}", text(&scan.stderr));
    assert!(
        text(&scan.stdout).contains("knowledge 2026.10.1 #2 (bundle signed by"),
        "{}",
        text(&scan.stdout)
    );
    let report: serde_json::Value =
        serde_json::from_slice(&fs::read(root.join("k.report.json")).unwrap()).unwrap();
    assert_eq!(report["provenance"]["knowledgeVersion"], "2026.10.1");
    assert_eq!(report["provenance"]["knowledgeSequence"], 2);
    assert_eq!(
        report["provenance"]["qDayEarliest"], 2028,
        "the bundle's policy is the default"
    );
    let cbom = fs::read_to_string(root.join("k.cbom.json")).unwrap();
    assert!(cbom.contains("\"lattice:knowledge-signer\""));

    // an older bundle cannot replace a newer one
    assert_eq!(code(&pack("2", "again.bundle.json")), 0);
    let rollback = lattice(
        &[&trust[..], &["knowledge", "install", "again.bundle.json"]].concat(),
        root,
    );
    assert_eq!(code(&rollback), 3, "{}", text(&rollback.stderr));
    assert!(text(&rollback.stderr).contains("roll back"));

    // an installed bundle without a trusted key, or tampered with, stops the scan
    let unkeyed = lattice(
        &[
            "--knowledge-dir",
            "kdir",
            "scan",
            "target-app",
            "-o",
            "u.cbom.json",
            "--report",
            "u.report.json",
        ],
        root,
    );
    assert_eq!(code(&unkeyed), 3, "{}", text(&unkeyed.stderr));
    let installed = root.join("kdir/knowledge.bundle.json");
    let tampered = fs::read_to_string(&installed)
        .unwrap()
        .replace("earliest_year = 2028", "earliest_year = 2040");
    fs::write(&installed, tampered).unwrap();
    let refused = lattice(
        &[
            &trust[..],
            &[
                "scan",
                "target-app",
                "-o",
                "t.cbom.json",
                "--report",
                "t.report.json",
            ],
        ]
        .concat(),
        root,
    );
    assert_eq!(code(&refused), 3, "{}", text(&refused.stderr));
    assert!(text(&refused.stderr).contains("refusing to run with this knowledge"));
    assert!(
        !root.join("t.cbom.json").exists(),
        "nothing is produced from unverified knowledge"
    );

    let status = lattice(&["knowledge", "status"], root);
    assert!(
        text(&status.stdout).contains("compiled-in  knowledge 2026.09.1 #1"),
        "{}",
        text(&status.stdout)
    );
}

#[test]
fn incremental_scans_reuse_unchanged_files_with_identical_output() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    project(root);
    let scan = |name: &str| {
        lattice(
            &[
                "scan",
                "target-app",
                "--cache",
                "cache",
                "-o",
                &format!("{name}.cbom.json"),
                "--report",
                &format!("{name}.report.json"),
            ],
            root,
        )
    };
    let first = scan("first");
    assert_eq!(code(&first), 0, "{}", text(&first.stderr));
    assert!(
        text(&first.stdout).contains("cache   0 of 2 files reused"),
        "{}",
        text(&first.stdout)
    );
    let second = scan("second");
    assert!(
        text(&second.stdout).contains("cache   2 of 2 files reused"),
        "{}",
        text(&second.stdout)
    );
    for kind in ["cbom", "report"] {
        assert_eq!(
            fs::read(root.join(format!("first.{kind}.json"))).unwrap(),
            fs::read(root.join(format!("second.{kind}.json"))).unwrap(),
            "cached and fresh {kind} are byte-identical"
        );
    }
    fs::write(
        root.join("target-app/src/receipt.py"),
        "import hashlib\n\ndef receipt(data):\n    return hashlib.sha512(data).hexdigest()\n",
    )
    .unwrap();
    let third = scan("third");
    assert!(
        text(&third.stdout).contains("cache   1 of 2 files reused"),
        "{}",
        text(&third.stdout)
    );
    assert!(text(&third.stdout).contains("SHA-512"));
}

#[test]
fn issued_tokens_are_enforced_and_audited() {
    use std::io::{BufRead, BufReader, Read as _, Write as _};
    use std::net::TcpStream;
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    project(root);

    let issued = lattice(
        &[
            "user",
            "add",
            "--name",
            "vera",
            "--role",
            "viewer",
            "--users",
            "users.toml",
        ],
        root,
    );
    assert_eq!(code(&issued), 0, "{}", text(&issued.stderr));
    let token = text(&issued.stdout).trim().to_owned();
    assert!(token.starts_with("lattice_"), "{token}");
    let again = lattice(
        &[
            "user",
            "add",
            "--name",
            "vera",
            "--role",
            "admin",
            "--users",
            "users.toml",
        ],
        root,
    );
    assert_eq!(code(&again), 2, "names are unique");
    let users = fs::read_to_string(root.join("users.toml")).unwrap();
    assert!(
        !users.contains(&token),
        "the users file holds digests, not tokens"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(root.join("users.toml"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let mut child = Command::new(env!("CARGO_BIN_EXE_lattice"))
        .args([
            "serve",
            "--bind",
            &format!("127.0.0.1:{port}"),
            "--root",
            "app=target-app",
            "--data-dir",
            "data",
            "--users",
            "users.toml",
        ])
        .current_dir(root)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let mut banner = String::new();
    BufReader::new(child.stdout.take().unwrap())
        .read_line(&mut banner)
        .unwrap();
    let request = |method: &str, path: &str, token: Option<&str>| {
        let auth = token.map_or_else(String::new, |t| format!("Authorization: Bearer {t}\r\n"));
        let length = if method == "POST" {
            "Content-Type: application/json\r\nContent-Length: 29\r\n"
        } else {
            ""
        };
        let body = if method == "POST" {
            r#"{"root":"app","path":"src"} "#
        } else {
            ""
        };
        for _ in 0..50 {
            if let Ok(mut stream) = TcpStream::connect(("127.0.0.1", port)) {
                stream
                    .write_all(
                        format!("{method} {path} HTTP/1.1\r\nHost: localhost\r\n{auth}{length}Connection: close\r\n\r\n{body}")
                            .as_bytes(),
                    )
                    .unwrap();
                let mut response = String::new();
                stream.read_to_string(&mut response).unwrap();
                return response;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        panic!("the server never answered");
    };
    let anonymous = request("GET", "/api/scans", None);
    let viewer = request("GET", "/api/scans", Some(&token));
    let refused = request("POST", "/api/scans", Some(&token));
    child.kill().unwrap();
    let _ = child.wait();
    assert!(anonymous.starts_with("HTTP/1.1 401"), "{anonymous}");
    assert!(viewer.starts_with("HTTP/1.1 200"), "{viewer}");
    assert!(
        refused.starts_with("HTTP/1.1 403"),
        "a viewer cannot scan: {refused}"
    );

    let verified = lattice(&["audit", "verify", "data/audit.jsonl"], root);
    assert_eq!(code(&verified), 0, "{}", text(&verified.stderr));
    assert!(
        text(&verified.stdout).contains("3 entries"),
        "{}",
        text(&verified.stdout)
    );
    let log = fs::read_to_string(root.join("data/audit.jsonl")).unwrap();
    assert!(log.contains(r#""actor":"vera""#) && log.contains(r#""status":403"#));
    fs::write(
        root.join("data/audit.jsonl"),
        log.replacen(r#""status":401"#, r#""status":200"#, 1),
    )
    .unwrap();
    assert_eq!(
        code(&lattice(&["audit", "verify", "data/audit.jsonl"], root)),
        3
    );
}

#[test]
fn large_cboms_validate_sign_and_verify() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    project(root);
    let scan = lattice(
        &[
            "scan",
            "target-app",
            "-o",
            "app.cbom.json",
            "--report",
            "app.report.json",
            "--quiet",
        ],
        root,
    );
    assert_eq!(code(&scan), 0, "{}", text(&scan.stderr));
    // real estates produce CBOMs of many megabytes; whitespace keeps this one valid JSON
    let mut cbom = fs::read(root.join("app.cbom.json")).unwrap();
    let close = cbom.iter().rposition(|b| *b == b'}').unwrap();
    cbom.splice(close..close, std::iter::repeat_n(b' ', 3 * 1024 * 1024));
    fs::write(root.join("big.cbom.json"), &cbom).unwrap();

    let validated = lattice(&["validate", "big.cbom.json"], root);
    assert_eq!(code(&validated), 0, "{}", text(&validated.stderr));
    assert_eq!(code(&lattice(&["keygen", "--out-dir", "keys"], root)), 0);
    let signed = lattice(
        &[
            "sign",
            "big.cbom.json",
            "--key",
            "keys/lattice-signing.key",
            "--public-key",
            "keys/lattice-signing.pub",
        ],
        root,
    );
    assert_eq!(code(&signed), 0, "{}", text(&signed.stderr));
    let verified = lattice(
        &[
            "verify",
            "big.cbom.json",
            "--public-key",
            "keys/lattice-signing.pub",
        ],
        root,
    );
    assert_eq!(code(&verified), 0, "{}", text(&verified.stderr));
}
