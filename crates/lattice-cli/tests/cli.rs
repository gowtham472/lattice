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
