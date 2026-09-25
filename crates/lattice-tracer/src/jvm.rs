//! Java: what running JVMs ask the Java Cryptography Architecture for.
//!
//! The JVM records this itself. Its Flight Recorder (JFR) has events for every provider service
//! lookup (`jdk.SecurityProviderService`: `Cipher` `AES/GCM/NoPadding` from `SunJCE`), every TLS
//! handshake (`jdk.TLSHandshake`: protocol and cipher suite) and every certificate it parses
//! (`jdk.X509Certificate`: key type and size, signature algorithm). LATTICE starts a recording
//! in each JVM with the JDK's own `jcmd`, lets it run, exports it with `jfr print --json`, and
//! turns it into trace events. Nothing is injected into the application: JFR is the JVM's
//! supported diagnostic channel, and a recording ends by itself.
//!
//! **Setup is not use**, as with OpenSSL: JSSE probes which ciphers and signature schemes are
//! available while it initialises (RC4 and DSA included), and the JDK's random generator mixes
//! with SHA-1. Every lookup whose stack passes through a static initialiser, an availability
//! check or the random generator is counted as ignored, never recorded.
//!
//! The JDK tools run before LATTICE confines itself; the recordings they export, which come from
//! the JVMs, are parsed only afterwards, inside the sandbox ([`events`]).

use lattice_collectors::trace::{CallKind, TraceEvent};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

/// The JFR settings LATTICE records with: the three security events, with stack traces so
/// setup can be told from use.
pub const SETTINGS: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<configuration version="2.0" label="LATTICE" description="Cryptographic API use, for LATTICE">
  <event name="jdk.SecurityProviderService"><setting name="enabled">true</setting><setting name="stackTrace">true</setting></event>
  <event name="jdk.TLSHandshake"><setting name="enabled">true</setting><setting name="stackTrace">false</setting></event>
  <event name="jdk.X509Certificate"><setting name="enabled">true</setting><setting name="stackTrace">false</setting></event>
</configuration>
"#;

const EVENTS: &str = "jdk.SecurityProviderService,jdk.TLSHandshake,jdk.X509Certificate";

/// JCA service types that select cryptography (not key stores, factories or random sources).
const SERVICES: &[&str] = &[
    "Cipher",
    "Signature",
    "MessageDigest",
    "Mac",
    "KeyAgreement",
    "KEM",
    "KeyPairGenerator",
    "KeyGenerator",
    "KDF",
    "SecretKeyFactory",
];

/// A running JVM.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Jvm {
    pub pid: u32,
    /// The `java` executable.
    pub java: PathBuf,
    /// What it runs: the main class or `-jar` archive.
    pub application: String,
    pub uid: u32,
    pub gid: u32,
}

/// The JVMs running now, from `/proc`.
pub fn running() -> Vec<Jvm> {
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return Vec::new();
    };
    let mut found = Vec::new();
    for entry in entries.flatten() {
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
            continue;
        };
        let Ok(java) = std::fs::read_link(entry.path().join("exe")) else {
            continue;
        };
        if java.file_name().and_then(|n| n.to_str()) != Some("java") {
            continue;
        }
        let Ok(cmdline) = std::fs::read(entry.path().join("cmdline")) else {
            continue;
        };
        let (uid, gid) = owner(&entry.path()).unwrap_or((0, 0));
        found.push(Jvm {
            pid,
            java,
            application: application(&cmdline),
            uid,
            gid,
        });
    }
    found.sort_by_key(|jvm| jvm.pid);
    found
}

fn owner(proc_dir: &Path) -> Option<(u32, u32)> {
    let status = std::fs::read_to_string(proc_dir.join("status")).ok()?;
    let field = |name: &str| {
        status
            .lines()
            .find_map(|l| l.strip_prefix(name))
            .and_then(|rest| rest.split_whitespace().nth(1))
            .and_then(|v| v.parse().ok())
    };
    Some((field("Uid:")?, field("Gid:")?))
}

/// The main class or `-jar` archive from a JVM's command line.
fn application(cmdline: &[u8]) -> String {
    let args: Vec<String> = cmdline
        .split(|b| *b == 0)
        .filter(|a| !a.is_empty())
        .map(|a| String::from_utf8_lossy(a).into_owned())
        .collect();
    let mut rest = args.iter().skip(1);
    while let Some(arg) = rest.next() {
        match arg.as_str() {
            "-jar" => return rest.next().map_or_else(|| "-jar".into(), |jar| jar.clone()),
            "-cp" | "-classpath" | "--class-path" | "-p" | "--module-path" | "--add-modules" => {
                rest.next();
            }
            "-m" | "--module" => return rest.next().cloned().unwrap_or_default(),
            other if other.starts_with('-') => {}
            main => return main.to_owned(),
        }
    }
    String::from("java")
}

/// The JDK tool beside the JVM's `java`, or in `jdk/bin`.
fn tool(jvm: &Jvm, jdk: Option<&Path>, name: &str) -> Result<PathBuf, String> {
    let candidates = jdk
        .map(|jdk| jdk.join("bin").join(name))
        .into_iter()
        .chain(jvm.java.parent().map(|bin| bin.join(name)));
    candidates
        .into_iter()
        .find(|path| path.exists())
        .ok_or_else(|| {
            format!(
                "no {name} beside {} (a JRE without the JDK tools); name a JDK with --jdk",
                jvm.java.display()
            )
        })
}

/// Runs a JDK tool as the JVM's owner: HotSpot accepts attach requests only from its own user.
fn run_as(jvm: &Jvm, program: &Path, args: &[String]) -> std::io::Result<std::process::Output> {
    let we_are_root = std::fs::metadata("/proc/self")
        .map(|m| std::os::unix::fs::MetadataExt::uid(&m) == 0)
        .unwrap_or(false);
    if we_are_root && jvm.uid != 0 {
        Command::new("setpriv")
            .args([
                format!("--reuid={}", jvm.uid),
                format!("--regid={}", jvm.gid),
                "--clear-groups".into(),
                "--".into(),
            ])
            .arg(program)
            .args(args)
            .output()
    } else {
        Command::new(program).args(args).output()
    }
}

/// One JVM's exported recording, or why there is none.
pub struct Recording {
    pub jvm: Jvm,
    pub json: Result<Vec<u8>, String>,
}

/// Records every JVM for `duration` and exports the recordings as JSON. Runs the JDK tools, so
/// call it before confinement; parse the result with [`events`] after.
pub fn record(jvms: &[Jvm], jdk: Option<&Path>, duration: Duration) -> Vec<Recording> {
    let directory = std::env::temp_dir().join(format!("lattice-jfr-{}", std::process::id()));
    // created afresh, never adopted: someone else's directory here could redirect the recordings
    if let Err(error) = std::fs::create_dir(&directory) {
        let reason = format!("cannot create {}: {error}", directory.display());
        return jvms
            .iter()
            .map(|jvm| Recording {
                jvm: jvm.clone(),
                json: Err(reason.clone()),
            })
            .collect();
    }
    // the JVMs write their recordings here, as their own users
    let _ = std::fs::set_permissions(
        &directory,
        std::os::unix::fs::PermissionsExt::from_mode(0o1777),
    );
    let settings = directory.join("lattice.jfc");
    let _ = std::fs::write(&settings, SETTINGS);
    let _ = std::fs::set_permissions(
        &settings,
        std::os::unix::fs::PermissionsExt::from_mode(0o644),
    );
    let seconds = duration.as_secs().max(1);

    let mut started = Vec::new();
    for jvm in jvms {
        let file = directory.join(format!("{}.jfr", jvm.pid));
        let outcome = tool(jvm, jdk, "jcmd").and_then(|jcmd| {
            let output = run_as(
                jvm,
                &jcmd,
                &[
                    jvm.pid.to_string(),
                    "JFR.start".into(),
                    format!("name=lattice-{}", std::process::id()),
                    format!("settings={}", settings.display()),
                    format!("filename={}", file.display()),
                    format!("duration={seconds}s"),
                ],
            )
            .map_err(|e| format!("jcmd: {e}"))?;
            if output.status.success()
                && !String::from_utf8_lossy(&output.stdout).contains("Could not")
            {
                Ok(())
            } else {
                Err(format!(
                    "jcmd could not start a recording: {}",
                    String::from_utf8_lossy(&output.stdout)
                        .lines()
                        .chain(String::from_utf8_lossy(&output.stderr).lines())
                        .find(|l| !l.trim().is_empty())
                        .unwrap_or("no output")
                        .trim()
                ))
            }
        });
        started.push((jvm.clone(), file, outcome));
    }

    // a recording is written when its duration ends; allow the JVMs time to finish writing
    let deadline = Instant::now() + duration + Duration::from_secs(20);
    std::thread::sleep(duration);
    let mut recordings = Vec::new();
    for (jvm, file, outcome) in started {
        let json = outcome.and_then(|()| {
            while !file.exists() && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(250));
            }
            std::thread::sleep(Duration::from_millis(500));
            let jfr = tool(&jvm, jdk, "jfr")?;
            // the recording is the JVM's; read it with no more privilege than the JVM has
            let output = run_as(
                &jvm,
                &jfr,
                &[
                    "print".into(),
                    "--json".into(),
                    "--stack-depth".into(),
                    "64".into(),
                    "--events".into(),
                    EVENTS.into(),
                    file.display().to_string(),
                ],
            )
            .map_err(|e| format!("jfr: {e}"))?;
            let _ = std::fs::remove_file(&file);
            if output.status.success() {
                Ok(output.stdout)
            } else {
                Err(format!(
                    "jfr could not read the recording (the JVM may have exited): {}",
                    String::from_utf8_lossy(&output.stderr).trim()
                ))
            }
        });
        recordings.push(Recording { jvm, json });
    }
    let _ = std::fs::remove_dir_all(&directory);
    recordings
}

#[derive(Deserialize)]
struct Export {
    recording: Events,
}

#[derive(Deserialize)]
struct Events {
    events: Vec<Event>,
}

#[derive(Deserialize)]
struct Event {
    #[serde(rename = "type")]
    kind: String,
    values: serde_json::Value,
}

fn text<'a>(values: &'a serde_json::Value, field: &str) -> Option<&'a str> {
    values.get(field).and_then(serde_json::Value::as_str)
}

/// Whether a lookup is JSSE or the JDK working out what it supports, or its random generator:
/// frames of a static initialiser, an availability check or the SecureRandom machinery.
fn setup(values: &serde_json::Value) -> bool {
    let Some(frames) = values
        .pointer("/stackTrace/frames")
        .and_then(serde_json::Value::as_array)
    else {
        return false;
    };
    frames.iter().any(|frame| {
        let method = frame
            .pointer("/method/name")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");
        let class = frame
            .pointer("/method/type/name")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");
        method == "<clinit>"
            || method.starts_with("isAvailable")
            || method == "isTransformationAvailable"
            || method == "isSupported"
            || class.starts_with("sun/security/provider/NativePRNG")
            || class.starts_with("sun/security/provider/SecureRandom")
            || class.starts_with("sun/security/provider/DRBG")
            || class.starts_with("sun/security/provider/AbstractDrbg")
    })
}

/// Trace events from one JVM's exported recording, and how many lookups were setup. Parses data
/// that came from the JVM: call it confined.
pub fn events(jvm: &Jvm, json: &[u8]) -> Result<(Vec<TraceEvent>, u64), String> {
    let export: Export =
        serde_json::from_slice(json).map_err(|e| format!("unreadable JFR export: {e}"))?;
    let executable = format!("{} ({})", jvm.java.display(), jvm.application);
    let mut counts: BTreeMap<(String, String, CallKind, String), u64> = BTreeMap::new();
    let mut ignored = 0;
    let mut add = |library: String, function: &str, kind: CallKind, value: String| {
        *counts
            .entry((library, function.to_owned(), kind, value))
            .or_default() += 1;
    };
    for event in export.recording.events {
        let v = &event.values;
        match event.kind.as_str() {
            "jdk.SecurityProviderService" => {
                let (Some(service), Some(algorithm)) = (text(v, "type"), text(v, "algorithm"))
                else {
                    continue;
                };
                if !SERVICES.contains(&service) || algorithm.starts_with("SunTls") {
                    continue;
                }
                if setup(v) {
                    ignored += 1;
                    continue;
                }
                let provider = text(v, "provider").unwrap_or("?");
                add(
                    format!("JCA provider {provider}"),
                    &format!("JCA {service}"),
                    CallKind::Algorithm,
                    algorithm.to_owned(),
                );
            }
            "jdk.TLSHandshake" => {
                if let Some(protocol) = text(v, "protocolVersion") {
                    add(
                        "JSSE".into(),
                        "JSSE handshake",
                        CallKind::Protocol,
                        protocol.to_owned(),
                    );
                }
                if let Some(suite) = text(v, "cipherSuite") {
                    add(
                        "JSSE".into(),
                        "JSSE handshake",
                        CallKind::CipherList,
                        suite.to_owned(),
                    );
                }
            }
            "jdk.X509Certificate" => {
                if let Some(signature) = text(v, "algorithm") {
                    add(
                        "X.509".into(),
                        "X.509 certificate signature",
                        CallKind::Algorithm,
                        signature.to_owned(),
                    );
                }
                if let (Some(key), Some(bits)) = (
                    text(v, "keyType"),
                    v.get("keyLength").and_then(serde_json::Value::as_u64),
                ) {
                    let (kind, value) = if key.eq_ignore_ascii_case("RSA") {
                        (CallKind::RsaBits, bits.to_string())
                    } else {
                        (CallKind::Algorithm, key.to_owned())
                    };
                    add("X.509".into(), "X.509 certificate key", kind, value);
                }
            }
            _ => {}
        }
    }
    let events = counts
        .into_iter()
        .map(|((library, function, kind, value), count)| TraceEvent {
            executable: executable.clone(),
            library,
            function,
            kind,
            value: Some(value),
            count,
        })
        .collect();
    Ok((events, ignored))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_application_is_found_on_the_command_line() {
        let line = |args: &[&str]| args.join("\0").into_bytes();
        assert_eq!(
            application(&line(&[
                "java",
                "-Xmx1g",
                "-cp",
                "a:b",
                "com.example.Main",
                "x"
            ])),
            "com.example.Main"
        );
        assert_eq!(
            application(&line(&[
                "/usr/bin/java",
                "-jar",
                "payments.jar",
                "--port",
                "8443"
            ])),
            "payments.jar"
        );
        assert_eq!(
            application(&line(&["java", "-m", "billing/com.example.App"])),
            "billing/com.example.App"
        );
        assert_eq!(application(&line(&["java"])), "java");
    }

    fn frame(class: &str, method: &str) -> serde_json::Value {
        serde_json::json!({"method": {"type": {"name": class}, "name": method}})
    }

    fn lookup(service: &str, algorithm: &str, frames: Vec<serde_json::Value>) -> serde_json::Value {
        serde_json::json!({
            "type": "jdk.SecurityProviderService",
            "values": {"type": service, "algorithm": algorithm, "provider": "SunJCE", "stackTrace": {"frames": frames}}
        })
    }

    #[test]
    fn setup_lookups_are_ignored_and_use_is_recorded() {
        let jvm = Jvm {
            pid: 7,
            java: PathBuf::from("/opt/jdk/bin/java"),
            application: "payments.jar".into(),
            uid: 1000,
            gid: 1000,
        };
        let export = serde_json::json!({"recording": {"events": [
            // JSSE working out which ciphers exist: not use
            lookup("Cipher", "ARCFOUR", vec![frame("javax/crypto/Cipher", "getInstance"), frame("sun/security/ssl/SSLCipher", "isTransformationAvailable"), frame("sun/security/ssl/SSLCipher", "<clinit>")]),
            // the random generator's SHA-1 mixing: not a migration target
            lookup("MessageDigest", "SHA-1", vec![frame("java/security/MessageDigest", "getInstance"), frame("sun/security/provider/SecureRandom", "<init>"), frame("sun/security/provider/NativePRNG$RandomIO", "getMixRandom")]),
            // the application, twice
            lookup("Cipher", "DESede/ECB/PKCS5Padding", vec![frame("javax/crypto/Cipher", "getInstance"), frame("com/example/Ledger", "seal")]),
            lookup("Cipher", "DESede/ECB/PKCS5Padding", vec![frame("javax/crypto/Cipher", "getInstance"), frame("com/example/Ledger", "seal")]),
            // not a cryptographic service
            lookup("KeyStore", "PKCS12", vec![]),
            {"type": "jdk.TLSHandshake", "values": {"protocolVersion": "TLSv1.3", "cipherSuite": "TLS_AES_256_GCM_SHA384", "peerHost": "localhost"}},
            {"type": "jdk.X509Certificate", "values": {"algorithm": "SHA256withRSA", "keyType": "RSA", "keyLength": 2048}}
        ]}});
        let (events, ignored) = events(&jvm, &serde_json::to_vec(&export).unwrap()).unwrap();
        assert_eq!(ignored, 2);
        let summary: Vec<(&str, CallKind, &str, u64)> = events
            .iter()
            .map(|e| {
                (
                    e.function.as_str(),
                    e.kind,
                    e.value.as_deref().unwrap(),
                    e.count,
                )
            })
            .collect();
        assert_eq!(
            summary,
            [
                (
                    "JCA Cipher",
                    CallKind::Algorithm,
                    "DESede/ECB/PKCS5Padding",
                    2
                ),
                (
                    "JSSE handshake",
                    CallKind::CipherList,
                    "TLS_AES_256_GCM_SHA384",
                    1
                ),
                ("JSSE handshake", CallKind::Protocol, "TLSv1.3", 1),
                ("X.509 certificate key", CallKind::RsaBits, "2048", 1),
                (
                    "X.509 certificate signature",
                    CallKind::Algorithm,
                    "SHA256withRSA",
                    1
                ),
            ]
        );
        assert_eq!(events[0].executable, "/opt/jdk/bin/java (payments.jar)");
        assert!(super::events(&jvm, b"not json").is_err());
    }

    /// Records `testdata/javacrypto` in a real JVM, with the JDK named by LATTICE_TEST_JDK; CI
    /// sets it, local runs skip without it.
    #[test]
    fn a_running_jvm_is_recorded() {
        let Ok(jdk) = std::env::var("LATTICE_TEST_JDK") else {
            eprintln!("LATTICE_TEST_JDK not set; skipping");
            return;
        };
        let bin = Path::new(&jdk).join("bin");
        let work = std::env::temp_dir().join(format!("lattice-jvm-test-{}", std::process::id()));
        std::fs::create_dir_all(&work).unwrap();
        let source =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/javacrypto/Workload.java");
        let run = |program: &str, args: &[&str]| {
            let status = Command::new(bin.join(program))
                .args(args)
                .current_dir(&work)
                .output()
                .unwrap();
            assert!(status.status.success(), "{program}: {status:?}");
        };
        run(
            "keytool",
            &[
                "-genkeypair",
                "-alias",
                "server",
                "-keyalg",
                "EC",
                "-groupname",
                "secp256r1",
                "-dname",
                "CN=localhost",
                "-ext",
                "SAN=dns:localhost",
                "-validity",
                "2",
                "-keystore",
                "server.p12",
                "-storetype",
                "PKCS12",
                "-storepass",
                "changeit",
                "-keypass",
                "changeit",
            ],
        );
        run("javac", &["-d", ".", source.to_str().unwrap()]);
        // waits 3 s before working, so the recording starts first, and 10 s after
        let mut workload = Command::new(bin.join("java"))
            .args(["-cp", ".", "Workload", "server.p12", "3000", "10000"])
            .current_dir(&work)
            .stdout(std::process::Stdio::null())
            .spawn()
            .unwrap();
        std::thread::sleep(Duration::from_millis(1000));
        let jvm = running()
            .into_iter()
            .find(|jvm| jvm.pid == workload.id())
            .expect("the workload is a running JVM");
        assert_eq!(jvm.application, "Workload");
        let recordings = record(std::slice::from_ref(&jvm), None, Duration::from_secs(6));
        let _ = workload.kill();
        let _ = workload.wait();
        let _ = std::fs::remove_dir_all(&work);

        let json = recordings[0].json.as_ref().unwrap();
        let (events, ignored) = events(&jvm, json).unwrap();
        let seen = |function: &str, value: &str| {
            events
                .iter()
                .any(|e| e.function == function && e.value.as_deref() == Some(value))
        };
        for (function, value) in [
            ("JCA Cipher", "AES/GCM/NoPadding"),
            ("JCA Cipher", "DESede"),
            ("JCA MessageDigest", "MD5"),
            ("JCA Signature", "SHA256withRSA"),
            ("JCA KeyAgreement", "X25519"),
            ("JCA KEM", "ML-KEM"),
            ("JSSE handshake", "TLSv1.3"),
            ("X.509 certificate signature", "SHA384withECDSA"),
        ] {
            assert!(seen(function, value), "{function} {value} in {events:#?}");
        }
        // JSSE's availability probes are setup, not use
        assert!(ignored > 0);
        assert!(!seen("JCA Cipher", "ARCFOUR"), "{events:#?}");
        assert!(!seen("JCA Signature", "SHA1withDSA"), "{events:#?}");
    }
}
