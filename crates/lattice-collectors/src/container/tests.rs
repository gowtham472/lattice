use super::*;
use crate::default_collectors;
use flate2::Compression;
use flate2::write::GzEncoder;
use lattice_core::Surface;
use std::io::Write;

const CERT: &[u8] = include_bytes!("../../tests/fixtures/rsa2048-sha256.pem");

fn tar(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());
    for (path, data) in entries {
        let mut header = tar::Header::new_gnu();
        header.set_size(data.len() as u64);
        header.set_mode(0o644);
        header.set_entry_type(tar::EntryType::Regular);
        header.set_cksum();
        builder.append_data(&mut header, path, *data).unwrap();
    }
    builder.into_inner().unwrap()
}

/// A raw entry with an arbitrary name, bypassing the builder's path validation.
fn tar_raw(name: &str, data: &[u8]) -> Vec<u8> {
    let mut header = tar::Header::new_old();
    header.as_old_mut().name[..name.len()].copy_from_slice(name.as_bytes());
    header.set_size(data.len() as u64);
    header.set_mode(0o644);
    header.set_entry_type(tar::EntryType::Regular);
    header.set_cksum();
    let mut out = header.as_bytes().to_vec();
    out.extend_from_slice(data);
    out.resize(out.len().div_ceil(512) * 512, 0);
    out.extend_from_slice(&[0u8; 1024]);
    out
}

fn gzip(bytes: &[u8]) -> Vec<u8> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
    encoder.write_all(bytes).unwrap();
    encoder.finish().unwrap()
}

const DPKG: &[u8] = b"Package: openssl\nStatus: install ok installed\nVersion: 3.0.13-0ubuntu3.4\n\nPackage: libssl3t64\nStatus: install ok installed\nVersion: 3.0.13-0ubuntu3.4\n\nPackage: libgnutls30\nStatus: deinstall ok config-files\nVersion: 3.8.9-2\n\nPackage: bash\nStatus: install ok installed\nVersion: 5.2.21-2\n";

fn run(
    dir: &tempfile::TempDir,
    name: &str,
    bytes: &[u8],
    options: &ScanOptions,
) -> (Findings, Vec<CollectionFailure>, ScanStats) {
    let path = dir.path().join(name);
    std::fs::write(&path, bytes).unwrap();
    let collectors = default_collectors().unwrap();
    scan_archive(&path, &format!("images/{name}"), ".", &collectors, options)
}

fn located(findings: &Findings, id: &str) -> Vec<String> {
    findings
        .observations
        .iter()
        .filter(
            |o| matches!(&o.finding, lattice_core::Finding::Algorithm(f) if f.algorithm.id == id),
        )
        .map(|o| o.location.path.clone())
        .collect()
}

fn docker_save() -> Vec<u8> {
    let layer1 = tar(&[
        ("app/legacy.py", b"import hashlib\nhashlib.md5(b'x')\n"),
        ("app/keep.py", b"import hashlib\nhashlib.sha1(b'x')\n"),
        (
            "etc/app/old/secret.py",
            b"import hashlib\nhashlib.md5(b'y')\n",
        ),
        ("etc/ssl/certs/server.pem", CERT),
        ("var/lib/dpkg/status", DPKG),
    ]);
    let layer2 = gzip(&tar(&[
        ("app/.wh.legacy.py", b""),
        ("etc/app/old/.wh..wh..opq", b""),
        (
            "etc/app/old/new.py",
            b"import hashlib\nhashlib.sha512(b'z')\n",
        ),
        (
            "app/tokens.py",
            b"from Crypto.Cipher import DES\nDES.new(key, DES.MODE_CBC)\n",
        ),
    ]));
    let config =
        br#"{"architecture":"amd64","config":{"Env":["PATH=/usr/bin","TLS_MIN_VERSION=TLSv1.1"]}}"#;
    let manifest = br#"[{"Config":"cfg.json","RepoTags":["gov/payments:4.2.0"],"Layers":["l1/layer.tar","l2/layer.tar"]}]"#;
    // docker writes the manifest last, after the layers it names
    tar(&[
        ("l1/layer.tar", &layer1),
        ("l2/layer.tar", &layer2),
        ("cfg.json", config),
        ("manifest.json", manifest),
    ])
}

#[test]
fn docker_save_archives_show_the_final_filesystem_of_the_image() {
    let dir = tempfile::tempdir().unwrap();
    let (findings, failures, stats) = run(
        &dir,
        "payments.tar",
        &docker_save(),
        &ScanOptions::default(),
    );
    assert!(failures.is_empty(), "{failures:?}");

    assert!(
        located(&findings, "md5").is_empty(),
        "files removed by whiteouts and opaque directories are not reported"
    );
    assert_eq!(
        located(&findings, "sha-1"),
        vec!["images/payments.tar!/app/keep.py".to_owned()]
    );
    assert_eq!(
        located(&findings, "sha-512"),
        vec!["images/payments.tar!/etc/app/old/new.py".to_owned()]
    );
    assert!(
        !located(&findings, "des").is_empty(),
        "files added by upper gzip layers are scanned"
    );
    assert!(
        findings
            .observations
            .iter()
            .all(|o| o.component == "gov/payments:4.2.0"),
        "the image tag is the component"
    );

    let certificate = findings
        .observations
        .iter()
        .find(|o| matches!(o.finding, lattice_core::Finding::Certificate(_)))
        .unwrap();
    assert_eq!(
        certificate.location.path,
        "images/payments.tar!/etc/ssl/certs/server.pem"
    );
    assert_eq!(certificate.surface, Surface::Certificate);

    let openssl: Vec<_> = findings
        .libraries
        .iter()
        .filter(|l| l.name == "OpenSSL")
        .collect();
    assert!(!openssl.is_empty());
    assert!(
        openssl
            .iter()
            .all(|l| l.version.as_deref() == Some("3.0.13") && !l.pqc_capable),
        "3.0.13 predates ML-KEM (3.5.0)"
    );
    assert!(
        !findings.libraries.iter().any(|l| l.name == "GnuTLS"),
        "removed packages do not count"
    );

    let env = findings
        .observations
        .iter()
        .find(|o| o.location.path.ends_with("!/.image-config/.env"))
        .expect("image environment is scanned");
    assert!(
        matches!(&env.finding, lattice_core::Finding::Protocol(p) if p.version.as_deref() == Some("1.1"))
    );
    assert_eq!(
        stats.files_seen, 5,
        "the final view: whiteouts and opaque-cleared files are not even read"
    );
    assert_eq!(
        stats.files_scanned, 4,
        "the package database is read by the package parser, not a file collector"
    );
}

#[test]
fn oci_layouts_inside_gzipped_archives() {
    let layer = gzip(&tar(&[(
        "srv/app.py",
        b"import hashlib\nhashlib.md5(b'x')\n",
    )]));
    let digest = |bytes: &[u8]| hex::encode(sha2::Sha256::digest(bytes));
    use sha2::Digest;
    let layer_digest = digest(&layer);
    let config = br#"{"config":{}}"#;
    let config_digest = digest(config);
    let manifest = format!(
        r#"{{"schemaVersion":2,"config":{{"digest":"sha256:{config_digest}"}},"layers":[{{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":"sha256:{layer_digest}"}}]}}"#
    );
    let manifest_digest = digest(manifest.as_bytes());
    let index = format!(
        r#"{{"schemaVersion":2,"manifests":[{{"digest":"sha256:{manifest_digest}","annotations":{{"org.opencontainers.image.ref.name":"registry.gov.in/ledger:1.9"}}}}]}}"#
    );
    let archive = gzip(&tar(&[
        ("oci-layout", br#"{"imageLayoutVersion":"1.0.0"}"#),
        ("index.json", index.as_bytes()),
        (
            &format!("blobs/sha256/{manifest_digest}"),
            manifest.as_bytes(),
        ),
        (&format!("blobs/sha256/{config_digest}"), config),
        (&format!("blobs/sha256/{layer_digest}"), &layer),
    ]));
    let dir = tempfile::tempdir().unwrap();
    let (findings, failures, _) = run(&dir, "ledger.oci.tar.gz", &archive, &ScanOptions::default());
    assert!(failures.is_empty(), "{failures:?}");
    assert_eq!(
        located(&findings, "md5"),
        vec!["images/ledger.oci.tar.gz!/srv/app.py".to_owned()]
    );
    assert_eq!(
        findings.observations[0].component,
        "registry.gov.in/ledger:1.9"
    );
}

#[test]
fn plain_tarballs_are_scanned_as_a_filesystem() {
    let archive = gzip(&tar(&[(
        "release/src/crypto.py",
        b"import hashlib\nhashlib.md5(b'x')\n",
    )]));
    let dir = tempfile::tempdir().unwrap();
    let (findings, failures, _) = run(
        &dir,
        "release-2.1.tar.gz",
        &archive,
        &ScanOptions::default(),
    );
    assert!(failures.is_empty(), "{failures:?}");
    assert_eq!(
        located(&findings, "md5"),
        vec!["images/release-2.1.tar.gz!/release/src/crypto.py".to_owned()]
    );
    assert_eq!(findings.observations[0].component, "release-2.1");
}

#[test]
fn decompression_bombs_and_unsupported_layers_fail_safely() {
    let dir = tempfile::tempdir().unwrap();
    let zeros = vec![0u8; 1 << 20];
    // an image whose only layer expands far past the limit
    let manifest = br#"[{"Config":"c.json","RepoTags":["bomb:1"],"Layers":["layer.tar"]}]"#;
    let bomb = tar(&[
        ("layer.tar", &gzip(&tar(&[("big.bin", &zeros)]))),
        ("c.json", b"{}"),
        ("manifest.json", manifest),
    ]);
    let options = ScanOptions {
        max_expanded_bytes: 64 * 1024,
        ..ScanOptions::default()
    };
    let (findings, failures, _) = run(&dir, "bomb.tar", &bomb, &options);
    assert!(findings.observations.is_empty());
    assert!(
        failures.iter().any(|f| f.reason.contains("size limit")),
        "{failures:?}"
    );

    let zstd_layer = [0x28, 0xb5, 0x2f, 0xfd, 0, 0, 0, 0];
    let manifest = br#"[{"Config":"c.json","RepoTags":["z:1"],"Layers":["layer.tar.zst"]}]"#;
    let archive = tar(&[
        ("layer.tar.zst", &zstd_layer),
        ("c.json", b"{}"),
        ("manifest.json", manifest),
    ]);
    let (_, failures, _) = run(&dir, "zstd.tar", &archive, &ScanOptions::default());
    assert!(
        failures.iter().any(|f| f.reason.contains("zstd")),
        "{failures:?}"
    );

    let (_, failures, _) = run(
        &dir,
        "garbage.tar",
        b"definitely not a tar archive at all",
        &ScanOptions::default(),
    );
    assert!(!failures.is_empty(), "corrupt archives are reported");
}

#[test]
fn traversal_paths_inside_archives_are_ignored() {
    let archive = tar_raw("../../etc/evil.py", b"import hashlib\nhashlib.md5(b'x')\n");
    let dir = tempfile::tempdir().unwrap();
    let (findings, failures, _) = run(&dir, "evil.tar", &archive, &ScanOptions::default());
    assert!(failures.is_empty(), "{failures:?}");
    assert!(findings.observations.is_empty());
    assert_eq!(normalize(b"./a//b/./c"), "a/b/c");
    assert_eq!(normalize(b"/abs/path"), "abs/path");
    assert_eq!(normalize(b"a/../../b"), "");
}

#[test]
fn archive_names_route_to_this_scanner() {
    for name in ["img.tar", "IMG.TAR.GZ", "x.tgz", "layout.oci"] {
        assert!(is_archive(name), "{name}");
    }
    for name in ["x.gz", "tar.py", "archive.zip"] {
        assert!(!is_archive(name), "{name}");
    }
}
