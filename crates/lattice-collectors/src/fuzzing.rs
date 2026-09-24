//! Entry points for the fuzz targets in `fuzz/`.
//!
//! In a scan every hostile-input parser runs inside [`crate::sandbox::isolate`], which turns a
//! panic into a per-artefact failure. That keeps scans alive but would also hide bugs from a
//! fuzzer, so these entry points call the parsers directly: any panic here is a finding.
//! Built only with the `fuzzing` feature.

use crate::sandbox::Deadline;
use crate::{Artifact, Collector, ScanOptions};
use std::path::Path;
use std::time::Duration;

/// Generous: a fuzz input that needs longer is a hang, which libFuzzer reports on its own.
const BUDGET: Duration = Duration::from_secs(30);

/// Runs one per-file collector on `bytes`, as the walker would after its pre-filter.
pub fn collect(collector: &dyn Collector, path: &str, bytes: &[u8]) {
    if !collector.accepts(path, &bytes[..bytes.len().min(512)]) {
        return;
    }
    let artifact = Artifact {
        path,
        component: "fuzz",
        bytes,
    };
    let mut findings = crate::Findings::default();
    let _ = collector.collect(&artifact, &Deadline::after(BUDGET), &mut findings);
}

/// Reads a pcap or pcapng capture and analyses every connection in it.
pub fn capture(bytes: &[u8]) {
    let _ = crate::capture::analyse_bytes(bytes, &Deadline::after(BUDGET));
}

/// Scans a container archive (docker save, OCI layout or plain tarball) stored at `path`.
pub fn archive(path: &Path, collectors: &[Box<dyn Collector>]) {
    let options = ScanOptions {
        // keep each input cheap: fuzzing explores structure, not size
        max_expanded_bytes: 64 * 1024 * 1024,
        ..ScanOptions::default()
    };
    let mut failures = Vec::new();
    let _ = crate::container::scan(
        path,
        "fuzz.tar",
        "fuzz",
        collectors,
        &options,
        &Deadline::after(BUDGET),
        &mut failures,
    );
}

/// The DER and OpenSSH key decoders behind the PKI collector.
pub fn keys(bytes: &[u8]) {
    use crate::pki::{der, ssh};
    let _ = der::spki(bytes);
    let _ = der::pkcs8(bytes);
    let _ = der::rsa_public_bits(bytes);
    let _ = der::rsa_pkcs1_private_bits(bytes);
    let _ = der::sec1_curve(bytes);
    if let Some(tlv) = der::read(bytes) {
        let _ = der::children(tlv.content);
        let _ = der::oid_from_content(tlv.content);
        let _ = der::integer_bits(tlv.content);
    }
    let _ = ssh::parse_public_blob(bytes);
    let _ = ssh::parse_private(bytes);
}
