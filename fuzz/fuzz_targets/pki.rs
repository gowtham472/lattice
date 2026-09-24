//! Certificates, keys, keystores and SSH files through the PKI collector.
#![no_main]

use lattice_collectors::{fuzzing, pki::PkiCollector};
use libfuzzer_sys::fuzz_target;

/// The first byte picks the file name, since the collector dispatches on it.
const NAMES: &[&str] = &[
    "cert.pem",
    "cert.der",
    "cert.crt",
    "server.key",
    "id_rsa",
    "id_ed25519.pub",
    "authorized_keys",
    "known_hosts",
    "store.p12",
    "store.jks",
    "bundle.p7b",
    "req.csr",
];

fuzz_target!(|data: &[u8]| {
    let Some((&pick, bytes)) = data.split_first() else {
        return;
    };
    let collector = PkiCollector::new();
    fuzzing::collect(&collector, NAMES[pick as usize % NAMES.len()], bytes);
});
