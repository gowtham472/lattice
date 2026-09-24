//! Server, cloud and application configuration through the config collector.
#![no_main]

use lattice_collectors::{config::ConfigCollector, fuzzing};
use libfuzzer_sys::fuzz_target;
use std::sync::LazyLock;

const NAMES: &[&str] = &[
    "nginx.conf",
    "sshd_config",
    "haproxy.cfg",
    "openssl.cnf",
    "java.security",
    ".env",
    "Dockerfile",
    "app.yaml",
    "app.json",
    "app.toml",
    "app.properties",
    "main.tf",
];
static COLLECTOR: LazyLock<ConfigCollector> = LazyLock::new(|| ConfigCollector::new().unwrap());

fuzz_target!(|data: &[u8]| {
    let Some((&pick, bytes)) = data.split_first() else {
        return;
    };
    fuzzing::collect(&*COLLECTOR, NAMES[pick as usize % NAMES.len()], bytes);
});
