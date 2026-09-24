//! Runtime traces: what running processes asked their cryptographic libraries for.
//!
//! `lattice trace` records, on a live host, the calls that select cryptography: OpenSSL fetching
//! an algorithm by name, legacy getters such as `EVP_des_ede3_cbc()`, RSA key generation sizes,
//! and the TLS group and cipher lists a program configures. It writes a `lattice-trace/1` JSON
//! file, aggregated per executable and call. Placed in the scanned estate (conventionally as
//! `<component>/<host>.lattice-trace.json`), this collector turns every traced call into runtime
//! evidence, so the assets it names become Confirmed: not merely compiled in or configured, but
//! used.
//!
//! A trace records algorithm names, key sizes and list strings only; never data, keys or memory
//! beyond those arguments.

use crate::sandbox::Deadline;
use crate::{Artifact, Collector, Findings};
use lattice_core::names;
use lattice_core::{
    AlgorithmFinding, AlgorithmRef, Evidence, EvidenceKind, Finding, Location, Observation, Params,
    Primitive, ProtocolFinding, ProtocolKind, Surface,
};
use serde::{Deserialize, Serialize};

pub const FORMAT: &str = "lattice-trace/1";
pub const SUFFIX: &str = ".lattice-trace.json";
const COLLECTOR: &str = "trace";
const RULE_VERSION: &str = "2026.09.1";

/// What a traced call tells us.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CallKind {
    /// The argument names an algorithm (`EVP_CIPHER_fetch(ctx, "AES-256-GCM", …)`).
    Algorithm,
    /// The function itself is the algorithm (`EVP_des_ede3_cbc()`).
    Getter,
    /// The argument is an RSA key size in bits (`RSA_generate_key_ex`).
    RsaBits,
    /// A colon-separated TLS group list.
    Groups,
    /// An OpenSSL cipher list (TLS 1.2 and below) or TLS 1.3 cipher suites.
    CipherList,
}

/// One kind of call from one executable, and how often it happened.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TraceEvent {
    /// The process's executable, or its command name when the executable could not be read.
    pub executable: String,
    pub library: String,
    pub function: String,
    pub kind: CallKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    pub count: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Trace {
    pub format: String,
    /// RFC 3339 start of the recording.
    pub started: String,
    pub duration_seconds: u64,
    /// Libraries that were probed.
    pub libraries: Vec<String>,
    pub events: Vec<TraceEvent>,
    /// Calls made while OpenSSL initialised itself or built a TLS context, when it enumerates
    /// every algorithm it supports: not evidence of use, so not recorded as events.
    #[serde(default)]
    pub ignored_setup_calls: u64,
}

pub struct TraceCollector;

impl TraceCollector {
    pub fn new() -> Self {
        Self
    }
}

impl Default for TraceCollector {
    fn default() -> Self {
        Self::new()
    }
}

fn clip(value: &str) -> String {
    value.chars().take(96).collect()
}

impl Collector for TraceCollector {
    fn name(&self) -> &'static str {
        COLLECTOR
    }

    fn accepts(&self, path: &str, head: &[u8]) -> bool {
        path.ends_with(SUFFIX) && head.windows(FORMAT.len()).any(|w| w == FORMAT.as_bytes())
    }

    fn collect(
        &self,
        artifact: &Artifact<'_>,
        deadline: &Deadline,
        findings: &mut Findings,
    ) -> Result<(), String> {
        let trace: Trace =
            serde_json::from_slice(artifact.bytes).map_err(|e| format!("invalid trace: {e}"))?;
        if trace.format != FORMAT {
            return Err(format!("unsupported trace format {:?}", trace.format));
        }
        for (index, event) in trace.events.iter().enumerate() {
            if index % 1024 == 0 {
                deadline.check()?;
            }
            let program = event
                .executable
                .rsplit('/')
                .next()
                .unwrap_or(&event.executable);
            let token = clip(&format!(
                "{program} {}({}) x{}",
                event.function,
                event.value.as_deref().unwrap_or(""),
                event.count
            ));
            let rule = format!("trace.{}", serde_label(event.kind));
            let mut push = |finding: Finding| {
                findings.observations.push(Observation {
                    surface: Surface::Runtime,
                    component: artifact.component.to_owned(),
                    location: Location::at_line(artifact.path, index as u64 + 1, 1),
                    finding,
                    evidence: Evidence {
                        collector: COLLECTOR.into(),
                        rule_id: rule.clone(),
                        rule_version: RULE_VERSION.into(),
                        kind: EvidenceKind::Trace,
                        matched_token: token.clone(),
                    },
                    usage: None,
                });
            };
            let value = event.value.as_deref().unwrap_or("");
            match event.kind {
                CallKind::Algorithm => {
                    if let Some(algorithm) = names::resolve(value) {
                        // the fetch says what the algorithm does: RSA fetched as a signature signs
                        let primitive = match event.function.as_str() {
                            "EVP_SIGNATURE_fetch"
                            | "crypto/rsa.SignPKCS1v15"
                            | "crypto/rsa.SignPSS" => Some(Primitive::Signature),
                            "EVP_KEM_fetch" => Some(Primitive::Kem),
                            "EVP_KEYEXCH_fetch" => Some(Primitive::KeyAgree),
                            // RSA encryption, and TLS 1.2 RSA key transport
                            "EVP_ASYM_CIPHER_fetch"
                            | "crypto/rsa.EncryptPKCS1v15"
                            | "crypto/rsa.EncryptOAEP"
                            | "crypto/rsa.DecryptPKCS1v15"
                            | "crypto/rsa.DecryptOAEP"
                            | "crypto/tls.(*rsaKeyAgreement).processClientKeyExchange"
                            | "crypto/tls.(*rsaKeyAgreement).generateClientKeyExchange" => {
                                Some(Primitive::Pke)
                            }
                            _ => None,
                        };
                        push(Finding::Algorithm(AlgorithmFinding {
                            algorithm,
                            primitive,
                            function: None,
                        }));
                    }
                }
                CallKind::Getter => {
                    let name = event
                        .function
                        .strip_prefix("EVP_")
                        .unwrap_or(&event.function);
                    if let Some(algorithm) = names::resolve(name) {
                        push(Finding::algorithm(algorithm));
                    }
                }
                CallKind::RsaBits => {
                    if let Ok(bits) = value.parse::<u32>()
                        && (256..=65536).contains(&bits)
                    {
                        push(Finding::algorithm(AlgorithmRef::with_params(
                            "rsa",
                            Params {
                                key_bits: Some(bits),
                                ..Params::default()
                            },
                        )));
                    }
                }
                CallKind::Groups => {
                    let mut groups = Vec::new();
                    // OpenSSL 3.5 lists: `?*X25519MLKEM768 / ?*X25519:?secp256r1`
                    for group in value.split([':', ',', '/']) {
                        let group = group.trim().trim_start_matches(['?', '*', '-']);
                        if let Some(algorithm) = names::resolve_group(group) {
                            groups.push(group.to_owned());
                            push(Finding::algorithm(algorithm));
                        }
                    }
                    if !groups.is_empty() {
                        push(Finding::Protocol(ProtocolFinding {
                            protocol: ProtocolKind::Tls,
                            version: None,
                            cipher_suites: Vec::new(),
                            groups,
                        }));
                    }
                }
                CallKind::CipherList => {
                    let mut suites = Vec::new();
                    let mut algorithms = Vec::new();
                    for name in value.split([':', ',']) {
                        if let Some(suite) = names::parse_cipher_suite(name) {
                            algorithms.extend(suite.algorithms().cloned());
                            suites.push(suite.name);
                        }
                    }
                    suites.sort();
                    suites.dedup();
                    algorithms.sort();
                    algorithms.dedup();
                    if !suites.is_empty() {
                        push(Finding::Protocol(ProtocolFinding {
                            protocol: ProtocolKind::Tls,
                            version: None,
                            cipher_suites: suites,
                            groups: Vec::new(),
                        }));
                    }
                    for algorithm in algorithms {
                        push(Finding::algorithm(algorithm));
                    }
                }
            }
        }
        Ok(())
    }
}

fn serde_label(kind: CallKind) -> String {
    serde_json::to_value(kind)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn event(function: &str, kind: CallKind, value: Option<&str>) -> TraceEvent {
        TraceEvent {
            executable: "/usr/sbin/nginx".into(),
            library: "/usr/lib/x86_64-linux-gnu/libcrypto.so.3".into(),
            function: function.into(),
            kind,
            value: value.map(str::to_owned),
            count: 3,
        }
    }

    fn run(trace: &Trace) -> Findings {
        let bytes = serde_json::to_vec_pretty(trace).unwrap();
        let path = "gateway/edge-1.lattice-trace.json";
        let collector = TraceCollector::new();
        assert!(collector.accepts(path, &bytes[..bytes.len().min(512)]));
        let mut findings = Findings::default();
        collector
            .collect(
                &Artifact {
                    path,
                    component: "gateway",
                    bytes: &bytes,
                },
                &Deadline::after(Duration::from_secs(5)),
                &mut findings,
            )
            .unwrap();
        findings
    }

    #[test]
    fn traced_calls_become_runtime_evidence() {
        let trace = Trace {
            format: FORMAT.into(),
            started: "2026-09-24T00:00:00Z".into(),
            duration_seconds: 60,
            libraries: vec!["/usr/lib/x86_64-linux-gnu/libcrypto.so.3".into()],
            ignored_setup_calls: 0,
            events: vec![
                event("EVP_CIPHER_fetch", CallKind::Algorithm, Some("AES-256-GCM")),
                event("EVP_des_ede3_cbc", CallKind::Getter, None),
                event("RSA_generate_key_ex", CallKind::RsaBits, Some("1024")),
                event(
                    "SSL_CTX_ctrl",
                    CallKind::Groups,
                    Some("?*X25519MLKEM768 / ?*X25519:?secp256r1"),
                ),
                event(
                    "SSL_CTX_set_cipher_list",
                    CallKind::CipherList,
                    Some("ECDHE-RSA-AES128-SHA:DES-CBC3-SHA"),
                ),
                event(
                    "EVP_MD_fetch",
                    CallKind::Algorithm,
                    Some("not-an-algorithm"),
                ),
            ],
        };
        let findings = run(&trace);
        assert!(findings.observations.iter().all(|o| {
            o.surface == Surface::Runtime
                && o.evidence.kind == EvidenceKind::Trace
                && o.component == "gateway"
        }));
        let names: Vec<String> = findings
            .observations
            .iter()
            .map(|o| o.finding.display_name())
            .collect();
        for expected in ["AES-256-GCM", "RSA-1024", "X25519MLKEM768", "X25519"] {
            assert!(
                names.iter().any(|n| n == expected),
                "{expected} in {names:?}"
            );
        }
        assert!(names.iter().any(|n| n.starts_with("3DES")), "{names:?}");
        assert!(
            findings
                .observations
                .iter()
                .any(|o| matches!(&o.finding, Finding::Protocol(p) if p.cipher_suites.len() == 2)),
            "{names:?}"
        );
        assert!(
            findings.observations.iter().all(|o| !o
                .evidence
                .matched_token
                .contains("not-an-algorithm")
                || o.finding.display_name() != "not-an-algorithm")
        );
        assert!(
            findings.observations[0]
                .evidence
                .matched_token
                .starts_with("nginx EVP_CIPHER_fetch(AES-256-GCM) x3")
        );
    }

    #[test]
    fn other_json_is_not_a_trace() {
        let collector = TraceCollector::new();
        assert!(!collector.accepts("gateway/app.json", b"{\"format\": \"lattice-trace/1\"}"));
        assert!(!collector.accepts("a.lattice-trace.json", b"{\"format\": \"other\"}"));
    }

    #[test]
    fn the_fetch_says_what_the_algorithm_does() {
        let trace = Trace {
            format: FORMAT.into(),
            started: "2026-09-24T00:00:00Z".into(),
            duration_seconds: 1,
            libraries: Vec::new(),
            ignored_setup_calls: 0,
            events: vec![event(
                "EVP_SIGNATURE_fetch",
                CallKind::Algorithm,
                Some("RSA"),
            )],
        };
        let findings = run(&trace);
        assert!(matches!(
            &findings.observations[0].finding,
            Finding::Algorithm(AlgorithmFinding {
                primitive: Some(Primitive::Signature),
                ..
            })
        ));
    }
}
