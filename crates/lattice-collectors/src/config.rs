//! Configuration collector: TLS/SSH policy and algorithm selections in server configuration,
//! application settings and infrastructure-as-code.
//!
//! Structural, not textual. Server configuration is read directive by directive (nginx, Apache,
//! HAProxy, OpenSSL, OpenSSH and others); structured data (YAML, JSON, TOML, properties, INI,
//! env) is flattened to key paths and only keys that name a cryptographic setting are
//! interpreted; Terraform and CloudFormation are read resource by resource. A value is reported
//! only when the strict name parser accepts it, so `algorithm: round-robin` is never a finding.

use crate::sandbox::Deadline;
use crate::{Artifact, Collector, CollectorError, Findings};
use lattice_core::names;
use lattice_core::{
    AlgorithmRef, EntryKind, EntryPoint, Evidence, EvidenceKind, Finding, FunctionFact, Location,
    Observation, ProtocolFinding, ProtocolKind, Registry, Surface,
};
use std::collections::{BTreeMap, BTreeSet};

const COLLECTOR: &str = "config";
const RULE_VERSION: &str = "2026.09.1";
const MAX_LINES: usize = 200_000;
const MAX_DEPTH: usize = 48;

#[derive(Debug, Default)]
pub struct ConfigCollector;

impl ConfigCollector {
    pub fn new() -> Result<Self, CollectorError> {
        Ok(Self)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Format {
    /// Line-oriented `directive value...` (nginx, Apache, HAProxy, sshd, openssl.cnf, ...).
    Directives,
    Yaml,
    Json,
    Toml,
    /// `key=value` / `key: value` with optional `[sections]` (properties, INI, env).
    KeyValue,
    Terraform,
}

fn format_of(path: &str) -> Option<Format> {
    let file = path.rsplit('/').next().unwrap_or(path);
    let lower = file.to_ascii_lowercase();
    if lower.ends_with(crate::trace::SUFFIX) {
        return None;
    }
    if matches!(
        lower.as_str(),
        "package-lock.json"
            | "yarn.lock"
            | "pnpm-lock.yaml"
            | "composer.lock"
            | "cargo.lock"
            | "tsconfig.json"
    ) {
        return None;
    }
    if matches!(
        lower.as_str(),
        "sshd_config"
            | "ssh_config"
            | "haproxy.cfg"
            | "openssl.cnf"
            | "httpd.conf"
            | "apache2.conf"
            | "ssl.conf"
            | "nginx.conf"
            | "main.cf"
            | "postgresql.conf"
            | "redis.conf"
            | "my.cnf"
            | "dovecot.conf"
            | "stunnel.conf"
            | "java.security"
            | "crypttab"
    ) || lower.starts_with("sshd_config")
    {
        return Some(if lower == "java.security" {
            Format::KeyValue
        } else {
            Format::Directives
        });
    }
    if lower.starts_with(".env") || lower == "dockerfile" {
        return Some(Format::KeyValue);
    }
    let extension = lower.rsplit_once('.').map(|(_, ext)| ext)?;
    Some(match extension {
        "conf" | "cnf" | "cfg" | "vhost" | "site" => Format::Directives,
        "yaml" | "yml" => Format::Yaml,
        "json" => Format::Json,
        "toml" => Format::Toml,
        "properties" | "ini" | "env" | "config" | "settings" => Format::KeyValue,
        "tf" | "tfvars" | "hcl" => Format::Terraform,
        _ => return None,
    })
}

impl Collector for ConfigCollector {
    fn name(&self) -> &'static str {
        COLLECTOR
    }

    fn accepts(&self, path: &str, head: &[u8]) -> bool {
        format_of(path).is_some() && !head.contains(&0)
    }

    fn collect(
        &self,
        artifact: &Artifact<'_>,
        deadline: &Deadline,
        findings: &mut Findings,
    ) -> Result<(), String> {
        let format = format_of(artifact.path).ok_or("not a configuration file")?;
        let text = String::from_utf8_lossy(artifact.bytes);
        let cloud = format == Format::Terraform
            || text.contains("AWSTemplateFormatVersion")
            || text.contains("\"AWS::")
            || text.contains(" AWS::");
        let mut out = Out {
            artifact,
            findings,
            text: &text,
            cloud,
            listener: None,
            served: BTreeSet::new(),
            hosts: BTreeSet::new(),
        };
        match format {
            Format::Directives => directives(&mut out, deadline)?,
            Format::Yaml => yaml(&mut out, deadline)?,
            Format::Json => {
                let value: serde_json::Value =
                    serde_json::from_str(&text).map_err(|_| "invalid JSON")?;
                walk_json(&mut out, &value, &mut Vec::new(), 0);
            }
            Format::Toml => {
                let value: toml::Value = toml::from_str(&text).map_err(|_| "invalid TOML")?;
                walk_toml(&mut out, &value, &mut Vec::new(), 0);
            }
            Format::KeyValue => key_values(&mut out, deadline)?,
            Format::Terraform => terraform(&mut out, deadline)?,
        }
        deadline.check()?;
        for reference in crate::custody::find(artifact.path, &text) {
            out.held_key(reference);
        }
        out.attach_served();
        Ok(())
    }
}

// ---- output ----------------------------------------------------------------------------------

struct Out<'a, 'f> {
    artifact: &'a Artifact<'a>,
    findings: &'f mut Findings,
    text: &'a str,
    cloud: bool,
    listener: Option<String>,
    /// Certificate and key files the configuration points its listener at.
    served: BTreeSet<String>,
    /// Host names the listener answers to.
    hosts: BTreeSet<String>,
}

impl Out<'_, '_> {
    fn surface(&self) -> Surface {
        if self.cloud {
            Surface::Cloud
        } else {
            Surface::Config
        }
    }

    fn push(&mut self, finding: Finding, rule: &str, token: &str, line: u64) {
        let kind = if self.cloud {
            EvidenceKind::Infrastructure
        } else {
            EvidenceKind::Configuration
        };
        self.findings.observations.push(Observation {
            surface: self.surface(),
            component: self.artifact.component.to_owned(),
            location: Location::at_line(self.artifact.path, line, 1),
            finding,
            evidence: Evidence {
                collector: COLLECTOR.into(),
                rule_id: rule.into(),
                rule_version: RULE_VERSION.into(),
                kind,
                matched_token: token.chars().take(96).collect(),
            },
            usage: None,
        });
    }

    /// A key held in hardware or a key service, referenced by this configuration.
    fn held_key(&mut self, reference: crate::custody::Reference) {
        self.custody_material(
            reference.material_type,
            None,
            reference.custody,
            &reference.key,
            reference.rule,
            &reference.token,
            reference.line,
        );
    }

    #[allow(clippy::too_many_arguments)]
    fn custody_material(
        &mut self,
        material_type: lattice_core::MaterialType,
        algorithm: Option<AlgorithmRef>,
        custody: lattice_core::Custody,
        key: &str,
        rule: &str,
        token: &str,
        line: u64,
    ) {
        let size_bits = algorithm.as_ref().and_then(|a| a.params.key_bits);
        let finding = Finding::RelatedCryptoMaterial(lattice_core::MaterialFinding {
            material_type,
            algorithm,
            size_bits,
            format: "reference".into(),
            encrypted: false,
            identity: blake3::hash(format!("custody|{key}").as_bytes()).to_hex()[..32].to_owned(),
            custody: Some(custody),
        });
        self.push(finding, rule, token, line);
    }

    fn algorithm(&mut self, algorithm: AlgorithmRef, rule: &str, token: &str, line: u64) {
        let mut algorithm = algorithm;
        if let Some(curve) = algorithm.params.curve.take() {
            algorithm.params.curve = Some(Registry::active().canonical_curve(&curve));
        }
        self.push(Finding::algorithm(algorithm), rule, token, line);
    }

    fn versions(
        &mut self,
        protocol: ProtocolKind,
        values: &[String],
        rule: &str,
        token: &str,
        line: u64,
    ) {
        for value in values {
            if let Some((kind, version)) = names::parse_protocol_version(value) {
                let kind = if protocol == ProtocolKind::Tls {
                    kind
                } else {
                    protocol
                };
                self.push(
                    Finding::Protocol(ProtocolFinding {
                        protocol: kind,
                        version: Some(version),
                        cipher_suites: Vec::new(),
                        groups: Vec::new(),
                    }),
                    rule,
                    token,
                    line,
                );
            }
        }
    }

    fn cipher_suites(&mut self, values: &[String], rule: &str, token: &str, line: u64) -> bool {
        let mut suites = Vec::new();
        let mut algorithms = Vec::new();
        for value in values {
            if let Some(suite) = names::parse_cipher_suite(value) {
                algorithms.extend(suite.algorithms().cloned());
                suites.push(suite.name);
            }
        }
        if suites.is_empty() {
            return false;
        }
        suites.sort();
        suites.dedup();
        self.push(
            Finding::Protocol(ProtocolFinding {
                protocol: ProtocolKind::Tls,
                version: None,
                cipher_suites: suites,
                groups: Vec::new(),
            }),
            rule,
            token,
            line,
        );
        algorithms.sort();
        algorithms.dedup();
        for algorithm in algorithms {
            self.algorithm(algorithm, rule, token, line);
        }
        true
    }

    fn groups(&mut self, values: &[String], rule: &str, token: &str, line: u64) -> bool {
        let mut groups = Vec::new();
        let mut algorithms = Vec::new();
        for value in values {
            if let Some(group) = names::resolve_group(value) {
                algorithms.push(group);
                groups.push(value.clone());
            }
        }
        if groups.is_empty() {
            return false;
        }
        self.push(
            Finding::Protocol(ProtocolFinding {
                protocol: ProtocolKind::Tls,
                version: None,
                cipher_suites: Vec::new(),
                groups,
            }),
            rule,
            token,
            line,
        );
        for algorithm in algorithms {
            self.algorithm(algorithm, rule, token, line);
        }
        true
    }

    /// SSH algorithm lists (`Ciphers`, `MACs`, `KexAlgorithms`, `HostKeyAlgorithms`).
    fn ssh_algorithms(&mut self, values: &[String], rule: &str, token: &str, line: u64) {
        let mut accepted = Vec::new();
        for value in values {
            // `+alg`, `-alg`, `^alg` modify defaults; removals are not selections
            if value.starts_with('-') {
                continue;
            }
            let name = value.trim_start_matches(['+', '^']);
            if let Some(algorithm) = names::resolve(name) {
                accepted.push(name.to_owned());
                self.algorithm(algorithm, rule, token, line);
            }
        }
        if !accepted.is_empty() {
            self.push(
                Finding::Protocol(ProtocolFinding {
                    protocol: ProtocolKind::Ssh,
                    version: Some("2.0".into()),
                    cipher_suites: accepted,
                    groups: Vec::new(),
                }),
                rule,
                token,
                line,
            );
        }
    }

    /// Records a certificate or key file the configuration serves, by file name: deployment
    /// paths (`/etc/nginx/tls/server.crt`) differ from repository paths, names do not.
    fn serve(&mut self, path: &str) {
        let name = path
            .trim_matches(['"', '\''])
            .rsplit(['/', '\\'])
            .next()
            .unwrap_or_default();
        if !name.is_empty() && self.served.len() < 32 {
            self.served.insert(name.to_owned());
        }
    }

    fn attach_served(&mut self) {
        if self.listener.is_none() {
            return;
        }
        let id = format!(
            "{}::{}::<tls-listener>",
            self.artifact.component, self.artifact.path
        );
        if let Some(listener) = self.findings.functions.iter_mut().find(|f| f.id == id) {
            listener.serves = std::mem::take(&mut self.served).into_iter().collect();
            listener.hosts = std::mem::take(&mut self.hosts).into_iter().collect();
        }
    }

    /// A host name the server answers to (`*.example.in` wildcards included; nginx's catch-all
    /// `_` and bare words are not host names).
    fn host(&mut self, name: &str) {
        let name = name
            .trim_matches(['"', '\''])
            .trim_end_matches('.')
            .to_ascii_lowercase();
        let valid = name.len() <= 253
            && name.contains('.')
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'*'));
        if valid && self.hosts.len() < 64 {
            self.hosts.insert(name);
        }
    }

    fn listener(&mut self, detail: &str, line: u64) {
        if self.listener.is_some() {
            return;
        }
        self.listener = Some(detail.to_owned());
        self.findings.functions.push(FunctionFact {
            id: format!(
                "{}::{}::<tls-listener>",
                self.artifact.component, self.artifact.path
            ),
            component: self.artifact.component.to_owned(),
            name: "<tls-listener>".into(),
            location: Location::at_line(self.artifact.path, line, 1),
            entry: Some(EntryPoint {
                kind: EntryKind::Listener,
                detail: detail.chars().take(120).collect(),
            }),
            parameters: Vec::new(),
            serves: Vec::new(),
            hosts: Vec::new(),
        });
    }

    /// Interprets one `key = value` pair from structured configuration.
    fn key_value(&mut self, path: &[String], value: &str, line: u64) {
        let Some(key) = path.last() else { return };
        let normalized: String = key
            .chars()
            .filter(|c| c.is_ascii_alphanumeric())
            .flat_map(char::to_lowercase)
            .collect();
        let dotted = path.join(".");
        // `tls: { minimumVersion: ... }`: a bare `version` key is a protocol version only
        // because of where it sits
        let setting = classify_key(&normalized).or_else(|| {
            let under_tls = path[..path.len() - 1].iter().any(|part| {
                let part = part.to_ascii_lowercase();
                part.contains("tls") || part.contains("ssl") || part == "https"
            });
            (under_tls && normalized.contains("version")).then_some(Setting::Protocols)
        });
        let rule = format!("config.key.{}", setting.map_or("unknown", Setting::name));
        let values = split_list(value);
        match setting {
            Some(Setting::Protocols) => {
                self.versions(ProtocolKind::Tls, &values, &rule, &dotted, line)
            }
            Some(Setting::Ciphers) => {
                if !self.cipher_suites(&values, &rule, &dotted, line) {
                    for value in &values {
                        if let Some(algorithm) = names::resolve(value) {
                            self.algorithm(algorithm, &rule, &dotted, line);
                        }
                    }
                }
            }
            Some(Setting::Groups) => {
                self.groups(&values, &rule, &dotted, line);
            }
            Some(Setting::Ssh) => self.ssh_algorithms(&values, &rule, &dotted, line),
            Some(Setting::KeySpec) => {
                for value in &values {
                    if let Some(algorithm) =
                        names::parse_key_spec(value).or_else(|| names::resolve(value))
                    {
                        self.algorithm(algorithm, &rule, &dotted, line);
                    }
                }
            }
            Some(Setting::Policy) => {
                if let Some((version, post_quantum)) = names::parse_tls_policy(value) {
                    self.push(
                        Finding::Protocol(ProtocolFinding {
                            protocol: ProtocolKind::Tls,
                            version: Some(version),
                            cipher_suites: Vec::new(),
                            groups: Vec::new(),
                        }),
                        &rule,
                        &dotted,
                        line,
                    );
                    if post_quantum {
                        self.algorithm(AlgorithmRef::new("x25519-mlkem768"), &rule, &dotted, line);
                    }
                }
            }
            Some(Setting::Algorithm) => {
                for value in &values {
                    if let Some(algorithm) =
                        names::resolve(value).or_else(|| names::parse_key_spec(value))
                    {
                        self.algorithm(algorithm, &rule, &dotted, line);
                    }
                }
            }
            None => {}
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum Setting {
    Protocols,
    Ciphers,
    Groups,
    Ssh,
    KeySpec,
    Policy,
    Algorithm,
}

impl Setting {
    fn name(self) -> &'static str {
        match self {
            Self::Protocols => "protocols",
            Self::Ciphers => "ciphers",
            Self::Groups => "groups",
            Self::Ssh => "ssh",
            Self::KeySpec => "key-spec",
            Self::Policy => "tls-policy",
            Self::Algorithm => "algorithm",
        }
    }
}

/// Which cryptographic setting a (normalised) key names, if any.
fn classify_key(key: &str) -> Option<Setting> {
    let has = |needle: &str| key.contains(needle);
    if matches!(
        key,
        "kexalgorithms"
            | "hostkeyalgorithms"
            | "pubkeyacceptedalgorithms"
            | "pubkeyacceptedkeytypes"
            | "casignaturealgorithms"
            | "macs"
    ) {
        return Some(Setting::Ssh);
    }
    if has("sslpolicy")
        || has("securitypolicy")
        || has("tlspolicy")
        || key == "minimumprotocolversion"
    {
        return Some(Setting::Policy);
    }
    if has("keyspec")
        || has("masterkeyspec")
        || key == "keyalgorithm"
        || key == "versiontemplatealgorithm"
    {
        return Some(Setting::KeySpec);
    }
    if has("protocol")
        && (has("ssl")
            || has("tls")
            || has("enabled")
            || has("min")
            || has("max")
            || key == "protocols")
        || has("tlsversion")
        || has("sslversion")
        || has("minversion")
        || has("maxversion")
        || key == "tlsprotocols"
    {
        return Some(Setting::Protocols);
    }
    if has("cipher") {
        return Some(Setting::Ciphers);
    }
    if has("curve")
        || has("namedgroup")
        || key == "groups"
        || has("ecdhcurve")
        || has("kexgroups")
        || key == "tlsgroups"
    {
        return Some(Setting::Groups);
    }
    if key == "alg"
        || key == "algo"
        || has("algorithm")
        || key.ends_with("hash")
        || key.ends_with("digest")
        || key.ends_with("signature")
        || has("sigalg")
        || key == "keytype"
        || key.ends_with("kdf")
        || key == "mac"
        || key.ends_with("encryption")
    {
        return Some(Setting::Algorithm);
    }
    None
}

/// Splits `a:b`, `a,b`, `a b` and `[a, b]` lists; strips quotes.
fn split_list(value: &str) -> Vec<String> {
    value
        .trim()
        .trim_matches(['[', ']'])
        .split([':', ',', ' ', ';'])
        .map(|item| item.trim().trim_matches(['"', '\'']).to_owned())
        .filter(|item| !item.is_empty())
        .collect()
}

fn strip_comment(line: &str) -> &str {
    let mut single = false;
    let mut double = false;
    for (index, c) in line.char_indices() {
        match c {
            '\'' if !double => single = !single,
            '"' if !single => double = !double,
            '#' if !single && !double => return &line[..index],
            _ => {}
        }
    }
    line
}

// ---- directive formats -----------------------------------------------------------------------

fn directives(out: &mut Out<'_, '_>, deadline: &Deadline) -> Result<(), String> {
    let text = out.text;
    let is_ssh = out.artifact.path.contains("ssh");
    for (index, raw) in text.lines().enumerate().take(MAX_LINES) {
        if index % 4096 == 0 {
            deadline.check()?;
        }
        let line_number = index as u64 + 1;
        let line = strip_comment(raw).trim().trim_end_matches(';').trim();
        if line.is_empty() {
            continue;
        }
        // `key value`, `key = value`, `key: value`
        let (key, value) = match line.split_once(|c: char| c.is_whitespace() || c == '=') {
            Some((key, value)) => (
                key.trim().trim_end_matches(':'),
                value.trim().trim_start_matches(['=', ':']).trim(),
            ),
            None => continue,
        };
        let value = value.trim_matches(['"', '\'']);
        let lower = key.to_ascii_lowercase();
        let rule = format!("config.directive.{lower}");
        let values = split_list(value);

        // TLS listeners make the configuration internet-facing
        if (lower == "listen" && value.contains("ssl"))
            || (lower == "bind" && value.contains(" ssl"))
        {
            out.listener(&format!("{key} {value}"), line_number);
        }
        if lower.starts_with("<virtualhost") && raw.contains(":443") {
            out.listener(raw.trim(), line_number);
        }
        // HAProxy: `bind :443 ssl crt /etc/haproxy/site.pem`
        if lower == "bind" {
            let mut tokens = value.split_whitespace();
            while let Some(token) = tokens.next() {
                if token == "crt"
                    && let Some(path) = tokens.next()
                {
                    out.serve(path);
                }
            }
        }
        if matches!(
            lower.as_str(),
            "ssl_certificate"
                | "ssl_certificate_key"
                | "sslcertificatefile"
                | "sslcertificatekeyfile"
                | "sslcertificatechainfile"
                | "smtpd_tls_cert_file"
                | "smtpd_tls_key_file"
                | "smtpd_tls_chain_files"
                | "tls-cert-file"
                | "tls-key-file"
                | "ssl_cert_file"
                | "ssl_key_file"
        ) {
            for path in &values {
                out.serve(path);
            }
        }
        if matches!(lower.as_str(), "server_name" | "servername" | "serveralias") {
            for name in value.split_whitespace() {
                out.host(name);
            }
        }

        match lower.as_str() {
            // nginx, Apache, HAProxy, Postfix, PostgreSQL, Redis, stunnel, OpenSSL
            "ssl_protocols"
            | "proxy_ssl_protocols"
            | "grpc_ssl_protocols"
            | "sslprotocol"
            | "sslproxyprotocol"
            | "ssl-min-ver"
            | "ssl-max-ver"
            | "minprotocol"
            | "maxprotocol"
            | "ssl_min_protocol_version"
            | "smtpd_tls_protocols"
            | "smtp_tls_protocols"
            | "smtpd_tls_mandatory_protocols"
            | "tls-protocols"
            | "ssl_min_protocol"
            | "tls_version"
            | "sslversion" => {
                // Apache: `all -SSLv3 -TLSv1`; removals are exclusions, not selections
                let selected: Vec<String> = values
                    .iter()
                    .filter(|v| !v.starts_with('-'))
                    .map(|v| v.trim_start_matches('+').to_owned())
                    .collect();
                out.versions(ProtocolKind::Tls, &selected, &rule, key, line_number);
            }
            "ssl_ciphers"
            | "proxy_ssl_ciphers"
            | "grpc_ssl_ciphers"
            | "sslciphersuite"
            | "sslproxyciphersuite"
            | "ssl-default-bind-ciphers"
            | "ssl-default-bind-ciphersuites"
            | "ssl-default-server-ciphers"
            | "ssl-default-server-ciphersuites"
            | "cipherstring"
            | "ciphersuites"
            | "ssl_cipher_list"
            | "tls-ciphers"
            | "tls-ciphersuites"
            | "ssl_cipher"
            | "tls_high_cipherlist"
            | "tls_medium_cipherlist"
            | "smtpd_tls_mandatory_ciphers"
            | "ssl_ciphers_tls13" => {
                out.cipher_suites(&values, &rule, key, line_number);
            }
            "ssl_ecdh_curve" | "groups" | "curves" | "ssl_ecdh_curves" | "tls_groups" => {
                out.groups(&values, &rule, key, line_number);
            }
            "sslopensslconfcmd" | "ssl_conf_command" => {
                let (command, rest) = value.split_once(char::is_whitespace).unwrap_or((value, ""));
                let items = split_list(rest);
                match command.to_ascii_lowercase().as_str() {
                    "groups" | "curves" => {
                        out.groups(&items, &rule, key, line_number);
                    }
                    "ciphersuites" | "cipherstring" => {
                        out.cipher_suites(&items, &rule, key, line_number);
                    }
                    "minprotocol" => {
                        out.versions(ProtocolKind::Tls, &items, &rule, key, line_number)
                    }
                    _ => {}
                }
            }
            "ciphers"
            | "macs"
            | "kexalgorithms"
            | "hostkeyalgorithms"
            | "pubkeyacceptedalgorithms"
            | "pubkeyacceptedkeytypes"
            | "casignaturealgorithms"
                if is_ssh || lower != "ciphers" =>
            {
                out.ssh_algorithms(&values, &rule, key, line_number);
            }
            "ciphers" => {
                out.cipher_suites(&values, &rule, key, line_number);
            }
            "bind" if value.contains(" ssl") => {
                // HAProxy inline bind options: `bind :443 ssl crt x ciphers A:B ssl-min-ver TLSv1.2`
                let tokens: Vec<&str> = value.split_whitespace().collect();
                for pair in tokens.windows(2) {
                    match pair[0] {
                        "ciphers" | "ciphersuites" => {
                            out.cipher_suites(&split_list(pair[1]), &rule, key, line_number);
                        }
                        "ssl-min-ver" | "ssl-max-ver" => out.versions(
                            ProtocolKind::Tls,
                            &[pair[1].to_owned()],
                            &rule,
                            key,
                            line_number,
                        ),
                        "curves" => {
                            out.groups(&split_list(pair[1]), &rule, key, line_number);
                        }
                        _ => {}
                    }
                }
            }
            _ => {
                // other `key value` settings: structured interpretation of the key name
                out.key_value(&[key.to_owned()], value, line_number);
            }
        }
    }
    Ok(())
}

// ---- structured data -------------------------------------------------------------------------

/// Indentation-based YAML reader: enough for configuration (mappings, block and flow lists,
/// multiple documents), with no dependency on a full YAML implementation.
fn yaml(out: &mut Out<'_, '_>, deadline: &Deadline) -> Result<(), String> {
    let text = out.text;
    let mut stack: Vec<(usize, String)> = Vec::new();
    for (index, raw) in text.lines().enumerate().take(MAX_LINES) {
        if index % 4096 == 0 {
            deadline.check()?;
        }
        let line_number = index as u64 + 1;
        if raw.trim() == "---" {
            stack.clear();
            continue;
        }
        let content = strip_comment(raw);
        if content.trim().is_empty() {
            continue;
        }
        let indent = content.len() - content.trim_start().len();
        let mut body = content.trim();
        let list_item = body.starts_with("- ") || body == "-";
        if list_item {
            body = body.trim_start_matches('-').trim();
        }
        while stack
            .last()
            .is_some_and(|(level, _)| *level > indent || (!list_item && *level == indent))
        {
            stack.pop();
        }
        if stack.len() > MAX_DEPTH {
            continue;
        }
        let key_value = body
            .split_once(": ")
            .or_else(|| body.strip_suffix(':').map(|key| (key, "")));
        match key_value {
            Some((key, value)) if !key.contains(' ') || key.starts_with(['"', '\'']) => {
                let key = key.trim().trim_matches(['"', '\'']).to_owned();
                let value = value.trim();
                let item_indent = if list_item { indent + 2 } else { indent };
                if value.is_empty() || value == "|" || value == ">" {
                    stack.push((item_indent, key));
                } else {
                    let mut path: Vec<String> = stack.iter().map(|(_, k)| k.clone()).collect();
                    path.push(key);
                    out.key_value(&path, value.trim_matches(['"', '\'']), line_number);
                }
            }
            _ if list_item => {
                let path: Vec<String> = stack.iter().map(|(_, k)| k.clone()).collect();
                out.key_value(&path, body.trim_matches(['"', '\'']), line_number);
            }
            _ => {}
        }
    }
    Ok(())
}

fn line_of(text: &str, needle: &str) -> u64 {
    text.find(needle)
        .map_or(1, |offset| text[..offset].matches('\n').count() as u64 + 1)
}

fn walk_json(
    out: &mut Out<'_, '_>,
    value: &serde_json::Value,
    path: &mut Vec<String>,
    depth: usize,
) {
    if depth > MAX_DEPTH {
        return;
    }
    match value {
        serde_json::Value::Object(map) => {
            for (key, child) in map {
                path.push(key.clone());
                walk_json(out, child, path, depth + 1);
                path.pop();
            }
        }
        serde_json::Value::Array(items) => {
            let strings: Vec<&str> = items.iter().filter_map(|item| item.as_str()).collect();
            if !strings.is_empty() {
                let line = line_of(out.text, strings[0]);
                out.key_value(path, &strings.join(","), line);
            }
            for item in items
                .iter()
                .filter(|item| item.is_object() || item.is_array())
            {
                walk_json(out, item, path, depth + 1);
            }
        }
        serde_json::Value::String(text) => {
            let line = line_of(out.text, text);
            out.key_value(path, text, line);
        }
        _ => {}
    }
}

fn walk_toml(out: &mut Out<'_, '_>, value: &toml::Value, path: &mut Vec<String>, depth: usize) {
    if depth > MAX_DEPTH {
        return;
    }
    match value {
        toml::Value::Table(table) => {
            for (key, child) in table {
                path.push(key.clone());
                walk_toml(out, child, path, depth + 1);
                path.pop();
            }
        }
        toml::Value::Array(items) => {
            let strings: Vec<&str> = items.iter().filter_map(|item| item.as_str()).collect();
            if !strings.is_empty() {
                let line = line_of(out.text, strings[0]);
                out.key_value(path, &strings.join(","), line);
            }
            for item in items.iter().filter(|item| item.is_table()) {
                walk_toml(out, item, path, depth + 1);
            }
        }
        toml::Value::String(text) => {
            let line = line_of(out.text, text);
            out.key_value(path, text, line);
        }
        _ => {}
    }
}

fn key_values(out: &mut Out<'_, '_>, deadline: &Deadline) -> Result<(), String> {
    let text = out.text;
    let mut section: Vec<String> = Vec::new();
    for (index, raw) in text.lines().enumerate().take(MAX_LINES) {
        if index % 4096 == 0 {
            deadline.check()?;
        }
        let line = raw.trim();
        if line.is_empty()
            || line.starts_with('#')
            || line.starts_with(';')
            || line.starts_with('!')
        {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            section = vec![line.trim_matches(['[', ']']).trim().to_owned()];
            continue;
        }
        let line = line
            .strip_prefix("export ")
            .or_else(|| line.strip_prefix("ENV "))
            .unwrap_or(line);
        let Some((key, value)) = line.split_once(['=', ':']) else {
            continue;
        };
        let mut path = section.clone();
        // `server.ssl.enabled-protocols` → [server, ssl, enabled-protocols]; the last part decides
        path.extend(
            key.trim()
                .split(['.', '_'])
                .filter(|part| !part.is_empty())
                .map(str::to_owned),
        );
        // keep the full key too, so `jdk.tls.disabledAlgorithms`-style names classify by suffix
        let full = key.trim().replace(['.', '-', '_'], "");
        if let Some(last) = path.last_mut()
            && classify_key(&last.to_ascii_lowercase().replace('-', "")).is_none()
            && classify_key(&full.to_ascii_lowercase()).is_some()
        {
            *last = full.clone();
        }
        // disabled-algorithm lists name what is *not* used
        if full.to_ascii_lowercase().contains("disabled") {
            continue;
        }
        out.key_value(
            &path,
            value.trim().trim_matches(['"', '\'']),
            index as u64 + 1,
        );
    }
    Ok(())
}

// ---- Terraform -------------------------------------------------------------------------------

/// A resource being read: its type, first line, and attributes with the line each was set on.
type OpenResource = (String, String, u64, BTreeMap<String, (String, u64)>);

/// Reads `resource "TYPE" "NAME" { ... }` blocks and their attributes (including one level of
/// nested blocks), then interprets each resource type's cryptographic attributes together, since
/// Azure spreads one key across `key_type`, `key_size` and `curve`.
fn terraform(out: &mut Out<'_, '_>, deadline: &Deadline) -> Result<(), String> {
    let text = out.text;
    let mut resource: Option<OpenResource> = None;
    let mut depth = 0i32;
    for (index, raw) in text.lines().enumerate().take(MAX_LINES) {
        if index % 4096 == 0 {
            deadline.check()?;
        }
        let line_number = index as u64 + 1;
        let line = strip_comment(raw).trim();
        if depth == 0 && line.starts_with("resource ") {
            let kind = line.split('"').nth(1).unwrap_or("").to_owned();
            let name = line.split('"').nth(3).unwrap_or("").to_owned();
            resource = Some((kind, name, line_number, BTreeMap::new()));
        }
        if let Some((_, _, _, attributes)) = resource.as_mut()
            && let Some((key, value)) = line.split_once('=')
            && !line.ends_with('{')
        {
            let value = value.trim().trim_matches('"').to_owned();
            attributes.insert(key.trim().to_owned(), (value, line_number));
        }
        depth += line.matches('{').count() as i32 - line.matches('}').count() as i32;
        if depth <= 0 {
            depth = 0;
            if let Some((kind, name, line, attributes)) = resource.take() {
                terraform_resource(out, &kind, &attributes);
                terraform_key(out, &kind, &name, line, &attributes);
            }
        }
    }
    if let Some((kind, name, line, attributes)) = resource.take() {
        terraform_resource(out, &kind, &attributes);
        terraform_key(out, &kind, &name, line, &attributes);
    }
    Ok(())
}

/// Cloud key resources are keys held by a key service: record each as a key with its custody,
/// its algorithm when the resource names one, and HSM backing when it asks for it.
fn terraform_key(
    out: &mut Out<'_, '_>,
    kind: &str,
    name: &str,
    line: u64,
    attributes: &BTreeMap<String, (String, u64)>,
) {
    use lattice_core::{Custody, CustodyKind, MaterialType};
    let get = |attribute: &str| attributes.get(attribute).map(|(value, _)| value.as_str());
    let (custody, service) = match kind {
        "aws_kms_key" => (
            if get("custom_key_store_id").is_some() {
                CustodyKind::CloudHsm
            } else {
                CustodyKind::CloudKms
            },
            "AWS KMS",
        ),
        "google_kms_crypto_key" => (
            if get("protection_level").is_some_and(|level| level.eq_ignore_ascii_case("HSM")) {
                CustodyKind::CloudHsm
            } else {
                CustodyKind::CloudKms
            },
            "Google Cloud KMS",
        ),
        "azurerm_key_vault_key" => (
            if get("key_type").is_some_and(|t| t.to_ascii_uppercase().ends_with("-HSM")) {
                CustodyKind::CloudHsm
            } else {
                CustodyKind::CloudKms
            },
            "Azure Key Vault",
        ),
        _ => return,
    };
    let algorithm = ["customer_master_key_spec", "key_spec", "algorithm"]
        .into_iter()
        .find_map(|attribute| {
            get(attribute).and_then(|v| names::parse_key_spec(v).or_else(|| names::resolve(v)))
        })
        .or_else(|| {
            let key_type = get("key_type")?.to_ascii_uppercase();
            if key_type.starts_with("RSA") {
                Some(AlgorithmRef::with_params(
                    "rsa",
                    lattice_core::Params {
                        key_bits: get("key_size").and_then(|bits| bits.parse().ok()),
                        ..Default::default()
                    },
                ))
            } else if key_type.starts_with("EC") {
                Some(AlgorithmRef::with_params(
                    "ecdsa",
                    lattice_core::Params {
                        curve: get("curve").and_then(names::resolve_curve),
                        ..Default::default()
                    },
                ))
            } else {
                None
            }
        })
        .map(|mut algorithm| {
            if let Some(curve) = algorithm.params.curve.take() {
                algorithm.params.curve = Some(Registry::active().canonical_curve(&curve));
            }
            algorithm
        });
    // what the service lets the key do: AWS key_usage, GCP purpose, Azure key_opts
    let usage = [get("key_usage"), get("purpose"), get("key_opts")]
        .into_iter()
        .flatten()
        .find_map(|value| {
            let value = value.to_ascii_lowercase();
            if value.contains("sign") {
                Some(lattice_core::KeyUsage::Sign)
            } else if value.contains("decrypt") || value.contains("unwrap") {
                Some(lattice_core::KeyUsage::Encrypt)
            } else {
                None
            }
        });
    // a resource that names no spec gets the service's default: a symmetric AES-256 key
    let algorithm = algorithm.or_else(|| match kind {
        "aws_kms_key" => names::parse_key_spec("SYMMETRIC_DEFAULT"),
        "google_kms_crypto_key"
            if get("purpose").is_none_or(|purpose| purpose == "ENCRYPT_DECRYPT") =>
        {
            names::parse_key_spec("GOOGLE_SYMMETRIC_ENCRYPTION")
        }
        _ => None,
    });
    let symmetric = algorithm.as_ref().is_some_and(|a| {
        matches!(
            Registry::active().get(&a.id).map(|spec| spec.primitive),
            Some(
                lattice_core::Primitive::BlockCipher
                    | lattice_core::Primitive::Ae
                    | lattice_core::Primitive::Mac
            )
        )
    });
    out.custody_material(
        if symmetric {
            MaterialType::SecretKey
        } else {
            MaterialType::PrivateKey
        },
        algorithm,
        Custody {
            kind: custody,
            detail: format!("{service} key {kind}.{name}"),
            usage,
        },
        &format!("terraform:{kind}.{name}"),
        &format!("config.custody.{kind}"),
        &format!("{kind}.{name}"),
        line,
    );
}

fn terraform_resource(
    out: &mut Out<'_, '_>,
    kind: &str,
    attributes: &BTreeMap<String, (String, u64)>,
) {
    let get = |name: &str| {
        attributes
            .get(name)
            .map(|(value, line)| (value.as_str(), *line))
    };
    let rule = format!("config.terraform.{kind}");
    // key specifications: AWS KMS, GCP KMS, ACM, tls provider
    for attribute in [
        "customer_master_key_spec",
        "key_spec",
        "algorithm",
        "key_algorithm",
    ] {
        if let Some((value, line)) = get(attribute)
            && let Some(algorithm) = names::parse_key_spec(value).or_else(|| names::resolve(value))
        {
            let mut algorithm = algorithm;
            if kind == "tls_private_key" {
                if let Some((bits, _)) = get("rsa_bits") {
                    algorithm.params.key_bits = bits.parse().ok();
                }
                if let Some((curve, _)) = get("ecdsa_curve") {
                    algorithm = AlgorithmRef::with_params(
                        "ecdsa",
                        lattice_core::Params {
                            curve: names::resolve_curve(curve),
                            ..Default::default()
                        },
                    );
                }
            }
            out.algorithm(algorithm, &rule, &format!("{kind}.{attribute}"), line);
        }
    }
    // Azure Key Vault: key_type + key_size / curve
    if let Some((key_type, line)) = get("key_type") {
        let normalized = key_type.to_ascii_uppercase();
        if normalized.starts_with("RSA") {
            let bits = get("key_size").and_then(|(bits, _)| bits.parse().ok());
            out.algorithm(
                AlgorithmRef::with_params(
                    "rsa",
                    lattice_core::Params {
                        key_bits: bits,
                        ..Default::default()
                    },
                ),
                &rule,
                &format!("{kind}.key_type"),
                line,
            );
        } else if normalized.starts_with("EC") {
            let curve = get("curve").and_then(|(curve, _)| names::resolve_curve(curve));
            out.algorithm(
                AlgorithmRef::with_params(
                    "ecdsa",
                    lattice_core::Params {
                        curve,
                        ..Default::default()
                    },
                ),
                &rule,
                &format!("{kind}.key_type"),
                line,
            );
        }
    }
    // managed TLS policies and minimum versions
    for attribute in [
        "ssl_policy",
        "security_policy",
        "minimum_protocol_version",
        "min_tls_version",
        "minimum_tls_version",
        "tls_version",
    ] {
        if let Some((value, line)) = get(attribute) {
            if let Some((version, post_quantum)) = names::parse_tls_policy(value) {
                out.push(
                    Finding::Protocol(ProtocolFinding {
                        protocol: ProtocolKind::Tls,
                        version: Some(version),
                        cipher_suites: Vec::new(),
                        groups: Vec::new(),
                    }),
                    &rule,
                    &format!("{kind}.{attribute}"),
                    line,
                );
                if post_quantum {
                    out.algorithm(
                        AlgorithmRef::new("x25519-mlkem768"),
                        &rule,
                        &format!("{kind}.{attribute}"),
                        line,
                    );
                }
            } else {
                out.versions(
                    ProtocolKind::Tls,
                    &[value.to_owned()],
                    &rule,
                    &format!("{kind}.{attribute}"),
                    line,
                );
            }
        }
    }
    if matches!(kind, "aws_lb_listener" | "aws_alb_listener")
        && get("protocol").is_some_and(|(p, _)| matches!(p, "HTTPS" | "TLS"))
    {
        let line = get("protocol").map_or(1, |(_, line)| line);
        out.listener(
            &format!("{kind} {} listener", get("protocol").map_or("", |(p, _)| p)),
            line,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn run(path: &str, text: &str) -> Findings {
        let collector = ConfigCollector::new().unwrap();
        assert!(
            collector.accepts(path, text.as_bytes()),
            "should accept {path}"
        );
        let artifact = Artifact {
            path,
            component: ".",
            bytes: text.as_bytes(),
        };
        let mut findings = Findings::default();
        collector
            .collect(
                &artifact,
                &Deadline::after(Duration::from_secs(5)),
                &mut findings,
            )
            .unwrap();
        findings
    }

    fn algorithm_ids(findings: &Findings) -> Vec<String> {
        let mut ids: Vec<String> = findings
            .observations
            .iter()
            .filter_map(|o| match &o.finding {
                Finding::Algorithm(f) => Some(f.algorithm.id.clone()),
                _ => None,
            })
            .collect();
        ids.sort();
        ids.dedup();
        ids
    }

    fn versions(findings: &Findings) -> Vec<String> {
        findings
            .observations
            .iter()
            .filter_map(|o| match &o.finding {
                Finding::Protocol(p) => p.version.clone(),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn nginx_protocols_ciphers_groups_and_listener() {
        let findings = run(
            "deploy/nginx.conf",
            "server {\n  listen 443 ssl;\n  ssl_protocols TLSv1 TLSv1.2;\n  ssl_ciphers 'ECDHE-RSA-AES128-GCM-SHA256:DES-CBC3-SHA:HIGH:!aNULL';\n  ssl_ecdh_curve X25519MLKEM768:secp384r1;\n}\n",
        );
        assert_eq!(
            versions(&findings),
            vec!["1.0".to_owned(), "1.2".to_owned()]
        );
        let ids = algorithm_ids(&findings);
        for expected in ["3des", "aes", "ecdh", "rsa", "x25519-mlkem768"] {
            assert!(
                ids.contains(&expected.to_owned()),
                "missing {expected} in {ids:?}"
            );
        }
        let listener = findings.functions.iter().find(|f| {
            f.entry
                .as_ref()
                .is_some_and(|e| e.kind == EntryKind::Listener)
        });
        assert!(listener.is_some(), "listen 443 ssl is a TLS listener");
        assert!(
            findings
                .observations
                .iter()
                .all(|o| o.surface == Surface::Config)
        );
    }

    #[test]
    fn apache_removals_are_not_selections() {
        let findings = run(
            "etc/apache2/ssl.conf",
            "SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1 +TLSv1.3\n",
        );
        assert_eq!(versions(&findings), vec!["1.3".to_owned()]);
    }

    #[test]
    fn sshd_algorithm_lists() {
        let findings = run(
            "etc/ssh/sshd_config",
            "KexAlgorithms mlkem768x25519-sha256,diffie-hellman-group1-sha1\nCiphers aes256-gcm@openssh.com,3des-cbc\nMACs hmac-sha1\nHostKeyAlgorithms ssh-rsa\n",
        );
        let ids = algorithm_ids(&findings);
        for expected in ["3des", "aes", "dh", "hmac", "rsa", "x25519-mlkem768"] {
            assert!(
                ids.contains(&expected.to_owned()),
                "missing {expected} in {ids:?}"
            );
        }
        assert!(findings.observations.iter().any(
            |o| matches!(&o.finding, Finding::Protocol(p) if p.protocol == ProtocolKind::Ssh)
        ));
    }

    #[test]
    fn yaml_only_interprets_crypto_keys_with_valid_values() {
        let findings = run(
            "config/application.yaml",
            "security:\n  keyAlgorithm: RSA\n  jwtAlgorithm: RS256\n  loadBalancerAlgorithm: round-robin\n  description: uses RSA internally\ntls:\n  minimumVersion: TLSv1.2\n  groups:\n    - X25519\n    - ML-KEM-768\n  cipherSuites:\n    - TLS_AES_256_GCM_SHA384\n",
        );
        let ids = algorithm_ids(&findings);
        assert!(ids.contains(&"rsa".to_owned()));
        assert!(ids.contains(&"x25519".to_owned()));
        assert!(ids.contains(&"ml-kem".to_owned()));
        assert!(
            ids.contains(&"aes".to_owned()),
            "TLS 1.3 suite decoded: {ids:?}"
        );
        assert!(ids.contains(&"sha-384".to_owned()));
        assert_eq!(versions(&findings), vec!["1.2".to_owned()]);
        // `description: uses RSA internally` and `round-robin` are not settings
        assert!(
            findings
                .observations
                .iter()
                .all(|o| !o.evidence.matched_token.contains("description"))
        );
        let jwt = findings
            .observations
            .iter()
            .find(|o| o.evidence.matched_token == "security.jwtAlgorithm")
            .unwrap();
        let Finding::Algorithm(finding) = &jwt.finding else {
            panic!()
        };
        assert_eq!(finding.algorithm.params.digest.as_deref(), Some("sha-256"));
    }

    #[test]
    fn spring_properties_and_disabled_lists() {
        let findings = run(
            "src/main/resources/application.properties",
            "server.ssl.enabled-protocols=TLSv1.1,TLSv1.2\nserver.ssl.ciphers=TLS_RSA_WITH_AES_128_CBC_SHA\njdk.tls.disabledAlgorithms=SSLv3, RC4, MD5\n",
        );
        assert_eq!(
            versions(&findings),
            vec!["1.1".to_owned(), "1.2".to_owned()]
        );
        let ids = algorithm_ids(&findings);
        assert!(
            !ids.contains(&"rc4".to_owned()),
            "a disabled list is not a selection"
        );
        assert!(ids.contains(&"rsa".to_owned()));
    }

    #[test]
    fn terraform_kms_acm_and_load_balancer_policies() {
        let findings = run(
            "infra/main.tf",
            r#"
resource "aws_kms_key" "signing" {
  customer_master_key_spec = "RSA_2048"
  key_usage                = "SIGN_VERIFY"
}
resource "aws_kms_key" "pq" {
  customer_master_key_spec = "ML_DSA_65"
}
resource "azurerm_key_vault_key" "k" {
  key_type = "EC"
  curve    = "P-384"
}
resource "aws_lb_listener" "https" {
  protocol   = "HTTPS"
  ssl_policy = "ELBSecurityPolicy-TLS13-1-2-PQ-2025-09"
}
resource "tls_private_key" "legacy" {
  algorithm = "RSA"
  rsa_bits  = 1024
}
"#,
        );
        assert!(findings.observations.iter().all(
            |o| o.surface == Surface::Cloud && o.evidence.kind == EvidenceKind::Infrastructure
        ));
        let ids = algorithm_ids(&findings);
        for expected in ["ecdsa", "ml-dsa", "rsa", "x25519-mlkem768"] {
            assert!(
                ids.contains(&expected.to_owned()),
                "missing {expected} in {ids:?}"
            );
        }
        assert!(findings.observations.iter().any(|o| matches!(&o.finding, Finding::Algorithm(f) if f.algorithm.id == "rsa" && f.algorithm.params.key_bits == Some(1024))));
        assert_eq!(versions(&findings), vec!["1.2".to_owned()]);
        assert!(findings.functions.iter().any(|f| {
            f.entry
                .as_ref()
                .is_some_and(|e| e.kind == EntryKind::Listener)
        }));
    }

    #[test]
    fn json_and_toml_structures() {
        let json = run(
            "conf/tls.json",
            r#"{"tls": {"cipherSuites": ["TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"], "minVersion": "TLSv1.2"}, "name": "RSA service"}"#,
        );
        assert!(algorithm_ids(&json).contains(&"ecdsa".to_owned()));
        assert_eq!(versions(&json), vec!["1.2".to_owned()]);
        let toml = run(
            "conf/app.toml",
            "[crypto]\nhash = \"sha1\"\nmode = \"fast\"\n",
        );
        assert_eq!(algorithm_ids(&toml), vec!["sha-1".to_owned()]);
    }

    #[test]
    fn lockfiles_are_ignored() {
        assert!(
            !ConfigCollector::new()
                .unwrap()
                .accepts("package-lock.json", b"{}")
        );
    }

    #[test]
    fn listeners_record_the_certificates_and_keys_they_serve() {
        let nginx = run(
            "gateway/nginx.conf",
            "server {\n  listen 443 ssl;\n  server_name pay.example.gov.in *.example.gov.in _;\n  ssl_certificate /etc/nginx/tls/server.crt;\n  ssl_certificate_key \"/etc/nginx/tls/legacy.key\";\n}\n",
        );
        let listener = nginx
            .functions
            .iter()
            .find(|f| f.name == "<tls-listener>")
            .unwrap();
        assert_eq!(
            listener.serves,
            vec!["legacy.key".to_owned(), "server.crt".to_owned()]
        );
        let haproxy = run(
            "haproxy.cfg",
            "frontend web\n  bind :443 ssl crt /etc/haproxy/site.pem alpn h2\n",
        );
        assert_eq!(haproxy.functions[0].serves, vec!["site.pem".to_owned()]);
    }

    fn held_keys(
        findings: &Findings,
    ) -> Vec<(String, lattice_core::Custody, lattice_core::MaterialType)> {
        findings
            .observations
            .iter()
            .filter_map(|o| match &o.finding {
                Finding::RelatedCryptoMaterial(m) => m
                    .custody
                    .clone()
                    .map(|c| (o.finding.display_name(), c, m.material_type)),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn cloud_keys_record_custody_usage_and_hsm_backing() {
        use lattice_core::{CustodyKind, KeyUsage};
        let findings = run(
            "infra/keys.tf",
            r#"resource "aws_kms_key" "signing" {
  customer_master_key_spec = "RSA_3072"
  key_usage                = "SIGN_VERIFY"
  custom_key_store_id      = "cks-1234"
}

resource "google_kms_crypto_key" "wrap" {
  purpose = "ASYMMETRIC_DECRYPT"
  version_template {
    algorithm        = "RSA_DECRYPT_OAEP_2048_SHA256"
    protection_level = "HSM"
  }
}

resource "azurerm_key_vault_key" "token" {
  key_type = "EC"
  curve    = "P-256"
  key_opts = ["sign", "verify"]
}

resource "aws_kms_key" "data" {
  description = "default symmetric key"
}
"#,
        );
        let held = held_keys(&findings);
        let summary: Vec<(
            &str,
            CustodyKind,
            Option<KeyUsage>,
            lattice_core::MaterialType,
        )> = held
            .iter()
            .map(|(name, c, t)| (name.as_str(), c.kind, c.usage, *t))
            .collect();
        assert_eq!(
            summary,
            [
                (
                    "RSA-3072 private-key",
                    CustodyKind::CloudHsm,
                    Some(KeyUsage::Sign),
                    lattice_core::MaterialType::PrivateKey
                ),
                (
                    "RSA-2048 (OAEP, SHA-256) private-key",
                    CustodyKind::CloudHsm,
                    Some(KeyUsage::Encrypt),
                    lattice_core::MaterialType::PrivateKey
                ),
                (
                    "ECDSA-P-256 private-key",
                    CustodyKind::CloudKms,
                    Some(KeyUsage::Sign),
                    lattice_core::MaterialType::PrivateKey
                ),
                (
                    "AES-256-GCM secret-key",
                    CustodyKind::CloudKms,
                    None,
                    lattice_core::MaterialType::SecretKey
                ),
            ],
            "{held:#?}"
        );
        assert!(held[0].1.detail.contains("aws_kms_key.signing"));
    }

    #[test]
    fn configuration_references_to_hardware_keys_are_inventoried() {
        let findings = run(
            "gateway/nginx.conf",
            "server {\n    listen 443 ssl;\n    ssl_certificate /etc/nginx/tls.crt;\n    ssl_certificate_key \"engine:pkcs11:pkcs11:token=edge;object=tls-key;type=private?pin-value=0000\";\n}\n",
        );
        let held = held_keys(&findings);
        assert_eq!(held.len(), 1, "{held:#?}");
        assert_eq!(held[0].1.kind, lattice_core::CustodyKind::Pkcs11Token);
        let observation = findings
            .observations
            .iter()
            .find(|o| matches!(&o.finding, Finding::RelatedCryptoMaterial(_)))
            .unwrap();
        assert!(!observation.evidence.matched_token.contains("pin"));
        assert!(
            run("etc/crypttab", "root UUID=1 none tpm2-device=auto\n")
                .observations
                .iter()
                .any(|o| o.evidence.rule_id == "config.custody.crypttab-tpm2")
        );
    }
}
