//! Offline, read-only collectors for cryptographic artifacts.

use lattice_core::{report_path, Algorithm, Evidence, EvidenceKind, Location, Observation, Surface};
use regex::Regex;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::panic::{catch_unwind, AssertUnwindSafe};
use thiserror::Error;
use tracing::{debug, warn};
use tree_sitter::{Parser, Tree};
use walkdir::{DirEntry, WalkDir};

const EMBEDDED_RULES: &str = include_str!("../../../rules/crypto-rules.yaml");
const DEFAULT_MAX_FILE_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Debug, Error)]
pub enum CollectorError {
    #[error("scan target does not exist: {0}")]
    TargetNotFound(PathBuf),
    #[error("scan target is neither a regular file nor a directory: {0}")]
    InvalidTarget(PathBuf),
    #[error("embedded rule database is invalid: {0}")]
    InvalidRules(String),
}

#[derive(Debug, Clone)]
pub struct ScanOptions {
    pub max_file_bytes: u64,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self { max_file_bytes: DEFAULT_MAX_FILE_BYTES }
    }
}

#[derive(Debug, Clone)]
pub struct CollectionFailure {
    pub path: String,
    pub reason: String,
}

#[derive(Debug, Default)]
pub struct CollectionResult {
    pub observations: Vec<Observation>,
    pub failures: Vec<CollectionFailure>,
    pub files_considered: u64,
    pub files_scanned: u64,
}

pub trait Collector {
    fn name(&self) -> &'static str;
    fn collect(&self, target: &Path, options: &ScanOptions) -> Result<CollectionResult, CollectorError>;
}

#[derive(Debug)]
pub struct SourceCollector {
    rule_version: String,
    rules: Vec<CompiledRule>,
}

#[derive(Debug, Deserialize)]
struct RuleDatabase {
    version: String,
    rules: Vec<RuleDefinition>,
}

#[derive(Debug, Deserialize)]
struct RuleDefinition {
    id: String,
    algorithm: String,
    primitive: String,
    pattern: String,
    #[serde(default)]
    languages: Vec<String>,
    key_size_capture: Option<usize>,
}

#[derive(Debug)]
struct CompiledRule {
    definition: RuleDefinition,
    regex: Regex,
}

impl SourceCollector {
    pub fn from_embedded_rules() -> Result<Self, CollectorError> {
        Self::from_yaml(EMBEDDED_RULES)
    }

    pub fn from_yaml(yaml: &str) -> Result<Self, CollectorError> {
        let database: RuleDatabase =
            serde_yaml::from_str(yaml).map_err(|error| CollectorError::InvalidRules(error.to_string()))?;
        let rules = database
            .rules
            .into_iter()
            .map(|definition| {
                let regex = Regex::new(&definition.pattern)
                    .map_err(|error| CollectorError::InvalidRules(format!("{}: {error}", definition.id)))?;
                Ok(CompiledRule { definition, regex })
            })
            .collect::<Result<Vec<_>, CollectorError>>()?;
        Ok(Self { rule_version: database.version, rules })
    }

    fn scan_file(&self, root: &Path, path: &Path, language: &str) -> Result<Vec<Observation>, String> {
        let bytes = fs::read(path).map_err(|error| error.to_string())?;
        let source = std::str::from_utf8(&bytes).map_err(|_| "source is not valid UTF-8".to_owned())?;
        let tree = parse_source(language, source)?;
        let safe_path = report_path(root, path);
        let mut observations = Vec::new();
        let mut line_start_byte = 0;

        for (line_index, line_with_ending) in source.split_inclusive('\n').enumerate() {
            let line = line_with_ending.trim_end_matches(['\r', '\n']);
            for rule in self.rules.iter().filter(|rule| {
                rule.definition.languages.is_empty()
                    || rule.definition.languages.iter().any(|item| item == language)
            }) {
                for captures in rule.regex.captures_iter(line) {
                    let Some(matched) = captures.get(0) else { continue };
                    let start_byte = line_start_byte + matched.start();
                    let end_byte = line_start_byte + matched.end();
                    let Some(evidence_kind) = ast_evidence_kind(&tree, start_byte, end_byte) else {
                        continue;
                    };
                    let key_size_bits = rule
                        .definition
                        .key_size_capture
                        .and_then(|index| captures.get(index))
                        .and_then(|value| value.as_str().parse::<u32>().ok());
                    let token = matched.as_str().chars().take(128).collect::<String>();
                    let lower_token = token.to_ascii_lowercase();
                    let mode = ["gcm", "cbc", "ctr", "ccm"]
                        .into_iter()
                        .find(|candidate| lower_token.contains(candidate))
                        .map(str::to_ascii_uppercase);
                    let mut parameters = BTreeMap::new();
                    parameters.insert("language".into(), language.into());

                    observations.push(Observation {
                        surface: Surface::Source,
                        location: Location {
                            path: safe_path.clone(),
                            line: Some((line_index + 1) as u64),
                            column: Some((matched.start() + 1) as u64),
                            byte_offset: Some(start_byte as u64),
                        },
                        algorithm: Algorithm {
                            family: rule.definition.algorithm.clone(),
                            primitive: rule.definition.primitive.clone(),
                            key_size_bits,
                            mode,
                            curve: None,
                        },
                        parameters,
                        evidence: Evidence {
                            collector: self.name().into(),
                            rule_id: rule.definition.id.clone(),
                            rule_version: self.rule_version.clone(),
                            kind: evidence_kind,
                            matched_token: token,
                        },
                    });
                }
            }
            line_start_byte += line_with_ending.len();
        }
        Ok(observations)
    }
}

impl Collector for SourceCollector {
    fn name(&self) -> &'static str {
        "source"
    }

    fn collect(&self, target: &Path, options: &ScanOptions) -> Result<CollectionResult, CollectorError> {
        if !target.exists() {
            return Err(CollectorError::TargetNotFound(target.to_owned()));
        }
        if !target.is_file() && !target.is_dir() {
            return Err(CollectorError::InvalidTarget(target.to_owned()));
        }

        let root = if target.is_file() { target.parent().unwrap_or(Path::new(".")) } else { target };
        let mut paths = if target.is_file() {
            vec![target.to_owned()]
        } else {
            WalkDir::new(target)
                .follow_links(false)
                .into_iter()
                .filter_entry(should_visit)
                .filter_map(|entry| match entry {
                    Ok(entry) if entry.file_type().is_file() => Some(entry.into_path()),
                    Ok(_) => None,
                    Err(error) => {
                        warn!(%error, "unable to walk scan target entry");
                        None
                    }
                })
                .collect::<Vec<_>>()
        };
        paths.sort();

        let mut result = CollectionResult::default();
        for path in paths {
            result.files_considered += 1;
            let Some(language) = language_for(&path) else { continue };
            match fs::metadata(&path) {
                Ok(metadata) if metadata.len() > options.max_file_bytes => {
                    result.failures.push(CollectionFailure {
                        path: report_path(root, &path),
                        reason: format!("file exceeds {} byte safety limit", options.max_file_bytes),
                    });
                    continue;
                }
                Err(error) => {
                    result.failures.push(CollectionFailure {
                        path: report_path(root, &path),
                        reason: error.to_string(),
                    });
                    continue;
                }
                _ => {}
            }

            let scan = catch_unwind(AssertUnwindSafe(|| self.scan_file(root, &path, language)));
            match scan {
                Ok(Ok(mut observations)) => {
                    debug!(path = %path.display(), findings = observations.len(), "source file scanned");
                    result.files_scanned += 1;
                    result.observations.append(&mut observations);
                }
                Ok(Err(reason)) => result.failures.push(CollectionFailure {
                    path: report_path(root, &path),
                    reason,
                }),
                Err(_) => result.failures.push(CollectionFailure {
                    path: report_path(root, &path),
                    reason: "collector panicked while parsing; isolated from scan".into(),
                }),
            }
        }
        Ok(result)
    }
}

#[derive(Debug)]
pub struct ConfigCollector {
    rules: Vec<ConfigRule>,
}

#[derive(Debug)]
struct ConfigRule {
    id: &'static str,
    algorithm: &'static str,
    primitive: &'static str,
    regex: Regex,
    key_size_capture: Option<usize>,
    mode_capture: Option<usize>,
    curve: Option<&'static str>,
}

impl ConfigCollector {
    pub fn new() -> Result<Self, CollectorError> {
        let definitions = [
            ("config.rsa", "RSA", "public-key", r"(?i)\bRSA(?:[_-](1024|2048|3072|4096))?\b", Some(1), None, None),
            ("config.jwt-rsa", "RSA", "public-key", r"(?i)\bRS(?:256|384|512)\b", None, None, None),
            ("config.ecdh", "ECDH", "key-agreement", r"(?i)\bECDHE?\b", None, None, None),
            ("config.x25519", "ECDH", "key-agreement", r"(?i)\bX25519\b", None, None, Some("X25519")),
            ("config.ecdsa", "ECDSA", "signature", r"(?i)\b(?:ECDSA|ES(?:256|384|512))\b", None, None, None),
            ("config.aes", "AES", "block-cipher", r"(?i)\bAES[_/-]?(128|192|256)(?:[_/-]?(GCM|CBC|CTR|CCM))?\b", Some(1), Some(2), None),
            ("config.sha1", "SHA-1", "hash", r"(?i)\bSHA-?1\b", None, None, None),
            ("config.sha256", "SHA-256", "hash", r"(?i)\bSHA-?256\b", None, None, None),
            ("config.md5", "MD5", "hash", r"(?i)\bMD5\b", None, None, None),
            ("config.des", "DES", "block-cipher", r"(?i)\b(?:DES|3DES|TRIPLEDES)\b", None, None, None),
            ("config.rc4", "RC4", "stream-cipher", r"(?i)\bRC4\b", None, None, None),
            ("config.mlkem", "ML-KEM", "key-encapsulation", r"(?i)\b(?:ML[-_]?KEM|KYBER)[-_]?(512|768|1024)?\b", Some(1), None, None),
            ("config.mldsa", "ML-DSA", "signature", r"(?i)\b(?:ML[-_]?DSA|DILITHIUM)[-_]?(44|65|87|2|3|5)?\b", Some(1), None, None),
        ];
        let rules = definitions
            .into_iter()
            .map(|(id, algorithm, primitive, pattern, key_size_capture, mode_capture, curve)| {
                Regex::new(pattern)
                    .map(|regex| ConfigRule {
                        id,
                        algorithm,
                        primitive,
                        regex,
                        key_size_capture,
                        mode_capture,
                        curve,
                    })
                    .map_err(|error| CollectorError::InvalidRules(format!("{id}: {error}")))
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self { rules })
    }

    fn scan_file(&self, root: &Path, path: &Path, source: &str) -> Vec<Observation> {
        let safe_path = report_path(root, path);
        let format = path
            .extension()
            .and_then(|extension| extension.to_str())
            .unwrap_or("config")
            .to_ascii_lowercase();
        let mut observations = Vec::new();
        let mut line_start_byte = 0;
        for (line_index, line_with_ending) in source.split_inclusive('\n').enumerate() {
            let line = line_with_ending.trim_end_matches(['\r', '\n']);
            let active_line = strip_config_comment(line);
            for rule in &self.rules {
                for captures in rule.regex.captures_iter(active_line) {
                    let Some(matched) = captures.get(0) else { continue };
                    let key_size_bits = rule
                        .key_size_capture
                        .and_then(|index| captures.get(index))
                        .and_then(|value| value.as_str().parse::<u32>().ok());
                    let mode = rule
                        .mode_capture
                        .and_then(|index| captures.get(index))
                        .map(|value| value.as_str().to_ascii_uppercase());
                    let mut parameters = BTreeMap::new();
                    parameters.insert("configFormat".into(), format.clone());
                    observations.push(Observation {
                        surface: Surface::Config,
                        location: Location {
                            path: safe_path.clone(),
                            line: Some((line_index + 1) as u64),
                            column: Some((matched.start() + 1) as u64),
                            byte_offset: Some((line_start_byte + matched.start()) as u64),
                        },
                        algorithm: Algorithm {
                            family: rule.algorithm.into(),
                            primitive: rule.primitive.into(),
                            key_size_bits,
                            mode,
                            curve: rule.curve.map(str::to_owned),
                        },
                        parameters,
                        evidence: Evidence {
                            collector: self.name().into(),
                            rule_id: rule.id.into(),
                            rule_version: "1.0.0".into(),
                            kind: EvidenceKind::Configuration,
                            matched_token: matched.as_str().chars().take(128).collect(),
                        },
                    });
                }
            }
            line_start_byte += line_with_ending.len();
        }
        observations
    }
}

impl Collector for ConfigCollector {
    fn name(&self) -> &'static str {
        "config"
    }

    fn collect(&self, target: &Path, options: &ScanOptions) -> Result<CollectionResult, CollectorError> {
        validate_target(target)?;
        let root = if target.is_file() { target.parent().unwrap_or(Path::new(".")) } else { target };
        let mut paths = collect_file_paths(target);
        paths.sort();
        let mut result = CollectionResult::default();
        for path in paths {
            result.files_considered += 1;
            if !is_config_file(&path) {
                continue;
            }
            let metadata = match fs::metadata(&path) {
                Ok(metadata) => metadata,
                Err(error) => {
                    result.failures.push(CollectionFailure {
                        path: report_path(root, &path),
                        reason: error.to_string(),
                    });
                    continue;
                }
            };
            if metadata.len() > options.max_file_bytes {
                result.failures.push(CollectionFailure {
                    path: report_path(root, &path),
                    reason: format!("file exceeds {} byte safety limit", options.max_file_bytes),
                });
                continue;
            }
            let bytes = match fs::read(&path) {
                Ok(bytes) => bytes,
                Err(error) => {
                    result.failures.push(CollectionFailure {
                        path: report_path(root, &path),
                        reason: error.to_string(),
                    });
                    continue;
                }
            };
            let source = match std::str::from_utf8(&bytes) {
                Ok(source) => source,
                Err(_) => {
                    result.failures.push(CollectionFailure {
                        path: report_path(root, &path),
                        reason: "configuration is not valid UTF-8".into(),
                    });
                    continue;
                }
            };
            let scan = catch_unwind(AssertUnwindSafe(|| self.scan_file(root, &path, source)));
            match scan {
                Ok(mut observations) => {
                    debug!(path = %path.display(), findings = observations.len(), "configuration file scanned");
                    result.files_scanned += 1;
                    result.observations.append(&mut observations);
                }
                Err(_) => result.failures.push(CollectionFailure {
                    path: report_path(root, &path),
                    reason: "collector panicked while parsing; isolated from scan".into(),
                }),
            }
        }
        Ok(result)
    }
}

#[derive(Debug, Default)]
pub struct BinaryCollector;

#[derive(Clone, Copy)]
struct BinarySignature {
    symbol: &'static [u8],
    algorithm: &'static str,
    primitive: &'static str,
    key_size_bits: Option<u32>,
    mode: Option<&'static str>,
}

const BINARY_SIGNATURES: &[BinarySignature] = &[
    BinarySignature { symbol: b"RSA_new", algorithm: "RSA", primitive: "public-key", key_size_bits: None, mode: None },
    BinarySignature { symbol: b"RSA_generate_key_ex", algorithm: "RSA", primitive: "public-key", key_size_bits: None, mode: None },
    BinarySignature { symbol: b"ECDH_compute_key", algorithm: "ECDH", primitive: "key-agreement", key_size_bits: None, mode: None },
    BinarySignature { symbol: b"ECDSA_sign", algorithm: "ECDSA", primitive: "signature", key_size_bits: None, mode: None },
    BinarySignature { symbol: b"EVP_aes_128_gcm", algorithm: "AES", primitive: "block-cipher", key_size_bits: Some(128), mode: Some("GCM") },
    BinarySignature { symbol: b"EVP_aes_256_gcm", algorithm: "AES", primitive: "block-cipher", key_size_bits: Some(256), mode: Some("GCM") },
    BinarySignature { symbol: b"SHA1_Init", algorithm: "SHA-1", primitive: "hash", key_size_bits: None, mode: None },
    BinarySignature { symbol: b"SHA256_Init", algorithm: "SHA-256", primitive: "hash", key_size_bits: None, mode: None },
    BinarySignature { symbol: b"MD5_Init", algorithm: "MD5", primitive: "hash", key_size_bits: None, mode: None },
    BinarySignature { symbol: b"ML_KEM_768", algorithm: "ML-KEM", primitive: "key-encapsulation", key_size_bits: Some(768), mode: None },
    BinarySignature { symbol: b"ML_DSA_65", algorithm: "ML-DSA", primitive: "signature", key_size_bits: Some(65), mode: None },
];

impl BinaryCollector {
    fn scan_file(&self, root: &Path, path: &Path, bytes: &[u8]) -> Vec<Observation> {
        let Some(format) = binary_format(bytes) else { return Vec::new() };
        let safe_path = report_path(root, path);
        let mut observations = Vec::new();
        for signature in BINARY_SIGNATURES {
            for offset in find_all(bytes, signature.symbol) {
                let mut parameters = BTreeMap::new();
                parameters.insert("binaryFormat".into(), format.into());
                observations.push(Observation {
                    surface: Surface::Binary,
                    location: Location {
                        path: safe_path.clone(),
                        line: None,
                        column: None,
                        byte_offset: Some(offset as u64),
                    },
                    algorithm: Algorithm {
                        family: signature.algorithm.into(),
                        primitive: signature.primitive.into(),
                        key_size_bits: signature.key_size_bits,
                        mode: signature.mode.map(str::to_owned),
                        curve: None,
                    },
                    parameters,
                    evidence: Evidence {
                        collector: self.name().into(),
                        rule_id: format!("binary.symbol.{}", signature.algorithm.to_ascii_lowercase()),
                        rule_version: "1.0.0".into(),
                        kind: EvidenceKind::Symbol,
                        matched_token: String::from_utf8_lossy(signature.symbol).into_owned(),
                    },
                });
            }
        }
        observations
    }
}

impl Collector for BinaryCollector {
    fn name(&self) -> &'static str {
        "binary"
    }

    fn collect(&self, target: &Path, options: &ScanOptions) -> Result<CollectionResult, CollectorError> {
        if !target.exists() {
            return Err(CollectorError::TargetNotFound(target.to_owned()));
        }
        if !target.is_file() && !target.is_dir() {
            return Err(CollectorError::InvalidTarget(target.to_owned()));
        }

        let root = if target.is_file() { target.parent().unwrap_or(Path::new(".")) } else { target };
        let mut paths = collect_file_paths(target);
        paths.sort();
        let mut result = CollectionResult::default();

        for path in paths {
            result.files_considered += 1;
            let metadata = match fs::metadata(&path) {
                Ok(metadata) => metadata,
                Err(error) => {
                    result.failures.push(CollectionFailure {
                        path: report_path(root, &path),
                        reason: error.to_string(),
                    });
                    continue;
                }
            };
            if metadata.len() > options.max_file_bytes {
                continue;
            }
            let bytes = match fs::read(&path) {
                Ok(bytes) => bytes,
                Err(error) => {
                    result.failures.push(CollectionFailure {
                        path: report_path(root, &path),
                        reason: error.to_string(),
                    });
                    continue;
                }
            };
            if binary_format(&bytes).is_none() {
                continue;
            }
            let scan = catch_unwind(AssertUnwindSafe(|| self.scan_file(root, &path, &bytes)));
            match scan {
                Ok(mut observations) => {
                    debug!(path = %path.display(), findings = observations.len(), "binary file scanned");
                    result.files_scanned += 1;
                    result.observations.append(&mut observations);
                }
                Err(_) => result.failures.push(CollectionFailure {
                    path: report_path(root, &path),
                    reason: "collector panicked while parsing; isolated from scan".into(),
                }),
            }
        }
        Ok(result)
    }
}

fn strip_config_comment(line: &str) -> &str {
    let bytes = line.as_bytes();
    let mut single_quoted = false;
    let mut double_quoted = false;
    let mut escaped = false;
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if escaped {
            escaped = false;
            index += 1;
            continue;
        }
        if byte == b'\\' && double_quoted {
            escaped = true;
            index += 1;
            continue;
        }
        if byte == b'\'' && !double_quoted {
            single_quoted = !single_quoted;
        } else if byte == b'"' && !single_quoted {
            double_quoted = !double_quoted;
        } else if !single_quoted && !double_quoted {
            if byte == b'#' || byte == b';' || (byte == b'/' && bytes.get(index + 1) == Some(&b'/')) {
                return &line[..index];
            }
        }
        index += 1;
    }
    line
}

fn validate_target(target: &Path) -> Result<(), CollectorError> {
    if !target.exists() {
        Err(CollectorError::TargetNotFound(target.to_owned()))
    } else if !target.is_file() && !target.is_dir() {
        Err(CollectorError::InvalidTarget(target.to_owned()))
    } else {
        Ok(())
    }
}

fn is_config_file(path: &Path) -> bool {
    let name = path.file_name().and_then(|name| name.to_str()).unwrap_or_default();
    if matches!(name, "Dockerfile" | "Containerfile") || name.starts_with(".env") {
        return true;
    }
    matches!(
        path.extension()
            .and_then(|extension| extension.to_str())
            .map(str::to_ascii_lowercase)
            .as_deref(),
        Some("yaml" | "yml" | "json" | "toml" | "conf" | "cnf" | "ini" | "properties" | "config" | "env")
    )
}

fn collect_file_paths(target: &Path) -> Vec<PathBuf> {
    if target.is_file() {
        return vec![target.to_owned()];
    }
    WalkDir::new(target)
        .follow_links(false)
        .into_iter()
        .filter_entry(should_visit)
        .filter_map(|entry| match entry {
            Ok(entry) if entry.file_type().is_file() => Some(entry.into_path()),
            Ok(_) => None,
            Err(error) => {
                warn!(%error, "unable to walk scan target entry");
                None
            }
        })
        .collect()
}

fn binary_format(bytes: &[u8]) -> Option<&'static str> {
    if bytes.starts_with(b"\x7fELF") {
        Some("ELF")
    } else if bytes.starts_with(b"MZ") {
        Some("PE")
    } else if bytes.starts_with(&[0xfe, 0xed, 0xfa, 0xce])
        || bytes.starts_with(&[0xfe, 0xed, 0xfa, 0xcf])
        || bytes.starts_with(&[0xce, 0xfa, 0xed, 0xfe])
        || bytes.starts_with(&[0xcf, 0xfa, 0xed, 0xfe])
        || bytes.starts_with(&[0xca, 0xfe, 0xba, 0xbe])
    {
        Some("Mach-O")
    } else {
        None
    }
}

fn find_all(haystack: &[u8], needle: &[u8]) -> Vec<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return Vec::new();
    }
    haystack
        .windows(needle.len())
        .enumerate()
        .filter_map(|(offset, window)| (window == needle).then_some(offset))
        .collect()
}

fn parse_source(language: &str, source: &str) -> Result<Tree, String> {
    let grammar = match language {
        "c" => tree_sitter_c::LANGUAGE.into(),
        "python" => tree_sitter_python::LANGUAGE.into(),
        "java" => tree_sitter_java::LANGUAGE.into(),
        _ => return Err(format!("unsupported source language: {language}")),
    };
    let mut parser = Parser::new();
    parser
        .set_language(&grammar)
        .map_err(|error| format!("failed to initialize {language} parser: {error}"))?;
    parser
        .parse(source, None)
        .ok_or_else(|| format!("{language} parser exceeded its resource limit"))
}

/// Returns `None` for matches inside comments. Syntax-error nodes are retained as lower-confidence
/// heuristic evidence so one malformed region does not suppress all useful results from a file.
fn ast_evidence_kind(tree: &Tree, start_byte: usize, end_byte: usize) -> Option<EvidenceKind> {
    let mut node = tree
        .root_node()
        .descendant_for_byte_range(start_byte, end_byte)?;
    let mut syntax_error = false;
    loop {
        if node.kind() == "comment" {
            return None;
        }
        syntax_error |= node.is_error() || node.is_missing();
        let Some(parent) = node.parent() else { break };
        node = parent;
    }
    Some(if syntax_error { EvidenceKind::Heuristic } else { EvidenceKind::Ast })
}

fn should_visit(entry: &DirEntry) -> bool {
    if entry.depth() == 0 {
        return true;
    }
    let name = entry.file_name().to_string_lossy();
    !matches!(name.as_ref(), ".git" | "target" | "node_modules" | ".lattice" | "vendor")
}

fn language_for(path: &Path) -> Option<&'static str> {
    match path.extension()?.to_str()?.to_ascii_lowercase().as_str() {
        "c" | "h" | "cc" | "cpp" | "cxx" | "hpp" => Some("c"),
        "py" | "pyi" => Some("python"),
        "java" => Some("java"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn embedded_rules_detect_python_crypto_without_storing_source_lines() {
        let suffix = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let directory = std::env::temp_dir().join(format!("lattice-collector-{suffix}"));
        fs::create_dir_all(&directory).unwrap();
        fs::write(
            directory.join("sample.py"),
            "import hashlib\ndigest = hashlib.sha1(secret_value).digest()\n",
        )
        .unwrap();

        let collector = SourceCollector::from_embedded_rules().unwrap();
        let result = collector.collect(&directory, &ScanOptions::default()).unwrap();
        fs::remove_dir_all(&directory).unwrap();

        assert_eq!(result.observations.len(), 1);
        assert_eq!(result.observations[0].algorithm.family, "SHA-1");
        assert_eq!(result.observations[0].evidence.matched_token, "hashlib.sha1");
        assert_eq!(result.observations[0].evidence.kind, EvidenceKind::Ast);
        assert!(!result.observations[0].evidence.matched_token.contains("secret_value"));
    }

    #[test]
    fn ast_validation_rejects_crypto_names_in_comments() {
        let suffix = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let directory = std::env::temp_dir().join(format!("lattice-comments-{suffix}"));
        fs::create_dir_all(&directory).unwrap();
        fs::write(
            directory.join("sample.py"),
            "# hashlib.sha1 is forbidden\nvalue = hashlib.sha256(payload).digest()\n",
        )
        .unwrap();

        let collector = SourceCollector::from_embedded_rules().unwrap();
        let result = collector.collect(&directory, &ScanOptions::default()).unwrap();
        fs::remove_dir_all(&directory).unwrap();

        assert_eq!(result.observations.len(), 1);
        assert_eq!(result.observations[0].algorithm.family, "SHA-256");
        assert_eq!(result.observations[0].evidence.kind, EvidenceKind::Ast);
    }

    #[test]
    fn binary_symbols_include_format_and_byte_offset() {
        let suffix = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let directory = std::env::temp_dir().join(format!("lattice-binary-{suffix}"));
        fs::create_dir_all(&directory).unwrap();
        let mut bytes = b"\x7fELF\0fixture\0".to_vec();
        bytes.extend_from_slice(b"RSA_new\0SHA256_Init\0");
        fs::write(directory.join("sample.so"), bytes).unwrap();

        let result = BinaryCollector
            .collect(&directory, &ScanOptions::default())
            .unwrap();
        fs::remove_dir_all(&directory).unwrap();

        assert_eq!(result.files_scanned, 1);
        assert_eq!(result.observations.len(), 2);
        assert!(result.observations.iter().all(|item| item.surface == Surface::Binary));
        assert!(result.observations.iter().all(|item| item.location.byte_offset.is_some()));
        assert!(result
            .observations
            .iter()
            .all(|item| item.parameters.get("binaryFormat").map(String::as_str) == Some("ELF")));
    }

    #[test]
    fn configuration_findings_set_configured_liveness_without_retaining_values() {
        let suffix = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let directory = std::env::temp_dir().join(format!("lattice-config-{suffix}"));
        fs::create_dir_all(&directory).unwrap();
        fs::write(
            directory.join("application.yaml"),
            "# legacy: SHA1\nsecurity:\n  keyAlgorithm: RSA\n  jwtAlgorithm: RS256\n",
        )
        .unwrap();

        let collector = ConfigCollector::new().unwrap();
        let result = collector.collect(&directory, &ScanOptions::default()).unwrap();
        fs::remove_dir_all(&directory).unwrap();

        assert_eq!(result.observations.len(), 2);
        assert!(result.observations.iter().all(|item| item.algorithm.family == "RSA"));
        assert!(result
            .observations
            .iter()
            .all(|item| item.evidence.kind == EvidenceKind::Configuration));
        let assets = lattice_core::normalize(result.observations);
        assert_eq!(assets.len(), 1);
        assert_eq!(assets[0].liveness, lattice_core::Liveness::Configured);
    }

    #[test]
    fn java_crypto_calls_are_ast_validated() {
        let suffix = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let directory = std::env::temp_dir().join(format!("lattice-java-{suffix}"));
        fs::create_dir_all(&directory).unwrap();
        fs::write(
            directory.join("Example.java"),
            "class Example { void run() throws Exception { java.security.KeyPairGenerator.getInstance(\"RSA\"); } }\n",
        )
        .unwrap();

        let collector = SourceCollector::from_embedded_rules().unwrap();
        let result = collector.collect(&directory, &ScanOptions::default()).unwrap();
        fs::remove_dir_all(&directory).unwrap();

        assert_eq!(result.observations.len(), 1);
        assert_eq!(result.observations[0].algorithm.family, "RSA");
        assert_eq!(result.observations[0].evidence.kind, EvidenceKind::Ast);
    }
}
