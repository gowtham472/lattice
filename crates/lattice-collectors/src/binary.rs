//! Binary collector: cryptography in compiled executables and libraries.
//!
//! Four independent kinds of evidence, strongest first:
//! 1. **Symbols**: imported and exported names from the ELF/PE/Mach-O symbol tables, matched
//!    with the same C rules the source collector uses (a binary's symbols *are* C API names).
//! 2. **Algorithm OIDs**: DER-encoded object identifiers of known algorithms, generated from the
//!    knowledge base, found in the data sections (certificates, ASN.1 templates).
//! 3. **Constant tables**: S-boxes, initial hash values and NTT twiddle factors that an
//!    implementation of the algorithm cannot avoid carrying, which also finds cryptography in
//!    stripped or statically linked binaries.
//! 4. **Library identification**: version strings and linked sonames, with whether that version
//!    ships post-quantum algorithms.
//!
//! Parsing is bounded: goblin reads only the structures it is asked for, and every table walk is
//! capped so a crafted header cannot make the collector iterate unboundedly.

use crate::sandbox::Deadline;
use crate::source::lang::Language;
use crate::source::rules::{RuleKind, RuleSet};
use crate::{Artifact, Collector, Findings};
use aho_corasick::{AhoCorasick, MatchKind};
use lattice_core::{
    AlgorithmRef, Evidence, EvidenceKind, Finding, LibraryFact, Location, Observation, Params,
    Registry, Surface,
};
use regex::bytes::Regex;
use serde::Deserialize;
use std::collections::BTreeSet;
use std::sync::OnceLock;

const COLLECTOR: &str = "binary";
const RULE_VERSION: &str = "2026.09.1";
const EMBEDDED_LIBRARIES: &str = include_str!("../../../knowledge/libraries.toml");
const MAX_SYMBOLS: usize = 200_000;
/// A constant-table or OID signature is reported at most this many times per file.
const MAX_HITS_PER_SIGNATURE: usize = 4;

pub struct BinaryCollector {
    rules: Option<RuleSet>,
}

impl std::fmt::Debug for BinaryCollector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BinaryCollector").finish_non_exhaustive()
    }
}

impl Default for BinaryCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl BinaryCollector {
    pub fn new() -> Self {
        // The source rules are embedded and validated by the source collector's own tests; if
        // they failed to load here, symbol matching degrades but signatures still work.
        Self {
            rules: RuleSet::active().ok(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Elf,
    Pe,
    MachO,
}

impl Format {
    fn name(self) -> &'static str {
        match self {
            Self::Elf => "ELF",
            Self::Pe => "PE",
            Self::MachO => "Mach-O",
        }
    }
}

pub fn detect(head: &[u8]) -> Option<Format> {
    if head.starts_with(b"\x7fELF") {
        Some(Format::Elf)
    } else if head.starts_with(b"MZ") {
        Some(Format::Pe)
    } else if [
        [0xfe, 0xed, 0xfa, 0xce],
        [0xfe, 0xed, 0xfa, 0xcf],
        [0xce, 0xfa, 0xed, 0xfe],
        [0xcf, 0xfa, 0xed, 0xfe],
        [0xca, 0xfe, 0xba, 0xbe],
    ]
    .iter()
    .any(|magic| head.starts_with(magic))
    {
        // 0xcafebabe is also the Java class-file magic; a fat Mach-O has a small arch count.
        if head.starts_with(&[0xca, 0xfe, 0xba, 0xbe])
            && head
                .get(4..8)
                .is_some_and(|n| u32::from_be_bytes([n[0], n[1], n[2], n[3]]) > 32)
        {
            return None;
        }
        Some(Format::MachO)
    } else {
        None
    }
}

impl Collector for BinaryCollector {
    fn name(&self) -> &'static str {
        COLLECTOR
    }

    fn accepts(&self, _path: &str, head: &[u8]) -> bool {
        detect(head).is_some()
    }

    fn collect(
        &self,
        artifact: &Artifact<'_>,
        deadline: &Deadline,
        findings: &mut Findings,
    ) -> Result<(), String> {
        let format = detect(artifact.bytes).ok_or("not a native binary")?;
        let mut out = Output {
            artifact,
            format,
            findings,
            seen: BTreeSet::new(),
        };

        // A damaged header still leaves the data sections worth searching.
        let (symbols, libraries) = read_symbols(artifact.bytes).unwrap_or_default();
        deadline.check()?;
        if let Some(rules) = &self.rules {
            for symbol in symbols.iter().take(MAX_SYMBOLS) {
                for (rule, captures) in rules.for_call(Language::C, symbol) {
                    if rule.def.kind != RuleKind::Algorithm {
                        continue;
                    }
                    let algorithm = if let Some(id) = &rule.def.algorithm {
                        Some(AlgorithmRef::with_params(
                            id.clone(),
                            rule.def.params.clone(),
                        ))
                    } else if let Some(capture) = rule
                        .def
                        .from
                        .as_ref()
                        .and_then(|from| from.capture.as_ref())
                    {
                        captures
                            .get(capture)
                            .and_then(|text| lattice_core::names::resolve(text))
                            .map(|mut algorithm| {
                                algorithm.params.fill_from(&rule.def.params);
                                algorithm
                            })
                    } else {
                        None
                    };
                    if let Some(algorithm) = algorithm {
                        out.emit(
                            algorithm,
                            EvidenceKind::Symbol,
                            &format!("binary.symbol.{}", rule.def.id),
                            symbol,
                            None,
                        );
                    }
                }
            }
        }
        deadline.check()?;
        search_signatures(&mut out);
        deadline.check()?;
        identify_libraries(artifact, &libraries, out.findings);
        Ok(())
    }
}

struct Output<'a, 'f> {
    artifact: &'a Artifact<'a>,
    format: Format,
    findings: &'f mut Findings,
    seen: BTreeSet<(String, String)>,
}

impl Output<'_, '_> {
    fn emit(
        &mut self,
        algorithm: AlgorithmRef,
        kind: EvidenceKind,
        rule_id: &str,
        token: &str,
        offset: Option<usize>,
    ) {
        // one observation per (algorithm, rule) per file keeps huge binaries readable
        if !self
            .seen
            .insert((format!("{algorithm:?}"), rule_id.to_owned()))
        {
            return;
        }
        let location = match offset {
            Some(offset) => Location::at_offset(self.artifact.path, offset as u64),
            None => Location::file(self.artifact.path),
        };
        self.findings.observations.push(Observation {
            surface: Surface::Binary,
            component: self.artifact.component.to_owned(),
            location,
            finding: Finding::algorithm(algorithm),
            evidence: Evidence {
                collector: COLLECTOR.into(),
                rule_id: rule_id.to_owned(),
                rule_version: format!("{RULE_VERSION}/{}", self.format.name()),
                kind,
                matched_token: token.chars().take(96).collect(),
            },
            usage: None,
        });
    }
}

/// Imported, exported and defined function names, plus linked library names.
fn read_symbols(bytes: &[u8]) -> Result<(Vec<String>, Vec<String>), String> {
    use goblin::Object;
    let object = Object::parse(bytes).map_err(|error| format!("unparseable binary: {error}"))?;
    let mut names = BTreeSet::new();
    let mut libraries = Vec::new();
    match object {
        Object::Elf(elf) => {
            for symbol in elf.dynsyms.iter().chain(elf.syms.iter()).take(MAX_SYMBOLS) {
                let table = if !elf.dynsyms.is_empty() {
                    &elf.dynstrtab
                } else {
                    &elf.strtab
                };
                if let Some(name) = table
                    .get_at(symbol.st_name)
                    .or_else(|| elf.strtab.get_at(symbol.st_name))
                    && !name.is_empty()
                {
                    names.insert(strip_version(name).to_owned());
                }
            }
            libraries.extend(elf.libraries.iter().map(|library| (*library).to_owned()));
        }
        Object::PE(pe) => {
            for import in pe.imports.iter().take(MAX_SYMBOLS) {
                names.insert(import.name.to_string());
            }
            for export in pe.exports.iter().take(MAX_SYMBOLS) {
                if let Some(name) = export.name {
                    names.insert(name.to_owned());
                }
            }
            libraries.extend(pe.libraries.iter().map(|library| (*library).to_owned()));
        }
        Object::Mach(goblin::mach::Mach::Binary(macho)) => {
            if let Ok(imports) = macho.imports() {
                names.extend(
                    imports
                        .iter()
                        .take(MAX_SYMBOLS)
                        .map(|import| import.name.trim_start_matches('_').to_owned()),
                );
            }
            if let Ok(exports) = macho.exports() {
                names.extend(
                    exports
                        .iter()
                        .take(MAX_SYMBOLS)
                        .map(|export| export.name.trim_start_matches('_').to_owned()),
                );
            }
            libraries.extend(macho.libs.iter().map(|library| (*library).to_owned()));
        }
        _ => {}
    }
    Ok((names.into_iter().collect(), libraries))
}

/// `EVP_aes_256_gcm@OPENSSL_3.0.0` → `EVP_aes_256_gcm`.
fn strip_version(name: &str) -> &str {
    name.split('@').next().unwrap_or(name)
}

// ---- constant tables and OIDs ----------------------------------------------------------------

struct Signature {
    rule_id: String,
    token: String,
    algorithm: AlgorithmRef,
    kind: EvidenceKind,
}

struct SignatureSet {
    automaton: AhoCorasick,
    signatures: Vec<Signature>,
}

fn words_be(words: &[u32]) -> Vec<u8> {
    words.iter().flat_map(|word| word.to_be_bytes()).collect()
}

fn words_le(words: &[u32]) -> Vec<u8> {
    words.iter().flat_map(|word| word.to_le_bytes()).collect()
}

fn signature_set() -> &'static SignatureSet {
    static SET: OnceLock<SignatureSet> = OnceLock::new();
    SET.get_or_init(|| {
        let mut patterns: Vec<Vec<u8>> = Vec::new();
        let mut signatures = Vec::new();
        let mut add =
            |bytes: Vec<u8>, id: &str, token: &str, algorithm: AlgorithmRef, kind: EvidenceKind| {
                patterns.push(bytes);
                signatures.push(Signature {
                    rule_id: id.to_owned(),
                    token: token.to_owned(),
                    algorithm,
                    kind,
                });
            };
        let constant = EvidenceKind::ByteSignature;

        // AES forward S-box, first 32 bytes (FIPS 197 Fig. 7)
        add(
            vec![
                0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7,
                0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf,
                0x9c, 0xa4, 0x72, 0xc0,
            ],
            "binary.constant.aes-sbox",
            "AES S-box",
            AlgorithmRef::new("aes"),
            constant,
        );
        // AES inverse S-box, first 16 bytes
        add(
            vec![
                0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3,
                0xd7, 0xfb,
            ],
            "binary.constant.aes-inverse-sbox",
            "AES inverse S-box",
            AlgorithmRef::new("aes"),
            constant,
        );
        // SHA-256 round constants K[0..8] (FIPS 180-4 §4.2.2)
        let sha256_k = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
            0xab1c5ed5,
        ];
        add(
            words_be(&sha256_k),
            "binary.constant.sha256-k",
            "SHA-256 K (BE)",
            AlgorithmRef::new("sha-256"),
            constant,
        );
        add(
            words_le(&sha256_k),
            "binary.constant.sha256-k",
            "SHA-256 K (LE)",
            AlgorithmRef::new("sha-256"),
            constant,
        );
        // SHA-512 round constants K[0..2], 64-bit
        let sha512_k: [u64; 2] = [0x428a2f98d728ae22, 0x7137449123ef65cd];
        add(
            sha512_k.iter().flat_map(|w| w.to_be_bytes()).collect(),
            "binary.constant.sha512-k",
            "SHA-512 K (BE)",
            AlgorithmRef::new("sha-512"),
            constant,
        );
        add(
            sha512_k.iter().flat_map(|w| w.to_le_bytes()).collect(),
            "binary.constant.sha512-k",
            "SHA-512 K (LE)",
            AlgorithmRef::new("sha-512"),
            constant,
        );
        // SHA-1 initial hash values H0..H4 (the fifth word distinguishes it from MD5)
        let sha1_h = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0];
        add(
            words_le(&sha1_h),
            "binary.constant.sha1-iv",
            "SHA-1 IV (LE)",
            AlgorithmRef::new("sha-1"),
            constant,
        );
        add(
            words_be(&sha1_h),
            "binary.constant.sha1-iv",
            "SHA-1 IV (BE)",
            AlgorithmRef::new("sha-1"),
            constant,
        );
        // MD5 sine table T[1..4] (RFC 1321 §3.4)
        let md5_t = [0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee];
        add(
            words_le(&md5_t),
            "binary.constant.md5-t",
            "MD5 T table",
            AlgorithmRef::new("md5"),
            constant,
        );
        add(
            words_be(&md5_t),
            "binary.constant.md5-t",
            "MD5 T table (BE)",
            AlgorithmRef::new("md5"),
            constant,
        );
        // Keccak-f round constants RC[0..3], 64-bit little-endian
        let keccak: [u64; 3] = [0x0000000000000001, 0x0000000000008082, 0x800000000000808a];
        add(
            keccak.iter().flat_map(|w| w.to_le_bytes()).collect(),
            "binary.constant.keccak-rc",
            "Keccak round constants",
            AlgorithmRef::new("sha3-256"),
            constant,
        );
        // Blowfish P-array P[0..4] followed by S-box start: pi digits alone are too common
        let blowfish = [
            0x243f6a88, 0x85a308d3, 0x13198a2e, 0x03707344, 0xa4093822, 0x299f31d0,
        ];
        add(
            words_le(&blowfish),
            "binary.constant.blowfish-p",
            "Blowfish P-array",
            AlgorithmRef::new("blowfish"),
            constant,
        );
        add(
            words_be(&blowfish),
            "binary.constant.blowfish-p",
            "Blowfish P-array (BE)",
            AlgorithmRef::new("blowfish"),
            constant,
        );
        // ChaCha20 / Salsa20 constant "expand 32-byte k"
        add(
            b"expand 32-byte k".to_vec(),
            "binary.constant.chacha-sigma",
            "ChaCha sigma",
            AlgorithmRef::new("chacha20"),
            constant,
        );
        // NIST P-256 field prime, big-endian (FIPS 186-5 / SP 800-186)
        let p256: Vec<u8> = [
            0xffffffffu32,
            0x00000001,
            0,
            0,
            0,
            0xffffffff,
            0xffffffff,
            0xffffffff,
        ]
        .iter()
        .flat_map(|w| w.to_be_bytes())
        .collect();
        add(
            p256,
            "binary.constant.p256-prime",
            "P-256 prime",
            AlgorithmRef::with_params(
                "ecdsa",
                Params {
                    curve: Some("P-256".into()),
                    ..Params::default()
                },
            ),
            constant,
        );
        // ML-KEM NTT zetas (FIPS 203 Appendix A, reference ordering), int16 little-endian
        let mlkem: Vec<u8> = [2285i16, 2571, 2970, 1812, 1493, 1422, 287, 202]
            .iter()
            .flat_map(|z| z.to_le_bytes())
            .collect();
        add(
            mlkem,
            "binary.constant.mlkem-zetas",
            "ML-KEM NTT zetas",
            AlgorithmRef::new("ml-kem"),
            constant,
        );
        // ML-DSA NTT zetas (FIPS 204 Appendix B), int32 little-endian
        let mldsa: Vec<u8> = [
            0i32, 25847, -2608894, -518909, 237124, -777960, -876248, 466468,
        ]
        .iter()
        .flat_map(|z| z.to_le_bytes())
        .collect();
        add(
            mldsa,
            "binary.constant.mldsa-zetas",
            "ML-DSA NTT zetas",
            AlgorithmRef::new("ml-dsa"),
            constant,
        );

        // DER-encoded OIDs (tag 0x06, length, content) for every OID in the knowledge base
        let registry = Registry::active();
        let oids: Vec<(String, AlgorithmRef)> = registry
            .oids()
            .filter_map(|oid| {
                registry
                    .by_oid(oid)
                    .map(|reference| (oid.to_owned(), reference))
            })
            .collect();
        for (oid, reference) in oids {
            if let Some(encoded) = encode_oid(&oid)
                && encoded.len() >= 8
            {
                add(
                    encoded,
                    &format!("binary.oid.{}", reference.id),
                    &oid,
                    reference,
                    EvidenceKind::Oid,
                );
            }
        }

        let automaton = AhoCorasick::builder()
            .match_kind(MatchKind::LeftmostLongest)
            .build(&patterns)
            .expect("signature patterns are valid");
        SignatureSet {
            automaton,
            signatures,
        }
    })
}

/// DER encoding of an OID including tag and length: `06 len <content>`.
pub fn encode_oid(dotted: &str) -> Option<Vec<u8>> {
    let arcs: Vec<u64> = dotted
        .split('.')
        .map(|arc| arc.parse().ok())
        .collect::<Option<_>>()?;
    if arcs.len() < 2 || arcs[0] > 2 {
        return None;
    }
    let mut content = Vec::new();
    let mut push_base128 = |mut value: u64| {
        let mut stack = vec![(value & 0x7f) as u8];
        value >>= 7;
        while value > 0 {
            stack.push((value & 0x7f) as u8 | 0x80);
            value >>= 7;
        }
        content.extend(stack.into_iter().rev());
    };
    push_base128(arcs[0] * 40 + arcs[1]);
    for arc in &arcs[2..] {
        push_base128(*arc);
    }
    if content.len() > 127 {
        return None;
    }
    let mut encoded = vec![0x06, content.len() as u8];
    encoded.extend(content);
    Some(encoded)
}

fn search_signatures(out: &mut Output<'_, '_>) {
    let set = signature_set();
    let mut hits = vec![0usize; set.signatures.len()];
    for found in set.automaton.find_iter(out.artifact.bytes) {
        let index = found.pattern().as_usize();
        if hits[index] >= MAX_HITS_PER_SIGNATURE {
            continue;
        }
        hits[index] += 1;
        let signature = &set.signatures[index];
        out.emit(
            signature.algorithm.clone(),
            signature.kind,
            &signature.rule_id,
            &signature.token,
            Some(found.start()),
        );
    }
}

// ---- libraries -------------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct LibraryFile {
    library: Vec<LibraryDef>,
}

#[derive(Debug, Deserialize)]
struct LibraryDef {
    name: String,
    pattern: String,
    #[serde(default)]
    soname: Vec<String>,
    #[serde(default)]
    packages: Vec<String>,
    pqc_since: String,
    basis: String,
}

struct LibraryMatcher {
    def: LibraryDef,
    pattern: Regex,
    sonames: Vec<regex::Regex>,
    packages: Vec<regex::Regex>,
}

/// Library knowledge in use: a verified bundle's, activated at startup, or the compiled-in file.
static MATCHERS: OnceLock<Vec<LibraryMatcher>> = OnceLock::new();

fn library_matchers() -> &'static [LibraryMatcher] {
    MATCHERS.get_or_init(|| {
        compile_libraries(EMBEDDED_LIBRARIES).expect("embedded library knowledge is valid")
    })
}

/// Makes `source` the active library knowledge. It must parse, and it must be activated before
/// the first binary is scanned.
pub fn activate_libraries(source: &str) -> Result<(), String> {
    let matchers = compile_libraries(source)?;
    MATCHERS
        .set(matchers)
        .map_err(|_| "library knowledge was already in use before activation".to_owned())
}

/// Parses library knowledge, rejecting invalid patterns instead of panicking.
pub fn validate_libraries(source: &str) -> Result<usize, String> {
    compile_libraries(source).map(|matchers| matchers.len())
}

fn compile_libraries(source: &str) -> Result<Vec<LibraryMatcher>, String> {
    let file: LibraryFile = toml::from_str(source).map_err(|e| e.to_string())?;
    let regex = |pattern: &String| {
        regex::Regex::new(pattern).map_err(|e| format!("pattern {pattern}: {e}"))
    };
    file.library
        .into_iter()
        .map(|def| {
            Ok(LibraryMatcher {
                pattern: Regex::new(&def.pattern)
                    .map_err(|e| format!("pattern {}: {e}", def.pattern))?,
                sonames: def.soname.iter().map(regex).collect::<Result<_, _>>()?,
                packages: def.packages.iter().map(regex).collect::<Result<_, _>>()?,
                def,
            })
        })
        .collect()
}

fn identify_libraries(artifact: &Artifact<'_>, linked: &[String], findings: &mut Findings) {
    for matcher in library_matchers() {
        let mut found: Option<(Option<String>, Location)> = None;
        if let Some(captures) = matcher.pattern.captures(artifact.bytes) {
            let version = captures
                .name("version")
                .map(|v| String::from_utf8_lossy(v.as_bytes()).into_owned());
            let offset = captures.get(0).map_or(0, |m| m.start());
            found = Some((version, Location::at_offset(artifact.path, offset as u64)));
        } else if linked.iter().any(|library| {
            matcher
                .sonames
                .iter()
                .any(|soname| soname.is_match(library))
        }) {
            found = Some((None, Location::file(artifact.path)));
        }
        let Some((version, location)) = found else {
            continue;
        };
        let version = version.filter(|v| v.chars().any(|c| c.is_ascii_digit()));
        findings
            .libraries
            .push(library_fact(matcher, artifact.component, location, version));
    }
}

fn library_fact(
    matcher: &LibraryMatcher,
    component: &str,
    location: Location,
    version: Option<String>,
) -> LibraryFact {
    let pqc_capable = match matcher.def.pqc_since.as_str() {
        "any" => true,
        "never" | "unknown" => false,
        minimum => version
            .as_deref()
            .is_some_and(|v| version_at_least(v, minimum)),
    };
    LibraryFact {
        component: component.to_owned(),
        location,
        name: matcher.def.name.clone(),
        version,
        pqc_capable,
        basis: matcher.def.basis.clone(),
    }
}

/// A cryptographic library installed as an OS package (container images). Debian and Alpine
/// versions carry an epoch and a distribution revision (`1:3.0.13-0ubuntu3.4`, `3.3.2-r0`);
/// the upstream version between them is what PQC support depends on.
pub(crate) fn package_library(
    package: &str,
    version: &str,
    component: &str,
    location: Location,
) -> Option<LibraryFact> {
    let matcher = library_matchers()
        .iter()
        .find(|m| m.packages.iter().any(|p| p.is_match(package)))?;
    let upstream = version.split_once(':').map_or(version, |(_, v)| v);
    let upstream = upstream.split(['-', '+', '~']).next().unwrap_or(upstream);
    let upstream = upstream
        .chars()
        .any(|c| c.is_ascii_digit())
        .then(|| upstream.to_owned());
    Some(library_fact(matcher, component, location, upstream))
}

/// Numeric comparison of dotted versions, ignoring letter suffixes (`1.1.1k`).
fn version_at_least(version: &str, minimum: &str) -> bool {
    let parse = |v: &str| -> Vec<u32> {
        v.split('.')
            .map(|part| {
                part.chars()
                    .take_while(char::is_ascii_digit)
                    .collect::<String>()
                    .parse()
                    .unwrap_or(0)
            })
            .collect()
    };
    parse(version) >= parse(minimum)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn run(bytes: &[u8]) -> Findings {
        let artifact = Artifact {
            path: "bin/app",
            component: ".",
            bytes,
        };
        let mut findings = Findings::default();
        BinaryCollector::new()
            .collect(
                &artifact,
                &Deadline::after(Duration::from_secs(5)),
                &mut findings,
            )
            .unwrap();
        findings
    }

    fn ids(findings: &Findings) -> BTreeSet<String> {
        findings
            .observations
            .iter()
            .filter_map(|o| match &o.finding {
                Finding::Algorithm(f) => Some(f.algorithm.id.clone()),
                _ => None,
            })
            .collect()
    }

    fn elf_with(payload: &[u8]) -> Vec<u8> {
        let mut bytes = b"\x7fELF\x02\x01\x01\0".to_vec();
        bytes.extend_from_slice(&[0u8; 56]);
        bytes.extend_from_slice(payload);
        bytes
    }

    #[test]
    fn oid_encoding_matches_der() {
        // rsaEncryption 1.2.840.113549.1.1.1
        assert_eq!(
            encode_oid("1.2.840.113549.1.1.1").unwrap(),
            vec![
                0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01
            ]
        );
    }

    #[test]
    fn constant_tables_find_algorithms_in_stripped_binaries() {
        let mut payload = vec![
            0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7,
            0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf,
            0x9c, 0xa4, 0x72, 0xc0,
        ];
        payload.extend(words_le(&[
            0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0,
        ]));
        payload.extend(
            [2285i16, 2571, 2970, 1812, 1493, 1422, 287, 202]
                .iter()
                .flat_map(|z| z.to_le_bytes()),
        );
        let findings = run(&elf_with(&payload));
        let found = ids(&findings);
        assert!(found.contains("aes"));
        assert!(found.contains("sha-1"));
        assert!(found.contains("ml-kem"), "PQC found from its NTT constants");
        assert!(
            findings
                .observations
                .iter()
                .all(|o| o.location.byte_offset.is_some())
        );
        assert!(
            findings
                .observations
                .iter()
                .all(|o| o.evidence.kind == EvidenceKind::ByteSignature)
        );
    }

    #[test]
    fn der_oids_are_recognised() {
        let payload = encode_oid("1.2.840.113549.1.1.11").unwrap(); // sha256WithRSAEncryption
        let findings = run(&elf_with(&payload));
        let rsa = findings
            .observations
            .iter()
            .find(|o| matches!(&o.finding, Finding::Algorithm(f) if f.algorithm.id == "rsa"))
            .expect("RSA from OID");
        assert_eq!(rsa.evidence.kind, EvidenceKind::Oid);
        let Finding::Algorithm(finding) = &rsa.finding else {
            unreachable!()
        };
        assert_eq!(finding.algorithm.params.digest.as_deref(), Some("sha-256"));
    }

    #[test]
    fn library_versions_decide_pqc_capability() {
        let old = run(&elf_with(b"\0OpenSSL 1.1.1k  25 Mar 2021\0"));
        assert_eq!(old.libraries.len(), 1);
        assert_eq!(old.libraries[0].version.as_deref(), Some("1.1.1k"));
        assert!(!old.libraries[0].pqc_capable);
        let new = run(&elf_with(b"\0OpenSSL 3.5.1 1 Jul 2025\0"));
        assert!(new.libraries[0].pqc_capable);
    }

    #[test]
    fn non_binaries_and_java_classes_are_not_accepted() {
        assert!(detect(b"#!/bin/sh\n").is_none());
        // Java class file: 0xcafebabe followed by a minor/major version, not an arch count
        assert!(detect(&[0xca, 0xfe, 0xba, 0xbe, 0x00, 0x00, 0x00, 0x41]).is_none());
        assert_eq!(detect(b"\x7fELF...."), Some(Format::Elf));
    }

    #[test]
    fn truncated_headers_do_not_fail_the_artifact() {
        // a lying ELF header: goblin rejects it, signature search still runs
        let findings = run(&elf_with(b"expand 32-byte k"));
        assert!(ids(&findings).contains("chacha20"));
    }

    #[test]
    fn versions_compare_numerically() {
        assert!(version_at_least("3.5.0", "3.5.0"));
        assert!(version_at_least("3.10.0", "3.5.0"));
        assert!(!version_at_least("3.4.9", "3.5.0"));
        assert!(!version_at_least("1.1.1k", "3.5.0"));
    }
}
