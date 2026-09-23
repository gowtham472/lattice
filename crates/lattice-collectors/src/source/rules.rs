//! The source rule database: which calls are cryptographic, and how to read the algorithm and
//! its parameters out of each call. Rules are data (`rules/source.toml`), embedded and versioned.

use crate::CollectorError;
use lattice_core::{ApiStyle, CryptoFunction, Params, Primitive, ProtocolKind};
use regex::Regex;
use serde::Deserialize;
use std::collections::HashMap;

const EMBEDDED_RULES: &str = include_str!("../../../../rules/source.toml");

/// The `version` of the embedded catalogue, read without compiling the rules.
pub fn embedded_version() -> &'static str {
    static VERSION: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    VERSION.get_or_init(|| {
        #[derive(Deserialize)]
        struct Header {
            version: String,
        }
        toml::from_str::<Header>(EMBEDDED_RULES)
            .map(|header| header.version)
            .unwrap_or_else(|_| "unknown".into())
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RuleKind {
    /// The call uses an algorithm.
    #[default]
    Algorithm,
    /// The call adds parameters to an algorithm bound earlier to its receiver
    /// (`kpg.initialize(2048)`, `cipher.NewGCM(block)`).
    Refine,
    /// Assigning a property of a bound object refines it (`aes.Mode = CipherMode.ECB`).
    Assign,
    /// The call configures a list of TLS cipher suites.
    CipherList,
    /// The call configures TLS key-exchange groups.
    GroupList,
    /// The call pins a protocol version.
    ProtocolVersion,
}

/// How a candidate string becomes an algorithm or parameter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Grammar {
    Name,
    JcaCipher,
    Group,
    Curve,
    Mode,
    Digest,
    Int,
    Padding,
    Version,
}

/// Where a value is read from.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValueSource {
    /// Positional argument index.
    #[serde(default)]
    pub arg: Option<usize>,
    /// Keyword argument (`key_size=2048`).
    #[serde(default)]
    pub keyword: Option<String>,
    /// Property of an object-literal argument (`{ modulusLength: 2048 }`); with `arg`, only that
    /// argument is searched, otherwise every argument.
    #[serde(default)]
    pub property: Option<String>,
    /// Named capture of the rule's `callee_regex`.
    #[serde(default)]
    pub capture: Option<String>,
    /// For `assign` rules: the assigned value.
    #[serde(default)]
    pub value: bool,
    #[serde(default)]
    pub grammar: Option<Grammar>,
    /// Prefixes removed from candidates before parsing (`EVP_`, `NID_`, `BCRYPT_`).
    #[serde(default)]
    pub strip_prefix: Vec<String>,
    #[serde(default)]
    pub strip_suffix: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ParamName {
    KeyBits,
    ParameterSet,
    Curve,
    Mode,
    Padding,
    Digest,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ParamDef {
    pub name: ParamName,
    #[serde(flatten)]
    pub source: ValueSource,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleDef {
    pub id: String,
    #[serde(default = "one")]
    pub version: u32,
    pub languages: Vec<String>,
    /// Callee suffixes, dotted: `Cipher.getInstance` matches `javax.crypto.Cipher.getInstance`.
    /// A leading `*.` matches any receiver: `*.initialize`.
    #[serde(default)]
    pub callee: Vec<String>,
    /// Alternative to `callee`: a regex over the full dotted callee, whose named captures can be
    /// read with `capture = "..."`.
    #[serde(default)]
    pub callee_regex: Option<String>,
    /// For `assign` rules: property names that trigger the rule.
    #[serde(default)]
    pub property: Vec<String>,
    pub style: ApiStyle,
    #[serde(default)]
    pub kind: RuleKind,
    /// A fixed algorithm id.
    #[serde(default)]
    pub algorithm: Option<String>,
    /// Several fixed algorithms, for constructs that commit to more than one (Fernet).
    #[serde(default)]
    pub algorithms: Vec<String>,
    /// Where to read the algorithm from when it is not fixed.
    #[serde(default)]
    pub from: Option<ValueSource>,
    /// Parameters implied by the API itself.
    #[serde(default)]
    pub params: Params,
    #[serde(default)]
    pub param: Vec<ParamDef>,
    /// For `refine`: which argument is the receiver (C-style `f(ctx, ...)`). Defaults to the
    /// object of the method call (`kpg` in `kpg.initialize(...)`).
    #[serde(default)]
    pub receiver_arg: Option<usize>,
    #[serde(default)]
    pub function: Option<CryptoFunction>,
    #[serde(default)]
    pub primitive: Option<Primitive>,
    #[serde(default)]
    pub protocol: Option<ProtocolKind>,
}

fn one() -> u32 {
    1
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImportDef {
    pub id: String,
    pub languages: Vec<String>,
    /// Matched against the import path with separators normalised to `/`.
    pub module: Vec<String>,
    pub algorithm: String,
    #[serde(default)]
    pub params: Params,
}

#[derive(Debug, Deserialize)]
struct RuleFile {
    version: String,
    #[serde(default)]
    rule: Vec<RuleDef>,
    #[serde(default)]
    import: Vec<ImportDef>,
}

#[derive(Debug)]
pub struct CompiledRule {
    pub def: RuleDef,
    pub regex: Option<Regex>,
    patterns: Vec<Vec<String>>,
}

impl CompiledRule {
    /// Matches a dotted callee. Returns the regex captures when the rule uses one.
    pub fn matches(
        &self,
        callee_segments: &[&str],
        callee: &str,
    ) -> Option<HashMap<String, String>> {
        if let Some(regex) = &self.regex {
            let captures = regex.captures(callee)?;
            let named = regex
                .capture_names()
                .flatten()
                .filter_map(|name| {
                    captures
                        .name(name)
                        .map(|value| (name.to_owned(), value.as_str().to_owned()))
                })
                .collect();
            return Some(named);
        }
        self.patterns
            .iter()
            .any(|pattern| suffix_matches(pattern, callee_segments))
            .then(HashMap::new)
    }
}

fn suffix_matches(pattern: &[String], segments: &[&str]) -> bool {
    let (wildcard, pattern) = match pattern.split_first() {
        Some((first, rest)) if first == "*" => (true, rest),
        _ => (false, pattern),
    };
    if segments.len() < pattern.len() + usize::from(wildcard) {
        return false;
    }
    segments[segments.len() - pattern.len()..]
        .iter()
        .zip(pattern)
        .all(|(segment, expected)| segment == expected)
}

#[derive(Debug)]
pub struct RuleSet {
    pub version: String,
    rules: Vec<CompiledRule>,
    /// Suffix rules indexed by the last callee segment they can match.
    by_last_segment: HashMap<String, Vec<usize>>,
    regex_rules: Vec<usize>,
    pub imports: Vec<ImportDef>,
}

impl RuleSet {
    pub fn embedded() -> Result<Self, CollectorError> {
        Self::from_toml(EMBEDDED_RULES)
    }

    pub fn from_toml(source: &str) -> Result<Self, CollectorError> {
        let file: RuleFile = toml::from_str(source)
            .map_err(|error| CollectorError::InvalidRules(error.to_string()))?;
        let registry = lattice_core::Registry::embedded();
        let mut rules = Vec::with_capacity(file.rule.len());
        let mut by_last_segment: HashMap<String, Vec<usize>> = HashMap::new();
        let mut regex_rules = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for def in file.rule {
            if !seen.insert(def.id.clone()) {
                return Err(CollectorError::InvalidRules(format!(
                    "duplicate rule id `{}`",
                    def.id
                )));
            }
            for id in def.algorithm.iter().chain(&def.algorithms) {
                if registry.get(id).is_none() {
                    return Err(CollectorError::InvalidRules(format!(
                        "rule `{}` names unknown algorithm `{id}`",
                        def.id
                    )));
                }
            }
            if def.callee.is_empty() && def.callee_regex.is_none() && def.kind != RuleKind::Assign {
                return Err(CollectorError::InvalidRules(format!(
                    "rule `{}` matches no callee",
                    def.id
                )));
            }
            let regex = def
                .callee_regex
                .as_deref()
                .map(Regex::new)
                .transpose()
                .map_err(|error| CollectorError::InvalidRules(format!("{}: {error}", def.id)))?;
            let patterns: Vec<Vec<String>> = def
                .callee
                .iter()
                .map(|pattern| pattern.split('.').map(str::to_owned).collect())
                .collect();
            let index = rules.len();
            if regex.is_some() {
                regex_rules.push(index);
            }
            for pattern in &patterns {
                if let Some(last) = pattern.last() {
                    by_last_segment.entry(last.clone()).or_default().push(index);
                }
            }
            if def.kind == RuleKind::Assign {
                for property in &def.property {
                    by_last_segment
                        .entry(format!("={property}"))
                        .or_default()
                        .push(index);
                }
            }
            rules.push(CompiledRule {
                def,
                regex,
                patterns,
            });
        }
        for import in &file.import {
            if registry.get(&import.algorithm).is_none() {
                return Err(CollectorError::InvalidRules(format!(
                    "import rule `{}` names unknown algorithm `{}`",
                    import.id, import.algorithm
                )));
            }
        }
        Ok(Self {
            version: file.version,
            rules,
            by_last_segment,
            regex_rules,
            imports: file.import,
        })
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Rules that match a call, with their regex captures.
    pub fn for_call<'s>(
        &'s self,
        language: super::lang::Language,
        callee: &str,
    ) -> Vec<(&'s CompiledRule, HashMap<String, String>)> {
        let segments: Vec<&str> = callee
            .split('.')
            .filter(|segment| !segment.is_empty())
            .collect();
        let Some(last) = segments.last() else {
            return Vec::new();
        };
        let mut candidates: Vec<usize> =
            self.by_last_segment.get(*last).cloned().unwrap_or_default();
        candidates.extend(&self.regex_rules);
        candidates.sort_unstable();
        candidates.dedup();
        candidates
            .into_iter()
            .map(|index| &self.rules[index])
            .filter(|rule| rule.def.kind != RuleKind::Assign)
            .filter(|rule| {
                rule.def
                    .languages
                    .iter()
                    .any(|l| language.matches_rule_language(l))
            })
            .filter_map(|rule| {
                rule.matches(&segments, callee)
                    .map(|captures| (rule, captures))
            })
            .collect()
    }

    /// `assign` rules triggered by assigning `property`.
    pub fn for_assignment(
        &self,
        language: super::lang::Language,
        property: &str,
    ) -> Vec<&CompiledRule> {
        self.by_last_segment
            .get(&format!("={property}"))
            .into_iter()
            .flatten()
            .map(|&index| &self.rules[index])
            .filter(|rule| {
                rule.def
                    .languages
                    .iter()
                    .any(|l| language.matches_rule_language(l))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source::lang::Language;

    #[test]
    fn embedded_rules_compile_and_reference_known_algorithms() {
        let rules = RuleSet::embedded().expect("embedded rules are valid");
        assert!(
            rules.len() > 80,
            "expected a substantial rule set, got {}",
            rules.len()
        );
    }

    #[test]
    fn suffix_matching_respects_segments() {
        let pattern: Vec<String> = ["Cipher", "getInstance"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert!(suffix_matches(
            &pattern,
            &["javax", "crypto", "Cipher", "getInstance"]
        ));
        assert!(suffix_matches(&pattern, &["Cipher", "getInstance"]));
        assert!(!suffix_matches(&pattern, &["MyCipher", "getInstance"]));
        let wildcard: Vec<String> = ["*", "initialize"].iter().map(|s| s.to_string()).collect();
        assert!(suffix_matches(&wildcard, &["kpg", "initialize"]));
        assert!(
            !suffix_matches(&wildcard, &["initialize"]),
            "wildcard needs a receiver"
        );
    }

    #[test]
    fn calls_find_their_rules() {
        let rules = RuleSet::embedded().unwrap();
        assert!(
            !rules
                .for_call(Language::Java, "Cipher.getInstance")
                .is_empty()
        );
        assert!(!rules.for_call(Language::Python, "hashlib.sha1").is_empty());
        assert!(!rules.for_call(Language::C, "EVP_aes_256_gcm").is_empty());
        assert!(
            rules
                .for_call(Language::Python, "Cipher.getInstance")
                .is_empty(),
            "language-scoped"
        );
        assert!(rules.for_call(Language::Java, "printLine").is_empty());
    }

    #[test]
    fn rejects_unknown_algorithms() {
        let bad = r#"
            version = "t"
            [[rule]]
            id = "x"
            languages = ["c"]
            callee = ["f"]
            style = "primitive"
            algorithm = "not-an-algorithm"
        "#;
        assert!(RuleSet::from_toml(bad).is_err());
    }
}
