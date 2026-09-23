//! What data does a cryptographic asset protect, and for how long must it stay secret?
//!
//! Transparent and offline. The classifier reads names, never values: identifiers passed to the
//! crypto call, the variable its result is bound to, the enclosing function's name and
//! parameters, and the file path. Each is split into tokens (`encryptCardNumber` → encrypt,
//! card, number) and matched against the data-class dictionary in `knowledge/policy.toml`.
//! Closer evidence weighs more. Every result names the rule, its confidence and the exact tokens
//! that decided it, and an analyst can override any label.

use lattice_core::policy::{Criticality, DataClass, Policy};
use lattice_core::{CryptoAsset, FunctionFact};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};

/// Where a token came from, and how much it counts. A name passed straight into the crypto call
/// says more about the protected data than the file it lives in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EvidenceSource {
    Argument,
    BoundVariable,
    Function,
    Parameter,
    Path,
}

impl EvidenceSource {
    fn weight(self) -> f64 {
        match self {
            Self::Argument => 1.0,
            Self::BoundVariable => 0.8,
            Self::Parameter => 0.7,
            Self::Function => 0.6,
            Self::Path => 0.4,
        }
    }

    fn describe(self) -> &'static str {
        match self {
            Self::Argument => "argument",
            Self::BoundVariable => "bound variable",
            Self::Function => "function",
            Self::Parameter => "parameter",
            Self::Path => "path",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TermMatch {
    pub source: EvidenceSource,
    /// The name the term was found in, e.g. `card_number`.
    pub name: String,
    pub term: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DataClassification {
    /// Stable id of the data asset node in the graph.
    pub data_asset_id: String,
    pub class: String,
    pub secrecy_lifetime_years: f64,
    pub criticality: Criticality,
    pub rule: String,
    pub confidence: f64,
    pub explanation: String,
    pub matches: Vec<TermMatch>,
}

pub struct Classifier<'p> {
    policy: &'p Policy,
    /// token → classes that list it
    index: HashMap<String, Vec<usize>>,
}

impl<'p> Classifier<'p> {
    pub fn new(policy: &'p Policy) -> Self {
        let mut index: HashMap<String, Vec<usize>> = HashMap::new();
        for (position, class) in policy.data_class.iter().enumerate() {
            for term in &class.terms {
                // multi-word terms (`secret_key`) are indexed by their joined tokens
                let joined: String = tokenize(term).concat();
                index.entry(joined).or_default().push(position);
            }
        }
        for classes in index.values_mut() {
            classes.sort_unstable();
            classes.dedup();
        }
        Self { policy, index }
    }

    /// Classifies the data an asset protects from the names around its uses.
    pub fn classify(
        &self,
        asset: &CryptoAsset,
        functions: &HashMap<&str, &FunctionFact>,
    ) -> DataClassification {
        let mut evidence: Vec<(EvidenceSource, String)> = Vec::new();
        for occurrence in &asset.occurrences {
            if let Some(usage) = &occurrence.usage {
                for identifier in &usage.identifiers {
                    evidence.push((EvidenceSource::Argument, identifier.clone()));
                }
                if let Some(function) = usage.function.as_deref().and_then(|id| functions.get(id)) {
                    evidence.push((EvidenceSource::Function, function.name.clone()));
                    for parameter in &function.parameters {
                        evidence.push((EvidenceSource::Parameter, parameter.clone()));
                    }
                }
            }
            evidence.push((EvidenceSource::Path, occurrence.location.path.clone()));
        }
        self.classify_evidence(&asset.id, &evidence)
    }

    /// Classification from explicit evidence. Exposed so protocol assets can inherit their
    /// component's most sensitive class and tests can drive it directly.
    pub fn classify_evidence(
        &self,
        asset_id: &str,
        evidence: &[(EvidenceSource, String)],
    ) -> DataClassification {
        // Score per class. A term counts once per class, at the strongest source it appears in.
        let mut best_weight: BTreeMap<(usize, String), (f64, TermMatch)> = BTreeMap::new();
        for (source, name) in evidence {
            let tokens = tokenize(name);
            // single tokens and adjacent pairs (`secret` + `key` → `secretkey`)
            let mut candidates: Vec<String> = tokens.clone();
            candidates.extend(tokens.windows(2).map(|pair| pair.concat()));
            for token in candidates {
                let Some(classes) = self.index.get(&token) else {
                    continue;
                };
                for &class in classes {
                    let key = (class, token.clone());
                    let weight = source.weight();
                    if best_weight
                        .get(&key)
                        .is_some_and(|(existing, _)| *existing >= weight)
                    {
                        continue;
                    }
                    best_weight.insert(
                        key,
                        (
                            weight,
                            TermMatch {
                                source: *source,
                                name: truncate(name),
                                term: token.clone(),
                            },
                        ),
                    );
                }
            }
        }
        let mut scores: BTreeMap<usize, (f64, Vec<TermMatch>)> = BTreeMap::new();
        for ((class, _), (weight, term_match)) in best_weight {
            let entry = scores.entry(class).or_default();
            entry.0 += weight;
            entry.1.push(term_match);
        }

        // Highest score wins; ties go to the longer secrecy lifetime (the conservative reading).
        let best = scores
            .into_iter()
            .max_by(|(a_class, (a_score, _)), (b_class, (b_score, _))| {
                a_score.total_cmp(b_score).then_with(|| {
                    let a = &self.policy.data_class[*a_class];
                    let b = &self.policy.data_class[*b_class];
                    a.lifetime_years.total_cmp(&b.lifetime_years)
                })
            });

        match best {
            Some((class, (score, mut matches))) => {
                let data_class: &DataClass = &self.policy.data_class[class];
                matches.sort_by(|a, b| a.source.cmp(&b.source).then_with(|| a.name.cmp(&b.name)));
                let explanation = format!(
                    "{} data (secrecy {} years): {}",
                    data_class.id,
                    data_class.lifetime_years,
                    matches
                        .iter()
                        .take(3)
                        .map(|m| format!(
                            "{} `{}` matches term `{}`",
                            m.source.describe(),
                            m.name,
                            m.term
                        ))
                        .collect::<Vec<_>>()
                        .join("; ")
                );
                DataClassification {
                    data_asset_id: data_asset_id(&data_class.id, asset_id),
                    class: data_class.id.clone(),
                    secrecy_lifetime_years: data_class.lifetime_years,
                    criticality: data_class.criticality,
                    rule: format!("data.{}@{}", data_class.id, self.policy.version),
                    confidence: round2((0.35 + 0.2 * score).min(0.95)),
                    explanation,
                    matches,
                }
            }
            None => self.unclassified(asset_id),
        }
    }

    pub fn unclassified(&self, asset_id: &str) -> DataClassification {
        DataClassification {
            data_asset_id: data_asset_id("unclassified", asset_id),
            class: "unclassified".into(),
            secrecy_lifetime_years: self.policy.defaults.secrecy_lifetime_years,
            criticality: self.policy.defaults.criticality,
            rule: format!("data.default@{}", self.policy.version),
            confidence: 0.25,
            explanation: format!(
                "no name around this asset identifies its data; the policy default of {} years applies",
                self.policy.defaults.secrecy_lifetime_years
            ),
            matches: Vec::new(),
        }
    }
}

fn data_asset_id(class: &str, asset_id: &str) -> String {
    let digest = blake3::hash(format!("{class}|{asset_id}").as_bytes()).to_hex();
    format!("data/{class}/{}", &digest[..16])
}

/// Splits a name into lowercase word tokens: camelCase, snake_case, kebab-case, paths and
/// digits all separate. `encryptCardNumber` → [encrypt, card, number]; `payments/api.py` →
/// [payments, api, py]; `HTTPServer` → [http, server].
pub fn tokenize(name: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let chars: Vec<char> = name.chars().collect();
    for (index, &c) in chars.iter().enumerate() {
        if !c.is_alphanumeric() {
            push(&mut tokens, &mut current);
            continue;
        }
        let previous = index.checked_sub(1).map(|i| chars[i]);
        let next = chars.get(index + 1).copied();
        let boundary = match previous {
            Some(p) if p.is_lowercase() && c.is_uppercase() => true,
            // `HTTPServer`: the `S` starts a word because a lowercase letter follows it
            Some(p)
                if p.is_uppercase() && c.is_uppercase() && next.is_some_and(char::is_lowercase) =>
            {
                true
            }
            Some(p) if p.is_ascii_digit() != c.is_ascii_digit() => true,
            _ => false,
        };
        if boundary {
            push(&mut tokens, &mut current);
        }
        current.extend(c.to_lowercase());
    }
    push(&mut tokens, &mut current);
    tokens
}

fn push(tokens: &mut Vec<String>, current: &mut String) {
    if !current.is_empty() {
        tokens.push(std::mem::take(current));
    }
}

fn truncate(name: &str) -> String {
    name.chars().take(64).collect()
}

fn round2(value: f64) -> f64 {
    (value * 100.0).round() / 100.0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn classifier() -> Classifier<'static> {
        Classifier::new(Policy::embedded())
    }

    #[test]
    fn tokenization_handles_every_naming_style() {
        assert_eq!(
            tokenize("encryptCardNumber"),
            vec!["encrypt", "card", "number"]
        );
        assert_eq!(tokenize("card_number"), vec!["card", "number"]);
        assert_eq!(tokenize("HTTPServer"), vec!["http", "server"]);
        assert_eq!(
            tokenize("services/payments/api.py"),
            vec!["services", "payments", "api", "py"]
        );
        assert_eq!(tokenize("sha256Digest"), vec!["sha", "256", "digest"]);
    }

    #[test]
    fn argument_names_decide_the_class() {
        let result = classifier().classify_evidence(
            "a",
            &[
                (EvidenceSource::Argument, "card_number".into()),
                (EvidenceSource::Path, "src/util.py".into()),
            ],
        );
        assert_eq!(result.class, "financial");
        assert_eq!(result.secrecy_lifetime_years, 10.0);
        assert_eq!(result.criticality, Criticality::Critical);
        assert!(
            result
                .explanation
                .contains("argument `card_number` matches term `card`")
        );
    }

    #[test]
    fn stronger_evidence_outweighs_a_misleading_path() {
        // the file is under `payments/` but the call hashes a password
        let result = classifier().classify_evidence(
            "a",
            &[
                (EvidenceSource::Argument, "userPassword".into()),
                (EvidenceSource::Path, "payments/login.py".into()),
            ],
        );
        assert_eq!(result.class, "credential");
    }

    #[test]
    fn ties_resolve_to_the_longer_lifetime() {
        let result = classifier().classify_evidence(
            "a",
            &[
                (EvidenceSource::Argument, "patient".into()),
                (EvidenceSource::Argument, "invoice".into()),
            ],
        );
        assert_eq!(
            result.class, "health",
            "20-year health beats 10-year financial on a tie"
        );
    }

    #[test]
    fn multi_word_terms_match_adjacent_tokens() {
        let result = classifier()
            .classify_evidence("a", &[(EvidenceSource::Argument, "secretKeyBytes".into())]);
        assert!(
            result.matches.iter().any(|m| m.term == "secretkey"),
            "{result:?}"
        );
    }

    #[test]
    fn unidentified_data_is_explicit_and_low_confidence() {
        let result =
            classifier().classify_evidence("a", &[(EvidenceSource::Path, "src/crypto.c".into())]);
        assert_eq!(result.class, "unclassified");
        assert!(result.confidence < 0.5);
        assert!(result.explanation.contains("policy default"));
    }

    #[test]
    fn classified_government_data_has_the_longest_lifetime() {
        let result = classifier().classify_evidence(
            "a",
            &[(EvidenceSource::Argument, "classifiedReport".into())],
        );
        assert_eq!(result.class, "classified");
        assert_eq!(result.secrecy_lifetime_years, 50.0);
    }

    #[test]
    fn a_term_counts_once_per_class() {
        let once =
            classifier().classify_evidence("a", &[(EvidenceSource::Argument, "card".into())]);
        let repeated = classifier().classify_evidence(
            "a",
            &[
                (EvidenceSource::Argument, "card".into()),
                (EvidenceSource::Argument, "card".into()),
                (EvidenceSource::Path, "card".into()),
            ],
        );
        assert_eq!(once.confidence, repeated.confidence);
    }
}
