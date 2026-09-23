//! The LATTICE pipeline, shared by the CLI and the server:
//!
//! collect → normalise → classify data → build the crypto graph → assess risk → recommend →
//! roadmap → CBOM.
//!
//! Every stage is deterministic. Given the same target, policy, timestamp and assessment year,
//! two runs produce byte-identical reports on any machine; the only inputs that vary between runs
//! are the ones the caller passes explicitly.

pub mod compare;
pub mod knowledge;

use lattice_cbom::{AssessedAsset, Bom, BomInput, Provenance, Summary};
use lattice_classify::{Classifier, DataClassification};
use lattice_collectors::{CollectionFailure, CollectorError, ScanOptions, ScanStats};
use lattice_core::policy::Policy;
use lattice_core::{CryptoAsset, FunctionFact, LibraryFact, Registry};
use lattice_graph::{AssetContext, CryptoGraph, GraphInput, GraphStats};
use lattice_risk::advisor::{Recommendation, RoadmapItem, recommend, roadmap};
use lattice_risk::{Assessment, Assessor};
use serde::Serialize;
use std::collections::{BTreeMap, HashMap};
use std::path::Path;
use thiserror::Error;

pub const REPORT_FORMAT: &str = "lattice-report/1";
pub const TOOL_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Error)]
pub enum EngineError {
    #[error("cannot scan {path}: {source}")]
    Collect {
        path: String,
        source: CollectorError,
    },
    #[error("internal invariant violated: {0}")]
    Invariant(String),
}

/// Everything a run depends on besides the target itself.
#[derive(Debug, Clone)]
pub struct Config {
    pub scan: ScanOptions,
    pub policy: Policy,
    /// Unix seconds stamped on the report.
    pub timestamp: i64,
    /// The year Mosca's X, Y and Z are measured from. Defaults to the timestamp's year.
    pub assessment_year: u16,
    /// Report subject; defaults to the target directory's name.
    pub subject: Option<String>,
    pub subject_version: Option<String>,
}

impl Config {
    /// Re-stamps a configuration for a new run: the timestamp and the assessment year it implies
    /// always move together, so a reused template never scores against a stale year.
    pub fn stamped(&self, timestamp: i64) -> Self {
        Self {
            timestamp,
            assessment_year: year_of(timestamp),
            ..self.clone()
        }
    }

    pub fn new(timestamp: i64) -> Self {
        Self {
            scan: ScanOptions::default(),
            policy: Policy::active().clone(),
            timestamp,
            assessment_year: year_of(timestamp),
            subject: None,
            subject_version: None,
        }
    }
}

fn year_of(timestamp: i64) -> u16 {
    lattice_core::rfc3339(timestamp)[..4]
        .parse()
        .unwrap_or(1970)
}

/// One asset with everything LATTICE concluded about it.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AssetReport {
    /// Display name, identical to the CBOM component name.
    pub name: String,
    pub asset: CryptoAsset,
    pub context: AssetContext,
    pub assessment: Assessment,
    pub recommendation: Recommendation,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReportProvenance {
    pub tool_version: String,
    pub knowledge_version: String,
    /// Sequence of the knowledge used: the compiled-in one, or an activated bundle's.
    pub knowledge_sequence: u64,
    /// Key id that signed the activated knowledge bundle; absent for compiled-in knowledge.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub knowledge_signer: Option<String>,
    pub rules_version: String,
    pub policy_version: String,
    pub assessment_year: u16,
    pub q_day_earliest: u16,
    pub q_day_latest: u16,
}

/// The full explainable report. The CBOM carries the same conclusions in CycloneDX form; this
/// carries the reasoning (every index term, agility factor and call path) for the cockpit.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Report {
    pub format: String,
    pub subject: String,
    pub generated: String,
    pub provenance: ReportProvenance,
    pub summary: Summary,
    pub stats: ScanStats,
    pub graph: GraphStats,
    pub failures: Vec<CollectionFailure>,
    /// Highest priority first.
    pub assets: Vec<AssetReport>,
    pub libraries: Vec<LibraryFact>,
    pub roadmap: Vec<RoadmapItem>,
}

pub struct Outcome {
    pub report: Report,
    pub cbom: Bom,
    /// The crypto graph, for visualisation.
    pub graph: lattice_graph::SerializableGraph,
}

/// Scans `target` and assesses everything found.
pub fn run(target: &Path, config: &Config) -> Result<Outcome, EngineError> {
    let collect_error = |source| EngineError::Collect {
        path: target.display().to_string(),
        source,
    };
    let collectors = lattice_collectors::default_collectors().map_err(collect_error)?;
    let collected = lattice_collectors::collect_target(target, &collectors, &config.scan)
        .map_err(collect_error)?;
    tracing::info!(
        files = collected.stats.files_scanned,
        observations = collected.findings.observations.len(),
        failures = collected.failures.len(),
        "collection finished"
    );
    let mut findings = collected.findings;
    attribute_traffic(&mut findings.observations, &findings.functions);

    let assets = lattice_core::normalize(std::mem::take(&mut findings.observations));
    let policy = &config.policy;
    let classifier = Classifier::new(policy);
    let functions: HashMap<&str, &FunctionFact> = findings
        .functions
        .iter()
        .map(|f| (f.id.as_str(), f))
        .collect();
    let classifications: BTreeMap<String, DataClassification> = assets
        .iter()
        .map(|asset| (asset.id.clone(), classifier.classify(asset, &functions)))
        .collect();

    let graph = CryptoGraph::build(&GraphInput {
        assets: &assets,
        functions: &findings.functions,
        calls: &findings.calls,
        bindings: &findings.bindings,
        libraries: &findings.libraries,
        classifications: &classifications,
        policy,
    });

    let assessor = Assessor {
        policy,
        assessment_year: config.assessment_year,
    };
    let mut reports = Vec::with_capacity(assets.len());
    for mut asset in assets {
        let context = graph
            .context(&asset.id)
            .cloned()
            .ok_or_else(|| EngineError::Invariant(format!("no graph context for {}", asset.id)))?;
        if context.reachable && asset.liveness < lattice_core::Liveness::Confirmed {
            let entry = context
                .entry
                .as_ref()
                .map_or_else(|| "an entry point".to_owned(), |e| e.detail.clone());
            asset.confirm(format!("reachable from {entry}"));
        }
        let assessment = assessor.assess(&asset, &context);
        let recommendation = recommend(&asset, &assessment, context.data.secrecy_lifetime_years);
        reports.push(AssetReport {
            name: asset.finding.display_name(),
            asset,
            context,
            assessment,
            recommendation,
        });
    }

    let plan = roadmap(
        &reports
            .iter()
            .map(|r| (&r.asset, &r.assessment, &r.recommendation))
            .collect::<Vec<_>>(),
    );

    let subject = config
        .subject
        .clone()
        .unwrap_or_else(|| subject_name(target));
    let provenance = ReportProvenance {
        tool_version: TOOL_VERSION.into(),
        knowledge_version: Registry::active().version().into(),
        knowledge_sequence: knowledge::active_bundle()
            .map_or(lattice_core::KNOWLEDGE_SEQUENCE, |b| b.sequence),
        knowledge_signer: knowledge::active_bundle().map(|b| b.key_id.clone()),
        rules_version: lattice_collectors::rules_version().into(),
        policy_version: policy.version.clone(),
        assessment_year: config.assessment_year,
        q_day_earliest: policy.q_day.earliest_year,
        q_day_latest: policy.q_day.latest_year,
    };

    let cbom = {
        let assessed: Vec<AssessedAsset<'_>> = reports
            .iter()
            .map(|r| AssessedAsset {
                asset: &r.asset,
                context: &r.context,
                assessment: &r.assessment,
                recommendation: &r.recommendation,
            })
            .collect();
        lattice_cbom::build(&BomInput {
            subject: &subject,
            subject_version: config.subject_version.as_deref(),
            timestamp: config.timestamp,
            provenance: Provenance {
                tool_version: &provenance.tool_version,
                knowledge_version: &provenance.knowledge_version,
                rules_version: &provenance.rules_version,
                policy_version: &provenance.policy_version,
                assessment_year: provenance.assessment_year,
                q_day: (provenance.q_day_earliest, provenance.q_day_latest),
                knowledge_sequence: provenance.knowledge_sequence,
                knowledge_signer: provenance.knowledge_signer.as_deref(),
            },
            assets: &assessed,
            libraries: &findings.libraries,
        })
    };
    let summary = {
        let assessed: Vec<AssessedAsset<'_>> = reports
            .iter()
            .map(|r| AssessedAsset {
                asset: &r.asset,
                context: &r.context,
                assessment: &r.assessment,
                recommendation: &r.recommendation,
            })
            .collect();
        Summary::of(&assessed)
    };

    reports.sort_by(|a, b| {
        b.assessment
            .priority
            .cmp(&a.assessment.priority)
            .then_with(|| a.asset.id.cmp(&b.asset.id))
    });
    let report = Report {
        format: REPORT_FORMAT.into(),
        subject,
        generated: lattice_core::rfc3339(config.timestamp),
        provenance,
        summary,
        stats: collected.stats,
        graph: graph.stats().clone(),
        failures: collected.failures,
        assets: reports,
        libraries: findings.libraries,
        roadmap: plan,
    };
    Ok(Outcome {
        report,
        cbom,
        graph: graph.to_serializable(),
    })
}

/// A captured TLS handshake names its server (SNI). When a TLS listener in the scanned
/// configuration answers to that name, the handshake is evidence about *that* listener's
/// component, so it moves there and merges with what the configuration selected: TLS 1.0 that
/// is configured and also negotiated in traffic becomes one confirmed asset, not two.
fn attribute_traffic(observations: &mut [lattice_core::Observation], functions: &[FunctionFact]) {
    let hosts: Vec<(&str, &str)> = functions
        .iter()
        .filter(|f| {
            f.entry
                .as_ref()
                .is_some_and(|e| e.kind == lattice_core::EntryKind::Listener)
        })
        .flat_map(|f| {
            f.hosts
                .iter()
                .map(move |h| (h.as_str(), f.component.as_str()))
        })
        .collect();
    let owner = |host: &str| {
        hosts.iter().find(|(name, _)| *name == host).or_else(|| {
            let (_, parent) = host.split_once('.')?;
            hosts
                .iter()
                .find(|(name, _)| name.strip_prefix("*.") == Some(parent))
        })
    };
    for observation in observations.iter_mut().filter(|o| {
        o.surface == lattice_core::Surface::Runtime && o.evidence.rule_id.starts_with("capture.tls")
    }) {
        if let Some((_, component)) = owner(&observation.evidence.matched_token) {
            observation.component = (*component).to_owned();
        }
    }
}

fn subject_name(target: &Path) -> String {
    let resolved = target
        .canonicalize()
        .unwrap_or_else(|_| target.to_path_buf());
    resolved
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| "scan".into())
}

#[cfg(test)]
mod tests;
