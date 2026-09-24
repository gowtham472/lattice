//! The parts of a `lattice-report/1` document the executive report reads.
//!
//! The PDF is rendered from the report JSON, not from the engine's types, so a report written
//! earlier (or by another machine) renders the same way and the server can render what it
//! stored. Unknown fields are ignored; fields added after the first release are optional.

use serde::Deserialize;

pub const REPORT_FORMAT: &str = "lattice-report/1";

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Report {
    pub format: String,
    pub subject: String,
    pub generated: String,
    pub provenance: Provenance,
    pub summary: Summary,
    pub stats: Stats,
    #[serde(default)]
    pub failures: Vec<serde_json::Value>,
    pub assets: Vec<Asset>,
    #[serde(default)]
    pub roadmap: Vec<RoadmapItem>,
    #[serde(default)]
    pub plan: Option<Plan>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Provenance {
    pub tool_version: String,
    pub knowledge_version: String,
    #[serde(default)]
    pub knowledge_sequence: Option<u64>,
    #[serde(default)]
    pub knowledge_signer: Option<String>,
    pub rules_version: String,
    pub policy_version: String,
    pub assessment_year: u16,
    pub q_day_earliest: u16,
    pub q_day_latest: u16,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Summary {
    pub assets: usize,
    pub quantum_vulnerable: usize,
    pub broken_now: usize,
    pub mosca_urgent: usize,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Stats {
    pub files_scanned: u64,
    pub bytes_scanned: u64,
}

#[derive(Debug, Deserialize)]
pub struct Asset {
    pub name: String,
    pub asset: AssetIdentity,
    pub assessment: Assessment,
    pub recommendation: Recommendation,
    #[serde(default)]
    pub effort: Option<Effort>,
}

#[derive(Debug, Deserialize)]
pub struct AssetIdentity {
    pub id: String,
    pub component: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Assessment {
    pub tier: String,
    pub priority: u8,
    #[serde(default)]
    pub broken_now: bool,
}

#[derive(Debug, Deserialize)]
pub struct Recommendation {
    pub action: String,
    pub target: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Effort {
    pub person_weeks: f64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RoadmapItem {
    pub asset_id: String,
    pub wave: u8,
    #[serde(default)]
    pub due_year: Option<u16>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Plan {
    pub timeline: String,
    pub reference: String,
    pub assessment_year: u16,
    pub total_person_weeks: f64,
    pub waves: Vec<Wave>,
    #[serde(default)]
    pub engineers_needed: Option<f64>,
    pub overdue: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Wave {
    pub wave: u8,
    pub name: String,
    pub items: usize,
    pub person_weeks: f64,
    #[serde(default)]
    pub due_year: Option<u16>,
    pub cumulative_person_weeks: f64,
    #[serde(default)]
    pub engineers_needed: Option<f64>,
    pub overdue: bool,
}
