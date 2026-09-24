//! Scan records: kept in memory, optionally persisted under a data directory so the cockpit's
//! history survives restarts. Artefacts are serialised once when a scan finishes and then served
//! as bytes; only the CBOM is also kept parsed, for comparisons.

use lattice_cbom::{Bom, Summary};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Queued,
    Running,
    Done,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanMeta {
    pub id: String,
    pub subject: String,
    /// Name of the configured root and the path scanned inside it, never a host path.
    pub root: String,
    pub path: String,
    pub status: Status,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub requested: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finished: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<Summary>,
    #[serde(default)]
    pub failures: usize,
    /// The principal that started the scan.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested_by: Option<String>,
    /// Live counters while the scan is queued or running; never persisted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub progress: Option<lattice_collectors::ProgressSnapshot>,
}

/// A finished scan's artefacts.
pub struct Artefacts {
    pub report: Vec<u8>,
    pub cbom: Vec<u8>,
    pub graph: Vec<u8>,
    pub bom: Bom,
}

pub struct Record {
    pub meta: ScanMeta,
    pub artefacts: Option<Arc<Artefacts>>,
}

#[derive(Default)]
pub struct Store {
    records: RwLock<BTreeMap<String, Record>>,
    data_dir: Option<PathBuf>,
}

const REPORT: &str = "report.json";
const CBOM: &str = "cbom.json";
const GRAPH: &str = "graph.json";
const META: &str = "meta.json";

/// Scan ids appear in URLs and directory names: a strict alphabet rules out traversal.
pub fn valid_id(id: &str) -> bool {
    (1..=64).contains(&id.len()) && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

impl Store {
    /// Opens the store, loading persisted scans. Scans that were queued or running when the
    /// server stopped are marked failed: their work is gone.
    pub fn open(data_dir: Option<PathBuf>) -> std::io::Result<Self> {
        let mut records = BTreeMap::new();
        if let Some(dir) = &data_dir {
            let scans = dir.join("scans");
            std::fs::create_dir_all(&scans)?;
            for entry in std::fs::read_dir(&scans)? {
                let entry = entry?;
                let name = entry.file_name().to_string_lossy().into_owned();
                if !valid_id(&name) || !entry.file_type()?.is_dir() {
                    continue;
                }
                match load(&entry.path()) {
                    Ok(record) => {
                        records.insert(name, record);
                    }
                    Err(error) => {
                        tracing::warn!(scan = %name, %error, "skipping unreadable stored scan")
                    }
                }
            }
        }
        Ok(Self {
            records: RwLock::new(records),
            data_dir,
        })
    }

    pub async fn insert(&self, meta: ScanMeta) {
        self.persist_meta(&meta).await;
        let id = meta.id.clone();
        self.records.write().await.insert(
            id,
            Record {
                meta,
                artefacts: None,
            },
        );
    }

    pub async fn update(&self, id: &str, change: impl FnOnce(&mut ScanMeta)) {
        let meta = {
            let mut records = self.records.write().await;
            let Some(record) = records.get_mut(id) else {
                return;
            };
            change(&mut record.meta);
            record.meta.clone()
        };
        self.persist_meta(&meta).await;
    }

    pub async fn complete(
        &self,
        id: &str,
        artefacts: Artefacts,
        change: impl FnOnce(&mut ScanMeta),
    ) {
        if let Some(dir) = self.scan_dir(id) {
            let write = async {
                tokio::fs::create_dir_all(&dir).await?;
                tokio::fs::write(dir.join(REPORT), &artefacts.report).await?;
                tokio::fs::write(dir.join(CBOM), &artefacts.cbom).await?;
                tokio::fs::write(dir.join(GRAPH), &artefacts.graph).await
            };
            if let Err(error) = write.await {
                tracing::error!(scan = %id, %error, "could not persist scan artefacts");
            }
        }
        let meta = {
            let mut records = self.records.write().await;
            let Some(record) = records.get_mut(id) else {
                return;
            };
            change(&mut record.meta);
            record.artefacts = Some(Arc::new(artefacts));
            record.meta.clone()
        };
        self.persist_meta(&meta).await;
    }

    pub async fn list(&self) -> Vec<ScanMeta> {
        let mut metas: Vec<ScanMeta> = self
            .records
            .read()
            .await
            .values()
            .map(|r| r.meta.clone())
            .collect();
        metas.sort_by(|a, b| b.requested.cmp(&a.requested).then_with(|| b.id.cmp(&a.id)));
        metas
    }

    pub async fn meta(&self, id: &str) -> Option<ScanMeta> {
        self.records.read().await.get(id).map(|r| r.meta.clone())
    }

    pub async fn artefacts(&self, id: &str) -> Option<Arc<Artefacts>> {
        self.records
            .read()
            .await
            .get(id)
            .and_then(|r| r.artefacts.clone())
    }

    pub async fn active(&self) -> usize {
        self.records
            .read()
            .await
            .values()
            .filter(|r| matches!(r.meta.status, Status::Queued | Status::Running))
            .count()
    }

    fn scan_dir(&self, id: &str) -> Option<PathBuf> {
        let dir = self.data_dir.as_ref()?;
        valid_id(id).then(|| dir.join("scans").join(id))
    }

    async fn persist_meta(&self, meta: &ScanMeta) {
        let Some(dir) = self.scan_dir(&meta.id) else {
            return;
        };
        let result = async {
            tokio::fs::create_dir_all(&dir).await?;
            let bytes = serde_json::to_vec_pretty(meta).map_err(std::io::Error::other)?;
            let temporary = dir.join(".meta.json.tmp");
            tokio::fs::write(&temporary, bytes).await?;
            tokio::fs::rename(&temporary, dir.join(META)).await
        };
        if let Err(error) = result.await {
            tracing::error!(scan = %meta.id, %error, "could not persist scan metadata");
        }
    }
}

fn load(dir: &Path) -> std::io::Result<Record> {
    let mut meta: ScanMeta =
        serde_json::from_slice(&std::fs::read(dir.join(META))?).map_err(std::io::Error::other)?;
    let artefacts = if meta.status == Status::Done {
        let cbom = std::fs::read(dir.join(CBOM))?;
        Some(Arc::new(Artefacts {
            report: std::fs::read(dir.join(REPORT))?,
            graph: std::fs::read(dir.join(GRAPH))?,
            bom: serde_json::from_slice(&cbom).map_err(std::io::Error::other)?,
            cbom,
        }))
    } else {
        if matches!(meta.status, Status::Queued | Status::Running) {
            meta.status = Status::Failed;
            meta.error = Some("interrupted: the server stopped before the scan finished".into());
        }
        None
    };
    Ok(Record { meta, artefacts })
}
