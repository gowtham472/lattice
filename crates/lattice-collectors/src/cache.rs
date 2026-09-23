//! Content-addressed cache of per-file findings, for incremental scans.
//!
//! A file's findings depend on its path, its component, its bytes, the collector code and the
//! knowledge in use. The cache key covers all of them: the path, component and a BLAKE3 of the
//! content, under a fingerprint of the running executable and the active catalogue, rules and
//! library knowledge. Any rebuild, any knowledge change and any edit to the file therefore misses;
//! a hit returns exactly what a fresh scan would have produced, so cached and uncached runs give
//! byte-identical reports.
//!
//! Only clean results are stored: a file whose scan recorded a failure (a timeout, a parse error)
//! is scanned again next time. The cache is an optimisation, never a source of truth; an unreadable
//! or corrupt entry is a miss, and the directory can be deleted at any time. It must be as trusted
//! as the output directory, since whoever can write to it can shape future results.

use crate::{Findings, ScanStats};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Entries above this size are not stored: rescanning is cheaper than a huge read.
const MAX_ENTRY_BYTES: usize = 8 * 1024 * 1024;
const LAYOUT: &str = "v1";

pub struct Cache {
    dir: PathBuf,
    fingerprint: blake3::Hash,
}

impl std::fmt::Debug for Cache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Cache")
            .field("dir", &self.dir)
            .field("fingerprint", &self.fingerprint.to_hex().as_str())
            .finish()
    }
}

/// A stored result: the findings and the statistics the scan would have counted.
#[derive(Serialize, Deserialize)]
pub struct Entry {
    pub findings: Findings,
    pub files_scanned: u64,
    pub bytes_scanned: u64,
    pub by_collector: BTreeMap<String, u64>,
}

impl Entry {
    pub fn stats(&self) -> ScanStats {
        ScanStats {
            files_scanned: self.files_scanned,
            bytes_scanned: self.bytes_scanned,
            by_collector: self.by_collector.clone(),
            cache_hits: 1,
            ..ScanStats::default()
        }
    }
}

impl Cache {
    /// Opens (creating) a cache directory under a fingerprint of this executable and the active
    /// knowledge. Call it before the process confines itself: it reads the executable.
    pub fn open(dir: &Path) -> std::io::Result<Self> {
        let executable = std::env::current_exe().and_then(std::fs::read)?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"lattice-cache|");
        hasher.update(blake3::hash(&executable).as_bytes());
        Self::with_fingerprint(dir, hasher.finalize().as_bytes())
    }

    /// Opens a cache under an explicit build fingerprint; the active knowledge is always added.
    pub fn with_fingerprint(dir: &Path, build: &[u8]) -> std::io::Result<Self> {
        let dir = dir.join(LAYOUT);
        std::fs::create_dir_all(&dir)?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(build);
        hasher.update(&lattice_core::Registry::active().digest());
        hasher.update(&crate::source::rules::active_digest());
        hasher.update(&crate::binary::active_libraries_digest());
        Ok(Self {
            dir,
            fingerprint: hasher.finalize(),
        })
    }

    pub fn key(&self, path: &str, component: &str, bytes: &[u8]) -> blake3::Hash {
        let mut hasher = blake3::Hasher::new();
        hasher.update(self.fingerprint.as_bytes());
        for field in [path.as_bytes(), component.as_bytes()] {
            hasher.update(&(field.len() as u64).to_be_bytes());
            hasher.update(field);
        }
        hasher.update(blake3::hash(bytes).as_bytes());
        hasher.finalize()
    }

    fn location(&self, key: &blake3::Hash) -> PathBuf {
        let hex = key.to_hex();
        self.dir.join(&hex[..2]).join(format!("{hex}.json"))
    }

    pub fn get(&self, key: &blake3::Hash) -> Option<Entry> {
        let path = self.location(key);
        let metadata = std::fs::metadata(&path).ok()?;
        if metadata.len() > MAX_ENTRY_BYTES as u64 {
            return None;
        }
        serde_json::from_slice(&std::fs::read(path).ok()?).ok()
    }

    /// Stores an entry. Failures are logged and ignored: the cache never fails a scan.
    pub fn put(&self, key: &blake3::Hash, entry: &Entry) {
        let Ok(bytes) = serde_json::to_vec(entry) else {
            return;
        };
        if bytes.len() > MAX_ENTRY_BYTES {
            return;
        }
        let path = self.location(key);
        let write = || -> std::io::Result<()> {
            let parent = path.parent().expect("entries live in a shard directory");
            std::fs::create_dir_all(parent)?;
            let temporary = parent.join(format!(".{}.tmp-{}", key.to_hex(), std::process::id()));
            std::fs::write(&temporary, &bytes)?;
            std::fs::rename(&temporary, &path)
        };
        if let Err(error) = write() {
            tracing::debug!(%error, "could not store a cache entry");
        }
    }
}
