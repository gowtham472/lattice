//! Offline, read-only collectors for cryptographic artefacts.
//!
//! A collector looks at one artefact (a report path plus its bytes) and reports what it finds.
//! Collectors never touch the filesystem themselves: [`collect_target`] walks the scan target,
//! reads each file once under a size limit, and hands the bytes to every collector that accepts
//! it. The same collectors therefore work on files streamed out of archives and container layers
//! without anything being extracted to disk.
//!
//! Every collector runs inside the isolation harness in [`sandbox`]: a panic or a parse that
//! overruns its deadline costs that one artefact, recorded as a partial-result warning, never the
//! scan (security.md §3).

pub mod binary;
pub mod cache;
pub mod capture;
pub mod config;
pub mod container;
pub mod custody;
#[cfg(feature = "fuzzing")]
pub mod fuzzing;
pub mod pki;
pub mod sandbox;
pub mod source;
pub mod trace;
mod walk;

use lattice_core::{CallFact, EntryBinding, FunctionFact, LibraryFact, Observation};
use rayon::prelude::*;
use std::path::{Path, PathBuf};
use std::time::Duration;
use thiserror::Error;

pub use walk::ComponentResolver;

const DEFAULT_MAX_FILE_BYTES: u64 = 16 * 1024 * 1024;
const DEFAULT_PARSE_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_MAX_ARCHIVE_BYTES: u64 = 16 * 1024 * 1024 * 1024;
const DEFAULT_MAX_EXPANDED_BYTES: u64 = 32 * 1024 * 1024 * 1024;
const DEFAULT_ARCHIVE_TIMEOUT: Duration = Duration::from_secs(900);

#[derive(Debug, Error)]
pub enum CollectorError {
    #[error("scan target does not exist: {0}")]
    TargetNotFound(PathBuf),
    #[error("scan target is neither a regular file nor a directory: {0}")]
    InvalidTarget(PathBuf),
    #[error("rule database is invalid: {0}")]
    InvalidRules(String),
}

#[derive(Debug, Clone)]
pub struct ScanOptions {
    /// Files larger than this are skipped and reported, never partially parsed.
    pub max_file_bytes: u64,
    /// Upper bound on the time one collector may spend on one artefact.
    pub parse_timeout: Duration,
    /// Also descend into dependency trees (`node_modules`, `vendor`). Off by default: third-party
    /// code is better inventoried through its package manifest than by rescanning it.
    pub include_dependencies: bool,
    /// Container image archives, tarballs and packet captures are streamed rather than read
    /// whole, so they get their own size limit.
    pub max_archive_bytes: u64,
    /// Upper bound on the bytes an archive may expand to (decompression bombs).
    pub max_expanded_bytes: u64,
    /// Upper bound on the time one archive or capture may take.
    pub archive_timeout: Duration,
    /// Incremental-scan cache, opened before the process is confined.
    pub cache: Option<std::sync::Arc<cache::Cache>>,
    /// Live counters for whoever reports the scan while it runs.
    pub progress: Option<std::sync::Arc<Progress>>,
}

/// Where a scan is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Phase {
    Queued,
    Listing,
    Collecting,
    Analysing,
    Rendering,
    Done,
}

impl Phase {
    fn from_u8(value: u8) -> Self {
        match value {
            1 => Self::Listing,
            2 => Self::Collecting,
            3 => Self::Analysing,
            4 => Self::Rendering,
            5 => Self::Done,
            _ => Self::Queued,
        }
    }
}

/// Live counters of a scan in progress. Updated by the walker, the collectors and the engine
/// from many threads; read by the CLI's progress line and the server's event stream.
#[derive(Debug, Default)]
pub struct Progress {
    phase: std::sync::atomic::AtomicU8,
    files_total: std::sync::atomic::AtomicU64,
    files_done: std::sync::atomic::AtomicU64,
    archives_total: std::sync::atomic::AtomicU64,
    archives_done: std::sync::atomic::AtomicU64,
    bytes_done: std::sync::atomic::AtomicU64,
}

/// A consistent-enough view of [`Progress`] for display.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProgressSnapshot {
    pub phase: Phase,
    pub files_total: u64,
    pub files_done: u64,
    pub archives_total: u64,
    pub archives_done: u64,
    pub bytes_done: u64,
}

impl Progress {
    pub fn set_phase(&self, phase: Phase) {
        self.phase
            .store(phase as u8, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> ProgressSnapshot {
        use std::sync::atomic::Ordering::Relaxed;
        ProgressSnapshot {
            phase: Phase::from_u8(self.phase.load(Relaxed)),
            files_total: self.files_total.load(Relaxed),
            files_done: self.files_done.load(Relaxed),
            archives_total: self.archives_total.load(Relaxed),
            archives_done: self.archives_done.load(Relaxed),
            bytes_done: self.bytes_done.load(Relaxed),
        }
    }

    fn totals(&self, files: usize, archives: usize) {
        use std::sync::atomic::Ordering::Relaxed;
        self.files_total.store(files as u64, Relaxed);
        self.archives_total.store(archives as u64, Relaxed);
    }

    fn file_done(&self, bytes: u64) {
        use std::sync::atomic::Ordering::Relaxed;
        self.files_done.fetch_add(1, Relaxed);
        self.bytes_done.fetch_add(bytes, Relaxed);
    }

    fn archive_done(&self, bytes: u64) {
        use std::sync::atomic::Ordering::Relaxed;
        self.archives_done.fetch_add(1, Relaxed);
        self.bytes_done.fetch_add(bytes, Relaxed);
    }
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            max_file_bytes: DEFAULT_MAX_FILE_BYTES,
            parse_timeout: DEFAULT_PARSE_TIMEOUT,
            include_dependencies: false,
            max_archive_bytes: DEFAULT_MAX_ARCHIVE_BYTES,
            max_expanded_bytes: DEFAULT_MAX_EXPANDED_BYTES,
            archive_timeout: DEFAULT_ARCHIVE_TIMEOUT,
            cache: None,
            progress: None,
        }
    }
}

/// One file handed to a collector.
#[derive(Debug, Clone, Copy)]
pub struct Artifact<'a> {
    /// Report-safe path relative to the scan root.
    pub path: &'a str,
    /// Component the artefact belongs to (see [`ComponentResolver`]).
    pub component: &'a str,
    pub bytes: &'a [u8],
}

/// Everything collectors report: cryptographic observations plus the code facts the graph needs.
#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize)]
pub struct Findings {
    pub observations: Vec<Observation>,
    pub functions: Vec<FunctionFact>,
    pub calls: Vec<CallFact>,
    pub bindings: Vec<EntryBinding>,
    pub libraries: Vec<LibraryFact>,
}

impl Findings {
    pub fn append(&mut self, mut other: Findings) {
        self.observations.append(&mut other.observations);
        self.functions.append(&mut other.functions);
        self.calls.append(&mut other.calls);
        self.bindings.append(&mut other.bindings);
        self.libraries.append(&mut other.libraries);
    }

    pub fn is_empty(&self) -> bool {
        self.observations.is_empty() && self.functions.is_empty() && self.calls.is_empty()
    }

    /// Sorts every list so output is independent of file and thread ordering.
    pub fn sort(&mut self) {
        self.observations.sort_by(|a, b| {
            (&a.location, &a.evidence, &a.finding).cmp(&(&b.location, &b.evidence, &b.finding))
        });
        self.functions.sort();
        self.functions.dedup();
        self.calls.sort();
        self.calls.dedup();
        self.bindings.sort();
        self.bindings.dedup();
        self.libraries.sort();
        self.libraries.dedup();
    }
}

pub trait Collector: Send + Sync {
    fn name(&self) -> &'static str;

    /// Cheap pre-filter on the path and the first bytes of the file.
    fn accepts(&self, path: &str, head: &[u8]) -> bool;

    /// Inspects one artefact. An `Err` is a recoverable, per-artefact failure.
    fn collect(
        &self,
        artifact: &Artifact<'_>,
        deadline: &sandbox::Deadline,
        findings: &mut Findings,
    ) -> Result<(), String>;
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
pub struct CollectionFailure {
    pub path: String,
    pub collector: String,
    pub reason: String,
}

#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanStats {
    pub files_seen: u64,
    pub files_scanned: u64,
    pub bytes_scanned: u64,
    pub skipped_too_large: u64,
    /// Files each collector inspected, keyed by collector name.
    pub by_collector: std::collections::BTreeMap<String, u64>,
    /// Files whose findings came from the incremental cache. A property of the run, not of the
    /// scanned system, so it stays out of reports (cached and uncached reports are identical).
    #[serde(skip)]
    pub cache_hits: u64,
}

#[derive(Debug, Default)]
pub struct CollectionResult {
    pub findings: Findings,
    pub failures: Vec<CollectionFailure>,
    pub stats: ScanStats,
}

/// Version of the embedded source-rule catalogue, recorded in every report.
pub fn rules_version() -> &'static str {
    source::rules::active_version()
}

/// The standard collector set.
pub fn default_collectors() -> Result<Vec<Box<dyn Collector>>, CollectorError> {
    Ok(vec![
        Box::new(source::SourceCollector::new()?),
        Box::new(binary::BinaryCollector::new()),
        Box::new(pki::PkiCollector::new()),
        Box::new(config::ConfigCollector::new()?),
        Box::new(trace::TraceCollector::new()),
    ])
}

/// Walks `target` and runs every accepting collector on every file, in parallel. The result is
/// sorted and therefore identical across runs regardless of thread scheduling.
pub fn collect_target(
    target: &Path,
    collectors: &[Box<dyn Collector>],
    options: &ScanOptions,
) -> Result<CollectionResult, CollectorError> {
    let progress = options.progress.as_deref();
    if let Some(progress) = progress {
        progress.set_phase(Phase::Listing);
    }
    let listing = walk::list_files(target, options)?;
    let resolver =
        ComponentResolver::from_paths(listing.files.iter().map(|file| file.report_path.as_str()));
    if let Some(progress) = progress {
        progress.totals(listing.files.len(), listing.archives.len());
        progress.set_phase(Phase::Collecting);
    }

    let mut per_file: Vec<(Findings, Vec<CollectionFailure>, ScanStats)> = listing
        .files
        .par_iter()
        .map(|file| {
            let scanned = scan_file(file, &resolver, collectors, options);
            if let Some(progress) = progress {
                progress.file_done(scanned.2.bytes_scanned);
            }
            scanned
        })
        .collect();
    // images, tarballs and captures are streamed by their own scanners
    per_file.extend(
        listing
            .archives
            .par_iter()
            .map(|file| {
                let component = resolver.component_of(&file.report_path);
                let scanned = if capture::is_capture(&file.report_path) {
                    capture::scan_capture(&file.path, &file.report_path, &component, options)
                } else {
                    container::scan_archive(
                        &file.path,
                        &file.report_path,
                        &component,
                        collectors,
                        options,
                    )
                };
                if let Some(progress) = progress {
                    progress.archive_done(scanned.2.bytes_scanned);
                }
                scanned
            })
            .collect::<Vec<_>>(),
    );

    let mut result = CollectionResult::default();
    result.stats.files_seen =
        (listing.files.len() + listing.archives.len() + listing.skipped_too_large.len()) as u64;
    result.stats.skipped_too_large = listing.skipped_too_large.len() as u64;
    for path in listing.skipped_too_large {
        result.failures.push(CollectionFailure {
            path,
            collector: "walker".into(),
            reason: "file exceeds its size safety limit; not parsed".into(),
        });
    }
    for failure in listing.unreadable {
        result.failures.push(failure);
    }
    for (findings, failures, stats) in per_file {
        result.findings.append(findings);
        result.failures.extend(failures);
        result.stats.files_scanned += stats.files_scanned;
        result.stats.bytes_scanned += stats.bytes_scanned;
        result.stats.cache_hits += stats.cache_hits;
        for (name, count) in stats.by_collector {
            *result.stats.by_collector.entry(name).or_default() += count;
        }
    }
    result.findings.sort();
    result.failures.sort();
    Ok(result)
}

/// Runs the collectors over one in-memory artefact. Used for files and, by the container
/// collector, for files inside image layers.
pub fn scan_bytes(
    artifact: &Artifact<'_>,
    collectors: &[Box<dyn Collector>],
    options: &ScanOptions,
) -> (Findings, Vec<CollectionFailure>, ScanStats) {
    let mut findings = Findings::default();
    let mut failures = Vec::new();
    let mut stats = ScanStats::default();
    let head = &artifact.bytes[..artifact.bytes.len().min(512)];
    let mut scanned = false;
    for collector in collectors {
        if !collector.accepts(artifact.path, head) {
            continue;
        }
        scanned = true;
        *stats
            .by_collector
            .entry(collector.name().to_owned())
            .or_default() += 1;
        match sandbox::isolate(options.parse_timeout, |deadline| {
            let mut local = Findings::default();
            collector
                .collect(artifact, deadline, &mut local)
                .map(|()| local)
        }) {
            Ok(local) => findings.append(local),
            Err(reason) => failures.push(CollectionFailure {
                path: artifact.path.to_owned(),
                collector: collector.name().to_owned(),
                reason,
            }),
        }
    }
    if scanned {
        stats.files_scanned = 1;
        stats.bytes_scanned = artifact.bytes.len() as u64;
    }
    (findings, failures, stats)
}

fn scan_file(
    file: &walk::ListedFile,
    resolver: &ComponentResolver,
    collectors: &[Box<dyn Collector>],
    options: &ScanOptions,
) -> (Findings, Vec<CollectionFailure>, ScanStats) {
    let bytes = match walk::read_bounded(&file.path, options.max_file_bytes) {
        Ok(bytes) => bytes,
        Err(reason) => {
            return (
                Findings::default(),
                vec![CollectionFailure {
                    path: file.report_path.clone(),
                    collector: "walker".into(),
                    reason,
                }],
                ScanStats::default(),
            );
        }
    };
    let component = resolver.component_of(&file.report_path);
    let artifact = Artifact {
        path: &file.report_path,
        component: &component,
        bytes: &bytes,
    };
    let Some(cache) = &options.cache else {
        return scan_bytes(&artifact, collectors, options);
    };
    let key = cache.key(&file.report_path, &component, &bytes);
    if let Some(entry) = cache.get(&key) {
        let stats = entry.stats();
        return (entry.findings, Vec::new(), stats);
    }
    let (findings, failures, stats) = scan_bytes(&artifact, collectors, options);
    // clean results of files some collector read; nothing is saved by caching the rest
    if failures.is_empty() && stats.files_scanned > 0 {
        let entry = cache::Entry {
            findings,
            files_scanned: stats.files_scanned,
            bytes_scanned: stats.bytes_scanned,
            by_collector: stats.by_collector.clone(),
        };
        cache.put(&key, &entry);
        return (entry.findings, failures, stats);
    }
    (findings, failures, stats)
}
