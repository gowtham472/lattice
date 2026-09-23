//! The incremental cache returns exactly what a fresh scan produces, and only reuses what is
//! provably unchanged.

use lattice_collectors::cache::Cache;
use lattice_collectors::{CollectionResult, ScanOptions, collect_target, default_collectors};
use std::fs;
use std::path::Path;
use std::sync::Arc;

fn project(root: &Path) {
    fs::create_dir_all(root.join("app")).unwrap();
    fs::write(root.join("app/a.py"), "import hashlib\nhashlib.md5(b'x')\n").unwrap();
    fs::write(
        root.join("app/b.py"),
        "import hashlib\nhashlib.sha1(b'x')\n",
    )
    .unwrap();
    fs::write(
        root.join("nginx.conf"),
        "server {\n  listen 443 ssl;\n  ssl_protocols TLSv1 TLSv1.2;\n}\n",
    )
    .unwrap();
    fs::write(root.join("README.md"), "no crypto here\n").unwrap();
}

fn scan(target: &Path, cache: Option<Arc<Cache>>) -> CollectionResult {
    let collectors = default_collectors().unwrap();
    let options = ScanOptions {
        cache,
        ..ScanOptions::default()
    };
    collect_target(target, &collectors, &options).unwrap()
}

fn serialised(result: &CollectionResult) -> String {
    serde_json::to_string(&result.findings).unwrap()
}

#[test]
fn cached_scans_are_identical_and_only_rescan_what_changed() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("target");
    project(&target);
    let cache = Arc::new(Cache::with_fingerprint(&dir.path().join("cache"), b"build-1").unwrap());

    let fresh = scan(&target, None);
    let first = scan(&target, Some(cache.clone()));
    assert_eq!(first.stats.cache_hits, 0);
    assert_eq!(
        serialised(&first),
        serialised(&fresh),
        "caching never changes results"
    );

    let second = scan(&target, Some(cache.clone()));
    assert_eq!(
        second.stats.cache_hits, fresh.stats.files_scanned,
        "every scanned file reused"
    );
    assert_eq!(serialised(&second), serialised(&fresh));
    assert_eq!(second.stats.files_scanned, fresh.stats.files_scanned);
    assert_eq!(second.stats.by_collector, fresh.stats.by_collector);

    fs::write(
        target.join("app/b.py"),
        "import hashlib\nhashlib.sha256(b'x')\n",
    )
    .unwrap();
    let third = scan(&target, Some(cache.clone()));
    assert_eq!(
        third.stats.cache_hits,
        fresh.stats.files_scanned - 1,
        "the edited file is rescanned"
    );
    let ids: Vec<String> = third
        .findings
        .observations
        .iter()
        .filter(|o| o.finding.dependencies().is_empty())
        .map(|o| o.finding.display_name())
        .collect();
    assert!(
        ids.iter().any(|n| n == "SHA-256") && !ids.iter().any(|n| n == "SHA-1"),
        "{ids:?}"
    );
}

#[test]
fn another_build_never_reuses_entries() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("target");
    project(&target);
    let cache_dir = dir.path().join("cache");
    scan(
        &target,
        Some(Arc::new(
            Cache::with_fingerprint(&cache_dir, b"build-1").unwrap(),
        )),
    );
    let other = scan(
        &target,
        Some(Arc::new(
            Cache::with_fingerprint(&cache_dir, b"build-2").unwrap(),
        )),
    );
    assert_eq!(other.stats.cache_hits, 0);
}

#[test]
fn corrupt_entries_are_misses_not_errors() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("target");
    project(&target);
    let cache_dir = dir.path().join("cache");
    let cache = Arc::new(Cache::with_fingerprint(&cache_dir, b"build-1").unwrap());
    let fresh = scan(&target, Some(cache.clone()));
    for shard in fs::read_dir(cache_dir.join("v1")).unwrap() {
        for entry in fs::read_dir(shard.unwrap().path()).unwrap() {
            fs::write(entry.unwrap().path(), b"{ not json").unwrap();
        }
    }
    let again = scan(&target, Some(cache));
    assert_eq!(again.stats.cache_hits, 0);
    assert_eq!(serialised(&again), serialised(&fresh));
}
