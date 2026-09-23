//! Enumerating the scan target safely, and deciding which component each file belongs to.

use crate::{CollectionFailure, CollectorError, ScanOptions};
use lattice_core::report_path;
use std::collections::BTreeSet;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use walkdir::{DirEntry, WalkDir};

/// Directories that never contain first-party cryptography worth parsing.
const ALWAYS_SKIPPED: &[&str] = &[
    ".git",
    ".hg",
    ".svn",
    ".lattice",
    "target",
    ".gradle",
    ".idea",
    ".vscode",
    "__pycache__",
    ".tox",
    ".mypy_cache",
];
/// Third-party dependency trees, skipped unless `include_dependencies` is set.
const DEPENDENCY_DIRS: &[&str] = &[
    "node_modules",
    "vendor",
    "bower_components",
    ".venv",
    "venv",
    "site-packages",
];

/// Files whose presence marks the root of a separately built and deployed component.
const MANIFESTS: &[&str] = &[
    "Cargo.toml",
    "package.json",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "go.mod",
    "pyproject.toml",
    "setup.py",
    "setup.cfg",
    "requirements.txt",
    "composer.json",
    "Gemfile",
    "CMakeLists.txt",
    "meson.build",
    "Package.swift",
    "mix.exs",
    "Dockerfile",
    "Chart.yaml",
];

pub(crate) struct ListedFile {
    pub path: PathBuf,
    pub report_path: String,
}

pub(crate) struct Listing {
    pub files: Vec<ListedFile>,
    /// Image archives, tarballs and packet captures, streamed by their own scanners.
    pub archives: Vec<ListedFile>,
    pub skipped_too_large: Vec<String>,
    pub unreadable: Vec<CollectionFailure>,
}

pub(crate) fn list_files(target: &Path, options: &ScanOptions) -> Result<Listing, CollectorError> {
    let metadata = std::fs::symlink_metadata(target)
        .map_err(|_| CollectorError::TargetNotFound(target.to_owned()))?;
    if !metadata.is_file() && !metadata.is_dir() {
        return Err(CollectorError::InvalidTarget(target.to_owned()));
    }
    let root = if metadata.is_file() {
        target.parent().unwrap_or(Path::new("."))
    } else {
        target
    };

    let mut listing = Listing {
        files: Vec::new(),
        archives: Vec::new(),
        skipped_too_large: Vec::new(),
        unreadable: Vec::new(),
    };
    let include_dependencies = options.include_dependencies;
    // Symlinks are never followed: a link could point outside the target, or loop.
    let walker = WalkDir::new(target)
        .follow_links(false)
        .sort_by_file_name()
        .into_iter()
        .filter_entry(|entry| should_visit(entry, include_dependencies));
    for entry in walker {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                let path = error
                    .path()
                    .map_or_else(|| ".".to_owned(), |path| report_path(root, path));
                listing.unreadable.push(CollectionFailure {
                    path,
                    collector: "walker".into(),
                    reason: "directory entry could not be read".into(),
                });
                continue;
            }
        };
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.into_path();
        let report = report_path(root, &path);
        let streamed = crate::container::is_archive(&report) || crate::capture::is_capture(&report);
        let limit = if streamed {
            options.max_archive_bytes
        } else {
            options.max_file_bytes
        };
        match std::fs::symlink_metadata(&path) {
            Ok(meta) if meta.len() > limit => listing.skipped_too_large.push(report),
            Ok(_) if streamed => listing.archives.push(ListedFile {
                path,
                report_path: report,
            }),
            Ok(_) => listing.files.push(ListedFile {
                path,
                report_path: report,
            }),
            Err(_) => listing.unreadable.push(CollectionFailure {
                path: report,
                collector: "walker".into(),
                reason: "file metadata could not be read".into(),
            }),
        }
    }
    Ok(listing)
}

fn should_visit(entry: &DirEntry, include_dependencies: bool) -> bool {
    if entry.depth() == 0 || !entry.file_type().is_dir() {
        return true;
    }
    let name = entry.file_name().to_string_lossy();
    if ALWAYS_SKIPPED.contains(&name.as_ref()) {
        return false;
    }
    include_dependencies || !DEPENDENCY_DIRS.contains(&name.as_ref())
}

/// Reads at most `limit` bytes. A file that grew past the limit after it was listed is refused
/// rather than truncated, so a partially parsed file can never be mistaken for a whole one.
pub(crate) fn read_bounded(path: &Path, limit: u64) -> Result<Vec<u8>, String> {
    let file = File::open(path).map_err(|error| format!("could not open: {}", error.kind()))?;
    let mut bytes = Vec::new();
    file.take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("could not read: {}", error.kind()))?;
    if bytes.len() as u64 > limit {
        return Err(format!(
            "file grew past the {limit} byte safety limit while being read"
        ));
    }
    Ok(bytes)
}

/// Maps each file to the component that owns it: the deepest directory above it that contains
/// a build or deployment manifest, or `.` for the scan root.
#[derive(Debug, Default, Clone)]
pub struct ComponentResolver {
    roots: BTreeSet<String>,
    /// The scan covers an estate (sub-projects with manifests, none at the top): a top-level
    /// directory without its own manifest is then a component too (`gateway/`, `infra/`),
    /// rather than being folded into an anonymous root.
    estate: bool,
}

impl ComponentResolver {
    pub fn from_paths<'a>(paths: impl IntoIterator<Item = &'a str>) -> Self {
        let roots: BTreeSet<String> = paths
            .into_iter()
            .filter_map(|path| {
                let (directory, file) = path.rsplit_once('/').unwrap_or((".", path));
                MANIFESTS.contains(&file).then(|| directory.to_owned())
            })
            .collect();
        let estate = !roots.is_empty() && !roots.contains(".");
        Self { roots, estate }
    }

    pub fn component_of(&self, path: &str) -> String {
        let mut directory = path
            .rsplit_once('/')
            .map_or(".", |(directory, _)| directory);
        loop {
            if self.roots.contains(directory) {
                return directory.to_owned();
            }
            match directory.rsplit_once('/') {
                Some((parent, _)) => directory = parent,
                None if directory != "." => {
                    if self.estate {
                        return directory.to_owned();
                    }
                    directory = ".";
                }
                None => return ".".to_owned(),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn components_are_the_deepest_manifest_directory() {
        let resolver = ComponentResolver::from_paths([
            "services/payments/pom.xml",
            "services/payments/src/main/java/Pay.java",
            "services/identity/go.mod",
            "tools/script.py",
            "Cargo.toml",
        ]);
        assert_eq!(
            resolver.component_of("services/payments/src/main/java/Pay.java"),
            "services/payments"
        );
        assert_eq!(
            resolver.component_of("services/identity/cmd/main.go"),
            "services/identity"
        );
        assert_eq!(resolver.component_of("tools/script.py"), ".");
        assert_eq!(resolver.component_of("README.md"), ".");
    }

    #[test]
    fn estates_make_each_top_level_directory_a_component() {
        let resolver = ComponentResolver::from_paths([
            "payments-api/requirements.txt",
            "payments-api/app/server.py",
            "gateway/nginx.conf",
            "infra/aws/kms.tf",
            "README.md",
        ]);
        assert_eq!(
            resolver.component_of("payments-api/app/server.py"),
            "payments-api"
        );
        assert_eq!(resolver.component_of("gateway/nginx.conf"), "gateway");
        assert_eq!(resolver.component_of("infra/aws/kms.tf"), "infra");
        assert_eq!(
            resolver.component_of("README.md"),
            ".",
            "top-level files stay in the root"
        );
    }

    #[test]
    fn a_scan_without_manifests_is_one_component() {
        let resolver = ComponentResolver::from_paths(["a.py", "b/c.py"]);
        assert_eq!(resolver.component_of("b/c.py"), ".");
    }

    #[test]
    fn bounded_reads_refuse_oversized_files() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("big.bin");
        std::fs::write(&path, vec![0u8; 100]).unwrap();
        assert!(read_bounded(&path, 99).is_err());
        assert_eq!(read_bounded(&path, 100).unwrap().len(), 100);
    }
}
