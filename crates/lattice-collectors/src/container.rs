//! Container images and tarballs.
//!
//! Reads `docker save` archives, OCI image layouts packed as tar, and plain tarballs, each
//! optionally gzip-compressed, without ever extracting to disk. For images the layers are applied
//! in order with OCI whiteout semantics, so a file deleted by a later layer is not reported: only
//! what a container started from the image would actually contain. Every regular file in that
//! final view is handed to the ordinary collectors, and the OS package database (dpkg, apk) is
//! read to identify cryptographic libraries by package version.
//!
//! The archive is streamed three times (index, layer listing, scan) rather than held in memory.
//! Hostile archives are bounded: expanded bytes, entries per layer, index size and wall time all
//! have limits, and a zstd layer (not supported offline here) is reported, never guessed at.

use crate::sandbox::Deadline;
use crate::{
    Artifact, CollectionFailure, Collector, Findings, ScanOptions, ScanStats, binary, scan_bytes,
};
use flate2::read::GzDecoder;
use lattice_core::Location;
use serde_json::Value;
use std::collections::HashMap;
use std::fs::File;
use std::io::{self, BufReader, Read};
use std::path::Path;

const MAX_INDEX_ENTRY_BYTES: u64 = 4 << 20;
const MAX_INDEX_BYTES: usize = 64 << 20;
const MAX_LAYER_ENTRIES: usize = 1_000_000;
const MAX_PATHS: usize = 4_000_000;
const DPKG_STATUS: &str = "var/lib/dpkg/status";
const APK_INSTALLED: &str = "lib/apk/db/installed";

/// File names routed to this scanner instead of the per-file collectors.
pub fn is_archive(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    [".tar", ".tar.gz", ".tgz", ".oci"]
        .iter()
        .any(|suffix| lower.ends_with(suffix))
}

/// One image inside an archive (an archive may hold several), or the archive itself when it is
/// a plain tarball.
struct Image {
    /// Component name: the first repository tag, or the archive's own name.
    name: String,
    /// Entry paths of the layers, bottom first. Empty for a plain tarball.
    layers: Vec<String>,
    config: Option<Value>,
}

/// What one layer adds and removes.
#[derive(Default)]
struct LayerListing {
    added: Vec<String>,
    whiteouts: Vec<String>,
    opaque: Vec<String>,
}

/// Scans one archive. Never panics and never runs past its time budget: failures are reported.
pub fn scan_archive(
    path: &Path,
    report: &str,
    component: &str,
    collectors: &[Box<dyn Collector>],
    options: &ScanOptions,
) -> (Findings, Vec<CollectionFailure>, ScanStats) {
    let mut failures = Vec::new();
    let result = crate::sandbox::isolate(options.archive_timeout, |deadline| {
        scan(
            path,
            report,
            component,
            collectors,
            options,
            deadline,
            &mut failures,
        )
    });
    match result {
        Ok((findings, stats)) => (findings, failures, stats),
        Err(reason) => {
            failures.push(CollectionFailure {
                path: report.to_owned(),
                collector: "container".into(),
                reason,
            });
            (Findings::default(), failures, ScanStats::default())
        }
    }
}

fn scan(
    path: &Path,
    report: &str,
    component: &str,
    collectors: &[Box<dyn Collector>],
    options: &ScanOptions,
    deadline: &Deadline,
    failures: &mut Vec<CollectionFailure>,
) -> Result<(Findings, ScanStats), String> {
    let open = || open_stream(path, options.max_expanded_bytes, deadline);

    // pass 1: small JSON documents (manifest.json, index.json, OCI manifests and configs)
    let index = read_index(open()?)?;
    let images = resolve_images(&index, path, component);

    let mut findings = Findings::default();
    let mut stats = ScanStats::default();
    let mut ctx = Context {
        report,
        collectors,
        options,
        deadline,
        findings: &mut findings,
        stats: &mut stats,
        failures,
    };

    if images.iter().all(|image| image.layers.is_empty()) {
        // a plain tarball: its entries are the filesystem
        let mut archive = tar::Archive::new(open()?);
        let entries = archive.entries().map_err(describe)?;
        let target = Target {
            component: images[0].name.clone(),
            keep: Keep::All,
        };
        scan_entries(entries, std::slice::from_ref(&target), &mut ctx)?;
        ctx.stats.by_collector.insert("container".into(), 1);
        return Ok((findings, stats));
    }

    // which entry of the archive is which layer of which image
    let mut uses: HashMap<&str, Vec<(usize, usize)>> = HashMap::new();
    for (i, image) in images.iter().enumerate() {
        for (l, layer) in image.layers.iter().enumerate() {
            uses.entry(layer.as_str()).or_default().push((i, l));
        }
    }

    // pass 2: list every layer, then apply them in order to find each path's final owner
    let mut listings: HashMap<String, LayerListing> = HashMap::new();
    let mut total_paths = 0usize;
    let mut archive = tar::Archive::new(open()?);
    for entry in archive.entries().map_err(describe)? {
        deadline.check()?;
        let entry = entry.map_err(describe)?;
        let name = normalize(&entry.path_bytes());
        if !uses.contains_key(name.as_str()) || listings.contains_key(&name) {
            continue;
        }
        let listing = list_layer(
            entry,
            options.max_expanded_bytes,
            deadline,
            &mut total_paths,
        )
        .map_err(|e| format!("layer {name}: {e}"))?;
        listings.insert(name, listing);
    }
    let owners: Vec<HashMap<String, usize>> = images
        .iter()
        .map(|image| {
            let mut owner: HashMap<String, usize> = HashMap::new();
            for (l, layer) in image.layers.iter().enumerate() {
                let Some(listing) = listings.get(layer) else {
                    continue;
                };
                for dir in &listing.opaque {
                    let prefix = format!("{dir}/");
                    owner.retain(|path, _| !path.starts_with(&prefix));
                }
                for removed in &listing.whiteouts {
                    let prefix = format!("{removed}/");
                    owner.retain(|path, _| path != removed && !path.starts_with(&prefix));
                }
                for added in &listing.added {
                    owner.insert(added.clone(), l);
                }
            }
            owner
        })
        .collect();
    for (image, missing) in images.iter().flat_map(|image| {
        image
            .layers
            .iter()
            .filter(|l| !listings.contains_key(*l))
            .map(move |l| (image, l))
    }) {
        ctx.failures.push(CollectionFailure {
            path: report.to_owned(),
            collector: "container".into(),
            reason: format!(
                "image {}: layer {missing} is referenced but not in the archive",
                image.name
            ),
        });
    }

    // image configuration: environment variables go through the configuration collector
    for image in &images {
        if let Some(env) = image
            .config
            .as_ref()
            .and_then(|c| c.pointer("/config/Env"))
            .and_then(Value::as_array)
        {
            let text: String = env
                .iter()
                .filter_map(Value::as_str)
                .map(|line| format!("{line}\n"))
                .collect();
            let path = format!("{report}!/.image-config/.env");
            let artifact = Artifact {
                path: &path,
                component: &image.name,
                bytes: text.as_bytes(),
            };
            let (found, failed, _) = scan_bytes(&artifact, collectors, options);
            ctx.findings.append(found);
            ctx.failures.extend(failed);
        }
    }

    // pass 3: scan each file in the final view of each image
    let mut archive = tar::Archive::new(open()?);
    for entry in archive.entries().map_err(describe)? {
        deadline.check()?;
        let entry = entry.map_err(describe)?;
        let name = normalize(&entry.path_bytes());
        let Some(targets) = uses.get(name.as_str()) else {
            continue;
        };
        let targets: Vec<Target<'_>> = targets
            .iter()
            .map(|&(i, layer)| Target {
                component: images[i].name.clone(),
                keep: Keep::OwnedBy {
                    owner: &owners[i],
                    layer,
                },
            })
            .collect();
        let layer = decompress(entry, options.max_expanded_bytes, deadline)
            .map_err(|e| format!("layer {name}: {e}"))?;
        let mut inner = tar::Archive::new(layer);
        let entries = inner
            .entries()
            .map_err(|e| format!("layer {name}: {}", describe(e)))?;
        scan_entries(entries, &targets, &mut ctx).map_err(|e| format!("layer {name}: {e}"))?;
    }
    ctx.stats
        .by_collector
        .insert("container".into(), images.len() as u64);
    Ok((findings, stats))
}

struct Context<'a, 'f> {
    report: &'a str,
    collectors: &'a [Box<dyn Collector>],
    options: &'a ScanOptions,
    deadline: &'a Deadline,
    findings: &'f mut Findings,
    stats: &'f mut ScanStats,
    failures: &'f mut Vec<CollectionFailure>,
}

/// Which files of a tar stream belong to an image's final filesystem.
enum Keep<'a> {
    /// A plain tarball: everything.
    All,
    /// A layer: the paths whose final owner is this layer.
    OwnedBy {
        owner: &'a HashMap<String, usize>,
        layer: usize,
    },
}

struct Target<'a> {
    component: String,
    keep: Keep<'a>,
}

impl Target<'_> {
    fn keeps(&self, path: &str) -> bool {
        match self.keep {
            Keep::All => true,
            Keep::OwnedBy { owner, layer } => owner.get(path) == Some(&layer),
        }
    }
}

/// Scans the regular files of one tar stream for each target that keeps them.
fn scan_entries<R: Read>(
    entries: tar::Entries<'_, R>,
    targets: &[Target<'_>],
    ctx: &mut Context<'_, '_>,
) -> Result<(), String> {
    for (count, entry) in entries.enumerate() {
        if count >= MAX_LAYER_ENTRIES {
            return Err(format!("more than {MAX_LAYER_ENTRIES} entries"));
        }
        if count % 256 == 0 {
            ctx.deadline.check()?;
        }
        let mut entry = entry.map_err(describe)?;
        // symlinks and hard links are never followed; devices and FIFOs have no content
        if !entry.header().entry_type().is_file() {
            continue;
        }
        let inner = normalize(&entry.path_bytes());
        if inner.is_empty() || is_whiteout(&inner) {
            continue;
        }
        let wanted: Vec<&str> = targets
            .iter()
            .filter(|t| t.keeps(&inner))
            .map(|t| t.component.as_str())
            .collect();
        if wanted.is_empty() {
            continue;
        }
        let size = entry.size();
        let path = format!("{}!/{inner}", ctx.report);
        if size > ctx.options.max_file_bytes {
            ctx.stats.skipped_too_large += 1;
            continue;
        }
        let mut bytes = Vec::with_capacity(size as usize);
        entry.read_to_end(&mut bytes).map_err(describe)?;
        ctx.stats.files_seen += 1;
        for component in wanted {
            if inner == DPKG_STATUS || inner == APK_INSTALLED {
                packages(&bytes, inner == DPKG_STATUS, &path, component, ctx.findings);
            }
            let artifact = Artifact {
                path: &path,
                component,
                bytes: &bytes,
            };
            let (found, failed, stats) = scan_bytes(&artifact, ctx.collectors, ctx.options);
            ctx.findings.append(found);
            ctx.failures.extend(failed);
            ctx.stats.files_scanned += stats.files_scanned;
            ctx.stats.bytes_scanned += stats.bytes_scanned;
            for (name, n) in stats.by_collector {
                *ctx.stats.by_collector.entry(name).or_default() += n;
            }
        }
    }
    Ok(())
}

/// Cryptographic libraries installed as OS packages.
fn packages(database: &[u8], dpkg: bool, path: &str, component: &str, findings: &mut Findings) {
    let text = String::from_utf8_lossy(database);
    for record in text.split("\n\n").take(100_000) {
        let field = |names: &[&str]| {
            record.lines().find_map(|line| {
                names
                    .iter()
                    .find_map(|name| line.strip_prefix(name))
                    .map(str::trim)
            })
        };
        let (name, version) = if dpkg {
            // only packages actually installed, not ones removed with config left behind
            if field(&["Status:"]).is_some_and(|s| !s.ends_with(" installed")) {
                continue;
            }
            (field(&["Package:"]), field(&["Version:"]))
        } else {
            (field(&["P:"]), field(&["V:"]))
        };
        if let (Some(name), Some(version)) = (name, version)
            && let Some(library) =
                binary::package_library(name, version, component, Location::file(path))
        {
            findings.libraries.push(library);
        }
    }
}

// ---- archive structure ---------------------------------------------------------------------

fn read_index<R: Read>(stream: R) -> Result<HashMap<String, Value>, String> {
    let mut documents = HashMap::new();
    let mut total = 0usize;
    let mut archive = tar::Archive::new(stream);
    for entry in archive.entries().map_err(describe)? {
        let mut entry = entry.map_err(describe)?;
        let size = entry.size();
        if !entry.header().entry_type().is_file()
            || size > MAX_INDEX_ENTRY_BYTES
            || total + size as usize > MAX_INDEX_BYTES
        {
            continue;
        }
        let name = normalize(&entry.path_bytes());
        let mut first = [0u8; 1];
        if entry.read(&mut first).map_err(describe)? == 0 || !matches!(first[0], b'{' | b'[') {
            continue;
        }
        let mut bytes = vec![first[0]];
        entry.read_to_end(&mut bytes).map_err(describe)?;
        total += bytes.len();
        if let Ok(value) = serde_json::from_slice::<Value>(&bytes) {
            documents.insert(name, value);
        }
    }
    Ok(documents)
}

/// The images an archive holds: Docker's `manifest.json`, else the OCI `index.json`, else none
/// (a plain tarball).
fn resolve_images(index: &HashMap<String, Value>, archive: &Path, component: &str) -> Vec<Image> {
    let fallback = || {
        let file = archive
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let stem = [".tar.gz", ".tgz", ".tar", ".oci"]
            .iter()
            .find_map(|suffix| file.strip_suffix(suffix))
            .unwrap_or(&file)
            .to_owned();
        if component == "." {
            stem
        } else {
            format!("{component}/{stem}")
        }
    };
    if let Some(manifests) = index.get("manifest.json").and_then(Value::as_array) {
        let images: Vec<Image> = manifests
            .iter()
            .filter_map(|m| {
                let layers: Vec<String> = m
                    .get("Layers")?
                    .as_array()?
                    .iter()
                    .filter_map(Value::as_str)
                    .map(|l| normalize(l.as_bytes()))
                    .collect();
                let name = m
                    .get("RepoTags")
                    .and_then(Value::as_array)
                    .and_then(|t| t.first())
                    .and_then(Value::as_str)
                    .map_or_else(fallback, sanitize);
                let config = m
                    .get("Config")
                    .and_then(Value::as_str)
                    .and_then(|c| index.get(&normalize(c.as_bytes())))
                    .cloned();
                Some(Image {
                    name,
                    layers,
                    config,
                })
            })
            .collect();
        if !images.is_empty() {
            return images;
        }
    }
    if let Some(descriptors) = index
        .get("index.json")
        .and_then(|i| i.get("manifests"))
        .and_then(Value::as_array)
    {
        let blob = |digest: &str| {
            digest
                .split_once(':')
                .map(|(algorithm, hex)| format!("blobs/{algorithm}/{hex}"))
        };
        let images: Vec<Image> = descriptors
            .iter()
            .filter_map(|descriptor| {
                let manifest = index.get(&blob(descriptor.get("digest")?.as_str()?)?)?;
                let layers: Vec<String> = manifest
                    .get("layers")?
                    .as_array()?
                    .iter()
                    .filter_map(|l| blob(l.get("digest")?.as_str()?))
                    .collect();
                let config = manifest
                    .pointer("/config/digest")
                    .and_then(Value::as_str)
                    .and_then(blob)
                    .and_then(|c| index.get(&c))
                    .cloned();
                let name = [
                    "org.opencontainers.image.ref.name",
                    "io.containerd.image.name",
                ]
                .iter()
                .find_map(|key| {
                    descriptor
                        .pointer(&format!("/annotations/{}", key.replace('/', "~1")))
                        .and_then(Value::as_str)
                })
                .map_or_else(fallback, sanitize);
                Some(Image {
                    name,
                    layers,
                    config,
                })
            })
            .collect();
        if !images.is_empty() {
            return images;
        }
    }
    vec![Image {
        name: fallback(),
        layers: Vec::new(),
        config: None,
    }]
}

fn list_layer<R: Read>(
    entry: tar::Entry<'_, R>,
    limit: u64,
    deadline: &Deadline,
    total: &mut usize,
) -> Result<LayerListing, String> {
    let mut listing = LayerListing::default();
    let mut inner = tar::Archive::new(decompress(entry, limit, deadline)?);
    for (count, entry) in inner.entries().map_err(describe)?.enumerate() {
        if count >= MAX_LAYER_ENTRIES {
            return Err(format!("more than {MAX_LAYER_ENTRIES} entries"));
        }
        if count % 256 == 0 {
            deadline.check()?;
        }
        let entry = entry.map_err(describe)?;
        let path = normalize(&entry.path_bytes());
        if path.is_empty() {
            continue;
        }
        *total += 1;
        if *total > MAX_PATHS {
            return Err(format!("image has more than {MAX_PATHS} paths"));
        }
        let (dir, file) = path.rsplit_once('/').unwrap_or(("", path.as_str()));
        if file == ".wh..wh..opq" {
            listing.opaque.push(dir.to_owned());
        } else if let Some(removed) = file.strip_prefix(".wh.") {
            listing.whiteouts.push(if dir.is_empty() {
                removed.to_owned()
            } else {
                format!("{dir}/{removed}")
            });
        } else if entry.header().entry_type().is_file() {
            listing.added.push(path);
        }
    }
    Ok(listing)
}

fn is_whiteout(path: &str) -> bool {
    path.rsplit('/')
        .next()
        .is_some_and(|file| file.starts_with(".wh."))
}

/// Archive-relative path: no leading `./` or `/`, and nothing that climbs out with `..`.
fn normalize(raw: &[u8]) -> String {
    let text = String::from_utf8_lossy(raw);
    let parts: Vec<&str> = text
        .split('/')
        .filter(|p| !p.is_empty() && *p != ".")
        .collect();
    if parts.contains(&"..") {
        return String::new();
    }
    parts.join("/")
}

/// Image names go into asset identities and report text: keep them printable and short.
fn sanitize(name: &str) -> String {
    name.chars()
        .filter(|c| c.is_ascii_graphic())
        .take(128)
        .collect()
}

fn describe(error: io::Error) -> String {
    error.to_string()
}

// ---- streams -------------------------------------------------------------------------------

/// Opens the archive, gunzipping it if needed, behind the expansion and time budget.
fn open_stream<'d>(
    path: &Path,
    limit: u64,
    deadline: &'d Deadline,
) -> Result<Budget<'d, Box<dyn Read>>, String> {
    let mut file =
        BufReader::new(File::open(path).map_err(|e| format!("could not open: {}", e.kind()))?);
    let magic = {
        use std::io::BufRead;
        file.fill_buf()
            .map_err(describe)?
            .get(..2)
            .map(<[u8]>::to_vec)
            .unwrap_or_default()
    };
    let stream: Box<dyn Read> = if magic == [0x1f, 0x8b] {
        Box::new(GzDecoder::new(file))
    } else {
        Box::new(file)
    };
    Ok(Budget {
        inner: stream,
        left: limit,
        deadline,
    })
}

/// A layer blob: plain tar or gzip, behind its own expansion and time budget. Other
/// compressions are refused by name.
fn decompress<'a, R: Read + 'a>(
    entry: R,
    limit: u64,
    deadline: &'a Deadline,
) -> Result<Box<dyn Read + 'a>, String> {
    let mut reader = io::BufReader::new(entry);
    let magic = {
        use std::io::BufRead;
        reader
            .fill_buf()
            .map_err(describe)?
            .get(..4)
            .map(<[u8]>::to_vec)
            .unwrap_or_default()
    };
    let stream: Box<dyn Read + 'a> = match magic.as_slice() {
        [0x1f, 0x8b, ..] => Box::new(GzDecoder::new(reader)),
        [0x28, 0xb5, 0x2f, 0xfd] => {
            return Err("zstd-compressed layer: not supported; convert with `skopeo copy --dest-compress-format gzip`".into());
        }
        _ => Box::new(reader),
    };
    Ok(Box::new(Budget {
        inner: stream,
        left: limit,
        deadline,
    }))
}

/// Fails reads past a byte budget (decompression bombs) or a deadline.
struct Budget<'d, R> {
    inner: R,
    left: u64,
    deadline: &'d Deadline,
}

impl<R: Read> Read for Budget<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.deadline.expired() {
            return Err(io::Error::other("archive exceeded its time budget"));
        }
        let n = self.inner.read(buf)?;
        self.left = self
            .left
            .checked_sub(n as u64)
            .ok_or_else(|| io::Error::other("archive expands beyond the size limit"))?;
        Ok(n)
    }
}

#[cfg(test)]
mod tests;
