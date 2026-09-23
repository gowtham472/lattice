//! LATTICE core: the domain model, the algorithm knowledge base, algorithm-name parsing and
//! normalisation. Dependency-light by design: every other crate builds on these types.

pub mod knowledge;
pub mod model;
pub mod names;
pub mod normalize;
pub mod policy;

pub use knowledge::{
    AlgorithmRef, AlgorithmSpec, ClassicalStatus, CryptoFunction, Params, Primitive, QuantumClass,
    Registry, Strength,
};
pub use model::*;
pub use normalize::normalize;

use std::path::{Component, Path};

/// CycloneDX specification version LATTICE emits.
pub const CBOM_SPEC_VERSION: &str = "1.6";

/// Converts a path to a stable, report-safe form: relative to the scan root, `/`-separated,
/// with no root, drive prefix or `..` that could reveal or escape the host layout.
pub fn report_path(root: &Path, path: &Path) -> String {
    let relative = path.strip_prefix(root).unwrap_or(path);
    let parts: Vec<_> = relative
        .components()
        .filter_map(|component| match component {
            Component::Normal(value) => Some(value.to_string_lossy().into_owned()),
            Component::ParentDir => Some("_parent_".to_owned()),
            _ => None,
        })
        .collect();
    if parts.is_empty() {
        ".".to_owned()
    } else {
        parts.join("/")
    }
}

/// Formats Unix seconds as an RFC 3339 UTC timestamp (proleptic Gregorian, civil-from-days).
pub fn rfc3339(seconds: i64) -> String {
    let days = seconds.div_euclid(86_400);
    let secs = seconds.rem_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        secs / 3600,
        (secs % 3600) / 60,
        secs % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_paths_do_not_leak_root() {
        let root = Path::new("/secret/project");
        assert_eq!(
            report_path(root, Path::new("/secret/project/src/main.rs")),
            "src/main.rs"
        );
        assert_eq!(
            report_path(root, Path::new("/elsewhere/../x")),
            "elsewhere/_parent_/x"
        );
    }

    #[test]
    fn rfc3339_conversion() {
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339(2_051_222_400), "2035-01-01T00:00:00Z");
        assert_eq!(rfc3339(-1), "1969-12-31T23:59:59Z");
    }
}
