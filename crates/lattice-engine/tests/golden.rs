//! The CBOM of the demo estate, byte for byte.
//!
//! Any change to what LATTICE finds, how it scores it or how it writes CycloneDX shows up here as
//! a diff against `golden/demo-estate.cbom.json`. When a change is intended, regenerate the file
//! with `LATTICE_BLESS=1 cargo test -p lattice-engine --test golden` and review the diff like code.

use lattice_engine::{Config, run};
use std::path::Path;

const TIMESTAMP: i64 = 1_790_121_600; // 2026-09-23T00:00:00Z

#[test]
fn demo_estate_cbom_matches_the_golden_file() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let estate = root.join("../../examples/demo-estate");
    let golden = root.join("tests/golden/demo-estate.cbom.json");

    let mut config = Config::new(TIMESTAMP);
    config.subject = Some("demo-estate".into());
    let outcome = run(&estate, &config).unwrap();
    assert!(
        outcome.report.failures.is_empty(),
        "{:?}",
        outcome.report.failures
    );
    let actual = lattice_cbom::render(&outcome.cbom);

    if std::env::var_os("LATTICE_BLESS").is_some() {
        std::fs::write(&golden, &actual).unwrap();
        return;
    }
    let expected =
        std::fs::read(&golden).expect("golden file present; bless it with LATTICE_BLESS=1");
    if actual != expected {
        let actual = String::from_utf8_lossy(&actual);
        let expected = String::from_utf8_lossy(&expected);
        let first = actual
            .lines()
            .zip(expected.lines())
            .position(|(a, e)| a != e)
            .unwrap_or_else(|| actual.lines().count().min(expected.lines().count()));
        let context = |text: &str| {
            text.lines()
                .skip(first.saturating_sub(3))
                .take(7)
                .collect::<Vec<_>>()
                .join("\n")
        };
        panic!(
            "the demo estate's CBOM changed at line {}\n--- expected\n{}\n--- actual\n{}\n\
             If intended, regenerate with LATTICE_BLESS=1 and review the diff.",
            first + 1,
            context(&expected),
            context(&actual)
        );
    }
}

#[test]
fn the_golden_cbom_is_valid_cyclonedx() {
    let golden = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/golden/demo-estate.cbom.json");
    let document: serde_json::Value =
        serde_json::from_slice(&std::fs::read(golden).unwrap()).unwrap();
    lattice_cbom::validate::validate(&document).unwrap_or_else(|found| panic!("{found:?}"));
    lattice_cbom::validate::check_references(&document).unwrap_or_else(|found| panic!("{found:?}"));
}
