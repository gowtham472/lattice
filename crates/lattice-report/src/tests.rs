use super::*;
use std::path::Path;
use std::sync::OnceLock;

const TIMESTAMP: i64 = 1_790_121_600; // 2026-09-23T00:00:00Z

/// The demo estate's report, as `lattice scan --report` writes it.
fn demo_report() -> &'static [u8] {
    static REPORT: OnceLock<Vec<u8>> = OnceLock::new();
    REPORT.get_or_init(|| {
        let estate = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/demo-estate");
        let mut config = lattice_engine::Config::new(TIMESTAMP);
        config.subject = Some("demo-estate".into());
        let outcome = lattice_engine::run(&estate, &config).unwrap();
        serde_json::to_vec_pretty(&outcome.report).unwrap()
    })
}

fn contains(haystack: &[u8], needle: &str) -> bool {
    let needle = pdf::encode(needle);
    haystack
        .windows(needle.len())
        .any(|w| w == needle.as_slice())
}

fn find(haystack: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    haystack[from..]
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|i| i + from)
}

#[test]
fn rendering_is_deterministic() {
    let first = executive_pdf(demo_report()).unwrap();
    let second = executive_pdf(demo_report()).unwrap();
    assert_eq!(first, second, "the same report always gives the same bytes");

    let mut other: serde_json::Value = serde_json::from_slice(demo_report()).unwrap();
    other["subject"] = "another-estate".into();
    let other = executive_pdf(&serde_json::to_vec_pretty(&other).unwrap()).unwrap();
    assert_ne!(first, other);
}

#[test]
fn the_file_is_well_formed() {
    let pdf = executive_pdf(demo_report()).unwrap();
    assert!(pdf.starts_with(b"%PDF-1.7\n"));
    assert!(pdf.ends_with(b"%%EOF\n"));

    // startxref points at the cross-reference table
    let tail = String::from_utf8_lossy(&pdf[pdf.len() - 64..]).into_owned();
    let start: usize = tail
        .split("startxref\n")
        .nth(1)
        .and_then(|rest| rest.lines().next())
        .and_then(|n| n.parse().ok())
        .unwrap();
    assert!(pdf[start..].starts_with(b"xref\n0 "));

    // every in-use entry points at the object it names
    let table = String::from_utf8_lossy(&pdf[start..]).into_owned();
    let entries: Vec<&str> = table
        .lines()
        .skip(3)
        .take_while(|l| l.ends_with(" n "))
        .collect();
    assert!(entries.len() > 8);
    for (i, entry) in entries.iter().enumerate() {
        let offset: usize = entry[..10].parse().unwrap();
        let header = format!("{} 0 obj\n", i + 1);
        assert!(
            pdf[offset..].starts_with(header.as_bytes()),
            "object {} is not at {offset}",
            i + 1
        );
    }

    // every stream's declared length is its real length
    let mut from = 0;
    let mut streams = 0;
    while let Some(at) = find(&pdf, b"/Length ", from) {
        let digits: String = pdf[at + 8..]
            .iter()
            .take_while(|b| b.is_ascii_digit())
            .map(|b| *b as char)
            .collect();
        let length: usize = digits.parse().unwrap();
        let body = find(&pdf, b"stream\n", at).unwrap() + 7;
        assert!(pdf[body + length..].starts_with(b"\nendstream"));
        streams += 1;
        from = body + length;
    }
    assert!(
        streams >= 2,
        "one content stream per page, at least two pages"
    );
}

#[test]
fn it_carries_the_findings_the_plan_and_the_inputs() {
    let pdf = executive_pdf(demo_report()).unwrap();
    let report: serde_json::Value = serde_json::from_slice(demo_report()).unwrap();
    for text in [
        "Quantum-readiness executive report",
        "demo-estate",
        "Key findings",
        "Where the risk is",
        "Plan against the national timeline",
        "India DST critical-infrastructure migration, 2027–2029",
        "Fix first",
        "Method and inputs",
        "Page 1 of",
    ] {
        assert!(contains(&pdf, text), "{text} missing");
    }
    let vulnerable = report["summary"]["quantumVulnerable"].as_u64().unwrap();
    assert!(contains(&pdf, &format!("{vulnerable} of the")));
    let digest = blake3::hash(demo_report()).to_hex().to_string();
    assert!(
        contains(&pdf, &digest),
        "the source report's digest is printed"
    );
    assert!(contains(&pdf, "/CreationDate (D:20260923000000Z)"));
}

#[test]
fn only_lattice_reports_are_accepted() {
    assert!(matches!(
        executive_pdf(b"not json"),
        Err(ReportError::Parse(_))
    ));
    let mut report: serde_json::Value = serde_json::from_slice(demo_report()).unwrap();
    report["format"] = "lattice-report/99".into();
    assert!(matches!(
        executive_pdf(&serde_json::to_vec(&report).unwrap()),
        Err(ReportError::Format(_))
    ));
}

#[test]
fn text_is_measured_and_wrapped_within_bounds() {
    // Helvetica: "A" is 667/1000 em
    assert!((pdf::text_width("A", Font::Regular, 10.0) - 6.67).abs() < 1e-3);
    assert!((pdf::text_width("A", Font::Mono, 10.0) - 6.0).abs() < 1e-3);
    let long =
        "registry.example.gov.in/payments-api:4.2.0 replace hybrid X25519 + ML-KEM-768 (FIPS 203)";
    for width in [40.0, 90.0, 200.0] {
        let lines = wrap(long, Font::Regular, 9.0, width);
        assert!(lines.len() > 1);
        for line in &lines {
            assert!(
                pdf::text_width(line, Font::Regular, 9.0) <= width,
                "{line:?} wider than {width}"
            );
        }
        assert_eq!(
            lines.concat().replace(' ', ""),
            long.replace(' ', ""),
            "nothing is lost"
        );
    }
    assert_eq!(pdf::encode("a → b ≥ c · d"), b"a -> b >= c \xB7 d");
    assert_eq!(
        fit("abcdefghijklmnop", Font::Regular, 10.0, 30.0)
            .chars()
            .last(),
        Some('…')
    );
}
