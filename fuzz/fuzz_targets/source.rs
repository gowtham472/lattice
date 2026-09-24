//! Source code in every supported language through tree-sitter and the rule engine.
#![no_main]

use lattice_collectors::{fuzzing, source::SourceCollector};
use libfuzzer_sys::fuzz_target;
use std::sync::LazyLock;

const NAMES: &[&str] = &[
    "a.py", "A.java", "a.go", "a.c", "a.cpp", "a.js", "a.ts", "a.tsx", "a.rs", "a.cs",
];
static COLLECTOR: LazyLock<SourceCollector> = LazyLock::new(|| SourceCollector::new().unwrap());

fuzz_target!(|data: &[u8]| {
    let Some((&pick, bytes)) = data.split_first() else {
        return;
    };
    fuzzing::collect(&*COLLECTOR, NAMES[pick as usize % NAMES.len()], bytes);
});
