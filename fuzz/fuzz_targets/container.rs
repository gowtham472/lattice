//! Container images: docker save, OCI layouts and plain tarballs, with every collector inside.
#![no_main]

use lattice_collectors::{Collector, default_collectors, fuzzing};
use libfuzzer_sys::fuzz_target;
use std::io::Write;
use std::sync::LazyLock;

static COLLECTORS: LazyLock<Vec<Box<dyn Collector>>> =
    LazyLock::new(|| default_collectors().unwrap());

fuzz_target!(|data: &[u8]| {
    // the scanner streams the archive several times, so it reads from a file
    let mut file = tempfile::Builder::new().suffix(".tar").tempfile().unwrap();
    file.write_all(data).unwrap();
    fuzzing::archive(file.path(), &COLLECTORS);
});
