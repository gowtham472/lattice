//! ELF, PE and Mach-O files through the binary collector.
#![no_main]

use lattice_collectors::{binary::BinaryCollector, fuzzing};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    fuzzing::collect(&BinaryCollector::new(), "fuzz.bin", data);
});
