//! The DER and OpenSSH key decoders on raw bytes.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| lattice_collectors::fuzzing::keys(data));
