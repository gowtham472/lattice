//! pcap and pcapng captures: packet reassembly and the TLS and SSH handshake parsers.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| lattice_collectors::fuzzing::capture(data));
