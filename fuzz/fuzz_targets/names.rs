//! Algorithm, group, curve and JCA transformation names as they appear in code and config.
#![no_main]

use lattice_core::names;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|text: &str| {
    let _ = names::resolve(text);
    let _ = names::resolve_group(text);
    let _ = names::resolve_curve(text);
    let _ = names::resolve_jca_cipher(text);
    let _ = lattice_core::knowledge::normalize_token(text);
});
