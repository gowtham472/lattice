//! Go function tables: `lattice trace` reads them from executables running on the host.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = lattice_tracer::golang::pclntab_functions(data, 0x40_1000, |_| true);
});
