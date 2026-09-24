//! `lattice trace`: observe which cryptography running processes actually ask for.
//!
//! Static scanning shows what code *can* do; this shows what it *does*. The recorder places
//! uprobes on the OpenSSL functions that select cryptography (algorithm fetches, legacy getters
//! such as `EVP_des_ede3_cbc`, RSA key generation, and the TLS group and cipher lists a program
//! configures) through the kernel's uprobe tracer in tracefs, reads the calls for a bounded
//! time, and writes an aggregated `lattice-trace/1` file for `lattice scan` to ingest.
//!
//! * **What is read:** the function called, the calling executable, and one argument: an
//!   algorithm name, a key size or a list string, fetched by the kernel from the caller's memory.
//!   Never data, keys or anything else.
//! * **Isolation:** events go to a private tracefs instance, so the global trace buffer and other
//!   tracers are untouched, and every probe is removed when recording ends (on error and Ctrl-C
//!   too).
//! * **Privilege:** defining uprobes needs root (`CAP_SYS_ADMIN`), exactly like eBPF uprobes. The
//!   plan (which functions, at which offsets) needs none: `lattice trace --dry-run` shows it.
//!
//! The kernel mechanism is the same as an eBPF uprobe, without the BPF toolchain, verifier or
//! CO-RE: the uprobe tracer's fetch arguments already read the strings needed.
//!
//! **Setup is not use.** While OpenSSL initialises (`OPENSSL_init_crypto`) it calls every legacy
//! getter, and while it builds a TLS context (`SSL_CTX_new_ex`) it fetches every cipher it
//! supports, RC4 and DES included. Entry and return probes on those two functions mark setup
//! windows per thread; calls inside them are counted as ignored, never recorded as use.

pub use lattice_collectors::trace::CallKind;
use lattice_collectors::trace::{FORMAT, Trace, TraceEvent};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

pub mod parse;
#[cfg(target_os = "linux")]
mod tracefs;

/// `SSL_CTRL_SET_GROUPS_LIST` (OpenSSL 3.x `ssl.h`): `SSL_CTX_set1_groups_list` is a macro over
/// `SSL_CTX_ctrl(ctx, 92, 0, list)`.
const SSL_CTRL_SET_GROUPS_LIST: i64 = 92;

/// A function to probe and the argument that says what it selects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Spec {
    pub function: &'static str,
    pub kind: CallKind,
    /// Zero-based index of the argument to record; `None` when the function is the answer.
    pub argument: Option<usize>,
    /// Record only calls whose argument at `.0` equals `.1` (e.g. an `SSL_CTX_ctrl` command).
    pub only_when: Option<(usize, i64)>,
}

const fn spec(function: &'static str, kind: CallKind, argument: usize) -> Spec {
    Spec {
        function,
        kind,
        argument: Some(argument),
        only_when: None,
    }
}

/// The OpenSSL 3 calls that select cryptography by name or size.
pub const SPECS: &[Spec] = &[
    spec("EVP_CIPHER_fetch", CallKind::Algorithm, 1),
    spec("EVP_MD_fetch", CallKind::Algorithm, 1),
    spec("EVP_MAC_fetch", CallKind::Algorithm, 1),
    spec("EVP_KDF_fetch", CallKind::Algorithm, 1),
    spec("EVP_SIGNATURE_fetch", CallKind::Algorithm, 1),
    spec("EVP_KEM_fetch", CallKind::Algorithm, 1),
    spec("EVP_KEYEXCH_fetch", CallKind::Algorithm, 1),
    spec("EVP_KEYMGMT_fetch", CallKind::Algorithm, 1),
    spec("EVP_ASYM_CIPHER_fetch", CallKind::Algorithm, 1),
    spec("EVP_PKEY_CTX_new_from_name", CallKind::Algorithm, 1),
    spec("EVP_PKEY_Q_keygen", CallKind::Algorithm, 2),
    spec("EVP_get_cipherbyname", CallKind::Algorithm, 0),
    spec("EVP_get_digestbyname", CallKind::Algorithm, 0),
    spec("RSA_generate_key_ex", CallKind::RsaBits, 1),
    spec("SSL_CTX_set_cipher_list", CallKind::CipherList, 1),
    spec("SSL_set_cipher_list", CallKind::CipherList, 1),
    spec("SSL_CTX_set_ciphersuites", CallKind::CipherList, 1),
    spec("SSL_set_ciphersuites", CallKind::CipherList, 1),
    Spec {
        function: "SSL_CTX_ctrl",
        kind: CallKind::Groups,
        argument: Some(3),
        only_when: Some((1, SSL_CTRL_SET_GROUPS_LIST)),
    },
    Spec {
        function: "SSL_ctrl",
        kind: CallKind::Groups,
        argument: Some(3),
        only_when: Some((1, SSL_CTRL_SET_GROUPS_LIST)),
    },
];

/// What a probe is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// A call to record.
    Call(CallKind),
    /// Entry to OpenSSL setup, where it enumerates what it supports.
    SetupEnter,
    /// Return from that setup (a return probe).
    SetupExit,
}

/// Functions whose execution is setup, not use.
const SETUP: &[&str] = &["OPENSSL_init_crypto", "SSL_CTX_new_ex"];

/// One uprobe to place.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Probe {
    pub library: PathBuf,
    /// File offset of the function's entry, as uprobes take it.
    pub offset: u64,
    pub function: String,
    pub role: Role,
    pub argument: Option<usize>,
    pub only_when: Option<(usize, i64)>,
}

impl Probe {
    /// The kind of call recorded, for probes that record.
    pub fn kind(&self) -> Option<CallKind> {
        match self.role {
            Role::Call(kind) => Some(kind),
            _ => None,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum TraceError {
    #[error("{0}: {1}")]
    Library(String, String),
    #[error("no OpenSSL library found; name one with --library")]
    NoLibrary,
    #[error("tracefs: {0}")]
    Tracefs(String),
    #[error("recording needs root (CAP_SYS_ADMIN) to define uprobes: {0}")]
    Privilege(String),
    #[error("runtime tracing is only available on Linux")]
    Unsupported,
}

/// Where OpenSSL 3 (and 1.1) usually lives.
pub fn default_libraries() -> Vec<PathBuf> {
    let directories = [
        "/usr/lib/x86_64-linux-gnu",
        "/usr/lib/aarch64-linux-gnu",
        "/lib/x86_64-linux-gnu",
        "/lib/aarch64-linux-gnu",
        "/usr/lib64",
        "/lib64",
        "/usr/lib",
        "/usr/local/lib64",
        "/usr/local/lib",
    ];
    let names = [
        "libcrypto.so.3",
        "libssl.so.3",
        "libcrypto.so.1.1",
        "libssl.so.1.1",
    ];
    let mut found: Vec<PathBuf> = Vec::new();
    for directory in directories {
        for name in names {
            if let Ok(path) = Path::new(directory).join(name).canonicalize()
                && !found.contains(&path)
            {
                found.push(path);
            }
        }
    }
    found
}

/// Legacy getters: `EVP_aes_256_gcm`, `EVP_sha1`, … named after the algorithm they return.
fn getter(name: &str) -> bool {
    name.strip_prefix("EVP_").is_some_and(|rest| {
        !rest.is_empty()
            && rest
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
            && lattice_core::names::resolve(rest).is_some()
    })
}

/// Computes the probes for `libraries`: every known function they export, at its file offset.
/// Needs no privilege.
pub fn plan(libraries: &[PathBuf]) -> Result<Vec<Probe>, TraceError> {
    let mut probes = Vec::new();
    for library in libraries {
        let error = |reason: String| TraceError::Library(library.display().to_string(), reason);
        let bytes = std::fs::read(library).map_err(|e| error(e.to_string()))?;
        let elf = goblin::elf::Elf::parse(&bytes).map_err(|e| error(e.to_string()))?;
        let loads: Vec<_> = elf
            .program_headers
            .iter()
            .filter(|h| h.p_type == goblin::elf::program_header::PT_LOAD)
            .collect();
        let file_offset = |address: u64| {
            loads
                .iter()
                .find(|h| h.p_vaddr <= address && address < h.p_vaddr + h.p_memsz)
                .map(|h| address - h.p_vaddr + h.p_offset)
        };
        let mut seen = std::collections::BTreeSet::new();
        for symbol in elf.dynsyms.iter() {
            if symbol.st_type() != goblin::elf::sym::STT_FUNC || symbol.st_value == 0 {
                continue;
            }
            let Some(name) = elf.dynstrtab.get_at(symbol.st_name) else {
                continue;
            };
            let spec = SPECS
                .iter()
                .find(|s| s.function == name)
                .copied()
                .or_else(|| {
                    getter(name).then_some(Spec {
                        function: "",
                        kind: CallKind::Getter,
                        argument: None,
                        only_when: None,
                    })
                });
            let (Some(spec), Some(offset)) = (spec, file_offset(symbol.st_value)) else {
                continue;
            };
            if !seen.insert(name.to_owned()) {
                continue;
            }
            probes.push(Probe {
                library: library.clone(),
                offset,
                function: name.to_owned(),
                role: Role::Call(spec.kind),
                argument: spec.argument,
                only_when: spec.only_when,
            });
        }
        for symbol in elf.dynsyms.iter() {
            let Some(name) = elf.dynstrtab.get_at(symbol.st_name) else {
                continue;
            };
            if symbol.st_type() != goblin::elf::sym::STT_FUNC
                || symbol.st_value == 0
                || !SETUP.contains(&name)
            {
                continue;
            }
            let Some(offset) = file_offset(symbol.st_value) else {
                continue;
            };
            for role in [Role::SetupEnter, Role::SetupExit] {
                probes.push(Probe {
                    library: library.clone(),
                    offset,
                    function: name.to_owned(),
                    role,
                    argument: None,
                    only_when: None,
                });
            }
        }
    }
    probes.sort_by(|a, b| {
        (&a.library, &a.function, a.role == Role::SetupExit).cmp(&(
            &b.library,
            &b.function,
            b.role == Role::SetupExit,
        ))
    });
    Ok(probes)
}

/// The uprobe_events line for one probe (x86-64 and AArch64 argument registers).
pub fn definition(group: &str, event: &str, probe: &Probe) -> Result<String, TraceError> {
    #[cfg(target_arch = "x86_64")]
    const REGISTERS: [&str; 6] = ["%di", "%si", "%dx", "%cx", "%r8", "%r9"];
    #[cfg(target_arch = "aarch64")]
    const REGISTERS: [&str; 6] = ["%x0", "%x1", "%x2", "%x3", "%x4", "%x5"];
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    return Err(TraceError::Unsupported);

    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    {
        let mut line = format!(
            "{}:{group}/{event} {}:0x{:x}",
            if probe.role == Role::SetupExit {
                "r"
            } else {
                "p"
            },
            probe.library.display(),
            probe.offset
        );
        if let Some((index, _)) = probe.only_when {
            line.push_str(&format!(" cmd={}:s64", REGISTERS[index]));
        }
        match (probe.kind(), probe.argument) {
            (Some(CallKind::RsaBits), Some(index)) => {
                line.push_str(&format!(" value={}:s32", REGISTERS[index]));
            }
            (_, Some(index)) => {
                line.push_str(&format!(" value=+0({}):string", REGISTERS[index]));
            }
            (_, None) => {}
        }
        Ok(line)
    }
}

/// Aggregates parsed events into a trace.
pub struct Aggregator {
    probes: Vec<Probe>,
    executables: BTreeMap<u32, String>,
    counts: BTreeMap<(String, usize, Option<String>), u64>,
    /// Setup depth per thread: calls at depth > 0 are enumeration, not use.
    setup: BTreeMap<u32, u32>,
    /// Distinct (executable, call, value) combinations kept; more are counted as dropped.
    limit: usize,
    pub dropped: u64,
    pub ignored_setup: u64,
}

impl Aggregator {
    pub fn new(probes: Vec<Probe>, limit: usize) -> Self {
        Self {
            probes,
            executables: BTreeMap::new(),
            counts: BTreeMap::new(),
            setup: BTreeMap::new(),
            limit,
            dropped: 0,
            ignored_setup: 0,
        }
    }

    /// Accepts one parsed line; `event` names are `p<index into probes>`. The line's pid is the
    /// thread id, which is what setup windows are tracked by.
    pub fn add(&mut self, line: &parse::Line, executable: impl FnOnce(u32) -> Option<String>) {
        let Some(index) = line
            .event
            .strip_prefix('p')
            .and_then(|n| n.parse::<usize>().ok())
            .filter(|i| *i < self.probes.len())
        else {
            return;
        };
        let depth = self.setup.entry(line.pid).or_default();
        match self.probes[index].role {
            Role::SetupEnter => {
                *depth += 1;
                return;
            }
            Role::SetupExit => {
                *depth = depth.saturating_sub(1);
                return;
            }
            Role::Call(_) if *depth > 0 => {
                self.ignored_setup += 1;
                return;
            }
            Role::Call(_) => {}
        }
        let value = line
            .fields
            .get("value")
            .map(|v| v.chars().take(256).collect::<String>());
        let executable = self
            .executables
            .entry(line.pid)
            .or_insert_with(|| executable(line.pid).unwrap_or_else(|| line.command.clone()))
            .clone();
        let key = (executable, index, value);
        if let Some(count) = self.counts.get_mut(&key) {
            *count += 1;
        } else if self.counts.len() < self.limit {
            self.counts.insert(key, 1);
        } else {
            self.dropped += 1;
        }
    }

    pub fn finish(self, started: String, duration_seconds: u64) -> Trace {
        let mut libraries: Vec<String> = self
            .probes
            .iter()
            .map(|p| p.library.display().to_string())
            .collect();
        libraries.sort();
        libraries.dedup();
        let mut events: Vec<TraceEvent> = self
            .counts
            .into_iter()
            .map(|((executable, index, value), count)| {
                let probe = &self.probes[index];
                TraceEvent {
                    executable,
                    library: probe.library.display().to_string(),
                    function: probe.function.clone(),
                    kind: probe.kind().expect("only calls are counted"),
                    value,
                    count,
                }
            })
            .collect();
        events.sort();
        Trace {
            format: FORMAT.into(),
            started,
            duration_seconds,
            libraries,
            events,
            ignored_setup_calls: self.ignored_setup,
        }
    }
}

/// What to record.
pub struct Options {
    pub libraries: Vec<PathBuf>,
    pub duration: std::time::Duration,
    /// Distinct calls kept (per executable, function and argument).
    pub max_distinct: usize,
}

/// Records for `options.duration`, or until `stop` returns true.
pub fn record(
    options: &Options,
    stop: &(dyn Fn() -> bool + Sync),
) -> Result<(Trace, u64), TraceError> {
    #[cfg(target_os = "linux")]
    {
        tracefs::record(options, stop)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (options, stop);
        Err(TraceError::Unsupported)
    }
}

#[cfg(test)]
mod tests;
