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

pub mod golang;
pub mod parse;
#[cfg(target_os = "linux")]
mod tracefs;

/// `SSL_CTRL_SET_GROUPS_LIST` (OpenSSL 3.x `ssl.h`): `SSL_CTX_set1_groups_list` is a macro over
/// `SSL_CTX_ctrl(ctx, 92, 0, list)`.
const SSL_CTRL_SET_GROUPS_LIST: i64 = 92;

/// What a probe reads when it fires, and how the value is recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fetch {
    /// Nothing: the call itself is the evidence.
    Nothing,
    /// A NUL-terminated string argument.
    String(usize),
    /// A C `int` argument.
    Int32(usize),
    /// A Go `int` argument.
    Int64(usize),
    /// A fixed value: the function names the algorithm (`crypto/md5.Sum` is MD5).
    Fixed(&'static str),
    /// The length of a Go `[]byte` key (the second word of the slice), recorded as
    /// `<prefix>-<bits>`: `crypto/aes.NewCipher` with a 32-byte key is AES-256.
    KeyBits(&'static str, usize),
    /// A TLS `CurveID` in the first 16 bits of the receiver (Go `crypto/tls` key exchanges),
    /// recorded as the group's name.
    CurveId,
}

/// The calling convention of the probed code, which decides the argument registers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Abi {
    /// C (System V AMD64, AAPCS64).
    C,
    /// Go's register-based ABIInternal (Go 1.17+).
    Go,
}

/// A function to probe and what it says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Spec {
    pub function: &'static str,
    pub kind: CallKind,
    pub fetch: Fetch,
    /// Record only calls whose argument at `.0` equals `.1` (e.g. an `SSL_CTX_ctrl` command).
    pub only_when: Option<(usize, i64)>,
}

const fn spec(function: &'static str, kind: CallKind, argument: usize) -> Spec {
    Spec {
        function,
        kind,
        fetch: if matches!(kind, CallKind::RsaBits) {
            Fetch::Int32(argument)
        } else {
            Fetch::String(argument)
        },
        only_when: None,
    }
}

const fn go(function: &'static str, kind: CallKind, fetch: Fetch) -> Spec {
    Spec {
        function,
        kind,
        fetch,
        only_when: None,
    }
}

const fn named(function: &'static str, algorithm: &'static str) -> Spec {
    go(function, CallKind::Algorithm, Fetch::Fixed(algorithm))
}

/// Go's standard library cryptography: the entry points that name what they do, the key size
/// of AES and RSA, and the group each TLS key exchange negotiated.
pub const GO_SPECS: &[Spec] = &[
    named("crypto/md5.New", "MD5"),
    named("crypto/md5.Sum", "MD5"),
    named("crypto/sha1.New", "SHA-1"),
    named("crypto/sha1.Sum", "SHA-1"),
    named("crypto/sha256.New", "SHA-256"),
    named("crypto/sha256.Sum256", "SHA-256"),
    named("crypto/sha256.New224", "SHA-224"),
    named("crypto/sha256.Sum224", "SHA-224"),
    named("crypto/sha512.New", "SHA-512"),
    named("crypto/sha512.Sum512", "SHA-512"),
    named("crypto/sha512.New384", "SHA-384"),
    named("crypto/sha512.Sum384", "SHA-384"),
    go(
        "crypto/aes.NewCipher",
        CallKind::Algorithm,
        Fetch::KeyBits("AES", 1),
    ),
    named("crypto/des.NewCipher", "DES"),
    named("crypto/des.NewTripleDESCipher", "3DES"),
    named("crypto/rc4.NewCipher", "RC4"),
    named("crypto/hmac.New", "HMAC"),
    named(
        "golang.org/x/crypto/chacha20poly1305.New",
        "ChaCha20-Poly1305",
    ),
    // GenerateKey(random io.Reader, bits int): the interface takes two registers
    go("crypto/rsa.GenerateKey", CallKind::RsaBits, Fetch::Int64(2)),
    named("crypto/rsa.SignPKCS1v15", "RSA"),
    named("crypto/rsa.SignPSS", "RSA"),
    named("crypto/rsa.EncryptPKCS1v15", "RSA"),
    named("crypto/rsa.EncryptOAEP", "RSA"),
    named("crypto/rsa.DecryptPKCS1v15", "RSA"),
    named("crypto/rsa.DecryptOAEP", "RSA"),
    named("crypto/ecdsa.GenerateKey", "ECDSA"),
    named("crypto/ecdsa.SignASN1", "ECDSA"),
    named("crypto/ed25519.GenerateKey", "Ed25519"),
    named("crypto/ed25519.Sign", "Ed25519"),
    named("crypto/mlkem.GenerateKey768", "ML-KEM-768"),
    named("crypto/mlkem.GenerateKey1024", "ML-KEM-1024"),
    named("crypto/ecdh.(*x25519Curve).GenerateKey", "X25519"),
    named("crypto/ecdh.(*nistCurve).GenerateKey", "ECDH"),
    // the key exchange TLS actually negotiated, with its group
    go(
        "crypto/tls.(*ecdhKeyExchange).serverSharedSecret",
        CallKind::Groups,
        Fetch::CurveId,
    ),
    go(
        "crypto/tls.(*ecdhKeyExchange).clientSharedSecret",
        CallKind::Groups,
        Fetch::CurveId,
    ),
    go(
        "crypto/tls.(*hybridKeyExchange).serverSharedSecret",
        CallKind::Groups,
        Fetch::CurveId,
    ),
    go(
        "crypto/tls.(*hybridKeyExchange).clientSharedSecret",
        CallKind::Groups,
        Fetch::CurveId,
    ),
    go(
        "crypto/tls.(*mlkem1024KeyExchange).serverSharedSecret",
        CallKind::Groups,
        Fetch::Fixed("MLKEM1024"),
    ),
    go(
        "crypto/tls.(*mlkem1024KeyExchange).clientSharedSecret",
        CallKind::Groups,
        Fetch::Fixed("MLKEM1024"),
    ),
    // TLS 1.2 RSA key transport: no forward secrecy
    named(
        "crypto/tls.(*rsaKeyAgreement).processClientKeyExchange",
        "RSA",
    ),
    named(
        "crypto/tls.(*rsaKeyAgreement).generateClientKeyExchange",
        "RSA",
    ),
];

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
        fetch: Fetch::String(3),
        only_when: Some((1, SSL_CTRL_SET_GROUPS_LIST)),
    },
    Spec {
        function: "SSL_ctrl",
        kind: CallKind::Groups,
        fetch: Fetch::String(3),
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
    /// The library or executable the function is in.
    pub library: PathBuf,
    /// File offset of the function's entry, as uprobes take it.
    pub offset: u64,
    pub function: String,
    pub role: Role,
    pub fetch: Fetch,
    pub abi: Abi,
    pub only_when: Option<(usize, i64)>,
    /// The probed file is the program itself (a Go binary, a static build), so every call
    /// through this probe is that program's, whatever /proc says.
    pub executable: bool,
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
    #[error(
        "nothing to probe: no OpenSSL library and no Go program found; name one with --library or --binary"
    )]
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

/// Computes the probes for `targets` (shared libraries or executables): OpenSSL's functions from
/// the dynamic and static symbol tables, Go's from its function table. Needs no privilege.
pub fn plan(targets: &[PathBuf]) -> Result<Vec<Probe>, TraceError> {
    let mut probes = Vec::new();
    for target in targets {
        let error = |reason: String| TraceError::Library(target.display().to_string(), reason);
        let bytes = std::fs::read(target).map_err(|e| error(e.to_string()))?;
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
        // a program has an interpreter or is not position-independent; a library has neither
        let executable = elf.header.e_type == goblin::elf::header::ET_EXEC
            || elf.interpreter.is_some()
            || golang::is_go(&elf);
        let mut seen = std::collections::BTreeSet::new();
        let mut add = |name: &str, address: u64, spec: Spec, role: Role, abi: Abi| {
            let Some(offset) = file_offset(address) else {
                return;
            };
            if !seen.insert((name.to_owned(), role == Role::SetupExit)) {
                return;
            }
            probes.push(Probe {
                library: target.clone(),
                offset,
                function: name.to_owned(),
                role,
                fetch: spec.fetch,
                abi,
                only_when: spec.only_when,
                executable,
            });
        };

        if golang::is_go(&elf) {
            let wanted = |name: &str| GO_SPECS.iter().any(|s| s.function == name);
            for function in golang::functions(&bytes, &elf, wanted).map_err(error)? {
                if let Some(spec) = GO_SPECS.iter().find(|s| s.function == function.name) {
                    add(
                        &function.name,
                        function.address,
                        *spec,
                        Role::Call(spec.kind),
                        Abi::Go,
                    );
                }
            }
            continue;
        }

        // C: exported functions, then the static symbol table of an unstripped static build
        let symbols = elf
            .dynsyms
            .iter()
            .map(|s| (s, &elf.dynstrtab))
            .chain(elf.syms.iter().map(|s| (s, &elf.strtab)));
        for (symbol, strings) in symbols {
            if symbol.st_type() != goblin::elf::sym::STT_FUNC || symbol.st_value == 0 {
                continue;
            }
            let Some(name) = strings.get_at(symbol.st_name) else {
                continue;
            };
            if SETUP.contains(&name) {
                let marker = Spec {
                    function: "",
                    kind: CallKind::Getter,
                    fetch: Fetch::Nothing,
                    only_when: None,
                };
                for role in [Role::SetupEnter, Role::SetupExit] {
                    add(name, symbol.st_value, marker, role, Abi::C);
                }
                continue;
            }
            let spec = SPECS
                .iter()
                .find(|s| s.function == name)
                .copied()
                .or_else(|| {
                    getter(name).then_some(Spec {
                        function: "",
                        kind: CallKind::Getter,
                        fetch: Fetch::Nothing,
                        only_when: None,
                    })
                });
            if let Some(spec) = spec {
                add(name, symbol.st_value, spec, Role::Call(spec.kind), Abi::C);
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

/// Executables of running processes, from `/proc/*/exe`. Only the links are read: parsing what
/// they point to happens later, inside the sandbox (see [`plan_discovered`]).
pub fn running_executables() -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return Vec::new();
    };
    let mut executables = std::collections::BTreeSet::new();
    for entry in entries.flatten() {
        if entry
            .file_name()
            .to_string_lossy()
            .bytes()
            .all(|b| b.is_ascii_digit())
            && let Ok(path) = std::fs::read_link(entry.path().join("exe"))
            && path.is_absolute()
            && !path.to_string_lossy().ends_with(" (deleted)")
        {
            executables.insert(path);
        }
    }
    executables.into_iter().collect()
}

/// Probes for discovered executables: the Go programs among them. Any file that cannot be read
/// or parsed is skipped, since discovery is best effort; a malformed binary costs its own probes,
/// never the recording.
pub fn plan_discovered(candidates: &[PathBuf]) -> Vec<Probe> {
    let mut probes = Vec::new();
    for path in candidates {
        let go = match std::fs::read(path) {
            Ok(bytes) => goblin::elf::Elf::parse(&bytes).is_ok_and(|elf| golang::is_go(&elf)),
            Err(error) => {
                tracing::debug!(path = %path.display(), %error, "discovered executable unreadable");
                continue;
            }
        };
        if !go {
            continue;
        }
        match plan(std::slice::from_ref(path)) {
            Ok(found) => {
                tracing::debug!(path = %path.display(), probes = found.len(), "Go program discovered");
                probes.extend(found);
            }
            Err(error) => tracing::debug!(path = %path.display(), %error, "Go program not planned"),
        }
    }
    probes
}

/// The register holding argument `index` (integer class) for `abi`.
fn register(abi: Abi, index: usize) -> Result<&'static str, TraceError> {
    #[cfg(target_arch = "x86_64")]
    let registers: &[&str] = match abi {
        Abi::C => &["%di", "%si", "%dx", "%cx", "%r8", "%r9"],
        Abi::Go => &[
            "%ax", "%bx", "%cx", "%di", "%si", "%r8", "%r9", "%r10", "%r11",
        ],
    };
    #[cfg(target_arch = "aarch64")]
    let registers: &[&str] = {
        let _ = abi;
        &["%x0", "%x1", "%x2", "%x3", "%x4", "%x5", "%x6", "%x7"]
    };
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    let registers: &[&str] = {
        let _ = abi;
        return Err(TraceError::Unsupported);
    };
    registers
        .get(index)
        .copied()
        .ok_or_else(|| TraceError::Tracefs(format!("no register for argument {index}")))
}

/// The uprobe_events line for one probe.
pub fn definition(group: &str, event: &str, probe: &Probe) -> Result<String, TraceError> {
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
        line.push_str(&format!(" cmd={}:s64", register(probe.abi, index)?));
    }
    let fetch = match probe.fetch {
        Fetch::String(index) => format!(" value=+0({}):string", register(probe.abi, index)?),
        Fetch::Int32(index) => format!(" value={}:s32", register(probe.abi, index)?),
        Fetch::Int64(index) | Fetch::KeyBits(_, index) => {
            format!(" value={}:s64", register(probe.abi, index)?)
        }
        Fetch::CurveId => format!(" value=+0({}):u16", register(probe.abi, 0)?),
        Fetch::Nothing | Fetch::Fixed(_) => String::new(),
    };
    line.push_str(&fetch);
    Ok(line)
}

/// What a fired probe's value means, once read.
fn interpret(fetch: Fetch, raw: Option<&str>) -> Option<String> {
    match fetch {
        Fetch::Fixed(value) => Some(value.to_owned()),
        Fetch::KeyBits(prefix, _) => {
            let bytes: i64 = raw?.parse().ok()?;
            (1..=1024)
                .contains(&bytes)
                .then(|| format!("{prefix}-{}", bytes * 8))
        }
        Fetch::CurveId => {
            let id: u64 = raw?.parse().ok()?;
            Some(golang::curve_name(id).map_or_else(|| format!("0x{id:04x}"), str::to_owned))
        }
        Fetch::Nothing => None,
        Fetch::String(_) | Fetch::Int32(_) | Fetch::Int64(_) => {
            raw.map(|v| v.chars().take(256).collect())
        }
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
        let value = interpret(
            self.probes[index].fetch,
            line.fields.get("value").map(String::as_str),
        );
        let probe = &self.probes[index];
        let executable = if probe.executable {
            probe.library.display().to_string()
        } else {
            self.executables
                .entry(line.pid)
                .or_insert_with(|| executable(line.pid).unwrap_or_else(|| line.command.clone()))
                .clone()
        };
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
    /// OpenSSL libraries; the system's when empty.
    pub libraries: Vec<PathBuf>,
    /// Executables to probe directly (Go programs, static OpenSSL builds).
    pub binaries: Vec<PathBuf>,
    /// Also probe the Go programs running when recording starts.
    pub discover: bool,
    pub duration: std::time::Duration,
    /// Distinct calls kept (per executable, function and argument).
    pub max_distinct: usize,
}

impl Options {
    /// What was asked for by name: the libraries (or the system's) and the named binaries.
    pub fn named_targets(&self) -> Vec<PathBuf> {
        let mut targets = if self.libraries.is_empty() {
            default_libraries()
        } else {
            self.libraries.clone()
        };
        for binary in &self.binaries {
            let binary = binary.canonicalize().unwrap_or_else(|_| binary.clone());
            if !targets.contains(&binary) {
                targets.push(binary);
            }
        }
        targets
    }

    /// Running executables to consider, when discovery is on: paths only, nothing parsed.
    pub fn candidates(&self) -> Vec<PathBuf> {
        if !self.discover {
            return Vec::new();
        }
        let named = self.named_targets();
        let own = std::env::current_exe().ok();
        running_executables()
            .into_iter()
            .filter(|path| !named.contains(path) && Some(path) != own.as_ref())
            .collect()
    }

    /// The full plan: named targets (errors are fatal) and discovered Go programs (best effort).
    /// Parses ELF files, so call it confined.
    pub fn plan(&self, candidates: &[PathBuf]) -> Result<Vec<Probe>, TraceError> {
        let mut probes = plan(&self.named_targets())?;
        probes.extend(plan_discovered(candidates));
        Ok(probes)
    }
}

/// Records for `options.duration`, or until `stop` returns true.
/// `probes` comes from [`Options::plan`].
pub fn record(
    options: &Options,
    probes: Vec<Probe>,
    stop: &(dyn Fn() -> bool + Sync),
) -> Result<(Trace, u64), TraceError> {
    #[cfg(target_os = "linux")]
    {
        tracefs::record(options, probes, stop)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (options, probes, stop);
        Err(TraceError::Unsupported)
    }
}

#[cfg(test)]
mod tests;
