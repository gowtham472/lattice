# Tech Stack

The crates and tools LATTICE uses, layer by layer, and why each fits. Rejected alternatives
and deeper trade-offs are in [decisions.md](decisions.md).

---

## Why Rust is the right base for this tool

1. **Static binaries.** A musl build is one self-contained executable with no runtime to
   install. For an air-gapped deployment, "copy one file onto the host" beats provisioning an
   interpreter, a database and a model server.
2. **Memory safety on hostile input.** A scanner parses untrusted binaries, certificates,
   archives and packet captures on a sensitive network. A memory-safety bug there is an exploit
   surface inside a security tool. Rust removes that class; bounds, deadlines, panic isolation
   and the sandbox handle the rest.
3. **The parsers this domain needs exist in Rust**: `x509-parser` (Rusticata), `goblin` for
   ELF/PE/Mach-O, tree-sitter bindings for source.
4. **Parallelism without a GC.** Scanning is embarrassingly parallel; `rayon` spreads it
   across cores with no pauses.
5. **Post-quantum signing in pure Rust.** `fips204` implements ML-DSA, so LATTICE signs its own
   output with the algorithm it recommends.

---

## Layer by layer

### Core
| Crate | Role | Why |
|-------|------|-----|
| `serde`, `serde_json`, `toml` | data | CBOM, reports, knowledge and policy files |
| `thiserror`, `anyhow` | errors | Typed library errors; contextual CLI errors |
| `tracing`, `tracing-subscriber` | logging | Structured logs to stderr |
| `blake3` | identity | Asset ids, fingerprints, signature chain |
| `rayon` | parallelism | Files and archives scanned across cores |
| `clap` | CLI | Subcommands, flags, environment variables |

### Collectors
| Crate | Role | Why |
|-------|------|-----|
| `tree-sitter` + 9 grammar crates | source ASTs | One parsing model for Python, Java, Go, C, C++, JavaScript, TypeScript, Rust, C#; cancellable parsing |
| `regex` | rule patterns | Callee patterns, library version strings |
| `goblin` | binaries | ELF, PE and Mach-O in one pure-Rust parser |
| `aho-corasick` | constant tables | Many byte signatures searched in one pass |
| `x509-parser` | certificates | Rigorous X.509 parsing (keys are read by an in-house bounds-checked DER reader) |
| `base64`, `sha2`, `hex` | key formats, fingerprints | PEM and OpenSSH decoding, SHA-256 fingerprints |
| `tar`, `flate2` | images and tarballs | Streamed layer reading with gzip; no extraction to disk |
| `walkdir` | traversal | Symlinks never followed |
| in-house | pcap/pcapng, TCP reassembly, TLS and SSH handshakes | Only handshake metadata is needed; a small bounded parser avoids a larger dependency surface |

### Connect and decide
| Crate | Role | Why |
|-------|------|-----|
| `petgraph` | crypto graph | Traversal without a graph database |
| pure Rust | classification, scoring, advice | Deterministic, explainable functions with their reasons |

### Output and integrity
| Crate | Role | Why |
|-------|------|-----|
| serde model | CycloneDX 1.6 | Full control of the CBOM fields |
| `jsonschema` (no default features) | validation | Validates against the vendored official schema, never over the network |
| `fips204` | ML-DSA-65 | Post-quantum signatures over CBOMs and release SBOMs |

### Server and cockpit
| Crate / library | Role | Why |
|-----------------|------|-----|
| `axum`, `tokio`, `tower-http` | HTTP API | Async server; security headers; static files |
| React 19 + TypeScript, Vite | cockpit | Strict typing; small bundle; no UI or chart framework (charts and the graph are SVG) |

### Confinement
| Crate | Role | Why |
|-------|------|-----|
| `landlock` | filesystem | Unprivileged, per-process filesystem rules |
| `seccompiler` | system calls | BPF filter generation without writing BPF by hand |
| `libc` | syscall numbers | Constants only; the workspace forbids `unsafe` code |

---

## Standards and knowledge (compiled in)

| Item | Source |
|------|--------|
| PQC algorithms and sizes | NIST FIPS 203 (ML-KEM), 204 (ML-DSA), 205 (SLH-DSA) |
| Classical strength and deprecations | NIST SP 800-57 Part 1, SP 800-131A, RFC 8996 (TLS 1.0/1.1) |
| CBOM schema | OWASP CycloneDX 1.6 (vendored 1.6.1 schema) |
| Migration guidance | NIST SP 1800-38, NIST IR 8547, NSA CNSA 2.0 |
| Q-day window | Policy default 2030–2035 |

---

## Build and packaging

| Concern | Choice |
|---------|--------|
| Toolchain | Rust 1.98.1 pinned in `rust-toolchain.toml`; edition 2024 |
| Static binaries | `x86_64-` and `aarch64-unknown-linux-musl` via `cargo-zigbuild` (zig as the C toolchain for tree-sitter) |
| Release profile | fat LTO, one codegen unit, stripped, `panic = "unwind"` (required for panic isolation) |
| Cockpit | `vite build` to static files shipped at `share/lattice/cockpit` |
| Releases | Reproducible archives, CycloneDX SBOM, ML-DSA-65 signature, self-CBOM ([release.md](release.md)) |
| Tests | `cargo test` per crate and end to end; cockpit type-checked with `tsc` |
