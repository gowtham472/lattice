# Tech Stack

Rust-first, layer by layer, with the crate chosen and the reason. Rejected alternatives and
the deeper trade-offs live in [decisions.md](decisions.md); this document is the "what we
use and why it fits."

---

## Why Rust is the right base for *this* tool (not just the hard one)

Rust is harder to move fast in than Python. For a general app that would be the wrong
trade. For a **cryptographic discovery tool that scans sensitive government estates**, the
properties Rust gives are exactly the ones this problem needs:

1. **Single static binary.** `cargo build --release` for a musl target produces one
   self-contained executable with no runtime, no interpreter, no dependency tree to install.
   For an **air-gapped NTRO deployment**, "copy one file onto the box" beats "provision
   Python + Neo4j + a model server" decisively.
2. **The best parsers in this exact domain are Rust-native.** The Rusticata project
   (`x509-parser`, `tls-parser`) and `rustls` are among the most rigorous X.509/TLS parsers
   anywhere, written precisely because C parsers in this space are a security liability.
   `goblin` parses ELF/PE/Mach-O in pure Rust. We are building a crypto tool on top of the
   ecosystem that already does crypto-adjacent parsing best.
3. **Memory safety for a tool that ingests hostile input.** A scanner parses untrusted
   binaries, certificates and container layers. A memory-safety bug in a C scanner is an
   exploit surface *inside a security tool on a sensitive network*. Rust removes that class.
4. **Performance on large estates without a GC.** Scanning a monorepo or a fleet of images
   is embarrassingly parallel; `rayon` gives data-parallelism with no runtime, and there is
   no GC pause to fight during a multi-gigabyte scan.
5. **Pure-Rust eBPF (`aya`) and pure-Rust PQC (`fips204`).** The two most novel parts -
   runtime confirmation and signing our own output with ML-DSA - both have first-class Rust
   crates, so we do not leave the language for the hardest bits.

The honest cost of this choice, and how we contain it, is in [decisions.md](decisions.md) §1.

---

## Layer-by-layer

### Core runtime
| Crate | Role | Why |
|-------|------|-----|
| `tokio` | async runtime | Concurrency for collectors and the server |
| `rayon` | data parallelism | Parallel file/layer scanning, no runtime overhead |
| `serde` / `serde_json` | serialization | CBOM, config, IPC |
| `anyhow` / `thiserror` | errors | Ergonomic app errors + typed library errors |
| `tracing` | structured logging | Audit trail of every scan action |
| `clap` | CLI | `scan` / `serve` / `ci` subcommands |

### Source collector
| Crate | Role | Why |
|-------|------|-----|
| `tree-sitter` + grammar crates | multi-language AST | One parsing model across Python, Java, Go, C/C++, JS, C#, Rust; incremental and fast |
| `regex` | rule matching | Fast secondary matching inside AST nodes |
| rule DB (`serde_yaml`) | crypto signatures | Human-editable algorithm/API rules, versioned, shippable offline |

### Binary / library collector
| Crate | Role | Why |
|-------|------|-----|
| `goblin` | ELF / PE / Mach-O parsing | One pure-Rust parser for all three formats |
| `object` | symbol / section access | Complements goblin for symbol tables |
| `capstone` | disassembly (optional) | Confirm crypto in stripped binaries by instruction patterns |

### Container collector
| Crate | Role | Why |
|-------|------|-----|
| `oci-client` | pull images | Daemonless OCI pull - no Docker daemon needed, air-gap friendly |
| `oci-spec` | manifest / config model | Typed OCI structures |
| `flate2` + `tar` | layer unpack | Walk each layer's filesystem, then reuse collectors 1–2 |

### Certificate / config collector
| Crate | Role | Why |
|-------|------|-----|
| `x509-parser`, `der`, `asn1-rs` | X.509 parsing | Rusticata-grade certificate analysis |
| `rustls` / `webpki` | chain / suite logic | Reason about TLS cipher suites and chains |
| `serde_yaml`, `toml` | config parsing | Cipher configs, policies, IaC |

### Runtime collector (opt-in)
| Crate | Role | Why |
|-------|------|-----|
| `aya` | eBPF | Pure-Rust eBPF to hook crypto library calls - no C toolchain |
| `pcap`, `etherparse` | capture / L2-L4 | Grab handshakes passively |
| `tls-parser` | TLS handshake parse | Extract negotiated group/cipher → the "Confirmed" state |

### Graph & storage
| Crate | Role | Why |
|-------|------|-----|
| `petgraph` | in-memory property graph | Reachability and traversal without a networked graph DB |
| `redb` | embedded persistence | Pure-Rust embedded store; keeps the single-binary, no-service promise |

### Classification
| Crate | Role | Why |
|-------|------|-----|
| `regex` | rule-based PII/data tags | Fast, transparent, offline |
| `ort` (ONNX Runtime) | optional ML classifier | Run a small data-classification model offline when rules are not enough |

### CBOM & risk
| Component | Role | Why |
|-----------|------|-----|
| serde structs → CycloneDX 1.6 JSON | standard output | Full control of the schema incl. our `lattice{}` extension; validated against the official schema |
| pure-Rust risk engine | QB / Mosca / HNDL / CAS | Deterministic, explainable, testable - no black box in the scoring |

### Cryptography (our own integrity)
| Crate | Role | Why |
|-------|------|-----|
| `blake3` | content addressing, hash-chain | Fast canonical IDs and a tamper-evident ledger |
| `sha2` | interop hashing | Standard digests where required |
| `fips204` / `pqcrypto` | ML-DSA signing | We sign our own CBOM with a post-quantum signature - dogfooding the future we recommend |

### Server & UI
| Crate / lib | Role | Why |
|-------------|------|-----|
| `axum` + `tower` | HTTP + WebSocket | Ergonomic async server on tokio; live scan progress |
| `rust-embed` | embed the UI | The React build is baked into the binary - still one artefact |
| React + TypeScript | cockpit | Mature, fast to build a rich UI |
| Cytoscape.js | graph visualisation | Purpose-built for interactive node/edge graphs |
| Recharts | charts | Risk heatmap, Mosca timeline |

---

## Standards & knowledge (shipped offline)

| Item | Source |
|------|--------|
| PQC algorithms | NIST FIPS 203 (ML-KEM), 204 (ML-DSA), 205 (SLH-DSA) |
| CBOM schema | OWASP CycloneDX 1.6 Cryptographic BOM |
| Migration guidance | NIST SP 1800-38, NIST IR 8547, NSA CNSA 2.0 |
| Crypto-agility framing | NIST CSWP 39 |
| National alignment | India DST Task Force PQC report (2026), RBI 2025 guidance |
| Vulnerability data | OSV.dev mirror + NVD feed (carried in as a signed bundle) |

---

## Build & packaging

| Concern | Choice |
|---------|--------|
| Build | `cargo build --release`, workspace of crates (core, collectors, graph, risk, server, cli) |
| Portable target | `x86_64-unknown-linux-musl` static binary; also Windows/macOS for laptops |
| UI build | `vite build` → static assets → embedded via `rust-embed` |
| Distribution | one binary + signed `.lattice-bundle` knowledge packs |
| Optional container | a Docker image is provided for convenience, but is never required |
| Tests | `cargo test`; golden CBOMs for OpenSSL as regression fixtures |

The full "why this and not that" reasoning is in [decisions.md](decisions.md).
