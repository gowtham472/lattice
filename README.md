# LATTICE

LATTICE is an offline cryptographic discovery and post-quantum migration decision engine. It scans an application estate, creates a Cryptographic Bill of Materials (CBOM), explains quantum and present-day risk, and recommends migration targets.

The product specification and architecture are in [`docs/00-INDEX.md`](docs/00-INDEX.md).

## Current implementation

This repository now contains the first end-to-end production slice:

- Cargo workspace split into core, collector, risk, CBOM, and CLI crates.
- Read-only source discovery for C/C++, Python, and Java using tree-sitter AST validation plus an embedded, versioned rule database.
- Bounded ELF, PE, and Mach-O crypto symbol discovery with byte-offset evidence.
- TLS, JWT, KMS/key-spec, and algorithm discovery in YAML, JSON, TOML, INI, properties, environment, and common config files.
- Cross-surface correlation by canonical cryptographic identity, producing `Configured` liveness and stronger evidence grades when source, binary, and config agree.
- Per-file size limits, panic isolation, graceful partial results, path redaction, and no scan-path networking dependency.
- Stable canonical asset IDs, deterministic ordering, and byte-stable report serialization.
- Transparent financial, health, identity, credential, public, and conservative-sensitive data classification from finding metadata.
- An in-memory crypto data-flow graph linking entry points, code units, crypto assets, and protected data.
- Graph-derived per-asset secrecy lifetime, criticality, reachability, and explainable Quantum Breakability, Mosca, HNDL, Crypto-Agility Score, and migration recommendations.
- CycloneDX 1.6-shaped CBOM JSON with a `lattice` analysis extension.
- Unit tests for normalization, secret-safe evidence, deterministic output, and scoring invariants.

The next implementation milestones are format-native binary parsing, semantic graph enrichment, container/certificate collectors, strict CycloneDX schema validation, report signing, and the embedded cockpit. See [`docs/IMPLEMENTATION.md`](docs/IMPLEMENTATION.md).

## Build

Prerequisites: Rust 1.78 or newer. Dependency resolution is only needed on the build machine; the scanner itself is offline.

```sh
cargo build --release -p lattice-cli
```

The binary is `target/release/lattice` (`lattice.exe` on Windows).

## Scan

```sh
cargo run -p lattice-cli -- scan fixtures/sample-payments \
  --output payment.cbom.json \
  --exposure internet \
  --data-lifetime-years 10 \
  --q-day-year 2035
```

Write the CBOM to stdout with `--output -`. Set `RUST_LOG=info` for structured scan events.

Risk-policy inputs are explicit CLI parameters so the same input and policy produce the same output. `--data-lifetime-years` is the conservative fallback when no specific classifier rule matches; known classes use the embedded versioned policy. The default assessment year is intentionally fixed rather than read from the system clock.

## Workspace

| Path | Responsibility |
|---|---|
| `crates/lattice-core` | Domain types, report-safe paths, canonical IDs, normalization, liveness/evidence grades |
| `crates/lattice-collectors` | Read-only collectors and hostile-input isolation |
| `crates/lattice-risk` | Deterministic QB, Mosca, HNDL, CAS, and migration advice |
| `crates/lattice-classify` | Explainable offline data classification and secrecy-lifetime policy |
| `crates/lattice-graph` | Entry point → code → crypto → protected-data graph and traversals |
| `crates/lattice-cbom` | Deterministic CycloneDX serialization |
| `crates/lattice-cli` | Operator interface and scan orchestration |
| `rules` | Versioned offline detection rules |
| `knowledge` | Versioned offline policy data |
| `fixtures` | Safe regression targets |

## Security boundary

The current scan command performs local filesystem reads and report writes only. It does not execute target code, follow symlinks, retain source lines, or include an HTTP client. Evidence stores only a bounded matched API token and a report-relative location.

Crypto signatures remain versioned regex rules, but every source candidate is checked against a language-specific tree-sitter syntax tree. Matches in comments are rejected; structurally valid findings receive AST evidence and grade `C`, while findings inside parser error-recovery nodes remain honest grade-`D` heuristics. Native binary findings are tied to bounded symbol signatures and exact byte offsets. Equivalent algorithm and parameter sets are correlated across surfaces while preserving all locations and collector metadata. Configuration evidence upgrades an asset to `Configured`; only future semantic live-path or runtime evidence can upgrade it to `Confirmed`.

## Validation

```sh
cargo fmt --all -- --check
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```
