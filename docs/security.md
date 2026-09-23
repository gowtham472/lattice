# Security and Explainability

LATTICE is a security tool for a national security agency. It must be at least as hard to
attack as the estate it scans, and every conclusion it prints must be defensible in an audit.
This document is the threat model, the controls and the explainability contract. Every control
is marked **Enforced** (built and tested) or **Planned**.

---

## 1. Guarantees

| # | Guarantee | Enforced by | Status |
|---|-----------|-------------|--------|
| G1 | **No network connections** during a scan | No network client in the scan path; seccomp forbids creating sockets once confined | Enforced |
| G2 | Hostile input **cannot take over or crash the tool** | Memory-safe parsers, size and time bounds, panic isolation per artefact, Landlock + seccomp confinement | Enforced |
| G3 | **No secret or key material** enters a report | Keys are described (type, size, format, encrypted or not) and identified by fingerprint; evidence keeps API names, never source lines | Enforced |
| G4 | Every **finding is traceable** to its evidence | Collector, rule id and version, `file:line`, byte offset, archive path or capture offset on every occurrence | Enforced |
| G5 | Every **score is explainable** | Deterministic functions; every term, factor and verdict carries its reason | Enforced |
| G6 | Output is **tamper-evident** | ML-DSA-65 detached signature over the exact CBOM bytes plus a per-component BLAKE3 chain | Enforced |
| G7 | Results are **reproducible** | Same input, knowledge version and `SOURCE_DATE_EPOCH` give byte-identical output | Enforced |

---

## 2. Threat model

LATTICE parses untrusted, potentially malicious input: source trees, binaries, certificates,
container images, configuration and packet captures that an adversary may have crafted. A
scanner is a high-value target because it runs with access to sensitive code on a sensitive
network.

| Asset to protect | Threat | Control |
|------------------|--------|---------|
| The host running LATTICE | A crafted input exploits a parser | §3 |
| The scanned code and secrets | Exfiltration | §3, §4, §5 |
| The CBOM | Tampering to hide a weak asset | §6 |
| The knowledge and rules | Poisoned or rolled-back rules that suppress findings | §7 |
| The cockpit | Unauthorised access to results or to scan roots | §8 |

Out of scope by design: LATTICE never writes to, rotates or exploits the target. It reads and
analyses (see [decisions.md §9](decisions.md)).

---

## 3. Parser isolation and confinement

- **Memory safety.** All parsers are Rust; the workspace forbids `unsafe` code.
  *Enforced.*
- **Panic isolation.** Each collector runs on each artefact inside `catch_unwind`; a failure is
  recorded for that artefact and the scan continues. *Enforced.*
- **Bounds.** File size (16 MiB default), archive size and expanded bytes (decompression
  bombs), entries per layer, packets, flows and bytes per flow, observations per file, and a
  deadline per collector per file (cancellable tree-sitter parsing) and per archive.
  *Enforced.* A per-artefact memory cap is *Planned*.
- **Self-confinement (Linux).** Before reading untrusted content, `scan`, `ci`, `validate`,
  `verify` and `serve` apply:
  - **Landlock**: scan targets read-only; only the output directories (or the server's data
    directory) writable; nothing else openable;
  - **seccomp**: no new sockets, no program execution, no ptrace or cross-process memory, no
    mounts, namespaces, kernel modules, BPF, keyrings or personality changes.

  Both cover every thread and cannot be undone. `lattice sandbox-check` proves them by
  attempting each forbidden operation in a confined child; `--sandbox required` refuses to run
  unconfined. *Enforced.*
- **Fuzzing** of every parser with `cargo-fuzz`. *Planned.*

---

## 4. Data handling

- **Metadata only.** A private key is recorded as its type, size, format, whether it is
  encrypted, and a BLAKE3 fingerprint; the key bytes never reach a report. Password-protected
  keystores are recorded as present and never opened. *Enforced.*
- **No source in reports.** Evidence carries the matched API token and location, not code.
  *Enforced.*
- **Relative paths only.** Reports never contain the absolute path of the scan root.
  *Enforced.*
- **Captures.** Only handshake metadata is read; application data and client addresses are
  never decoded or stored. *Enforced.*
- **No telemetry.** No analytics, crash reporting or beacons. *Enforced.*
- **Zeroisation** of transient key buffers and **encryption at rest** for stored results.
  *Planned.*

---

## 5. Air gap

- The scan path links no HTTP client; the server crate is only used by `serve`. *Enforced.*
- The knowledge base, rules, risk policy and CycloneDX schemas are compiled in; nothing is
  fetched, including schema references during validation. *Enforced.*
- Container images are scanned from exported archives, never pulled. *Enforced.*
- Static musl binaries need no libc, interpreter or package manager on the host. *Enforced.*

---

## 6. Output integrity

- `lattice sign` writes a detached signature over the exact CBOM bytes (SHA-256 and BLAKE3
  digests), a BLAKE3 chain over the components in order, the serial number and the component
  count, signed with **ML-DSA-65** (FIPS 204) under a dedicated context string. *Enforced.*
- `lattice verify` takes the trusted public key as an argument and never trusts a key shipped
  alongside. A changed, removed or reordered component is named; a re-hashed forgery fails the
  signature. *Enforced.*
- Releases are signed the same way, over an SBOM that carries every file's SHA-256 and the
  archive's hash (see [release.md](release.md)). *Enforced.*

---

## 7. Knowledge integrity

- The algorithm knowledge, detection rules and risk policy are versioned; every report and CBOM
  records the versions that produced it, so a result can be reproduced and audited against the
  exact rules. *Enforced.*
- Knowledge ships inside the signed release, so it is covered by the release signature.
  *Enforced.*
- **Signed knowledge bundles** update the catalogue, library knowledge, rules and policy between
  releases. Each is signed with ML-DSA-65 under its own context string (`lattice-knowledge-v1`)
  and verified against an operator-supplied key; every file must parse and the rules must compile
  against the bundle's own catalogue before anything is used. *Enforced.*
- **Rollback protection.** Bundles carry a monotonic sequence: installation refuses one not newer
  than the installed bundle, and activation refuses one not newer than the knowledge compiled into
  the binary. *Enforced.*
- **Fail closed.** An installed bundle that does not verify, or with no trusted key given, stops
  `scan`, `ci` and `serve` with exit code 3; nothing is produced from unverified knowledge.
  Reports and CBOMs record the knowledge sequence and the signing key. *Enforced.*

---

## 8. The cockpit and API

- Binds **127.0.0.1** by default; binding any other address requires a bearer token (compared
  through BLAKE3 digests). *Enforced.*
- Loopback-bound servers reject requests whose `Host` is not a loopback name, which defeats DNS
  rebinding. *Enforced.*
- Scans may read only inside operator-declared roots; paths are canonicalised and symlink
  escapes refused. *Enforced.*
- Strict Content-Security-Policy with no inline script, `no-store` on the API, `nosniff`,
  frame denial, 16 KiB request bodies, unknown fields rejected, a bounded scan queue.
  *Enforced.*
- Confined after binding: the server can accept connections but never open one. *Enforced.*
- Roles (viewer, analyst, admin), an append-only audit log and mTLS. *Planned.*

---

## 9. Explainability contract

An analyst must always be able to answer "why did it say that?"

- **Every finding → evidence**: collector, rule id and version, and the exact location.
- **Every score → its inputs**: quantum breakability with its reason; Mosca's X, Y and Z with
  theirs; each exposure-index term; each agility factor with its points; the reasons behind the
  priority. The cockpit's drawer shows all of it.
- **No learned models.** Classification and scoring are rules and formulas with published
  weights ([`knowledge/policy.toml`](../knowledge/policy.toml)).
- **Determinism.** Two runs on the same input produce identical output, so results diff
  cleanly and can be reproduced independently.

---

## 10. Standards alignment

| Framework | How LATTICE aligns |
|-----------|--------------------|
| **NIST SP 1800-38 / IR 8547** | The discover → assess → prioritise → migrate workflow they prescribe |
| **NIST SSDF (SP 800-218)** | Reproducible builds, SBOMs, signed artefacts, pinned dependencies (`Cargo.lock`, `package-lock.json`) |
| **India DPDP Act 2023** | Data minimisation: metadata only, no exfiltration, no source in reports |
| **CERT-In directions** | On-premises, no third-party data sharing |

`cargo-deny`, `cargo-audit` and `cargo-vet` gates in CI are *Planned*.

---

## 11. Supply chain of LATTICE itself

- Pinned dependencies: `Cargo.lock` and the cockpit's `package-lock.json` are committed; builds
  use `--locked` and `npm ci`. *Enforced.*
- Reproducible release archives, verified by building twice. *Enforced.*
- A CycloneDX SBOM per release, listing every crate and npm package actually shipped. *Enforced.*
- LATTICE scans its own binary and publishes the CBOM with each release. *Enforced.*

Cross-references: the scoring these controls protect is in [architecture.md](architecture.md);
the trade-offs behind them are in [decisions.md](decisions.md).
