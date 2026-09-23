# Security & Explainability

LATTICE is a security tool for a national security agency. It must be at least as hard to
attack as the estate it scans, and every conclusion it prints must be defensible in an
audit. This document is the threat model, the hardening, and the explainability contract.

Nothing here is aspirational. Each control names the exact mechanism and crate.

---

## 1. Security principles (the guarantees)

| # | Guarantee | Enforced by |
|---|-----------|-------------|
| G1 | LATTICE makes **zero outbound network connections** during a scan | No network client is linked into the scan path; egress-blocked by build feature flag + runtime assertion |
| G2 | Hostile input **cannot execute or crash the tool** | Every parser runs in a resource-limited sandbox with panic isolation |
| G3 | No **secret or private key** ever leaves the machine or enters a report | Secret redaction + `zeroize`; CBOM stores metadata only, never key material |
| G4 | Every **finding is traceable** to raw evidence | Each CBOM entry carries collector, rule ID+version, and a byte-level location |
| G5 | Every **score is explainable** with its inputs | Scores are deterministic functions; the report shows each contributing term |
| G6 | Output is **tamper-evident** | Hash-chained CBOM ledger, signed with ML-DSA (FIPS 204) |
| G7 | Results are **reproducible** | Same input + same knowledge version → byte-identical CBOM |

---

## 2. Threat model

LATTICE parses **untrusted, potentially malicious input**: binaries, certificates,
container layers, config files and packet captures crafted by an adversary. That is the
primary attack surface - a scanner is a high-value target because it runs with access to
sensitive code on a sensitive network.

| Asset to protect | Threat | Control (see section) |
|------------------|--------|------------------------|
| The host running LATTICE | Malicious binary/cert triggers RCE in a parser | §3 sandboxing |
| The scanned source & secrets | Exfiltration | §1 G1, §4 data hygiene |
| The CBOM report | Tampering to hide a weak asset | §6 signing |
| The knowledge bundles | Poisoned rules that suppress findings | §7 bundle integrity |
| The runtime collector | eBPF abused for capture beyond scope | §8 runtime isolation |
| The cockpit | Unauthorised access to results | §9 access control |

Out of scope by design: LATTICE never writes to, rotates, or exploits the target. It is
strictly read-only and analytic (see [decisions.md §9](decisions.md)).

---

## 3. Parser sandboxing & resource limits (the core control)

Rust's memory safety removes buffer-overflow-class bugs, but a parser can still panic,
recurse infinitely, or exhaust memory on a malformed input. So every collector that touches
untrusted bytes runs under a strict harness:

- **Panic isolation** - each parse runs inside `std::panic::catch_unwind`; a panicking
  parser fails that one artefact and is logged, never the whole scan.
- **Resource caps** - per-artefact limits on **wall-clock time**, **peak memory**, and
  **recursion/nesting depth**, enforced before parsing (input size gates) and during (a
  watchdog thread). Zip/OCI layers are bounded against decompression bombs (`flate2` with a
  hard output-size ceiling).
- **OS confinement (Linux)** - the scan process drops privileges and applies a **`seccomp`**
  filter (via `seccompiler`) and **Landlock** rules that permit reading the target and
  writing only the output directory: no exec, no network syscalls, no other filesystem.
- **WASM option for third-party rules** - any future community-supplied parser rule runs in
  a `wasmtime` sandbox with no host access, so extending the rule set never widens the
  attack surface.
- **Continuous fuzzing** - the certificate, binary and container parsers are fuzzed with
  `cargo-fuzz` (libFuzzer) in CI against a corpus of malformed inputs; crashes block merge.

---

## 4. Data handling & secret hygiene

LATTICE sees source code, configs and sometimes embedded secrets. It must be a vault, not a
leak.

- **Metadata only in the CBOM.** We record *that* an RSA-2048 key exists at a location and
  its properties - never the key bytes. Private keys, if encountered, are recorded as a
  presence finding with the value redacted.
- **Secret redaction.** A redaction pass masks anything matching secret patterns (keys,
  tokens, passwords) before it can reach a report or a log line.
- **Memory zeroization.** Any buffer that transiently holds key material is wrapped in
  `zeroize::Zeroizing`, so it is wiped on drop rather than lingering in memory.
- **Encryption at rest (optional).** The embedded `redb` graph/result store can be sealed
  with an operator-supplied key (XChaCha20-Poly1305 via `chacha20poly1305`) for classified
  environments.
- **No telemetry.** There is no analytics, crash-reporting, or usage beacon. Ever.

---

## 5. Air-gap & zero-egress enforcement

- The scan and analysis crates link **no HTTP client at all**; the only networked crate
  (`axum`) lives in the `serve` binary and binds **loopback by default**.
- A runtime self-check asserts no socket is opened during `scan`/`ci`; violation aborts.
- All knowledge - algorithm map, CVE data, policy tables - is embedded or carried as a
  signed bundle (§7). Nothing is fetched.
- Builds are produced for `x86_64-unknown-linux-musl` as a fully static binary, so the
  air-gapped host needs no libc, no interpreter, no package manager.

---

## 6. Output integrity - signed, hash-chained CBOM

- Each CBOM entry is content-addressed with **BLAKE3**; entries form a **hash chain**, so a
  removed or altered finding breaks verification.
- The finished CBOM ledger is signed with **ML-DSA (FIPS 204)** via `fips204`. We sign our
  own output with post-quantum crypto: the tool that tells you to migrate has already
  migrated.
- `lattice verify report.cbom.json` re-checks the chain and the signature offline.

---

## 7. Knowledge-bundle integrity

The rules and CVE data are security-critical: poisoned rules could silently hide a weak
algorithm.

- Bundles are **ML-DSA-signed** by the LATTICE maintainers; the binary ships the public key
  and refuses to load an unsigned or mis-signed bundle.
- Bundles are **version-pinned with monotonic counters**; the loader rejects a bundle older
  than the one already installed (**rollback protection**).
- Every CBOM records the **knowledge version** it was produced with, so a result can always
  be reproduced and audited against the exact rules that generated it.

---

## 8. Runtime collector isolation (eBPF)

The opt-in runtime collector is the highest-privilege component, so it is the most
constrained:

- eBPF programs are **read-only observers** - they hook crypto-library entry points and
  parse captured packets; they never inject, modify, or block traffic.
- The BPF objects are **signed and pinned**; the loader verifies them before attach.
- It is **off by default**, requires explicit `--runtime` opt-in and elevated rights, and is
  scoped to named processes/interfaces - never a blanket capture.
- On any platform without a verified eBPF path, LATTICE degrades gracefully to
  pcap-file analysis, still producing the **Confirmed** state without kernel hooks.

---

## 9. Access control, audit & the cockpit

- `lattice serve` binds **127.0.0.1** by default; exposing it requires explicit config and
  turns on **mTLS**.
- **Role-based access control** - Viewer, Analyst, Admin - gates who can scan, export, and
  change policy.
- Every privileged action (scan start, export, policy change, bundle install) is written to
  an **append-only, hash-chained audit log**.
- Sessions are short-lived; no long-lived tokens; no default credentials.

---

## 10. Explainability contract - nothing is a black box

This is a hard product requirement: an analyst must always be able to answer "why did it say
that?"

- **Every finding → evidence.** Each CBOM entry links to `file:line`, byte offset, certificate
  DN, container layer digest, or pcap frame - the exact raw source.
- **Every score → its inputs.** Quantum Breakability is a published lookup table
  ([architecture.md §6.1](architecture.md)); Mosca shows the actual X, Y, Z; the HNDL Index
  and Crypto-Agility Score display each contributing term and its weight. The report renders
  the arithmetic, not just the number.
- **Provenance.** Each finding records which collector and which rule ID + version produced
  it.
- **The single ML use is advisory and overridable.** The data classifier (is this field
  PII?) can assist but never *decides* risk, always has a rule-based fallback, and any
  analyst can override its label. No risk score depends on a model.
- **Determinism.** Stable ordering + canonical JSON means two runs on the same input produce
  identical output, so results diff cleanly and can be independently reproduced.

---

## 11. Compliance & standards mapping

LATTICE is built to the same frameworks it helps organisations satisfy.

| Framework | How LATTICE aligns |
|-----------|--------------------|
| **NIST SSDF (SP 800-218)** | Reproducible builds, dependency vetting, signed artefacts, fuzzed parsers |
| **India DPDP Act 2023** | Data minimisation (metadata-only), no exfiltration, redaction of personal data in reports |
| **CERT-In directions** | On-prem, auditable logs, no third-party data sharing |
| **ISO/IEC 27001** | Access control, audit trail, integrity controls, documented threat model |
| **NIST SP 1800-38 / IR 8547** | The migration workflow LATTICE implements is the one these documents prescribe |
| **Supply-chain (SLSA-style)** | `cargo-deny` (license/advisory gates), `cargo-audit` (RUSTSEC), `cargo-vet` (dependency review), a self-CBOM/SBOM of LATTICE itself, signed releases |

---

## 12. Supply-chain security of LATTICE itself

We dogfood: LATTICE runs on itself.

- **`cargo-deny`** blocks disallowed licences and known-vulnerable crates at build.
- **`cargo-audit`** checks the dependency tree against the RUSTSEC advisory DB (mirrored
  offline).
- **`cargo-vet`** requires human review records for dependencies.
- **Pinned, hash-locked dependencies** (`Cargo.lock` committed; vendored for air-gapped
  builds).
- **Reproducible builds** so a released binary can be rebuilt bit-for-bit and verified.
- **LATTICE scans its own repository** in CI and publishes its own CBOM - the tool is its own
  first customer.

---

Cross-references: the scoring these controls protect is in
[architecture.md](architecture.md); the trade-offs behind them are in
[decisions.md](decisions.md).
