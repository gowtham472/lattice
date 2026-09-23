# Decisions - Why X over Y

Every significant choice, the alternative we rejected, and the honest reasoning. This is the
document to read when someone asks "why did you build it *that* way?"

---

## 1. Core language: Rust over Python (and over Go)

**Chosen: Rust. Rejected: Python, Go.**

| | Rust (chosen) | Python | Go |
|---|---|---|---|
| Single air-gapped binary | ✅ one static file | ❌ needs interpreter + deps | ✅ single binary |
| Best-in-class X.509 / TLS parsers | ✅ `rustls`, `x509-parser`, `tls-parser` | partial (`cryptography`) | weaker |
| Binary parsing (ELF/PE/Mach-O) | ✅ `goblin` pure-Rust | via bindings (`pyelftools`, `LIEF`) | `debug/elf` (ELF only, well) |
| Pure-Rust eBPF | ✅ `aya` | C toolchain (`bcc`) | `cilium/ebpf` (good) |
| Memory safety on hostile input | ✅ guaranteed | ✅ (but slow) | ✅ (GC) |
| Speed on large estates | ✅ no GC, `rayon` | ❌ slow | ✅ good, GC pauses |
| Time-to-first-prototype | ❌ slowest | ✅ fastest | 🟡 medium |

**Why Rust wins for this specific problem.** Three of this tool's requirements point
straight at Rust: (a) it must deploy as one file into an air-gapped estate; (b) it must
parse hostile binaries and certificates safely - a memory bug in a C-based scanner is an
exploit *inside a security tool on a sensitive network*; (c) the domain's best parsers
(`rustls`, the Rusticata crates) are already Rust. Go would satisfy (a) and (c) partially
but its X.509/TLS analysis story is weaker and it has GC pauses on large scans. Python is
the fastest to prototype and the worst to deploy air-gapped - the exact opposite of what an
NTRO tool needs.

**The honest cost, and how we contain it.** Rust is the slowest to move in, which is a real
risk in a hackathon timeline. We contain it three ways: (1) the risk engine, CBOM writer and
graph logic are plain deterministic Rust - easy to write and test; (2) the collectors are
thin wrappers over mature crates (`tree-sitter`, `goblin`, `x509-parser`) that do the hard
work; (3) the UI is React, so the visual polish that judges see is not gated on Rust speed.
The MVP is scoped (see [roadmap.md](roadmap.md)) so Rust's cost lands only where its benefits
matter.

---

## 2. Graph store: embedded `petgraph` + `redb` over Neo4j

**Chosen: embedded graph. Rejected: Neo4j / Memgraph.**

Neo4j has the nicest visualisation and Cypher is expressive. But it is a **networked service
you must stand up**, which breaks the two promises that matter most here: single-binary and
air-gapped. Inside a sensitive NTRO estate, "also deploy and secure a Neo4j server" is a
real operational tax and an extra attack surface.

`petgraph` gives us in-memory graph traversal (reachability is a simple DFS/BFS), `redb`
persists it in-process, and the cockpit's graph view is rendered by **Cytoscape.js** in the
browser from JSON we emit - so we get great visualisation *without* a graph database. We
keep an optional Neo4j *export* for organisations that already run one, but never depend on
it.

**Trade-off accepted:** we hand-write the few traversals we need instead of getting Cypher
for free. For the handful of queries LATTICE actually runs, that is a small, well-contained
amount of code.

---

## 3. Runtime confirmation: opt-in, not mandatory

**Chosen: static-first, runtime confirmation as an opt-in module.**

The "Confirmed" liveness state is our headline differentiator, and it needs eBPF or packet
capture - which needs privileges and a running system, not just source. If the core
*depended* on runtime, LATTICE could not scan a bare repository, which is the common case
and the PS's primary dataset (OpenSSL, GitHub).

So the architecture makes runtime an **optional collector**. Static analysis alone still
produces Capable and Configured states and a full CBOM; turning on the `aya`/`tls-parser`
collector upgrades assets to **Confirmed**. Best of both: works on a plain repo, shines on a
live system.

---

## 4. Demo anchor: generic engine, banking/UPI flagship scenario

**Chosen: build generic, tell the story through one sector.**

A tool themed only to banking would look narrow to NTRO. A purely generic demo has no
emotional hook. We build the engine sector-agnostic, but the **flagship demo scenario is a
payment gateway** - because it ties directly to the **RBI 2025 quantum-safe push** and makes
"card data, 10-year secrecy, internet-facing, migrate-first" concrete. The engine scans
anything; the story lands in one place.

---

## 5. CBOM output: hand-authored CycloneDX 1.6 over a generator library

**Chosen: serde structs → CycloneDX 1.6 JSON, schema-validated. Rejected: leaning on a
Rust CBOM generator crate.**

CycloneDX 1.6 is the standard the PS's "standardised format" clause points to, and it is the
format IBM/OWASP have converged on. Rust CBOM-generation crates lag the newest CBOM fields.
By emitting the JSON from our own serde types and validating against the official schema, we
(a) stay current with 1.6, (b) can attach our `lattice{}` extension cleanly, and (c) can
strip that extension to produce a pure, vendor-neutral CBOM for interoperability. We give up
a little convenience for full control of the exact thing the PS grades.

---

## 6. Risk scoring: transparent formulas over an ML risk model

**Chosen: deterministic, explainable scoring. Rejected: a learned risk model.**

For a government security tool, "the model said this is high risk" is not acceptable -
analysts must see *why*. Quantum Breakability is a lookup table grounded in Shor/Grover.
Mosca is an inequality. HNDL and CAS are weighted sums with published weights. Every score
is inspectable and defensible in an audit. ML appears only in *one narrow place* - the
optional data classifier (is this field PII?) - where it assists, never decides risk.

---

## 7. Signing our own CBOM with ML-DSA (dogfooding)

**Chosen: sign the CBOM with ML-DSA (FIPS 204), not just Ed25519.**

We recommend organisations move to PQC; our own tool should live it. Signing the CBOM ledger
with ML-DSA makes the output tamper-evident *and* quantum-safe, and it is a quietly powerful
demo point: "the tool that tells you to go post-quantum is itself already post-quantum."
Pure-Rust `fips204`/`pqcrypto` make this practical.

---

## 8. Air-gapped, offline knowledge bundles over live feeds

**Chosen: everything offline; update via signed bundles. Rejected: live NVD/OSV calls.**

An NTRO scanner cannot reach out to the internet mid-scan. All knowledge - the algorithm
map, CVE data, policy tables - ships inside the binary or as a signed `.lattice-bundle` that
is carried in and verified. This is a hard requirement of the deployment environment, not a
preference, and it shaped the graph and CVE choices above.

---

## 9. What we deliberately did **not** build

| Not building | Why |
|--------------|-----|
| A key-management or PKI product | Out of scope; LATTICE *discovers and assesses*, it does not issue or rotate keys |
| An actual quantum-attack simulator | The risk is analytic (Shor/Grover are known); no need to simulate a quantum computer |
| Automated code rewriting to PQC | High risk, low trust; we *recommend and rank*, humans migrate. A future assisted-refactor is P3 at most |
| Cloud-hosted SaaS | The customer is a sovereign agency; on-prem/air-gapped is the whole point |
| An offensive / evasion capability | Explicitly avoided; this is a defensive discovery and assessment tool |

---

## 10. PDF report: embedded Typst over `printpdf` or HTML-to-PDF

**Chosen: Typst compiled in as a library. Rejected: `printpdf`, HTML→PDF.**

The signed executive report must be **deterministic**, **pure-Rust** (air-gap, no headless
browser), and **good-looking**. `printpdf` gives control but every layout is hand-coded.
HTML→PDF needs a browser engine - a heavy, non-deterministic, network-adjacent dependency we
will not ship into an air-gapped estate. **Typst** is pure Rust, embeddable as a library,
templated, and renders deterministically - polished reports without a browser. It wins on all
three requirements.

---

## 11. Resolved build decisions (previously open - now locked)

No open placeholders remain. These are the final calls for the MVP.

| Question | Decision | Reason |
|----------|----------|--------|
| MVP source languages | **C, Python, Java** | OpenSSL is C (the PS dataset); the sample payments app is Python/Java. The rule DB is data, so more languages are added later without code change. |
| "Confirmed" liveness in MVP | **Captured-pcap path**, eBPF in P2 | Same visual result (asset jumps to Confirmed) with far less setup; the `aya` eBPF path is a Phase-2 upgrade, not a demo dependency. |
| Report engine | **Typst (embedded)** | §10 above. |
| Graph persistence | **`redb`** (embedded) | Pure-Rust, in-process, keeps the single-binary/air-gap promise; see §2. |
| At-rest encryption | **Optional, XChaCha20-Poly1305** | Off for the demo, available for classified deployments; see [security.md §4](security.md). |
| Self-integrity | **LATTICE scans itself in CI, publishes its own CBOM** | Dogfooding is the strongest correctness and supply-chain signal; see [security.md §12](security.md). |
