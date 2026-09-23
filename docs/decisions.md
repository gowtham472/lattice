# Decisions - Why X over Y

Every significant choice, the alternative we rejected, and the honest reasoning. This is the
document to read when someone asks "why did you build it *that* way?"

---

## 1. Core language: Rust over Python (and over Go)

**Chosen: Rust. Rejected: Python, Go.**

| | Rust (chosen) | Python | Go |
|---|---|---|---|
| Single air-gapped binary | ✅ one static file | ❌ needs interpreter + deps | ✅ single binary |
| Best-in-class X.509 parsing | ✅ `x509-parser` | partial (`cryptography`) | weaker |
| Binary parsing (ELF/PE/Mach-O) | ✅ `goblin` pure-Rust | via bindings (`pyelftools`, `LIEF`) | `debug/elf` (ELF only, well) |
| Kernel confinement and eBPF | ✅ `landlock`, `seccompiler`; `aya` for eBPF | C toolchain (`bcc`) | `cilium/ebpf` (good) |
| Memory safety on hostile input | ✅ guaranteed | ✅ (but slow) | ✅ (GC) |
| Speed on large estates | ✅ no GC, `rayon` | ❌ slow | ✅ good, GC pauses |
| Time-to-first-prototype | ❌ slowest | ✅ fastest | 🟡 medium |

**Why Rust wins for this specific problem.** Three of this tool's requirements point
straight at Rust: (a) it must deploy as one file into an air-gapped estate; (b) it must
parse hostile binaries and certificates safely - a memory bug in a C-based scanner is an
exploit *inside a security tool on a sensitive network*; (c) the domain's best parsers
(the Rusticata crates, `goblin`) are already Rust. Go would satisfy (a) and (c) partially
but its X.509/TLS analysis story is weaker and it has GC pauses on large scans. Python is
the fastest to prototype and the worst to deploy air-gapped - the exact opposite of what an
NTRO tool needs.

**The honest cost, and how we contain it.** Rust is the slowest to move in. We contain it
three ways: (1) the risk engine, CBOM writer and graph logic are plain deterministic Rust,
easy to write and test; (2) the collectors build on mature crates (`tree-sitter`, `goblin`,
`x509-parser`) that do the hardest parsing; (3) the cockpit is React, so interface work is
not gated on Rust.

---

## 2. Graph store: in-process `petgraph` over Neo4j

**Chosen: an in-process graph built per scan. Rejected: Neo4j / Memgraph.**

Neo4j has the nicest visualisation and Cypher is expressive. But it is a **networked service
you must stand up**, which breaks the two promises that matter most here: single-binary and
air-gapped. Inside a sensitive NTRO estate, "also deploy and secure a Neo4j server" is a
real operational tax and an extra attack surface.

`petgraph` gives us in-memory traversal (reachability is a breadth-first search from the
entry points); the graph is exported as JSON with each scan and drawn by the cockpit in SVG,
so we get visualisation *without* a graph database. The server keeps each scan's artefacts
as files. An embedded store (`redb`) and a Neo4j export are possible later additions, never
dependencies.

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

So runtime evidence is **optional input**. Static analysis alone produces Capable and
Configured states, reachability from entry points (which also yields Confirmed) and a full
CBOM. Dropping a packet capture into the target adds runtime evidence: negotiated TLS and SSH
algorithms, attributed to the listener that served them, upgrade assets to **Confirmed**. A
capture needs no privileges on the scanning host; live eBPF hooks (`aya`) are the planned next
step for hosts where capturing traffic is not possible.

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
(a) stay current with 1.6 and (b) carry our analysis as namespaced `lattice:` properties.
An earlier design used a custom `lattice{}` block; the official schema forbids unknown fields,
so properties are the only way to stay strictly valid, and every CycloneDX tool preserves
them. We give up a little convenience for full control of the exact thing the PS grades.

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

We recommend organisations move to PQC; our own tool should live it. Signing CBOMs (and our
own release SBOMs) with ML-DSA-65 makes the output tamper-evident *and* quantum-safe: "the
tool that tells you to go post-quantum is itself already post-quantum." The signature is
detached, so the CBOM stays pristine CycloneDX. Pure-Rust `fips204` makes this practical.

---

## 8. Air-gapped, offline knowledge bundles over live feeds

**Chosen: everything offline; update via signed bundles. Rejected: live NVD/OSV calls.**

An NTRO scanner cannot reach out to the internet mid-scan. All knowledge (the algorithm map,
library PQC support, rules, policy) ships inside the signed release as versioned TOML, and
signed knowledge bundles carry updates in between: verified against an operator-supplied key,
validated whole, monotonic, and fail-closed. This is a hard
requirement of the deployment environment, not a preference, and it shaped the graph choice
above and the decision to scan exported images rather than pull them.

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

## 10. PDF report (planned): embedded Typst over `printpdf` or HTML-to-PDF

**Chosen for when it is built: Typst compiled in as a library. Rejected: `printpdf`,
HTML→PDF.** The CBOM, the explainable report JSON and the cockpit cover reporting today.

The signed executive report must be **deterministic**, **pure-Rust** (air-gap, no headless
browser), and **good-looking**. `printpdf` gives control but every layout is hand-coded.
HTML→PDF needs a browser engine - a heavy, non-deterministic, network-adjacent dependency we
will not ship into an air-gapped estate. **Typst** is pure Rust, embeddable as a library,
templated, and renders deterministically - polished reports without a browser. It wins on all
three requirements.

---

## 11. Build decisions as implemented

| Question | Decision | Reason |
|----------|----------|--------|
| Source languages | **Python, Java, Go, C, C++, JavaScript, TypeScript, Rust, C#** | The rule catalogue is data; each language adds a tree-sitter grammar and node tables. |
| Knowledge and rules format | **TOML**, versioned, compiled in | Strict parsing, comments for provenance, no YAML ambiguities. |
| "Confirmed" liveness | **Reachability, or negotiation in a packet capture**; eBPF planned | A capture needs no privileges on the scanning host and proves what was negotiated. |
| Correlating traffic with configuration | **By TLS server name** against listener host names | Captures and configurations come from different machines; the name is the stable link. |
| Container images | **Exported archives** (`docker save`, OCI), streamed | Air-gapped: nothing is pulled; nothing is extracted to disk. |
| Graph persistence | **Per scan, exported as JSON** | Enough for the cockpit and history; an embedded store is planned only if queries need it. |
| Self-confinement | **Landlock + seccomp**, verified by `sandbox-check` | Unprivileged, per-process, and checkable on the operator's own kernel. |
| Report engine | **Typst (embedded)**, planned | §10 above. |
| At-rest encryption | **Planned** | See [security.md §4](security.md). |
| Self-integrity | **Each release carries LATTICE's CBOM of its own binary and a signed SBOM** | Dogfooding is the strongest correctness and supply-chain signal; see [security.md §11](security.md). |
