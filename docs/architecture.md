# Architecture

LATTICE is a Rust analyser with a web cockpit that runs air-gapped. This document is the
engineering specification of the system as built: the tiers, every component, the data model,
the graph, the scoring and the deployment modes. What is designed but not yet built is listed
separately in §12, so nothing below is aspirational.

---

## 1. Design constraints that shape everything

| Constraint | Consequence in the architecture |
|------------|--------------------------------|
| **Air-gapped**: NTRO estates cannot phone home | No network client in the scan path. The knowledge base, rules and risk policy are compiled into the binary as versioned TOML and updated by signed knowledge bundles carried in. Images and captures are read from files, never pulled. |
| **Read-only and safe** | Targets are parsed, never executed. The process confines itself (Landlock + seccomp) before reading untrusted content. |
| **Few artefacts** | One statically linked binary (musl) plus the cockpit's static files. No database or external service. |
| **Tamper-evident** | CBOMs are signed with ML-DSA-65 (FIPS 204) in a detached signature with a per-component BLAKE3 chain. |
| **Reproducible** | The same input, knowledge version and `SOURCE_DATE_EPOCH` give byte-identical CBOMs and reports. |

---

## 2. The three tiers

```
 ┌──────────────────────────────────────────────────────────────────────┐
 │ TIER 3 · DECIDE                                        lattice-risk    │
 │   Quantum breakability · HNDL/TNFL index · crypto-agility · Mosca     │
 │   over a Q-day window · priority and tier · advisor · migration waves │
 ├──────────────────────────────────────────────────────────────────────┤
 │ TIER 2 · CONNECT                        lattice-classify, lattice-graph│
 │   Data classifier · crypto graph (entry → function → crypto → data) · │
 │   reachability and exposure · tri-state liveness · evidence grade     │
 ├──────────────────────────────────────────────────────────────────────┤
 │ TIER 1 · DISCOVER                     lattice-collectors, lattice-core │
 │   Collectors → observations → normalisation → assets                  │
 └──────────────────────────────────────────────────────────────────────┘
   lattice-engine runs the pipeline; lattice-cbom writes CycloneDX 1.6;
   lattice-cli (scan · ci · serve · …) and lattice-server (HTTP API + cockpit)
   are the front ends; lattice-sandbox confines the process.
```

---

## 3. Tier 1: Discovery

### 3.1 Collectors

Every collector implements the `Collector` trait (`accepts(path, head)`,
`collect(artifact, deadline, findings)`) and emits uniform `Observation`s: a surface, a
component, a location, a finding, the evidence (collector, rule id and version, kind, matched
token) and, for code, a usage (language, API, enclosing function, identifiers, how the
algorithm was chosen). Collectors also emit the code facts the graph needs: functions, calls,
entry-point bindings and library facts.

| Collector | Technique | Evidence |
|-----------|-----------|----------|
| **Source** | tree-sitter AST walk over Python, Java, Go, C, C++, JavaScript, TypeScript, Rust and C#, matched against a versioned rule catalogue (`rules/source.toml`); constants, bindings, refinement of later calls (`init(2048)`), route registrations, imports | `file:line:column`, rule id and version, API |
| **Binary** | ELF/PE/Mach-O symbols and imports (`goblin`); constant tables (AES S-box, SHA/MD5/Keccak/ChaCha/P-256/ML-KEM/ML-DSA constants) by Aho-Corasick; DER-encoded algorithm OIDs; library identification by version string and soname | byte offset |
| **PKI** | X.509 certificates (`x509-parser`); an in-house bounds-checked DER reader for SPKI, PKCS#8, PKCS#1 and SEC1 keys; OpenSSH keys; keystore presence (never opened) | byte offset, fingerprint |
| **Configuration** | Directive formats (nginx, Apache, HAProxy, OpenSSL, sshd, Postfix, ...), YAML, JSON, TOML, key-value files, Terraform and CloudFormation; TLS listeners, served certificates and host names recorded for the graph | `file:line` |
| **Container** | `docker save`, OCI layouts packed as tar and plain tarballs, optionally gzipped, streamed three times without extraction; layers applied with OCI whiteout and opaque-directory semantics; dpkg/apk package databases for library versions; image environment through the configuration collector | `archive!/path` |
| **Capture** | pcap and pcapng (Ethernet, VLAN, Linux cooked, loopback, raw IP; IPv4 and IPv6); bounded TCP reassembly; TLS ClientHello/ServerHello/ServerKeyExchange/Certificate and SSH KEXINIT parsing; negotiated algorithms only | capture byte offset, server name |

The walker never follows symlinks, skips VCS and build directories, bounds every file
(16 MiB by default; archives and captures 16 GiB, streamed) and runs each collector on each
file inside `catch_unwind` with a deadline. Components are the deepest directory holding a
build manifest; in an estate without a root manifest each top-level directory is a component,
and an image's tag is its component.

### 3.2 Normalisation

Observations collapse into assets by identity: the component plus the canonical algorithm and
parameters (or a certificate's fingerprint, a key's fingerprint, a protocol and version).
Asset ids are `crypto/<type>/<slug>/<blake3-16>`. Normalisation also:

- inventories dependencies as their own assets: a certificate's key and signature algorithm,
  a signature's digest (but not the digest inside HMAC, HKDF or PBKDF2, where collisions do
  not apply);
- folds under-specified observations into the single more specific one (`AES` into
  `AES-256-GCM`), never guessing between two candidates;
- attaches version-less protocol settings (cipher and group lists) to the versions declared in
  the same file;
- assigns liveness and an evidence grade, each with its reason (§6).

Before normalisation, the engine attributes captured TLS handshakes to the component whose
listener answers to the handshake's server name, so a version configured in nginx and
negotiated on the wire becomes one asset.

---

## 4. Tier 2: Connect

### 4.1 The crypto graph

A `petgraph` graph built per scan.

| Nodes | Edges |
|-------|-------|
| `component`, `entry` (HTTP route, listener, library export, main), `function`, `crypto`, `data`, `library` | `contains`, `exposes` (entry → function), `calls`, `uses` (function or listener → crypto), `protects` (crypto → data), `depends-on` (crypto → crypto), `links` (component → library) |

A breadth-first search from the entry points, most exposed first, records for every function
the entry and the call path that reaches it. An asset is **reachable** when a function using it
is reached, when it is configured on a TLS listener, when the listener presents it (a
certificate or key file its configuration references), or when it was negotiated in captured
traffic. Exposure comes from the entry kind (policy: HTTP route and listener 1.0, library
export 0.6, main 0.3, nothing reaching it 0.3, which is not treated as dead code).

Code is linked to crypto both where the API is called and where a module-level crypto object
is used (`_key = rsa.generate_private_key(...)` at module scope, used inside a request
handler).

### 4.2 Tri-state liveness

| State | Meaning |
|-------|---------|
| **Capable** | Present in code or a binary, not otherwise corroborated |
| **Configured** | Selected by configuration, infrastructure-as-code or deployed key material |
| **Confirmed** | Reachable from an entry point, or negotiated in captured traffic |

### 4.3 Data classification

Identifiers are tokenised (`cardNumber` → `card`, `number`) and matched against policy data
classes by where they occur: call arguments (weight 1.0), bound variables (0.8), function
parameters (0.7), function names (0.6), paths (0.4). API vocabulary (`public_exponent=`,
`padding.OAEP`) is excluded. Each class has a secrecy lifetime and criticality (policy
defaults: classified 50 years, identity 25, health 20, financial 10, personal 10, credential 5,
public 0). Assets with no evidence of their own inherit the most sensitive class observed in
their component, and say so.

---

## 5. Tier 3: Decide

Pure functions over the enriched graph. Deterministic, explainable, no learned models.

- **Quantum breakability** and **threat**: harvest (key establishment and encryption),
  forge (signatures and certificates) or integrity (hashes, MACs, KDFs).
- **Exposure index**: HNDL for harvest threats, TNFL (trust-now-forge-later) for forgery.
- **Crypto-agility score**, measured from how the code uses the algorithm.
- **Mosca** over a Q-day window, applicable only to assets a quantum computer actually breaks.
- **Priority and tier**, with the reasons.
- **Advisor**: a target (hybrid X25519 + ML-KEM-768, ML-DSA-65, AES-256-GCM, SHA-384, TLS 1.3
  with X25519MLKEM768, rotate) with its rationale and the key-share or signature size change
  computed from the FIPS 203/204 tables.
- **Roadmap**: four waves (urgent quick wins, urgent re-engineering, planned migration,
  opportunistic hygiene).
- **Effort**: person-weeks per change = the action's base effort × the hardest surface it is
  changed in × a crypto-agility penalty × the spread across files (logarithmic) × the criticality
  of the data it protects. Every factor is reported with its reason, and every weight is in the
  policy.
- **Executive report**: `lattice-report` renders a PDF from the report JSON (so the CLI and
  the server render the same way, and an old report re-renders identically): headline figures,
  key findings, risk by tier and by component, the plan against the timeline, the first fifteen
  changes, and the method with the exact inputs and the source report's BLAKE3. The writer is
  deterministic, so the PDF carries a detached ML-DSA-65 signature like the CBOM.
- **Timeline**: the policy maps the waves onto a regulatory schedule (by default the India DST
  2027–2029 window for critical information infrastructure: waves 1–3 due 2027, 2028, 2029). The
  plan gives each wave's effort, the cumulative work due by its year, the full-time engineers that
  work needs from the assessment year, and flags waves already overdue.
- **CI gate**: compares two CBOMs by asset identity and tier.

---

## 6. The scoring, precisely

### 6.1 Quantum breakability (QB)
```
Shor-broken asymmetric (RSA, DH, ECDH, ECDSA, EdDSA, DSA)      1.0
Broken classically today (MD5, SHA-1 in collision use, DES)    1.0  + "broken now"
Grover with too little margin (128-bit keys, unknown size)     0.5
SHA-256 / 256-bit outputs (preimage halved to 128 bits)        0.2
AES-256, SHA-384 and larger                                    0.1
ML-KEM, ML-DSA, SLH-DSA, hybrid PQ groups                      0.0
quantum-vulnerable  ⇔  QB ≥ 0.5
```

### 6.2 Mosca's inequality
```
X = secrecy lifetime of the protected data (years); for a certificate, its remaining validity
Y = migration time = 0.25 + (100 − CAS) × 0.04 years
Z = years until Q-day, a window (policy default 2030–2035)
urgent               = applicable ∧ X + Y > Z_earliest
urgent even if late  = applicable ∧ X + Y > Z_latest
applicable           = quantum-vulnerable
```

### 6.3 Exposure index (0–100)
```
index = 100 × exposure × min(X / 25, 1) × QB × liveness
liveness: Confirmed 1.0 · Configured 0.7 · Capable 0.4
kind: HNDL for harvest threats, TNFL for forgery
```

### 6.4 Evidence grade
Layers are independent kinds of evidence: source code, a built or deployed artefact (binary,
image, certificate, configuration, IaC), and live runtime.
```
A = all three layers · B = two · C = one · D = only unconfirmed textual matches
```

### 6.5 Crypto-agility score (CAS, 0–100, higher is cheaper to migrate)
```
+40  used through a provider interface that selects the algorithm by name (JCA, EVP, ...)
+20  selected by configuration rather than written at the call site
+15  negotiated (TLS, SSH): both ends need not change together
+15  centralised in few places
+10  a PQC-capable library version is present in the component
```

### 6.6 Priority and tier
```
priority = exposure index
         raised to at least 90 when broken now, 70 when disallowed, 35 when legacy
         + 15 when Mosca-urgent, + 10 more when urgent even at the latest Q-day
         + 5 when it protects critical data and is quantum-vulnerable
         capped at 5 when quantum-safe and classically sound
tier: ≥ 80 critical · ≥ 60 high · ≥ 35 medium · ≥ 10 low · otherwise info
```

All weights live in [`knowledge/policy.toml`](../knowledge/policy.toml), versioned and
replaceable with `--policy`; every report records the policy, knowledge and rule versions.

---

## 7. Data model: CycloneDX 1.6 with `lattice:` properties

The CBOM is strict CycloneDX 1.6 and validates against the official 1.6.1 schema, which
forbids unknown fields. Standard fields carry the standard facts (`cryptoProperties`,
`algorithmProperties`, `certificateProperties`, `protocolProperties`,
`relatedCryptoMaterialProperties`, `evidence.occurrences`, `dependencies`); LATTICE's analysis
travels as namespaced properties, which any CycloneDX tool preserves and can ignore.

```jsonc
{
  "type": "cryptographic-asset",
  "bom-ref": "crypto/algorithm/rsa/2a54d5912b080796",
  "name": "RSA-2048",
  "cryptoProperties": {
    "assetType": "algorithm",
    "algorithmProperties": { "primitive": "pke", "parameterSetIdentifier": "2048",
                             "cryptoFunctions": ["keygen"],
                             "classicalSecurityLevel": 112, "nistQuantumSecurityLevel": 0 },
    "oid": "1.2.840.113549.1.1.1"
  },
  "evidence": { "occurrences": [{ "location": "payments-api/app/server.py", "line": 8,
                                  "symbol": "rsa.generate_private_key" }] },
  "properties": [
    { "name": "lattice:liveness", "value": "confirmed" },
    { "name": "lattice:entry-point", "value": "@app.route(\"/v1/payments\", methods=[\"POST\"])" },
    { "name": "lattice:data-class", "value": "financial" },
    { "name": "lattice:quantum-breakability", "value": "1" },
    { "name": "lattice:hndl-index", "value": "40" },
    { "name": "lattice:mosca-verdict", "value": "X + Y = 13.85 years exceeds even the latest Q-day (9 years away): already late" },
    { "name": "lattice:tier", "value": "high" },
    { "name": "lattice:recommendation-target", "value": "hybrid X25519 + ML-KEM-768 (FIPS 203)" }
  ]
}
```

The full reasoning (every index term, agility factor, call path and data match) is in the
companion report JSON, which the cockpit reads.

---

## 8. The cockpit

A React 19 + TypeScript single-page app built with Vite to static files, served by
`lattice serve` (axum) with a strict Content-Security-Policy. The API is plain JSON over HTTP;
the cockpit polls scan status.

| View | Content |
|------|---------|
| Overview | Headline counts, the Mosca timeline (X + Y against the Q-day window per asset), risk by component, threat split, fix-first list |
| Inventory | Filterable, sortable table; a drawer explains each asset: priority reasons, Mosca inputs, index terms, exposure path, data evidence, agility factors, occurrences |
| Crypto graph | Entry points → functions by call depth → crypto → data classes, drawn in SVG, with path tracing |
| Roadmap | The plan against the national timeline (effort, due year, engineers needed per wave) and the four migration waves |
| Compare | Two scans, as the CI gate sees them |
| Scans | History, and a launcher that browses the configured roots |

---

## 9. Deployment modes

```
lattice scan ./target -o t.cbom.json --report t.report.json   # CLI
lattice ci ./target --baseline t.cbom.json --fail-on high      # pipeline gate
lattice serve --root estate=/srv/code                          # API + cockpit
lattice sign | verify | validate | keygen | sandbox-check
```

Static binaries for `x86_64-unknown-linux-musl` and `aarch64-unknown-linux-musl`; releases,
the systemd unit and the container image are described in [release.md](release.md).

---

## 10. Crate map

```
lattice-core        domain model · knowledge base · name parsers · normalisation · policy
                    serde · toml · blake3
lattice-collectors  tree-sitter (+9 grammars) · goblin · aho-corasick · x509-parser · regex
                    tar · flate2 · rayon · walkdir
lattice-classify    tokeniser and data-class rules
lattice-graph       petgraph
lattice-risk        assessor · advisor · roadmap
lattice-cbom        CycloneDX 1.6 model · jsonschema (offline) · fips204 · blake3 · sha2
lattice-engine      the pipeline · traffic attribution · comparison
lattice-server      axum · tokio · tower-http
lattice-sandbox     landlock · seccompiler
lattice-cli         clap · tracing
cockpit             React · TypeScript · Vite (no UI framework, no chart library)
```

The reasoning behind these choices is in [techstack.md](techstack.md) and
[decisions.md](decisions.md).

---

## 11. Production engineering

- **Determinism.** Stable ordering everywhere, canonical JSON for signing, content-derived ids;
  `SOURCE_DATE_EPOCH` pins timestamps. Tested byte-for-byte.
- **Incremental scans.** With `--cache`, each file's findings are stored under a BLAKE3 key of
  its path, component and bytes, within a fingerprint of the executable and the active catalogue,
  rules and library knowledge. Unchanged files are not parsed again; any rebuild or knowledge
  change starts afresh; only clean results are cached. Output is byte-identical with or without
  the cache (tested).
- **Graceful degradation.** A collector failing on one artefact records the reason and the scan
  continues; failures are part of the report.
- **Bounds.** File sizes, archive expansion (decompression bombs), entries, packets, flows,
  bytes per flow, observations per file and wall time are limited.
- **Exit codes.** `0` clean · `1` regression (`ci`) · `2` usage or scan error · `3`
  verification failure.
- **Versioning.** Knowledge, rules and policy carry versions recorded in every report and CBOM.
- **Tests.** Unit and end-to-end tests per crate, including schema validation of emitted CBOMs,
  tamper detection, sandbox probes and a server started as a real process.
- **Property tests** (`proptest`) state the scoring invariants over generated assets: every score
  stays in range and the tier agrees with the score; more sensitive data or more exposure never
  lowers an asset's priority; a longer symmetric key is never more quantum-breakable.
- **A golden CBOM.** The demo estate's CBOM is checked byte for byte against
  `crates/lattice-engine/tests/golden/`; any change to detection, scoring or CycloneDX output is a
  reviewed diff (`LATTICE_BLESS=1` regenerates it).
- **Fuzzing.** `fuzz/` holds `cargo-fuzz` targets for every parser of hostile input: certificates
  and keys (through the collector and the raw DER/OpenSSH decoders), configuration, source in
  every language, binaries, packet captures, container archives and algorithm names. The targets
  call the parsers without the per-file panic isolation a scan uses, so a panic is a finding, not
  a contained failure. `scripts/fuzz.py` seeds them from the repository and runs them.

---

## 12. Designed but not yet built

| Item | Status |
|------|--------|
| eBPF runtime hooks (`aya`) on crypto-library calls | Planned; captured traffic provides the Confirmed state today |
| Pulling images from registries | Not planned for air-gapped use; images are scanned from `docker save`/OCI archives |
| Persistent graph store (`redb`) and encryption at rest | Planned; the server keeps scan artefacts as JSON files |
| Live scan progress over WebSocket | Not built; the cockpit polls |
| Role-based access control, audit log, mTLS | Planned; the server has loopback binding and a bearer token |
| A golden CBOM of an OpenSSL release | Planned; the demo estate has one today |
| Windows and macOS builds | Not built; the sandbox is Linux-only |
