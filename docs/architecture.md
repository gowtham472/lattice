# Architecture

LATTICE is a **Rust-first, single-binary, air-gapped** analyser with a web cockpit. This
document is the engineering specification: the three tiers, every component, the data
model, the graph schema, the scoring, and the deployment topology.

---

## 1. Design constraints that shape everything

| Constraint | Consequence in the architecture |
|------------|--------------------------------|
| **Air-gapped** - NTRO estates cannot phone home | No runtime call to NVD/OSV/cloud. Knowledge bases ship offline, update via signed bundles. Graph store is embedded, not a networked service. |
| **Read-only & safe** | Static analysis first. The target's code is parsed, never executed. Runtime confirmation is opt-in and passive. |
| **Single artefact** | One statically-linked binary (musl). The web UI is embedded into it. No external database to stand up. |
| **Tamper-evident** | The CBOM is hash-chained and signed with ML-DSA (dogfooding PQC). |
| **Incremental** | Content-addressed caching; a re-scan processes only the diff, so it lives in CI. |

---

## 2. The three tiers

```
 ┌──────────────────────────────────────────────────────────────────────┐
 │ TIER 3 · DECIDE                                                        │
 │   Quantum-Breakability map · Mosca (X+Y>Z) · HNDL Index · CAS ·        │
 │   Migration planner · CI gate · CBOM signer                           │
 ├──────────────────────────────────────────────────────────────────────┤
 │ TIER 2 · CONNECT                                                       │
 │   Crypto Data-Flow Graph (petgraph) · Tri-state liveness resolver ·   │
 │   Data classifier (regex + ONNX)                                      │
 ├──────────────────────────────────────────────────────────────────────┤
 │ TIER 1 · DISCOVER                                                     │
 │   6 collectors → Normaliser → CycloneDX 1.6 CBOM                       │
 └──────────────────────────────────────────────────────────────────────┘
        ▲ CLI  ▲ REST/WebSocket (axum)  ▲ CI mode   → all one binary
```

---

## 3. Tier 1 - Discovery

### 3.1 The six collectors

Each collector is a Rust module implementing a common `Collector` trait and emitting a
uniform `Observation`.

```rust
pub struct Observation {
    pub surface: Surface,          // Source | Binary | Container | Config | Cloud | Runtime
    pub location: Location,        // file:line, offset, layer digest, cert DN, pcap frame
    pub algorithm: AlgId,          // canonical: RSA, ECDH, AES, SHA2, ML-KEM, ...
    pub params: Params,            // key size, curve, mode, padding, TLS group
    pub evidence: Evidence,        // how we know: ast | symbol | constant | oid | handshake
    pub raw_ref: Blob,             // pointer back to the raw finding for audit
}
```

| # | Collector | Technique | Primary crates |
|---|-----------|-----------|----------------|
| 1 | **Source** | tree-sitter AST walk; match crypto API calls, key sizes, modes against a rule DB | `tree-sitter` + grammar crates (Python, Java, Go, C/C++, JS, C#, Rust) |
| 2 | **Binary / library** | Parse ELF/PE/Mach-O; imported crypto symbols (`EVP_*`, libsodium); S-box / algorithm-OID constant signatures | `goblin`, `object`, `capstone` (opt. disasm) |
| 3 | **Container image** | Pull OCI, unpack layers, run collectors 1–2 over the filesystem; read any embedded SBOM | `oci-client`, `oci-spec`, `flate2`, `tar` |
| 4 | **Certificate / config** | Parse X.509 (key type, sig alg, validity, chain), TLS cipher configs, SSH keys, JWT `alg` | `x509-parser`, `der`, `asn1-rs`, `rustls`, `serde_yaml`, `toml` |
| 5 | **Cloud KMS** | Parse IaC (Terraform / CloudFormation / K8s) and KMS key specs - from config, not live keys | in-house parsers over `serde` |
| 6 | **Runtime (opt-in)** | eBPF hooks on crypto library calls; passive TLS handshake capture → negotiated group/cipher | `aya` (eBPF), `pcap`, `tls-parser`, `etherparse` |

### 3.2 Normaliser
Deduplicates observations and maps them to **CycloneDX 1.6 Cryptographic components**.
The canonical asset ID is `blake3(algorithm ‖ params ‖ location-class)`, so the same
RSA-2048 seen from source *and* binary collapses to **one node with two evidence sources** -
which drives the evidence grade (§6.4).

---

## 4. Tier 2 - Connect

### 4.1 The Crypto Data-Flow Graph
An in-memory **`petgraph`** property graph, persisted to embedded **`redb`**.

**Node types**
`CryptoAsset` · `DataAsset` · `CodeUnit` (function/module) · `EntryPoint` (service/route) ·
`Certificate` · `Key` · `Library` · `Config`

**Edge types**
`USES` (CodeUnit → CryptoAsset) · `PROTECTS` (CryptoAsset → DataAsset) ·
`REACHABLE_FROM` (EntryPoint → CodeUnit) · `CONFIGURES` (Config → CryptoAsset) ·
`DEPENDS_ON` (Library → Library) · `SIGNED_BY` (Asset → Certificate)

**The query that a flat list cannot answer** (expressed as a graph traversal):
> every `CryptoAsset` with `QuantumBreakability > 0.5`, `REACHABLE_FROM` an
> `EntryPoint` whose exposure is `internet`, that `PROTECTS` a `DataAsset` with
> `secrecyLifetime > 10y`.

That result set is the migrate-first list.

### 4.2 Tri-state liveness resolver
For each `CryptoAsset` it computes the highest attained state:
- **Capable** if any binary/library observation exists.
- **Configured** if a `CONFIGURES` edge selects it.
- **Confirmed** if it is reachable from a live entry point *or* has a runtime observation.

### 4.3 Data classifier
Attaches `secrecyLifetime` and `classification` (PII / financial / credential / public) to
`DataAsset` nodes. Rule layer = `regex`; optional small model run via **`ort`** (ONNX
Runtime) so it stays offline. Lifetimes come from a configurable policy table
(e.g. card data 10y, health 20y, identity keys 25y, session tokens 0).

---

## 5. Tier 3 - Decide

Pure Rust functions over the enriched graph. Deterministic, explainable, no black boxes.

- **Quantum-Breakability map** - a static table (§6.1) keyed by algorithm family.
- **Mosca engine** - computes X + Y > Z per asset (§6.2).
- **HNDL Index** - the prioritiser (§6.3).
- **Crypto-Agility Score** - mechanical agility measurement (§6.5).
- **Migration planner** - topological sort over `DEPENDS_ON`, produces an ordered roadmap
  with FIPS 203/204/205 or hybrid recommendations and latency/size deltas.
- **CI gate** - diff current CBOM against a signed baseline; non-zero exit on regression.
- **CBOM signer** - hash-chains entries, signs with ML-DSA via `fips204`/`pqcrypto`.

---

## 6. The scoring, precisely

### 6.1 Quantum Breakability (QB)
```
Shor-broken asymmetric (RSA/DH/ECDH/ECDSA/DSA/ElGamal)   QB = 1.0
Broken-today (MD5/SHA-1/DES/RC4)                          QB = 1.0  + flag "broken now"
Grover-weakened symmetric <256-bit (AES-128/3DES)        QB = 0.5
SHA-256 (preimage halved, still safe)                    QB = 0.2
Quantum-safe classical (AES-256/SHA-384+)                QB = 0.1
PQC (ML-KEM/ML-DSA/SLH-DSA)                               QB = 0.0
```

### 6.2 Mosca's inequality
```
X = data secrecy lifetime (years)   - from the data classifier on PROTECTS edges
Y = migration time (years)          - derived inversely from the Crypto-Agility Score
Z = Q-day − now (years)             - configurable RANGE, default 2030–2035
urgent  = (X + Y) > Z
urgency = (X + Y) − Z               - magnitude used for ranking
```

### 6.3 HNDL Exposure Index (0–100)
```
HNDL = 100 · ExternalExposure · min(X / Lmax, 1) · QB · LivenessWeight

ExternalExposure : internet 1.0 · DMZ/partner 0.6 · internal 0.3 · dead-code 0.0
LivenessWeight   : Confirmed 1.0 · Configured 0.7 · Capable 0.4
```

### 6.4 Evidence grade (confidence, A–D)
```
A = corroborated across 3 layers (source + binary + runtime)
B = 2 layers
C = 1 layer
D = string / heuristic match only
```

### 6.5 Crypto-Agility Score (CAS, 0–100) - higher = cheaper to migrate
```
+40  behind a provider interface (JCA / OpenSSL EVP / PKCS#11)   (hardcoded call = 0)
+20  key size / algorithm is config-driven                        (constant = 0)
+15  has a negotiation layer (e.g. TLS cipher suite)
+15  crypto centralised in one module                             (scattered = 0)
+10  dependency current and PQC-capable
→ maps inversely to Y (migration effort, person-weeks)
```

---

## 7. Data model - the `lattice{}` CBOM extension

Output is valid CycloneDX 1.6; our value-add lives in an extension block that can be
stripped without breaking the standard.

```jsonc
{
  "bom-ref": "crypto/ecdhe-p256/tls",
  "cryptoProperties": {
    "assetType": "protocol",
    "protocolProperties": { "type": "tls", "version": "1.2" },
    "algorithmProperties": { "primitive": "key-agreement",
                             "nistQuantumSecurityLevel": 0 }
  },
  "lattice": {
    "liveness": "Confirmed",
    "evidenceGrade": "A",
    "protectsData": ["data/pii-card"],
    "reachableFrom": ["svc/payments-api"],
    "externalExposure": 1.0,
    "quantumBreakability": 1.0,
    "dataSecrecyLifetimeYears": 10,
    "cryptoAgilityScore": 78,
    "moscaUrgent": true,
    "hndlIndex": 91,
    "recommendation": { "target": "hybrid: X25519+ML-KEM-768",
                        "handshakeBytesDelta": 1184, "latencyMsDelta": 0.4 }
  }
}
```

---

## 8. The cockpit (GUI)

Served as static assets embedded into the binary via `rust-embed`; backend is `axum` with a
WebSocket channel streaming live scan progress.

| View | Content | Library |
|------|---------|---------|
| Inventory | Sortable CBOM table, filter by liveness / grade / surface | React + TS |
| Graph | Interactive crypto data-flow graph, drill to file:line | Cytoscape.js |
| Risk heatmap | Systems × HNDL index | Recharts |
| Mosca timeline | X+Y vs Z, per asset, with the Q-day band | Recharts |
| Migration roadmap | Dependency-ordered, cost-ranked plan | React |
| Export | CycloneDX JSON + signed PDF | - |

---

## 9. Deployment modes (all one binary)

```
lattice scan ./target                 # CLI: prints CBOM + summary, local
lattice serve                         # API + cockpit + embedded graph, on-prem
lattice ci --baseline cbom.json       # pass/fail gate for pipelines
```

- **100% offline.** Knowledge bases (algorithm map, CVE mirror, policy tables) update via
  signed `.lattice-bundle` files carried in.
- **Cross-compiles** to `x86_64-unknown-linux-musl` for a portable static binary; Windows
  and macOS targets for developer laptops.

---

## 10. Component/crate map (summary - full rationale in techstack.md)

```
core        anyhow · thiserror · tracing · serde · serde_json · rayon
cli         clap
collectors  tree-sitter(+grammars) · goblin · object · capstone
            oci-client · oci-spec · flate2 · tar
            x509-parser · der · asn1-rs · rustls · serde_yaml · toml
            aya · pcap · tls-parser · etherparse            (runtime, opt-in)
graph       petgraph · redb
classify    regex · ort (ONNX)
cbom        serde structs → CycloneDX 1.6 JSON (schema-validated)
risk        pure Rust (QB map, Mosca, HNDL, CAS)
crypto      blake3 · sha2 · fips204 / pqcrypto (ML-DSA signing)
server      axum · tokio · tower · rust-embed
ui          React + TypeScript · Cytoscape.js · Recharts (built to static, embedded)
```

The reasoning for every one of these choices - and what we rejected - is in
[techstack.md](techstack.md) and [decisions.md](decisions.md).

---

## 11. Production-grade engineering

The properties that make LATTICE a product an agency can run, not a demo.

### 11.1 Determinism & reproducibility
Two scans of the same input, under the same knowledge version, produce a **byte-identical
CBOM**. This is enforced by stable node ordering, canonical JSON serialisation, and content
addressing. It makes results auditable, diffable across time, and independently verifiable.

### 11.2 Incremental scanning
Every artefact is content-addressed (BLAKE3). A re-scan reuses cached results for unchanged
files and processes only the diff, so LATTICE runs in seconds inside CI on a large repo
after the first full scan.

### 11.3 Graceful degradation
The scan is a pipeline of independent collectors. A collector that fails on one artefact
records the failure with its reason and continues; **one bad file never fails the scan**.
Partial results are always valid and clearly marked.

### 11.4 Observability
Structured `tracing` spans cover every collector, parse, and scoring pass; a `--metrics`
flag emits scan throughput, artefact counts, and per-collector timing. Every log line is
correlatable to a scan ID.

### 11.5 Error taxonomy & exit codes
Typed errors (`thiserror`) distinguish *user error* (bad target), *environment error*
(missing permission), and *internal error*. `lattice ci` uses distinct exit codes:
`0` clean · `1` policy regression · `2` scan error · `3` verification failure - so pipelines
branch correctly.

### 11.6 Versioning
The **CBOM schema**, the **rule DB**, and the **knowledge bundle** are independently
versioned and recorded in every report. A result is always reproducible against the exact
versions that produced it.

### 11.7 Testing & quality gates
- **Golden fixtures** - a checked-in expected CBOM for OpenSSL; any drift fails CI.
- **Schema validation** - every emitted CBOM is validated against the official CycloneDX 1.6
  JSON schema in CI.
- **Fuzzing** - the certificate, binary and container parsers are fuzzed (`cargo-fuzz`).
- **Property tests** - scoring invariants (e.g. QB monotonicity) checked with `proptest`.

### 11.8 Performance budgets
Targets the build holds itself to: source scanning **≥ 50k LoC/s** per core (`rayon`
data-parallel), a full OpenSSL scan in **under a minute** on a laptop, and an incremental
re-scan in **under a second**.

---

## 12. Security posture (summary)

LATTICE parses hostile input on a sensitive network, so security is a first-class part of
the architecture, not a bolt-on. In short:

- **Sandboxed parsers** - panic isolation, resource caps, `seccomp` + Landlock confinement.
- **Zero egress** - no network client in the scan path; air-gapped by construction.
- **Secret hygiene** - metadata-only CBOM, redaction, `zeroize`, optional encryption at rest.
- **Tamper-evident output** - BLAKE3 hash chain + ML-DSA signature.
- **Signed knowledge bundles** - with rollback protection.
- **Full explainability** - every finding to raw evidence, every score to its inputs.

The complete threat model, controls, and compliance mapping are in
[security.md](security.md).
