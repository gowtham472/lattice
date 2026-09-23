# Features

The full feature set, grouped by tier, each tagged with a build phase
(**MVP** = hackathon demo · **P2** = pilot · **P3** = production) and the PS clause it
satisfies.

---

## Tier 1 - Discovery

| Feature | Phase | PS clause |
|---------|-------|-----------|
| Source scanning across 7 languages (Python, Java, Go, C/C++, JS, C#, Rust) via tree-sitter | MVP | (i) |
| Crypto rule DB: algorithms, key sizes, modes, padding, curves | MVP | (i) |
| Binary / library scanning: imported crypto symbols, S-box & OID constant signatures | MVP | (i) |
| Container image scanning: OCI pull, layer unpack, embedded-SBOM read | MVP | (i) |
| Certificate & config scanning: X.509, TLS cipher configs, SSH keys, JWT `alg` | Partial: config signatures implemented; X.509/SSH pending | (i) |
| Cloud KMS discovery from IaC (Terraform / CloudFormation / K8s) | P2 | (i) |
| Runtime confirmation: eBPF crypto-call hooks + passive TLS handshake capture | P2 | (i), (ii) |
| Hardware module (HSM/TPM) discovery via config & PKCS#11 slot enumeration | P3 | (i) |
| Normalisation to canonical assets with content-addressed dedupe | MVP | (i) |

---

## Tier 2 - Connect (the differentiators)

| Feature | Phase | PS clause |
|---------|-------|-----------|
| **Tri-state liveness**: Capable → Configured → Confirmed | MVP (Capable/Configured), P2 (Confirmed) | (ii) |
| **Crypto Data-Flow Graph**: asset ↔ data ↔ code ↔ entry point | MVP | (ii), (iii) |
| Reachability analysis from external entry points | MVP | (ii) |
| Data classifier: PII / financial / credential / public + secrecy lifetime | MVP | (iii) |
| Evidence grading (A–D) from cross-layer corroboration | MVP | (ii) |

---

## Tier 3 - Decide

| Feature | Phase | PS clause |
|---------|-------|-----------|
| Quantum-Breakability map (Shor / Grover) | MVP | (ii) |
| **Mosca's inequality** computed per asset (X + Y > Z) | MVP | (iii) |
| **HNDL Exposure Index** ranking | MVP | (ii), (iii) |
| **Crypto-Agility Score** (0–100) | MVP | (iii), (iv) |
| Business-criticality tagging | MVP | (iii) |
| PQC / hybrid advisor (FIPS 203/204/205) with latency & handshake-size deltas | MVP | (iv) |
| Dependency-ordered migration roadmap | MVP | (iv) |
| Cost estimate (person-weeks) derived from CAS | P2 | (iv) |
| **Crypto-agility CI gate**: fail build on new weak crypto vs baseline | P2 | - |

---

## Reporting & output

| Feature | Phase | PS deliverable |
|---------|-------|----------------|
| **CycloneDX 1.6 CBOM** export (JSON) | MVP | standardised report |
| Signed PDF executive report | MVP | standardised report |
| ML-DSA-signed, hash-chained CBOM ledger (tamper-evident) | P2 | - |
| Diff report between two scans (what changed) | P2 | - |
| Mapping to the India DST 2027–2029 CII timeline | P2 | - |

---

## Interactive GUI (the cockpit)

| Feature | Phase | PS deliverable |
|---------|-------|----------------|
| Inventory table: sort/filter by liveness, grade, surface, algorithm | MVP | interactive GUI |
| Interactive crypto data-flow graph (drill to file:line) | MVP | interactive GUI |
| Risk heatmap: systems × HNDL index | MVP | interactive GUI |
| Mosca timeline: X+Y vs the Q-day band | MVP | interactive GUI |
| Migration roadmap board | MVP | interactive GUI |
| Live scan progress (WebSocket) | MVP | interactive GUI |

---

## Platform / non-functional

| Feature | Phase |
|---------|-------|
| Single static binary (musl), UI embedded | MVP |
| Fully air-gapped; signed offline knowledge bundles | MVP |
| Three modes: `scan` (CLI), `serve` (cockpit), `ci` (gate) | MVP (`scan`,`serve`), P2 (`ci`) |
| Incremental / cached re-scan | P2 |
| Multi-repo / estate-wide orchestration | P3 |
| Role-based access control on the cockpit | P3 |

---

## What the hackathon demo shows (MVP scope)

The vertical slice that proves the whole thesis end to end:

1. Scan the **OpenSSL** source + a sample **Java/Python** app + one **container image**.
2. Build and export a **CycloneDX 1.6 CBOM**.
3. Show the **data-flow graph** linking a TLS endpoint → "card data."
4. Demonstrate **tri-state liveness** live: Capable (lib) → Configured (cipher config) →
   Confirmed (captured handshake).
5. Compute **QB, Mosca, HNDL, CAS** per asset.
6. Drive the **cockpit**: inventory, graph, heatmap, Mosca timeline, ranked roadmap.
7. The money shot: a commit adds **RSA** → the **CI gate fails** with the reason.

Full script in [roadmap.md](roadmap.md).
