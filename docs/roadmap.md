# Roadmap & Build Plan

How LATTICE gets built, in what order, and the exact demo we show the judges.

---

## 1. Workspace layout (Cargo workspace)

```
lattice/
├── Cargo.toml                 # workspace
├── crates/
│   ├── lattice-core/          # Observation, CBOM types, canonical IDs, config
│   ├── lattice-collectors/    # source, binary, container, config, cloud, runtime
│   ├── lattice-graph/         # petgraph model + redb persistence + reachability
│   ├── lattice-classify/      # data classifier (regex + optional ort)
│   ├── lattice-risk/          # QB map, Mosca, HNDL, CAS, evidence grade
│   ├── lattice-cbom/          # CycloneDX 1.6 writer + lattice{} extension + signer
│   ├── lattice-server/        # axum API + WebSocket + rust-embed UI
│   └── lattice-cli/           # clap: scan / serve / ci
├── ui/                        # React + TS cockpit (vite) → built into lattice-server
├── rules/                     # crypto detection rule DB (YAML)
├── knowledge/                 # algorithm map, policy tables, CVE mirror (bundle source)
└── fixtures/                  # OpenSSL golden CBOM, sample app, sample image
```

---

## 2. Milestones

### Phase 1 - MVP (hackathon)
Goal: the full vertical slice on a small target set, cockpit included.

1. **Skeleton** - workspace, `Observation`/CBOM types, `clap` CLI, `tracing`.
2. **Source collector** - tree-sitter for C + Python + Java; rule DB v1.
3. **Binary collector** - `goblin` symbol + constant signatures.
4. **Container collector** - `oci-client` pull + layer walk reusing 2–3.
5. **Normaliser + CBOM** - CycloneDX 1.6 JSON with `lattice{}` extension.
6. **Graph** - `petgraph` model; reachability; data classifier v1 (regex).
7. **Risk engine** - QB map, Mosca, HNDL, CAS, evidence grade.
8. **Advisor** - FIPS 203/204/205 recommendations + latency/size deltas table.
9. **Cockpit** - inventory, Cytoscape graph, heatmap, Mosca timeline, roadmap, WebSocket.
10. **Signing + export** - blake3 hash-chain, ML-DSA signature, PDF + JSON.

### Phase 2 - Pilot
- Certificate/config + cloud KMS collectors.
- Runtime confirmation (`aya` eBPF + `tls-parser`) → the "Confirmed" state on a live host.
- `lattice ci` gate; incremental/cached scans; signed knowledge bundles.
- Diff reports; DST 2027–2029 timeline mapping.

### Phase 3 - Production
- HSM/TPM discovery; estate-wide orchestration; RBAC on the cockpit.
- Assisted-migration suggestions (still human-approved).

---

## 3. The demo script (what the judges see, ~4 minutes)

1. **The problem in one line** - "A quantum computer will break today's crypto, and
   adversaries are recording it now. First you must find all of it. Nobody can tell you what
   they actually *use*, or what to fix first." (~20s)
2. **`lattice scan`** on OpenSSL + a sample payments app + a container image. Live progress
   streams in the cockpit. (~30s)
3. **Inventory** - the CBOM table fills; filter to Shor-breakable assets. (~20s)
4. **The graph** - click the payments TLS endpoint; the graph shows it reaches **card data**,
   internet-facing, 10-year secrecy. (~40s)
5. **Tri-state liveness** - toggle a captured handshake; the ECDHE asset jumps
   Capable → Configured → **Confirmed**. "We don't guess that you use it. We prove it." (~30s)
6. **Decide** - the Mosca timeline shows X+Y>Z; the HNDL heatmap ranks the payments channel
   top; the Crypto-Agility Score says it's a cheap fix because it uses OpenSSL EVP. (~40s)
7. **Recommend** - the roadmap card: "Hybrid X25519+ML-KEM-768, +1184 bytes, +0.4 ms,
   do-first." Export the signed CBOM. (~20s)
8. **The money shot** - a commit adds RSA; `lattice ci` **fails the build** with the reason.
   "It doesn't just find crypto once. It stops you backsliding." (~20s)

---

## 4. Datasets (all open, per the PS)

| Purpose | Dataset |
|---------|---------|
| Primary scan target | OpenSSL source (the PS names it) |
| Sample app for data-flow | a small payments-style Python/Java service (we author) |
| Container | an off-the-shelf image with known crypto libs |
| Handshake for "Confirmed" | a captured TLS pcap (we generate) |
| CVE / library data | OSV.dev mirror, packaged offline |

---

## 5. Risks to the build (and mitigations)

| Risk | Mitigation |
|------|------------|
| Rust slows the MVP | Scope tight (§2 Phase 1); collectors are thin wrappers over mature crates |
| eBPF setup eats time | Phase-2; MVP shows "Confirmed" via a captured pcap, same visual result |
| tree-sitter rule coverage | Start with C/Python/Java only; rule DB is data, expandable later |
| CycloneDX 1.6 detail churn | Validate against the official schema in CI (golden OpenSSL CBOM) |
| Scope creep on the cockpit | Six fixed views (features.md); no more for the MVP |

---

## 6. Definition of done for the MVP

- `lattice scan` produces a schema-valid CycloneDX 1.6 CBOM for OpenSSL.
- Every asset carries liveness, evidence grade, QB, Mosca verdict, HNDL index, CAS.
- The cockpit renders all six views from a real scan.
- The CI gate fails on an introduced weak-crypto commit.
- The CBOM is ML-DSA-signed and verifies.
- The whole thing runs offline from a single binary.
