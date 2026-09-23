# Roadmap

What has been built, in what order, what comes next, and the demo.

---

## 1. Workspace layout

```
SIH26164/
├── Cargo.toml                 # workspace (Rust 2024, toolchain pinned)
├── crates/
│   ├── lattice-core/          # domain model, knowledge base, name parsers, normalisation, policy
│   ├── lattice-collectors/    # source, binary, PKI, config, container, capture; walker, sandbox
│   ├── lattice-classify/      # data classification
│   ├── lattice-graph/         # crypto graph, reachability, exposure
│   ├── lattice-risk/          # assessor, advisor, roadmap
│   ├── lattice-cbom/          # CycloneDX 1.6, schema validation, ML-DSA-65 signing
│   ├── lattice-engine/        # pipeline, traffic attribution, comparison
│   ├── lattice-server/        # axum API and cockpit host
│   ├── lattice-sandbox/       # Landlock + seccomp self-confinement
│   └── lattice-cli/           # the `lattice` binary
├── cockpit/                   # React + TypeScript (Vite)
├── knowledge/                 # algorithms, libraries, risk policy (TOML, versioned)
├── rules/                     # source detection rules (TOML, versioned)
├── examples/demo-estate/      # six services, an image archive, a packet capture
├── packaging/                 # systemd unit, Dockerfile
└── scripts/                   # toolchain, demo artefacts, release, SBOM
```

---

## 2. Delivered

Each phase is one commit in the history.

1. **Design**: problem statement, solution, architecture, decisions, security.
2. **Core**: domain model, knowledge base, name parsers, normalisation, policy.
3. **Collectors**: source (nine languages), binary, PKI, configuration and IaC.
4. **Connect and decide**: data classification, crypto graph, risk engine, advisor, roadmap.
5. **Output**: CycloneDX 1.6 CBOM with offline schema validation, ML-DSA-65 signing, the
   engine, the CLI and the CI gate.
6. **Cockpit**: HTTP API with request guards, the React cockpit, the demo estate.
7. **Runtime and images**: container-image and packet-capture collectors; traffic attributed
   to TLS listeners by host name.
8. **Hardening and releases**: Landlock + seccomp sandbox; reproducible, signed releases with
   SBOMs; systemd unit; container image.
9. **Documentation** brought in line with the built system.
10. **Signed knowledge bundles**: algorithms, library knowledge, rules and policy updated between
    releases; ML-DSA-65 signed, validated whole, monotonic, fail-closed.
11. **Incremental scans**: a content-addressed cache keyed by file content, the executable and the
    active knowledge; unchanged files are not parsed again and output stays byte-identical.

Status by component: [IMPLEMENTATION.md](IMPLEMENTATION.md). Feature by feature:
[features.md](features.md).

---

## 3. Next

In order of value to an operator:

1. **eBPF runtime collector**: observe crypto-library calls on live hosts, opt-in and
   read-only.
2. **PDF executive report**: deterministic and signed.
3. **Access control**: roles, an audit log and mTLS for multi-user deployments.
4. **Assurance**: fuzzing of every parser, property tests for scoring invariants, a golden
   CBOM for OpenSSL.
5. **Effort estimates** in person-weeks and the India DST 2027–2029 timeline mapping.
6. **HSM/TPM discovery** through PKCS#11.

---

## 4. The demo script (about four minutes)

1. **The problem in one line**: "A quantum computer will break today's public-key
   cryptography, and adversaries are recording traffic now. First you must find all of it,
   and know which of it matters."
2. **Scan** the demo estate in the cockpit: 47 assets from code, config, certificates, keys,
   Terraform, a container image and a packet capture.
3. **Overview**: the Mosca timeline shows which assets are already late.
4. **The path**: open RSA-2048: `POST /v1/payments` → `create_payment` → `tokenize_card`, card
   data, 10-year secrecy. "We don't just find RSA. We show what it protects and who can reach
   it."
5. **Proof**: TLS 1.0 is configured in nginx and negotiated on the wire. "We don't guess that
   you use it. We saw it."
6. **Decide**: the roadmap puts cheap urgent fixes first; the advisor gives the hybrid target
   and its size change.
7. **The gate**: a commit adds MD5; `lattice ci` fails with the reason.
8. **Trust**: the CBOM is signed with ML-DSA-65; tampering is caught and located.
   `lattice sandbox-check` shows the scanner itself is confined.

---

## 5. Datasets (open, per the problem statement)

| Purpose | Dataset |
|---------|---------|
| Public scan target | OpenSSL source (named in the problem statement) |
| Data-flow story | `examples/demo-estate`, authored for this purpose |
| Container | `examples/demo-estate/images/payments-api-4.2.0.tar` |
| Confirmed state | `examples/demo-estate/captures/edge-traffic.pcap`: real OpenSSL 3.5 handshakes |

---

## 6. Risks and mitigations

| Risk | Mitigation |
|------|------------|
| Rule coverage gaps in a language | Rules are data (`rules/source.toml`); unmatched crypto still surfaces through imports, binaries, configuration and traffic |
| Kernels without Landlock | `best-effort` reports it; `required` refuses to run; seccomp is near-universal |
| Very large archives or captures | Streamed with size, expansion, packet and time bounds; partial results reported |
| CycloneDX changes | Official schema vendored and every emitted CBOM validated in tests |
