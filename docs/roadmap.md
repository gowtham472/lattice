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
12. **Assurance**: property tests for the scoring invariants, a golden CBOM of the demo estate,
    and `cargo-fuzz` targets for every parser of hostile input.
13. **Effort and timeline**: person-weeks per change with every factor explained; the roadmap
    scheduled against the India DST 2027–2029 timeline, with the team size that meets it.
14. **Executive report**: a deterministic, signed PDF from the CLI (`scan --pdf`, `report`) and
    the cockpit.
15. **Access control**: named users with viewer, operator and admin roles, and a hash-chained
    audit log of every API call that the server verifies before starting.
16. **Post-quantum TLS**: the server speaks TLS 1.3 with X25519MLKEM768 first, and mutual TLS
    with client certificates pinned to users.
17. **Key custody**: keys held in HSMs, smart cards, TPMs and cloud key services are inventoried
    from the configuration that references them, with migration advice for the device.
18. **CI and the OpenSSL golden scan**: every push is formatted, linted, tested, fuzzed and
    compared against a reviewed scan of OpenSSL 3.5.5; parsers are fuzzed for longer nightly.
19. **Runtime tracing**: `lattice trace` records which cryptography running processes ask
    OpenSSL for, through kernel uprobes, ignoring OpenSSL's own setup enumeration.
20. **Go tracing**: Go programs, stripped or not, found automatically; key sizes and the TLS
    group each handshake negotiated.
21. **Live progress**: scans stream their progress to the cockpit and the terminal.
22. **Windows build**: cross-compiled with zig, identical output to Linux, process mitigations
    as its sandbox.
23. **Java tracing**: the JCA services, TLS handshakes and certificates of running JVMs, through
    their own Flight Recorder, with JSSE's setup lookups ignored.

Status by component: [IMPLEMENTATION.md](IMPLEMENTATION.md). Feature by feature:
[features.md](features.md).

---

## 3. Next

In order of value to an operator:

1. **Tracing BoringSSL, rustls and the JVM**: statically linked TLS stacks without Go's
   function table, and the JCA providers of a running JVM.
2. **macOS builds**, and filesystem confinement on Windows (an AppContainer relaunch).

---

## 4. The demo script (about four minutes)

1. **The problem in one line**: "A quantum computer will break today's public-key
   cryptography, and adversaries are recording traffic now. First you must find all of it,
   and know which of it matters."
2. **Scan** the demo estate in the cockpit: 49 assets from code, config, certificates, keys,
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
| Targets on 9p (WSL Windows drives), where Landlock rules do not hold | Detected before confinement: `best-effort` skips Landlock and says why, `required` refuses; readable roots are re-checked after confinement so no filesystem can turn into a silently empty scan |
| Very large archives or captures | Streamed with size, expansion, packet and time bounds; partial results reported |
| CycloneDX changes | Official schema vendored and every emitted CBOM validated in tests |
