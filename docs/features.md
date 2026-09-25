# Features

The feature set, each marked **Delivered** (built and covered by tests) or **Planned**, with
the problem-statement clause it answers: (i) discover cryptographic assets, (ii) identify
vulnerable and live ones, (iii) assess risk, (iv) recommend migration.

---

## Tier 1: Discovery

| Feature | Status | PS clause |
|---------|--------|-----------|
| Source scanning of Python, Java, Go, C, C++, JavaScript, TypeScript, Rust and C# via tree-sitter | Delivered | (i) |
| Versioned rule catalogue: algorithms, key sizes, modes, padding, curves, digests, protocol versions, cipher and group lists | Delivered | (i) |
| Binary scanning: ELF/PE/Mach-O symbols and imports, constant tables, algorithm OIDs, library versions | Delivered | (i) |
| Certificates and keys: X.509, PKCS#1/#8, SEC1, OpenSSH, keystore presence (never opened) | Delivered | (i) |
| Server configuration: nginx, Apache, HAProxy, OpenSSL, sshd, Postfix and more; TLS listeners, served certificates, host names | Delivered | (i) |
| Structured configuration (YAML, JSON, TOML, properties, env) and JWT/JOSE algorithm settings | Delivered | (i) |
| Cloud KMS key specs from Terraform and CloudFormation | Delivered | (i) |
| Container images from `docker save` and OCI archives, with whiteouts and dpkg/apk library versions | Delivered | (i) |
| Runtime evidence from packet captures: TLS and SSH negotiated algorithms, TLS 1.2 certificates | Delivered | (i), (ii) |
| Runtime evidence from live hosts: `lattice trace` places kernel uprobes on the OpenSSL calls that select cryptography (algorithm fetches, legacy getters, RSA key sizes, TLS group and cipher lists), ignores what OpenSSL enumerates during its own setup, and writes a trace that `scan` turns into Confirmed assets | Delivered | (i), (ii) |
| Runtime tracing of Go programs, stripped or not: the `crypto/...` entry points, AES and RSA key sizes, and the group each TLS handshake negotiated (X25519MLKEM768 included); running Go programs are found automatically | Delivered | (i), (ii) |
| Runtime tracing of Java: the JCA services every running JVM looks up, its TLS handshakes (version and suite) and the certificates it parses, through the JVM's own Flight Recorder; JSSE's availability probing is ignored | Delivered | (i), (ii) |
| Runtime tracing of BoringSSL, AWS-LC and rustls (on AWS-LC or ring), statically linked with versioned symbols included: key exchange (X25519, ML-KEM), suites, key sizes, signatures; such programs are found automatically | Delivered | (i), (ii) |
| Pulling images from registries | Not planned (air-gapped); scan exported archives | (i) |
| Keys held in hardware or key services: PKCS#11 URIs, OpenSSL engine and TPM handle references, Java PKCS#11 keystores, Vault seals, TPM2-sealed LUKS volumes, TPM-wrapped key files, cloud KMS and HSM keys (with their signing or decryption use); CycloneDX `securedBy` | Delivered | (i) |
| Live enumeration of PKCS#11 tokens and TPMs | Not planned: it means loading vendor code into the scanner; custody is found from the configuration that uses the keys | (i) |
| Normalisation to canonical assets, with dependency, refinement and protocol-setting merges | Delivered | (i) |

---

## Tier 2: Connect

| Feature | Status | PS clause |
|---------|--------|-----------|
| **Tri-state liveness**: Capable → Configured → Confirmed, each with its reason | Delivered | (ii) |
| **Crypto graph**: entry point → function → crypto → data | Delivered | (ii), (iii) |
| Reachability from HTTP routes, TLS listeners, library exports and `main` | Delivered | (ii) |
| Traffic attribution: captured handshakes matched to the listener serving that host name | Delivered | (ii) |
| Data classification with secrecy lifetimes (identity, health, financial, personal, credential, classified, public) | Delivered | (iii) |
| Evidence grading (A–D) from agreement between source, artefact and runtime layers | Delivered | (ii) |

---

## Tier 3: Decide

| Feature | Status | PS clause |
|---------|--------|-----------|
| Quantum breakability (Shor / Grover / post-quantum) and classical status | Delivered | (ii) |
| **Mosca's inequality** per asset over a Q-day window | Delivered | (iii) |
| **HNDL / TNFL exposure index** | Delivered | (ii), (iii) |
| **Crypto-agility score** (0–100), measured from code | Delivered | (iii), (iv) |
| Priority and tier with the reasons | Delivered | (iii) |
| PQC and hybrid advisor (FIPS 203/204/205) with key-share and signature size changes | Delivered | (iv) |
| Migration roadmap in four waves | Delivered | (iv) |
| **CI gate**: fail a pipeline on new or worsened crypto against a (signed) baseline | Delivered | (iv) |
| Effort estimate in person-weeks per change, factor by factor (action, surface, agility, spread, data criticality) | Delivered | (iv) |

---

## Reporting and output

| Feature | Status | PS deliverable |
|---------|--------|----------------|
| **CycloneDX 1.6 CBOM**, validated against the official schema | Delivered | standardised report |
| Explainable report JSON (every score with its inputs) | Delivered | standardised report |
| ML-DSA-65 signatures with a per-component BLAKE3 chain (tamper-evident) | Delivered | - |
| Comparison of two scans | Delivered | - |
| Crypto graph export (JSON) | Delivered | - |
| PDF executive report: findings, risk by component, the plan against the national timeline, what to fix first, method and inputs; deterministic and ML-DSA-65 signed | Delivered | standardised report |
| Roadmap scheduled against the India DST 2027–2029 critical-infrastructure timeline: due year per wave, the team size that meets every deadline, overdue waves flagged | Delivered | - |

---

## Interactive GUI (the cockpit)

| Feature | Status | PS deliverable |
|---------|--------|----------------|
| Overview: headline counts, Mosca timeline, risk by component, threat split | Delivered | interactive GUI |
| Inventory: filter and sort; drawer explaining each asset down to `file:line` | Delivered | interactive GUI |
| Exposure graph: entry → function → crypto → data, with path tracing | Delivered | interactive GUI |
| Migration roadmap board | Delivered | interactive GUI |
| Compare two scans | Delivered | interactive GUI |
| Scan launcher confined to operator-declared roots | Delivered | interactive GUI |
| Dark and light themes; works at phone width | Delivered | interactive GUI |
| Live scan progress pushed to the cockpit (server-sent events) and shown on the terminal | Delivered | interactive GUI |

---

## Platform and non-functional

| Feature | Status |
|---------|--------|
| Static musl binaries for x86_64 and aarch64 | Delivered |
| Fully offline: knowledge, rules and policy compiled in; no network client in the scan path | Delivered |
| Self-confinement with Landlock and seccomp, verifiable with `sandbox-check` | Delivered |
| Reproducible releases with SBOMs, signatures and a self-CBOM | Delivered |
| Hardened systemd unit and `scratch` container image | Delivered |
| Modes: `scan`, `ci`, `serve`, `sign`, `verify`, `validate`, `keygen`, `sandbox-check`, `knowledge` | Delivered |
| Bearer-token authentication, loopback by default, DNS-rebinding protection | Delivered |
| Signed knowledge bundles updated independently of releases, with rollback protection | Delivered |
| Incremental scans: a content-addressed cache reuses unchanged files, with byte-identical output | Delivered |
| Named users with viewer, operator and admin roles; a hash-chained, verifiable audit log of every API call | Delivered |
| TLS 1.3 only with hybrid X25519MLKEM768 key exchange first; mutual TLS with client certificates pinned to users | Delivered |
| Windows build (x86_64): the same CBOM and report as Linux, byte for byte; process mitigations (no child processes, no dynamic code, no remote images) in place of Landlock and seccomp | Delivered |
| Cockpit compiled into the binary: one file serves the API and the UI (`--ui` still serves a directory instead) | Delivered |

---

## What the demo shows

Run against [`examples/demo-estate`](../examples/demo-estate), a six-service estate with a
container image and a packet capture of real OpenSSL handshakes:

1. `lattice scan` inventories 49 assets across source, configuration, certificates, keys,
   Terraform, the image and the capture, and writes a schema-valid CBOM.
2. The graph traces `POST /v1/payments` → `create_payment` → `tokenize_card` → RSA-2048,
   protecting card data with a 10-year secrecy: "already late" by Mosca.
3. TLS 1.0 is configured in nginx and negotiated in the capture: one asset, Confirmed.
4. The image's OpenSSL 3.0.13 (from dpkg) has no ML-KEM; the ledger already negotiates
   X25519MLKEM768.
5. The cockpit ranks the fixes and groups them into waves.
6. A commit adds MD5; `lattice ci` fails the build and names it.
7. The CBOM is signed with ML-DSA-65; altering one component makes verification name it.
