# LATTICE

LATTICE is an offline cryptographic discovery and post-quantum migration decision engine. It reads
an estate (source code, binaries, certificates, keys, server configuration, infrastructure-as-code,
container images, and packet captures of live traffic)
without executing or modifying anything. It produces a strict CycloneDX 1.6 CBOM and an explainable
risk assessment: which cryptography protects long-lived data on an exposed path, when a quantum
computer breaks it, what replaces it, and in what order.

Specification and architecture: [`docs/00-INDEX.md`](docs/00-INDEX.md). Build status: [`docs/IMPLEMENTATION.md`](docs/IMPLEMENTATION.md).

## Build

Requires Rust (pinned in `rust-toolchain.toml`) and, for the cockpit, Node.js 20+. Dependencies
are fetched on the build machine only; the scanner and server make no network calls.

```bash
cargo build --release -p lattice-cli
cd cockpit && npm ci && npm run build
```

The binary is `target/release/lattice`.

## Use

```bash
# scan: CBOM + explainable report (+ the executive PDF)
lattice scan examples/demo-estate -o demo.cbom.json --report demo.report.json --pdf demo.pdf

# or render the PDF later from a report, signed like a CBOM
lattice report demo.report.json -o demo.pdf \
    --sign-with keys/lattice-signing.key --public-key keys/lattice-signing.pub
lattice verify demo.pdf --public-key keys/lattice-signing.pub

# sign and verify (ML-DSA-65, FIPS 204)
lattice keygen --out-dir keys
lattice sign demo.cbom.json --key keys/lattice-signing.key --public-key keys/lattice-signing.pub
lattice verify demo.cbom.json --public-key keys/lattice-signing.pub

# validate against the official CycloneDX 1.6 schema (offline)
lattice validate demo.cbom.json

# on a live Linux host (root): which cryptography do running processes actually use?
sudo lattice trace --duration 300 -o estate/payments-api/prod-1.lattice-trace.json
lattice trace --dry-run      # what would be probed, without privilege
# OpenSSL and the Go programs already running are probed; name others with --binary

# serve the cockpit to named users with roles; every call lands in a hash-chained audit log
lattice user add --name alice --role operator --users users.toml
lattice serve --root estate=/srv/code --users users.toml --data-dir .lattice \
    --bind 0.0.0.0:7443 --tls-cert server.pem --tls-key server.key   # TLS 1.3, X25519MLKEM768 first
# or pin client certificates instead of tokens, and require them (mutual TLS)
lattice user add --name bob --role viewer --certificate bob.pem --users users.toml
lattice serve ... --client-ca clients-ca.pem
lattice audit verify .lattice/audit.jsonl

# CI gate: exit 1 on new or worsened high-risk crypto, 3 if the signed baseline fails verification
lattice ci examples/demo-estate --baseline demo.cbom.json --trusted-key keys/lattice-signing.pub --fail-on high

# cockpit and API on http://127.0.0.1:7443; scans can read only the named roots
lattice serve --root demo=examples/demo-estate --ui cockpit/dist
```

On Linux every command that reads untrusted content confines itself first (Landlock: targets
read-only, outputs the only writable places; seccomp: no network, no program execution).
`lattice sandbox-check` shows what the kernel enforces; `--sandbox required` refuses to run without it.
Release builds, verification, the systemd unit and the container image: [`docs/release.md`](docs/release.md).

Set `SOURCE_DATE_EPOCH` for byte-reproducible output. Add `--cache DIR` to `scan`, `ci` or
`serve` to skip files that have not changed since the last scan; the output is identical. `--policy` replaces the embedded risk policy
([`knowledge/policy.toml`](knowledge/policy.toml)): Q-day window, exposure and liveness weights,
data classes and their secrecy lifetimes.

## Workspace

| Path | Responsibility |
|---|---|
| `crates/lattice-core` | Domain model, algorithm knowledge base, name parsing, normalisation, policy |
| `crates/lattice-collectors` | Source (9 languages), binary, PKI, configuration, container-image and packet-capture collectors; bounded, isolated |
| `crates/lattice-classify` | Explainable data classification and secrecy lifetimes |
| `crates/lattice-graph` | Entry point → function → crypto → data graph, reachability and exposure |
| `crates/lattice-risk` | Quantum breakability, HNDL/TNFL index, crypto-agility, Mosca, priority, advisor, roadmap, effort and timeline |
| `crates/lattice-cbom` | CycloneDX 1.6 emitter, schema validation, ML-DSA-65 signatures |
| `crates/lattice-engine` | The pipeline and baseline comparison |
| `crates/lattice-server` | HTTP API and cockpit host (axum) |
| `crates/lattice-sandbox` | Landlock and seccomp self-confinement |
| `crates/lattice-cli` | `scan`, `ci`, `keygen`, `sign`, `verify`, `validate`, `serve`, `sandbox-check` |
| `packaging`, `scripts/release.sh` | systemd unit, container image, reproducible releases with SBOMs |
| `cockpit` | React cockpit: overview, Mosca timeline, inventory, exposure graph, roadmap, compare |
| `knowledge`, `rules` | Versioned algorithm knowledge, risk policy and detection rules |
| `examples/demo-estate` | A realistic multi-service estate for demonstration |

## Validation

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cd cockpit && npm run typecheck
scripts/fuzz.py -t 300                  # every parser, 5 minutes each (nightly + cargo-fuzz)
```

CI (`.github/workflows/ci.yml`) runs all of the above on every push, plus a scan of OpenSSL 3.5.5
compared against a reviewed summary (`scripts/openssl-golden.py --lattice target/release/lattice`)
and a fuzz of every parser (longer nightly).

The demo estate's CBOM is a golden file: when a change to it is intended, regenerate it with
`LATTICE_BLESS=1 cargo test -p lattice-engine --test golden` and review the diff.
