# Releases, installation and hardening

## What a release contains

`scripts/release.sh` builds, for each target (`x86_64-unknown-linux-musl`,
`aarch64-unknown-linux-musl`, `x86_64-pc-windows-gnu`):

| File | Purpose |
|---|---|
| `lattice-<v>-<target>.tar.gz` | Static binary (`bin/lattice`), cockpit, knowledge base, rules, demo estate, docs, systemd unit |
| `lattice-<v>-x86_64-pc-windows-gnu.zip` | The same for Windows (`bin/lattice.exe`), without the systemd unit; a reproducible zip |
| `lattice-<v>-<target>.sbom.cdx.json` | CycloneDX 1.6 SBOM: the archive's SHA-256, every Rust crate compiled in (with crates.io checksums and licences), every npm package in the cockpit bundle, every file with its SHA-256 |
| `lattice-<v>-<target>.sbom.cdx.json.sig.json` | ML-DSA-65 signature over the SBOM (when built with a release key) |
| `lattice-<v>-<target>.cbom.json` | LATTICE's CBOM of that target's binary, produced by the host build under its own sandbox |
| `SHA256SUMS` | SHA-256 of everything above |

A note on the self-CBOM: LATTICE's binary carries the constant tables its binary collector
searches for (the AES S-box, MD5 and ML-KEM constants, among others), and constant-table detection
cannot tell a table kept for searching from one used for computing. The CBOM therefore lists those
algorithms alongside the ones LATTICE actually uses (ML-DSA-65 with SHA-3/SHAKE for signatures,
SHA-256 and BLAKE3 for digests). The occurrences say `byte-signature`, which is the cue. For the
same reason the library list names GnuTLS, LibreSSL and OpenSSL with versions: those are the
release strings in LATTICE's own library knowledge base, not linked libraries. BoringSSL is real
(aws-lc, the cryptography under LATTICE's TLS, is a BoringSSL fork), as is Windows CNG in the
Windows build, which it uses for random numbers.

ML-DSA signing is hedged (randomised, FIPS 204), so two signatures over the same SBOM differ;
everything else in a release is byte-reproducible.

Binaries are static (musl), so they run on any Linux distribution without dependencies.
Archives are reproducible: the same commit, toolchain (`rust-toolchain.toml`) and
`SOURCE_DATE_EPOCH` give byte-identical files. Build paths are remapped out of the binary.

## Building

```bash
scripts/install-toolchain.sh        # rustup, zig, cargo-zigbuild (once)
rustup target add aarch64-unknown-linux-musl
scripts/release.sh                  # unsigned
LATTICE_RELEASE_KEY=release.key LATTICE_RELEASE_PUB=release.pub scripts/release.sh
```

The release key is an ML-DSA-65 key from `lattice keygen`. Keep the private half offline; publish
the public half separately from the release (a website, a signed commit, an out-of-band channel).

## Windows

`scripts/release.sh` builds the Windows package with the others. Unzip it anywhere and run
`bin\lattice.exe`, with the cockpit compiled in (a copy is in `share\lattice\cockpit`). To build
only the binary:

```bash
rustup target add x86_64-pc-windows-gnu
cargo zigbuild --release --target x86_64-pc-windows-gnu -p lattice-cli   # lattice.exe
```

The Windows build produces the same CBOM and report as Linux, byte for byte (CI compares them
on a Windows runner). Its sandbox is the process mitigation policies: no child processes, no
dynamic code, no remote or low-integrity images; `lattice sandbox-check` shows which apply.
Filesystem and network confinement are Linux-only, so run `--sandbox best-effort` there.
`lattice trace` is Linux-only. The binary is not code-signed; Smart App Control or a WDAC policy
may block it until it is signed or allowed.

## Verifying a download

```bash
sha256sum -c SHA256SUMS --ignore-missing
lattice verify lattice-1.0.0-x86_64-unknown-linux-musl.sbom.cdx.json --public-key release.pub
```

The signature covers the SBOM, and the SBOM's subject carries the archive's SHA-256: a valid
signature and a matching checksum authenticate the archive and, through the SBOM, every file in it.
Verification takes the trusted key as an argument and never trusts a key shipped alongside.

## Installing

```bash
tar -xzf lattice-1.0.0-x86_64-unknown-linux-musl.tar.gz
sudo cp -r lattice-1.0.0-x86_64-unknown-linux-musl/{bin,share,lib} /usr/
lattice --version
lattice sandbox-check
```

`serve` uses the cockpit compiled into the binary; `--ui <dir>` serves another build instead. A copy
also ships at `<prefix>/share/lattice/cockpit`, which a build without the cockpit compiled in
finds next to the binary.

### As a service

```bash
sudo install -D -m 0600 /usr/share/doc/lattice/lattice.env.example /etc/lattice/lattice.env
sudoedit /etc/lattice/lattice.env          # roots, bind address
sudo lattice user add --name alice --role operator --users /etc/lattice/users.toml
sudo systemctl edit --full lattice         # uncomment LoadCredential and LATTICE_USERS
sudo systemctl enable --now lattice
```

To serve beyond loopback, give the service a certificate: the unit has commented
`LoadCredential` lines for the certificate, its key and, for mutual TLS, the client CA. The server
then speaks TLS 1.3 only, preferring the hybrid X25519MLKEM768 key exchange.

Each `lattice user add` without `--certificate` prints the new token once; the users file keeps only its digest. Every API
call is recorded in `/var/lib/lattice/audit.jsonl`; check it with `lattice audit verify`.

The unit runs with a dynamic user and no capabilities, a read-only filesystem except its
state directory, no outbound network, and a system-call allow-list. Inside it, LATTICE applies
its own sandbox with `--sandbox required`, so it refuses to start unconfined.

### As a container

```bash
docker build -f packaging/Dockerfile -t lattice:1.0.0 .
docker run --rm -v "$PWD/estate:/estate:ro" -v "$PWD/out:/out" lattice:1.0.0 \
    scan /estate -o /out/estate.cbom.json --report /out/estate.report.json
```

The image is `scratch`, runs as UID 65532, and contains one static binary plus the cockpit and
knowledge files.

## Knowledge updates between releases

The algorithm catalogue, library PQC knowledge, detection rules and risk policy can be updated
without a new binary, through a signed knowledge bundle.

```bash
# publisher: next sequence number, signed with the knowledge key
lattice knowledge pack --source knowledge --rules rules/source.toml --sequence 2 \
    --key knowledge.key --public-key knowledge.pub

# operator: verify and install, then every scan uses it
lattice knowledge install lattice-knowledge-2026.10.1-2.bundle.json \
    --knowledge-dir /var/lib/lattice/knowledge --knowledge-key /etc/lattice/knowledge.pub
lattice knowledge status --knowledge-dir /var/lib/lattice/knowledge --knowledge-key /etc/lattice/knowledge.pub
```

`--knowledge-dir` and `--knowledge-key` (or `LATTICE_KNOWLEDGE_DIR` and `LATTICE_KNOWLEDGE_KEY`)
apply to `scan`, `ci` and `serve`. A bundle must be newer than the installed one and than the
knowledge compiled into the binary; a present bundle that does not verify stops the command with
exit code 3. Reports, CBOMs and `/api/health` record which knowledge was used and who signed it.

## The sandbox

On Linux every command that reads untrusted content confines itself before doing so:

| Layer | Mechanism | Effect |
|---|---|---|
| Filesystem | Landlock | Scan targets read-only; only the output directories (or the server's data directory) writable; nothing else openable |
| System calls | seccomp | No new sockets (no network; the server's listener is opened first), no program execution, no ptrace or cross-process memory, no mounts, namespaces, kernel modules, BPF or keyrings |

`--sandbox best-effort` (default) applies what the kernel supports and reports it;
`--sandbox required` refuses to run otherwise; `--sandbox off` disables it. `lattice sandbox-check`
proves what is enforced on the current machine by attempting each forbidden operation in a
confined child process. The scan summary and the server's `/api/health` report the status.

Landlock cannot confine paths on 9p, the filesystem WSL uses for Windows drives (`/mnt/c`, `/mnt/d`).
There `best-effort` applies only the system-call layer and names the path; `required` refuses.
Copy the target to a Linux filesystem to scan it fully confined.
