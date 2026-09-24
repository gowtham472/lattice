#!/usr/bin/env python3
"""Seeds and runs the cargo-fuzz targets in fuzz/.

    scripts/fuzz.py                 # every target, 60 s each
    scripts/fuzz.py capture pki -t 600

Seeds come from the repository (the demo estate and the test fixtures), so every target starts
from real, well-formed inputs and mutates outward. Corpora grow in fuzz/corpus/<target> and
crashes land in fuzz/artifacts/<target>; neither is committed. Needs a nightly toolchain and
cargo-fuzz (`cargo +nightly install cargo-fuzz --locked`). Exits non-zero if any target crashed.
"""

import argparse
import os
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
FUZZ = ROOT / "fuzz"
ESTATE = ROOT / "examples" / "demo-estate"
FIXTURES = ROOT / "crates" / "lattice-collectors" / "tests" / "fixtures"

# The first input byte picks the file name for targets whose collector dispatches on it; these
# lists mirror the NAMES tables in fuzz/fuzz_targets.
NAMED = {
    "pki": ["cert.pem", "cert.der", "cert.crt", "server.key", "id_rsa", "id_ed25519.pub",
            "authorized_keys", "known_hosts", "store.p12", "store.jks", "bundle.p7b", "req.csr"],
    "config": ["nginx.conf", "sshd_config", "haproxy.cfg", "openssl.cnf", "java.security", ".env",
               "Dockerfile", "app.yaml", "app.json", "app.toml", "app.properties", "main.tf"],
    "source": ["a.py", "A.java", "a.go", "a.c", "a.cpp", "a.js", "a.ts", "a.tsx", "a.rs", "a.cs"],
}
TARGETS = ["pki", "keys", "config", "source", "binary", "capture", "container", "names"]


def files(*patterns):
    for pattern in patterns:
        for base in (ESTATE, FIXTURES):
            yield from sorted(p for p in base.rglob(pattern) if p.is_file())


def named(target, path, pick):
    return bytes([NAMED[target].index(pick)]) + path.read_bytes()


def seeds(target):
    if target == "pki":
        for path in files("*.pem", "*.crt", "*.key", "*.pub"):
            pick = {".pem": "cert.pem", ".crt": "cert.crt", ".key": "server.key",
                    ".pub": "id_ed25519.pub"}[path.suffix]
            yield named(target, path, pick)
    elif target == "keys":
        import base64
        import re
        for path in files("*.pem", "*.crt", "*.key"):
            for block in re.findall(rb"-----BEGIN [^-]+-----(.*?)-----END", path.read_bytes(), re.S):
                yield base64.b64decode(b"".join(block.split()))
        for path in files("*.pub"):
            yield base64.b64decode(path.read_text().split()[1])
    elif target == "config":
        for path in files("nginx.conf"):
            yield named(target, path, "nginx.conf")
        for path in files("*.tf"):
            yield named(target, path, "main.tf")
        for path in files("package.json"):
            yield named(target, path, "app.json")
    elif target == "source":
        by_suffix = {".py": "a.py", ".java": "A.java", ".go": "a.go", ".js": "a.js"}
        for path in files("*.py", "*.java", "*.go", "*.js"):
            yield named(target, path, by_suffix[path.suffix])
    elif target == "binary":
        for candidate in ("/bin/true", "/usr/bin/true"):
            if os.path.exists(candidate):
                yield pathlib.Path(candidate).read_bytes()
                break
    elif target == "capture":
        for path in files("*.pcap"):
            yield path.read_bytes()
    elif target == "container":
        for path in files("*.tar"):
            yield path.read_bytes()
    elif target == "names":
        yield from (name.encode() for name in [
            "RSA-2048", "AES-256-GCM", "secp256r1", "X25519MLKEM768", "ML-KEM-768",
            "AES/CBC/PKCS5Padding", "ECDHE-RSA-AES128-GCM-SHA256", "SHA3-256", "ed25519"])


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("targets", nargs="*", help="default: all of " + ", ".join(TARGETS))
    parser.add_argument("-t", "--seconds", type=int, default=60, help="time per target")
    args = parser.parse_args()
    unknown = set(args.targets) - set(TARGETS)
    if unknown:
        parser.error("unknown target: " + ", ".join(sorted(unknown)))
    args.targets = args.targets or TARGETS

    env = dict(os.environ)
    env.setdefault("CARGO_TARGET_DIR", str(pathlib.Path.home() / ".cache" / "lattice-fuzz-target"))
    crashed = []
    for target in args.targets:
        corpus = FUZZ / "corpus" / target
        corpus.mkdir(parents=True, exist_ok=True)
        for i, seed in enumerate(seeds(target)):
            (corpus / f"seed-{i:03}").write_bytes(seed)
        print(f"== {target}: {len(list(corpus.iterdir()))} inputs, {args.seconds} s", flush=True)
        result = subprocess.run(
            ["cargo", "+nightly", "fuzz", "run", target, str(corpus), "--",
             f"-max_total_time={args.seconds}", "-timeout=20", "-rss_limit_mb=4096",
             "-max_len=1048576", "-print_final_stats=1"],
            cwd=FUZZ, env=env)
        if result.returncode != 0:
            crashed.append(target)
    if crashed:
        print("crashed: " + ", ".join(crashed) + " (inputs in fuzz/artifacts)", file=sys.stderr)
        return 1
    print("no crashes")
    return 0


if __name__ == "__main__":
    sys.exit(main())
