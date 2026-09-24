#!/usr/bin/env python3
"""Scans a pinned OpenSSL release and compares the result with a reviewed golden summary.

    scripts/openssl-golden.py --lattice target/release/lattice          # check
    scripts/openssl-golden.py --lattice target/release/lattice --bless  # accept changes

OpenSSL is the largest body of real cryptographic code most estates depend on: every algorithm
family, legacy and post-quantum, in C, Perl, configuration, certificates and keys. A change to
detection, normalisation or scoring shows up here as a diff against
crates/lattice-engine/tests/golden/openssl-<version>.tsv, one line per asset (bom-ref, name,
tier, priority, recommended action, occurrences), sorted, so it can be reviewed like code.

The release tarball is downloaded once into the cache directory and checked against the SHA-256
pinned below; it is never committed. The scan runs under the required sandbox with a fixed
SOURCE_DATE_EPOCH, and the CBOM must validate against the CycloneDX 1.6 schema.
"""

import argparse
import difflib
import hashlib
import json
import os
import pathlib
import subprocess
import sys
import tarfile
import urllib.request

VERSION = "3.5.5"
SHA256 = "b28c91532a8b65a1f983b4c28b7488174e4a01008e29ce8e69bd789f28bc2a89"
URL = f"https://github.com/openssl/openssl/releases/download/openssl-{VERSION}/openssl-{VERSION}.tar.gz"
EPOCH = "1790121600"  # 2026-09-23T00:00:00Z

ROOT = pathlib.Path(__file__).resolve().parent.parent
GOLDEN = ROOT / "crates" / "lattice-engine" / "tests" / "golden" / f"openssl-{VERSION}.tsv"


def sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def fetch(cache):
    cache.mkdir(parents=True, exist_ok=True)
    tarball = cache / f"openssl-{VERSION}.tar.gz"
    if not tarball.exists() or sha256(tarball) != SHA256:
        print(f"downloading {URL}", file=sys.stderr)
        partial = tarball.with_suffix(".part")
        with urllib.request.urlopen(URL, timeout=120) as response, open(partial, "wb") as out:
            while block := response.read(1 << 20):
                out.write(block)
        partial.replace(tarball)
    actual = sha256(tarball)
    if actual != SHA256:
        sys.exit(f"openssl-{VERSION}.tar.gz has SHA-256 {actual}, expected {SHA256}")
    source = cache / f"openssl-{VERSION}"
    if not source.is_dir():
        with tarfile.open(tarball) as archive:
            archive.extractall(cache, filter="data")
    return source


def lattice(binary, *args):
    env = dict(os.environ, SOURCE_DATE_EPOCH=EPOCH)
    env.pop("LATTICE_CACHE", None)
    result = subprocess.run([str(binary), *args], env=env, capture_output=True, text=True)
    if result.returncode != 0:
        sys.exit(f"lattice {' '.join(args)} failed ({result.returncode}):\n{result.stderr}")
    return result


def summary(cbom):
    lines = []
    for component in cbom["components"]:
        properties = {p["name"]: p["value"] for p in component.get("properties", [])}
        occurrences = len(component.get("evidence", {}).get("occurrences", []))
        lines.append("\t".join([
            component["bom-ref"],
            component["name"],
            properties.get("lattice:tier", "-"),
            properties.get("lattice:priority", "-"),
            properties.get("lattice:recommendation-action", "-"),
            str(occurrences),
        ]))
    lines.sort()
    meta = {p["name"]: p["value"] for p in cbom["metadata"].get("properties", [])}
    header = [
        f"# OpenSSL {VERSION} (openssl-{VERSION}.tar.gz, SHA-256 {SHA256})",
        f"# scanned at SOURCE_DATE_EPOCH={EPOCH} with policy {meta.get('lattice:policy-version')}, "
        f"knowledge {meta.get('lattice:knowledge-version')}, rules {meta.get('lattice:rules-version')}",
        f"# assets {meta.get('lattice:summary:assets')} · quantum-vulnerable "
        f"{meta.get('lattice:summary:quantum-vulnerable')} · broken now {meta.get('lattice:summary:broken-now')} "
        f"· critical {meta.get('lattice:summary:critical')} · high {meta.get('lattice:summary:high')}",
        "# bom-ref\tname\ttier\tpriority\taction\toccurrences",
    ]
    return "\n".join(header + lines) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--lattice", required=True, type=pathlib.Path, help="the lattice binary to test")
    parser.add_argument("--cache", type=pathlib.Path,
                        default=pathlib.Path.home() / ".cache" / "lattice-openssl",
                        help="where the release is downloaded and extracted")
    parser.add_argument("--bless", action="store_true", help="write the golden file instead of comparing")
    parser.add_argument("--sandbox", default="required", choices=["required", "best-effort", "off"])
    args = parser.parse_args()

    source = fetch(args.cache)
    out = args.cache / "out"
    out.mkdir(exist_ok=True)
    cbom_path, report_path = out / "openssl.cbom.json", out / "openssl.report.json"
    lattice(args.lattice, "--sandbox", args.sandbox, "scan", str(source), "--subject", "openssl",
            "--subject-version", VERSION, "-o", str(cbom_path), "--report", str(report_path), "--quiet")
    lattice(args.lattice, "validate", str(cbom_path))

    actual = summary(json.loads(cbom_path.read_text(encoding="utf-8")))
    if args.bless:
        GOLDEN.write_text(actual, encoding="utf-8", newline="\n")
        print(f"wrote {GOLDEN.relative_to(ROOT)} ({actual.count(chr(10)) - 4} assets)")
        return 0
    expected = GOLDEN.read_text(encoding="utf-8") if GOLDEN.exists() else ""
    if actual == expected:
        print(f"OpenSSL {VERSION}: {actual.count(chr(10)) - 4} assets match the golden summary")
        return 0
    diff = list(difflib.unified_diff(expected.splitlines(), actual.splitlines(),
                                     "golden", "this build", lineterm="", n=0))
    print("\n".join(diff[:200]))
    if len(diff) > 200:
        print(f"... {len(diff) - 200} more diff lines")
    print(f"\nOpenSSL {VERSION} scan differs from {GOLDEN.relative_to(ROOT)}; "
          "if the change is intended, rerun with --bless and review the diff.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
