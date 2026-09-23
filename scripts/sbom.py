#!/usr/bin/env python3
"""CycloneDX 1.6 SBOM for one LATTICE release package.

The SBOM names the release archive (with its SHA-256) as its subject and lists:
* every Rust crate compiled into ``lattice`` for the target: the resolved dependency graph from
  ``cargo metadata`` restricted to normal dependencies reachable from ``lattice-cli``, with the
  crates.io checksum from ``Cargo.lock`` and the declared licence;
* every npm package shipped in the cockpit bundle (production dependencies only);
* every file in the package, with its SHA-256.
Signed with ``lattice sign``, it authenticates the archive and each file in it.
Output is deterministic for a given source tree, archive and SOURCE_DATE_EPOCH.
"""

from __future__ import annotations

import argparse
import base64
import datetime
import hashlib
import json
import os
import subprocess
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def serial(seed: str) -> str:
    raw = bytearray(hashlib.sha256(("lattice-sbom|" + seed).encode()).digest()[:16])
    raw[6] = (raw[6] & 0x0F) | 0x40
    raw[8] = (raw[8] & 0x3F) | 0x80
    h = raw.hex()
    return f"urn:uuid:{h[0:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"


def rust_components(target: str) -> tuple[list[dict], list[dict], str]:
    metadata = json.loads(subprocess.run(
        ["cargo", "metadata", "--format-version", "1", "--locked", "--filter-platform", target],
        cwd=ROOT, check=True, capture_output=True).stdout)
    lock = tomllib.loads((ROOT / "Cargo.lock").read_text())
    checksums = {(p["name"], p["version"]): p.get("checksum") for p in lock["package"]}
    packages = {p["id"]: p for p in metadata["packages"]}
    nodes = {n["id"]: n for n in metadata["resolve"]["nodes"]}
    root = next(i for i, p in packages.items() if p["name"] == "lattice-cli")

    # normal (runtime) dependencies reachable from the binary's crate
    reachable, stack = set(), [root]
    while stack:
        current = stack.pop()
        if current in reachable:
            continue
        reachable.add(current)
        for dep in nodes[current]["deps"]:
            if any(k["kind"] is None for k in dep["dep_kinds"]):
                stack.append(dep["pkg"])

    def ref(pid: str) -> str:
        p = packages[pid]
        return f"pkg:cargo/{p['name']}@{p['version']}"

    components, dependencies = [], []
    for pid in sorted(reachable, key=ref):
        p = packages[pid]
        component = {"type": "library", "bom-ref": ref(pid), "name": p["name"], "version": p["version"], "purl": ref(pid)}
        if p.get("license"):
            component["licenses"] = [{"expression": p["license"]}]
        if checksums.get((p["name"], p["version"])):
            component["hashes"] = [{"alg": "SHA-256", "content": checksums[(p["name"], p["version"])]}]
        if p.get("source") is None:
            component["properties"] = [{"name": "lattice:source", "value": "workspace"}]
        components.append(component)
        deps = sorted({ref(d["pkg"]) for d in nodes[pid]["deps"] if d["pkg"] in reachable and any(k["kind"] is None for k in d["dep_kinds"])})
        dependencies.append({"ref": ref(pid), **({"dependsOn": deps} if deps else {})})
    return components, dependencies, ref(root)


def npm_components() -> list[dict]:
    lock = json.loads((ROOT / "cockpit" / "package-lock.json").read_text())
    components = []
    for path, p in sorted(lock.get("packages", {}).items()):
        if not path.startswith("node_modules/") or p.get("dev"):
            continue
        name = path.split("node_modules/")[-1]
        purl = f"pkg:npm/{name.replace('@', '%40')}@{p['version']}"
        component = {"type": "library", "bom-ref": purl, "name": name, "version": p["version"], "purl": purl}
        if p.get("license"):
            component["licenses"] = [{"expression": p["license"]}]
        integrity = p.get("integrity", "")
        if integrity.startswith("sha512-"):
            component["hashes"] = [{"alg": "SHA-512", "content": base64.b64decode(integrity[7:]).hex()}]
        components.append(component)
    return components


def file_components(stage: Path) -> list[dict]:
    files = []
    for path in sorted(p for p in stage.rglob("*") if p.is_file()):
        relative = path.relative_to(stage).as_posix()
        files.append({"type": "file", "bom-ref": f"file:{relative}", "name": relative,
                      "hashes": [{"alg": "SHA-256", "content": sha256(path)}]})
    return files


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--stage", type=Path, required=True)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    epoch = int(os.environ.get("SOURCE_DATE_EPOCH", "0"))
    archive_hash = sha256(args.archive)
    crates, dependencies, cli_ref = rust_components(args.target)
    npm = npm_components()
    subject = "pkg:generic/lattice@" + args.version + "?arch=" + args.target
    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": serial(archive_hash),
        "version": 1,
        "metadata": {
            "timestamp": datetime.datetime.fromtimestamp(epoch, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "tools": {"components": [{"type": "application", "name": "lattice-release", "version": args.version}]},
            "component": {
                "type": "application", "bom-ref": subject, "name": "lattice", "version": args.version, "purl": subject,
                "licenses": [{"expression": "Apache-2.0"}],
                "hashes": [{"alg": "SHA-256", "content": archive_hash}],
                "properties": [{"name": "lattice:archive", "value": args.archive.name},
                               {"name": "lattice:target", "value": args.target}],
            },
        },
        "components": crates + npm + file_components(args.stage),
        "dependencies": [{"ref": subject, "dependsOn": sorted([cli_ref] + [c["bom-ref"] for c in npm])}] + dependencies
                        + [{"ref": c["bom-ref"]} for c in npm],
    }
    args.output.write_text(json.dumps(bom, indent=2, sort_keys=False) + "\n")
    print(f"{args.output.name}: {len(crates)} crates, {len(npm)} npm packages, {len(bom['components']) - len(crates) - len(npm)} files")


if __name__ == "__main__":
    main()
