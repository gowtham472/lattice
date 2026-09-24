#!/usr/bin/env bash
# Builds reproducible LATTICE release packages.
#
#   scripts/release.sh                          # all targets, unsigned
#   LATTICE_RELEASE_KEY=release.key LATTICE_RELEASE_PUB=release.pub scripts/release.sh
#
# For each target it produces, in dist/:
#   lattice-<version>-<target>.tar.gz           static binary, cockpit, knowledge, rules, docs, units
#                                               (a .zip, without the systemd unit, for Windows)
#   lattice-<version>-<target>.sbom.cdx.json    CycloneDX 1.6 SBOM: every file's SHA-256, every
#                                               Rust crate and npm package shipped, the tarball hash
#   lattice-<version>-<target>.sbom.cdx.json.sig.json   ML-DSA-65 signature (when a key is given)
#   lattice-<version>-<target>.cbom.json        LATTICE's own CBOM: its scan of its own binary
# plus SHA256SUMS over all of them.
#
# Reproducible: the same commit, toolchain and SOURCE_DATE_EPOCH give byte-identical archives
# (sorted entries, fixed timestamps and ownership, gzip without names, remapped build paths).
# The Windows binary's own CBOM is produced by the Linux build scanning it, since release builds
# run on Linux.
set -euo pipefail

cd "$(dirname "$0")/.."
ROOT=$PWD
VERSION=$(sed -n 's/^version = "\([^"]*\)".*/\1/p' Cargo.toml | head -1)
[ -n "$VERSION" ] || { echo "could not read the version from Cargo.toml" >&2; exit 1; }
export SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct 2>/dev/null || echo 1790035200)}
TARGETS=${TARGETS:-"x86_64-unknown-linux-musl aarch64-unknown-linux-musl x86_64-pc-windows-gnu"}
DIST=$ROOT/dist
HOST_TARGET="$(uname -m)-unknown-linux-musl"

echo "LATTICE $VERSION, SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH, targets: $TARGETS"
rm -rf "$DIST"
mkdir -p "$DIST"

# ---- cockpit ----------------------------------------------------------------------------------
if command -v npm >/dev/null 2>&1; then
    (cd cockpit && npm ci --no-audit --no-fund --loglevel=error && npm run build >/dev/null)
fi
[ -f cockpit/dist/index.html ] || { echo "cockpit/dist is missing and npm is unavailable" >&2; exit 1; }

# ---- binaries ---------------------------------------------------------------------------------
# Paths inside the binary never reveal the build machine.
export RUSTFLAGS="--remap-path-prefix=$ROOT=/lattice --remap-path-prefix=$HOME/.cargo=/cargo --remap-path-prefix=$HOME/.rustup=/rustup"
for target in $TARGETS; do
    echo "building $target"
    cargo zigbuild --release --locked --quiet --target "$target" -p lattice-cli
done

zip_reproducibly() { # <directory> <archive>
    python3 - "$1" "$2" <<'PY'
import os, pathlib, sys, time, zipfile
stage, archive = pathlib.Path(sys.argv[1]), sys.argv[2]
stamp = time.gmtime(int(os.environ["SOURCE_DATE_EPOCH"]))[:6]
with zipfile.ZipFile(archive, "w") as out:
    for path in sorted(p for p in stage.rglob("*") if p.is_file()):
        name = (pathlib.Path(stage.name) / path.relative_to(stage)).as_posix()
        entry = zipfile.ZipInfo(name, date_time=max(stamp, (1980, 1, 1, 0, 0, 0)))
        entry.external_attr = (0o755 if path.suffix == ".exe" else 0o644) << 16
        entry.create_system = 3
        entry.compress_type = zipfile.ZIP_DEFLATED
        out.writestr(entry, path.read_bytes(), compresslevel=9)
PY
}

tar_reproducibly() { # <directory> <archive>
    tar --sort=name --mtime="@$SOURCE_DATE_EPOCH" --owner=0 --group=0 --numeric-owner \
        --format=posix --pax-option=exthdr.name=%d/PaxHeaders/%f,delete=atime,delete=ctime \
        -C "$(dirname "$1")" -cf - "$(basename "$1")" | gzip -n -9 > "$2"
}

# the host binary first: it scans the others for their own CBOMs
host_first=$(for target in $TARGETS; do
    [ "$target" = "$HOST_TARGET" ] && echo 0 "$target" || echo 1 "$target"
done | sort | cut -d' ' -f2)

for target in $host_first; do
    name="lattice-$VERSION-$target"
    stage="$DIST/stage/$name"
    windows=false
    case "$target" in *windows*) windows=true ;; esac
    if $windows; then
        install -D -m 0755 "target/$target/release/lattice.exe" "$stage/bin/lattice.exe"
    else
        install -D -m 0755 "target/$target/release/lattice" "$stage/bin/lattice"
    fi
    mkdir -p "$stage/share/lattice" "$stage/share/doc/lattice"
    cp -r cockpit/dist "$stage/share/lattice/cockpit"
    cp -r knowledge rules "$stage/share/lattice/"
    cp -r examples/demo-estate "$stage/share/lattice/demo-estate"
    cp README.md docs/release.md "$stage/share/doc/lattice/"
    if ! $windows; then
        mkdir -p "$stage/lib/systemd/system"
        cp packaging/lattice.env.example "$stage/share/doc/lattice/"
        cp packaging/lattice.service "$stage/lib/systemd/system/"
    fi
    if [ -f LICENSE ]; then
        cp LICENSE "$stage/share/doc/lattice/"
    else
        echo "warning: no LICENSE file; the package declares Apache-2.0 in its SBOM only" >&2
    fi
    find "$stage" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +
    chmod -R u=rwX,go=rX "$stage"
    chmod 0755 "$stage"/bin/*
    if $windows; then
        archive="$DIST/$name.zip"
        zip_reproducibly "$stage" "$archive"
    else
        archive="$DIST/$name.tar.gz"
        tar_reproducibly "$stage" "$archive"
    fi

    python3 scripts/sbom.py --stage "$stage" --archive "$archive" --target "$target" \
        --version "$VERSION" --output "$DIST/$name.sbom.cdx.json"
    # LATTICE's own cryptography, found by LATTICE (the host build), confined by its own sandbox
    host="$DIST/stage/lattice-$VERSION-$HOST_TARGET/bin/lattice"
    if [ -x "$host" ]; then
        report=$(mktemp)
        "$host" --sandbox best-effort scan "$stage/bin" --subject lattice \
            --subject-version "$VERSION" --max-file-bytes 268435456 \
            -o "$DIST/$name.cbom.json" --report "$report" --quiet
        rm -f "$report"
        "$host" validate "$DIST/$name.sbom.cdx.json" >/dev/null
        "$host" validate "$DIST/$name.cbom.json" >/dev/null
    fi
done

# ---- signatures and checksums ---------------------------------------------------------------
if [ -n "${LATTICE_RELEASE_KEY:-}" ]; then
    signer="$DIST/stage/lattice-$VERSION-$HOST_TARGET/bin/lattice"
    for sbom in "$DIST"/*.sbom.cdx.json; do
        "$signer" sign "$sbom" --key "$LATTICE_RELEASE_KEY" --public-key "$LATTICE_RELEASE_PUB" >/dev/null
        "$signer" verify "$sbom" --public-key "$LATTICE_RELEASE_PUB" >/dev/null
    done
else
    echo "warning: LATTICE_RELEASE_KEY not set; SBOMs are unsigned" >&2
fi
rm -rf "$DIST/stage"
(cd "$DIST" && sha256sum -- $(ls *.tar.gz *.zip *.json 2>/dev/null) > SHA256SUMS)
echo
ls -l "$DIST"
