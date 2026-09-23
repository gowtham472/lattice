#!/usr/bin/env bash
# Builds reproducible LATTICE release packages.
#
#   scripts/release.sh                          # all targets, unsigned
#   LATTICE_RELEASE_KEY=release.key LATTICE_RELEASE_PUB=release.pub scripts/release.sh
#
# For each target it produces, in dist/:
#   lattice-<version>-<target>.tar.gz           static binary, cockpit, knowledge, rules, docs, units
#   lattice-<version>-<target>.sbom.cdx.json    CycloneDX 1.6 SBOM: every file's SHA-256, every
#                                               Rust crate and npm package shipped, the tarball hash
#   lattice-<version>-<target>.sbom.cdx.json.sig.json   ML-DSA-65 signature (when a key is given)
#   lattice-<version>-<target>.cbom.json        LATTICE's own CBOM: its scan of its own binary
# plus SHA256SUMS over all of them.
#
# Reproducible: the same commit, toolchain and SOURCE_DATE_EPOCH give byte-identical archives
# (sorted entries, fixed timestamps and ownership, gzip without names, remapped build paths).
set -euo pipefail

cd "$(dirname "$0")/.."
ROOT=$PWD
VERSION=$(sed -n 's/^version = "\([^"]*\)".*/\1/p' Cargo.toml | head -1)
[ -n "$VERSION" ] || { echo "could not read the version from Cargo.toml" >&2; exit 1; }
export SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct 2>/dev/null || echo 1790035200)}
TARGETS=${TARGETS:-"x86_64-unknown-linux-musl aarch64-unknown-linux-musl"}
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

tar_reproducibly() { # <directory> <archive>
    tar --sort=name --mtime="@$SOURCE_DATE_EPOCH" --owner=0 --group=0 --numeric-owner \
        --format=posix --pax-option=exthdr.name=%d/PaxHeaders/%f,delete=atime,delete=ctime \
        -C "$(dirname "$1")" -cf - "$(basename "$1")" | gzip -n -9 > "$2"
}

for target in $TARGETS; do
    name="lattice-$VERSION-$target"
    stage="$DIST/stage/$name"
    install -D -m 0755 "target/$target/release/lattice" "$stage/bin/lattice"
    mkdir -p "$stage/share/lattice" "$stage/share/doc/lattice" "$stage/lib/systemd/system"
    cp -r cockpit/dist "$stage/share/lattice/cockpit"
    cp -r knowledge rules "$stage/share/lattice/"
    cp -r examples/demo-estate "$stage/share/lattice/demo-estate"
    cp README.md docs/release.md "$stage/share/doc/lattice/"
    cp packaging/lattice.env.example "$stage/share/doc/lattice/"
    cp packaging/lattice.service "$stage/lib/systemd/system/"
    if [ -f LICENSE ]; then
        cp LICENSE "$stage/share/doc/lattice/"
    else
        echo "warning: no LICENSE file; the package declares Apache-2.0 in its SBOM only" >&2
    fi
    find "$stage" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +
    chmod -R u=rwX,go=rX "$stage"
    chmod 0755 "$stage/bin/lattice"
    tar_reproducibly "$stage" "$DIST/$name.tar.gz"

    python3 scripts/sbom.py --stage "$stage" --archive "$DIST/$name.tar.gz" --target "$target" \
        --version "$VERSION" --output "$DIST/$name.sbom.cdx.json"
    if [ "$target" = "$HOST_TARGET" ]; then
        # LATTICE's own cryptography, found by LATTICE, confined by its own sandbox
        report=$(mktemp)
        "$stage/bin/lattice" --sandbox best-effort scan "$stage/bin" --subject lattice \
            --subject-version "$VERSION" --max-file-bytes 268435456 \
            -o "$DIST/$name.cbom.json" --report "$report" --quiet
        rm -f "$report"
        "$stage/bin/lattice" validate "$DIST/$name.sbom.cdx.json" >/dev/null
        "$stage/bin/lattice" validate "$DIST/$name.cbom.json" >/dev/null
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
(cd "$DIST" && sha256sum -- *.tar.gz *.json > SHA256SUMS)
echo
ls -l "$DIST"
