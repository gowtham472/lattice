#!/usr/bin/env bash
# One-shot, user-space toolchain for building LATTICE on Linux (including WSL2).
#
#   bash scripts/install-toolchain.sh
#
# Installs, without root:
#   * rustup + the toolchain pinned in rust-toolchain.toml (with the musl target)
#   * zig, used as the C compiler and linker, so no system gcc is required
#   * cargo-zigbuild, which drives zig for release builds (static musl binary)
#   * `cc` / `c++` shims in ~/.local/bin so build scripts and proc-macros (which are
#     always compiled for the host) link through zig as well
#
# Every download is fetched over HTTPS; cargo-zigbuild is verified against its published
# SHA-256 before it is extracted. Everything lands in ~/.cargo, ~/.rustup and ~/.local and
# can be removed with `rustup self uninstall` and `rm -rf ~/.local/opt/zig-* ~/.local/bin/{zig,cc,c++,cargo-zigbuild}`.
set -euo pipefail

BIN="$HOME/.local/bin"
OPT="$HOME/.local/opt"
mkdir -p "$BIN" "$OPT"
export PATH="$BIN:$HOME/.cargo/bin:$PATH"

step() { printf '\n==> %s\n' "$*"; }
# downloads retry: CI runners are sometimes refused or rate-limited for a moment
fetch() { curl --proto "=https" --tlsv1.2 -sSfL --retry 6 --retry-all-errors --retry-delay 10 "$@"; }

step "rustup"
if ! command -v rustup >/dev/null 2>&1; then
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
    | sh -s -- -y --profile minimal --default-toolchain none --no-modify-path
fi
# rust-toolchain.toml selects the exact version; this installs it with its components/targets.
here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
(cd "$here" && rustup show active-toolchain >/dev/null)
rustc --version

step "zig"
if [ ! -x "$BIN/zig" ]; then
  url=$(fetch https://ziglang.org/download/index.json | python3 -c '
import json, sys
d = json.load(sys.stdin)
releases = sorted((k for k in d if k != "master"), key=lambda s: [int(x) for x in s.split(".")])
print(d[releases[-1]]["x86_64-linux"]["tarball"])
')
  echo "fetching $url"
  (cd "$OPT" && fetch "$url" -o zig.tar.xz && tar -xf zig.tar.xz && rm zig.tar.xz)
  zigdir=$(ls -d "$OPT"/zig-*/ | sort | tail -1)
  ln -sf "${zigdir}zig" "$BIN/zig"
fi
zig version

step "cargo-zigbuild"
if [ ! -x "$BIN/cargo-zigbuild" ]; then
  # in CI the job's read-only token lifts the API's anonymous rate limit
  auth=()
  if [ -n "${GITHUB_TOKEN:-}" ]; then auth=(-H "Authorization: Bearer $GITHUB_TOKEN"); fi
  tag=$(fetch "${auth[@]}" https://api.github.com/repos/rust-cross/cargo-zigbuild/releases/latest \
        | python3 -c 'import json, sys; print(json.load(sys.stdin)["tag_name"])')
  asset="cargo-zigbuild-x86_64-unknown-linux-musl.tar.xz"
  base="https://github.com/rust-cross/cargo-zigbuild/releases/download/${tag}"
  tmp=$(mktemp -d)
  fetch "$base/$asset" -o "$tmp/$asset"
  fetch "$base/$asset.sha256" -o "$tmp/$asset.sha256"
  expected=$(awk '{print $1}' "$tmp/$asset.sha256")
  actual=$(sha256sum "$tmp/$asset" | awk '{print $1}')
  if [ "$expected" != "$actual" ]; then
    echo "cargo-zigbuild checksum mismatch: expected $expected, got $actual" >&2
    exit 1
  fi
  tar -xJf "$tmp/$asset" -C "$tmp"
  install -m 0755 "$(find "$tmp" -type f -name cargo-zigbuild | head -1)" "$BIN/cargo-zigbuild"
  rm -rf "$tmp"
fi
cargo-zigbuild --version

step "host cc/c++ shims (build scripts and proc-macros link through zig)"
for tool in cc c++; do
  if [ -e "$BIN/$tool" ] || ! command -v "$tool" >/dev/null 2>&1; then
    cat > "$BIN/$tool" <<EOF
#!/bin/sh
exec cargo-zigbuild zig $tool -- -target x86_64-linux-gnu "\$@"
EOF
    chmod 0755 "$BIN/$tool"
    echo "installed $BIN/$tool"
  else
    echo "system $tool found at $(command -v "$tool"); leaving it in place"
  fi
done

step "smoke test"
tmp=$(mktemp -d)
printf '#include <stdio.h>\nint main(void) { puts("zig cc ok"); return 0; }\n' > "$tmp/hello.c"
cc "$tmp/hello.c" -o "$tmp/hello"
"$tmp/hello"
rm -rf "$tmp"

echo
echo "Toolchain ready. Before building:  . scripts/dev-env.sh"
