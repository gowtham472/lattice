#!/usr/bin/env bash
# The LATTICE demo, end to end, in the order it is presented. Every step checks its exit code,
# so a run that finishes is a rehearsed demo.
#
#   scripts/demo.sh                 pause before each step (for presenting or recording)
#   scripts/demo.sh --no-pause      run straight through (rehearsal, CI)
#   scripts/demo.sh --serve         end by serving the cockpit on http://127.0.0.1:7443
#
# The demo estate is copied to a Linux filesystem first (~/lattice-demo): under WSL, a Windows
# drive (/mnt/c, /mnt/d) cannot be confined by Landlock, and the sandbox would block the reads.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
LATTICE=${LATTICE:-$ROOT/target/release/lattice}
WORK=${LATTICE_DEMO_DIR:-$HOME/lattice-demo}
PAUSE=1
SERVE=0
for argument in "$@"; do
    case $argument in
        --no-pause) PAUSE=0 ;;
        --serve) SERVE=1 ;;
        *) echo "usage: $0 [--no-pause] [--serve]" >&2; exit 2 ;;
    esac
done
[ -x "$LATTICE" ] || { echo "build it first: cargo build --release -p lattice-cli" >&2; exit 2; }
export SOURCE_DATE_EPOCH=1790121600

step() {
    printf '\n\033[1;36m== %s\033[0m\n' "$1"
    if [ "$PAUSE" = 1 ]; then read -r -p "   (enter) " _ </dev/tty; fi
}
expect() { # expect <exit code> <command...>
    local want=$1; shift
    set +e; "$@"; local got=$?; set -e
    [ "$got" = "$want" ] || { echo "demo: expected exit $want, got $got: $*" >&2; exit 1; }
}

rm -rf "$WORK"; mkdir -p "$WORK"; cd "$WORK"
cp -r "$ROOT/examples/demo-estate" estate

step "1. The kernel confines LATTICE: no network, no programs, read-only targets"
"$LATTICE" sandbox-check

step "2. One offline binary scans source, configs, certificates, a container image and live traffic"
"$LATTICE" scan estate -o demo.cbom.json --report demo.report.json --pdf demo.pdf --top 10

step "3. The CBOM is standard CycloneDX 1.6, checked against the official schema offline"
"$LATTICE" validate demo.cbom.json

step "4. Signed with ML-DSA-65 (FIPS 204): the tool that says go post-quantum already is"
"$LATTICE" keygen --out-dir keys
"$LATTICE" sign demo.cbom.json --key keys/lattice-signing.key --public-key keys/lattice-signing.pub
"$LATTICE" verify demo.cbom.json --public-key keys/lattice-signing.pub

step "5. Change one byte of one component: verification names it"
cp demo.cbom.json tampered.cbom.json
cp demo.cbom.json.sig.json tampered.cbom.json.sig.json
python3 - <<'EOF'
text = open("tampered.cbom.json", encoding="utf-8").read()
# weaken one recorded key size, as someone hiding a finding would
text = text.replace('"RSA-1024"', '"RSA-4096"', 1)
open("tampered.cbom.json", "w", encoding="utf-8").write(text)
EOF
expect 3 "$LATTICE" verify tampered.cbom.json --public-key keys/lattice-signing.pub

step "6. The CI gate: a commit adds MD5 to the clean ledger service and the build fails"
cat > estate/ledger/receipts.go <<'EOF'
package main

import "crypto/md5"

func receiptDigest(statement []byte) [16]byte {
	return md5.Sum(statement)
}
EOF
expect 1 "$LATTICE" ci estate --baseline demo.cbom.json --trusted-key keys/lattice-signing.pub --fail-on high
rm estate/ledger/receipts.go

step "7. Change the future: Q-day in 2029 instead of 2030, and the plan moves"
sed 's/^earliest_year = 2030/earliest_year = 2029/' "$ROOT/knowledge/policy.toml" > early-qday.toml
"$LATTICE" scan estate --policy early-qday.toml -o early.cbom.json --report early.report.json --top 5

step "8. Run it twice, get the same bytes"
"$LATTICE" scan estate -o again.cbom.json --report again.report.json --quiet
cmp demo.cbom.json again.cbom.json && echo "identical CBOM: $(sha256sum demo.cbom.json | cut -c1-16)…"

echo
echo "demo complete in $WORK: demo.cbom.json, demo.report.json, demo.pdf (open it for the executive view)"
if [ "$SERVE" = 1 ]; then
    step "9. The cockpit: overview, inventory, exposure graph, roadmap, compare"
    exec "$LATTICE" serve --root demo="$WORK/estate" --data-dir "$WORK/.lattice" --bind 127.0.0.1:7443
fi
