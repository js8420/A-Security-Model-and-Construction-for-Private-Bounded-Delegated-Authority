#!/bin/bash
# The independent STARK verifier against the deployed Plonky3 one: honest
# proofs, altered proofs, proofs of statements with no witness, and the
# monitor's gate under a simulated verifier bug, then the timing study of
# both verifiers. Usage: run_stark.sh TAG
set -euo pipefail
export PATH="$HOME/.cargo/bin:$PATH"
if [ -s "$HOME/.nvm/nvm.sh" ]; then . "$HOME/.nvm/nvm.sh"; fi
for t in cargo node npm; do
    command -v $t >/dev/null || { echo "missing: $t"; exit 1; }
done
tag=${1:?tag}
here=$(cd "$(dirname "$0")" && pwd)
circuits=$(cd "$here/../../Circuits" && pwd)
hist=$(cd "$here/../../WorkingHistory" && pwd)
statement="$here/../Reserve/test/Statement.sol"
work=$(mktemp -d)
cp "$statement" "$work/Statement.sol"
if [ -f "$circuits/target/proof_128_keccak.bin" ]; then cp "$circuits/target/proof_128_keccak.bin" "$work/kept.bin"; fi
restore() {
    cp "$work/Statement.sol" "$statement"
    if [ -f "$work/kept.bin" ]; then cp "$work/kept.bin" "$circuits/target/proof_128_keccak.bin"; fi
    rm -rf "$work"
}
trap restore EXIT

log="$work/build.txt"
(cd "$circuits" && cargo build --release > "$log" 2>&1) || { tail -20 "$log"; exit 1; }
if grep -q "^warning" "$log"; then grep -A6 "^warning" "$log"; exit 1; fi
bin="$circuits/target/release/delegation-circuit"
cd "$circuits"
"$bin" export-constraints
"$bin" export-keccak 128
cp target/proof_128_keccak.bin "$work/full.bin"
"$bin" export-keccak 4
cp target/proof_128_keccak.bin "$work/small.bin"
mkdir "$work/broken"
"$bin" export-broken "$work/broken"

cd "$here"
npm ci --no-audit --no-fund >/dev/null
npx tsc --noEmit
CONSTRAINTS="$circuits/target/constraints.dag" PROOF_FULL="$work/full.bin" PROOF_SMALL="$work/small.bin" \
    BROKEN_DIR="$work/broken" CIRCUIT_BIN="$bin" REPS=11 \
    npx tsx e2e/stark.ts | tee "$hist/run_${tag}_stark.txt"
CONSTRAINTS="$circuits/target/constraints.dag" PROOF_FULL="$work/full.bin" CIRCUIT_BIN="$bin" \
    npx tsx e2e/stark_time.ts | tee "$hist/run_${tag}_stark_time.txt"
