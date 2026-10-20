#!/bin/bash
# The evidence behind the independent verifier: its own test set, differential
# testing of both verifiers on randomly altered proofs, and mutation testing of
# the independent verifier's code against the smaller first test set and
# against the full one.
# Usage: run_assurance.sh TAG [seeds] [per-seed]. With MUTATE set to a
# comma-separated list of files under src/stark, only those are mutated.
set -euo pipefail
export PATH="$HOME/.cargo/bin:$PATH"
if [ -s "$HOME/.nvm/nvm.sh" ]; then . "$HOME/.nvm/nvm.sh"; fi
for t in cargo node npm; do
    command -v $t >/dev/null || { echo "missing: $t"; exit 1; }
done
tag=${1:?tag}
seeds=${2:-8}
per=${3:-250}
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
"$bin" export-constraints >/dev/null
"$bin" export-keccak 128 >/dev/null
cp target/proof_128_keccak.bin "$work/full.bin"
"$bin" export-keccak 4 >/dev/null
cp target/proof_128_keccak.bin "$work/small.bin"
"$bin" export-keccak 1 >/dev/null
cp target/proof_128_keccak.bin "$work/one.bin"
mkdir "$work/broken"
"$bin" export-broken "$work/broken" >/dev/null
"$bin" export-vectors "$work/vectors.json" >/dev/null
cp "$work/Statement.sol" "$statement"

cd "$here"
npm ci --no-audit --no-fund >/dev/null
npx tsc --noEmit
export CONSTRAINTS="$circuits/target/constraints.dag" PROOF_FULL="$work/full.bin" PROOF_SMALL="$work/small.bin" PROOF_ONE="$work/one.bin" \
    BROKEN_DIR="$work/broken" VECTORS="$work/vectors.json" CIRCUIT_BIN="$bin"

out="$hist/run_${tag}_control.txt"
npx tsx e2e/stark_control.ts | tee "$out"

out="$hist/run_${tag}_fuzz.txt"
{
    echo "DIFFERENTIAL TESTING OF THE TWO VERIFIERS: $seeds SEEDS, $per ALTERATIONS EACH"
    pids=()
    for s in $(seq 1 "$seeds"); do
        SEED=$s COUNT=$per npx tsx e2e/stark_fuzz.ts > "$work/fuzz_$s.txt" &
        pids+=($!)
    done
    for p in "${pids[@]}"; do wait "$p"; done
    cat "$work"/fuzz_*.txt
} | tee "$out"

cores=$(nproc)
workers=${STRYKER_CONCURRENCY:-$(( cores > 2 ? cores / 2 : 1 ))}
for set in base full; do
    if [ $set = base ]; then cfg=stryker.base.config.json; json=reports/mutation/mutation-base.json; else cfg=stryker.config.json; json=reports/mutation/mutation.json; fi
    only=()
    if [ -n "${MUTATE:-}" ]; then only=(--mutate "$MUTATE"); fi
    npx stryker run "$cfg" --concurrency "$workers" "${only[@]}" > "$work/stryker_$set.txt" 2>&1 || { tail -30 "$work/stryker_$set.txt"; exit 1; }
    cp "$json" "$hist/mutation_${tag}_$set.json"
    python3 "$here/../Analysis/mutation_summary.py" "$json" > "$hist/run_${tag}_mutation_$set.txt"
    echo "MUTATION SCORE, $set test set"
    sed -n '1,9p' "$hist/run_${tag}_mutation_$set.txt"
done
