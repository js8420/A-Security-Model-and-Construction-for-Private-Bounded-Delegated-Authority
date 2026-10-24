#!/bin/bash
# The bounded scheme through the x402 SDK on a local chain, and the principal's
# monitor across two local chains: every settlement decided at one time and
# challenged on chain when not in order, proofs through both verifiers,
# openings checked in the clear, the answerer's sealed openings, and the same
# actions whatever the cause.
# Usage: run_e2e.sh TAG
set -euo pipefail
export PATH="$HOME/.foundry/bin:$HOME/.cargo/bin:$PATH"
if [ -s "$HOME/.nvm/nvm.sh" ]; then . "$HOME/.nvm/nvm.sh"; fi
for t in forge anvil cast cargo node npm; do
    command -v $t >/dev/null || { echo "missing: $t"; exit 1; }
done
tag=${1:?tag}
here=$(cd "$(dirname "$0")" && pwd)
circuits=$(cd "$here/../../Circuits" && pwd)
hist=$(cd "$here/../../WorkingHistory" && pwd)
node -e 'process.exit(Number(process.versions.node.split(".")[0]) >= 20 ? 0 : 1)' || { echo "node 20 or later needed, found $(node --version)"; exit 1; }

statement="$here/../Reserve/test/Statement.sol"
work=$(mktemp -d)
cp "$statement" "$work/Statement.sol"
if [ -f "$circuits/target/proof_keccak.bin" ]; then cp "$circuits/target/proof_keccak.bin" "$work/kept.bin"; fi
a=""
b=""
c=""
cleanup() {
    if [ -n "$a" ]; then kill $a 2>/dev/null || true; fi
    if [ -n "$b" ]; then kill $b 2>/dev/null || true; fi
    if [ -n "$c" ]; then kill $c 2>/dev/null || true; fi
    cp "$work/Statement.sol" "$statement"
    if [ -f "$work/kept.bin" ]; then cp "$work/kept.bin" "$circuits/target/proof_keccak.bin"; fi
    rm -rf "$work"
}
trap cleanup EXIT

log="$work/build.txt"
(cd "$circuits" && cargo build --release > "$log" 2>&1) || { tail -20 "$log"; exit 1; }
if grep -q "^warning" "$log"; then grep -A6 "^warning" "$log"; exit 1; fi
bin="$circuits/target/release/delegation-circuit"
(cd "$circuits" && "$bin" export-constraints >/dev/null && "$bin" export-keccak 4 >/dev/null && cp target/proof_keccak.bin "$work/small.bin")
cp "$work/Statement.sol" "$statement"
(cd "$here/../Reserve" && forge build > "$log" 2>&1) || { tail -20 "$log"; exit 1; }
cd "$here"
npm ci --no-audit --no-fund >/dev/null
npx tsc --noEmit

# The x402 run has a chain of its own, since it moves the clock a day. The
# monitor's domain A starts its clock at the time the exported payments were
# signed.
anvil --silent --port 8547 &
c=$!
anvil --silent --timestamp 5000 &
a=$!
anvil --silent --port 8546 --chain-id 31338 &
b=$!
for port in 8545 8546 8547; do
    for i in $(seq 1 50); do
        cast block-number --rpc-url http://127.0.0.1:$port >/dev/null 2>&1 && break
        sleep 0.2
    done
done
RPC_URL=http://127.0.0.1:8547 npx tsx e2e/run.ts | tee "$hist/run_${tag}_x402.txt"
CONSTRAINTS="$circuits/target/constraints.dag" PROOF_SMALL="$work/small.bin" CIRCUIT_BIN="$bin" \
    npx tsx e2e/monitor.ts | tee "$hist/run_${tag}_monitor.txt"
