#!/bin/bash
# The bounded scheme through the x402 SDK on a local chain. Usage: run_e2e.sh TAG
set -euo pipefail
export PATH="$HOME/.foundry/bin:$PATH"
if [ -s "$HOME/.nvm/nvm.sh" ]; then . "$HOME/.nvm/nvm.sh"; fi
for t in forge anvil node npm; do
    command -v $t >/dev/null || { echo "missing: $t"; exit 1; }
done
tag=${1:?tag}
here=$(cd "$(dirname "$0")" && pwd)
hist=$(cd "$here/../../WorkingHistory" && pwd)
node -e 'process.exit(Number(process.versions.node.split(".")[0]) >= 20 ? 0 : 1)' || { echo "node 20 or later needed, found $(node --version)"; exit 1; }

(cd "$here/../Reserve" && forge build >/dev/null)
cd "$here"
npm ci --no-audit --no-fund >/dev/null
npx tsc --noEmit

anvil --silent &
node_pid=$!
trap 'kill $node_pid 2>/dev/null || true' EXIT
for i in $(seq 1 50); do
    cast block-number --rpc-url http://127.0.0.1:8545 >/dev/null 2>&1 && break
    sleep 0.2
done
npx tsx e2e/run.ts | tee "$hist/run_${tag}_x402.txt"
