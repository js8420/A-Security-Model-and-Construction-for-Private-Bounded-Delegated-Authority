#!/bin/bash
# Contract tests and on-chain receipts in one run, after taking real state
# proofs from Ethereum and Base mainnet for the cross-domain read. Usage:
# measure_gas.sh TAG. L1_RPC and L2_RPC choose the endpoints.
set -euo pipefail
export PATH="$HOME/.foundry/bin:$PATH"
for t in forge anvil cast python3; do
    command -v $t >/dev/null || { echo "missing: $t"; exit 1; }
done
tag=${1:?tag}
here=$(cd "$(dirname "$0")" && pwd)
hist=$(cd "$here/../../WorkingHistory" && pwd)
cd "$here"

python3 fetch_state_proofs.py "$hist/state_proofs" | tee "$hist/run_${tag}_state_proofs.txt"
forge test -vv > "$hist/run_${tag}_forge.txt" 2>&1 || true
grep -E "Suite result|^Ran |FAIL|rror" "$hist/run_${tag}_forge.txt" || { echo "forge test printed no results:"; tail -20 "$hist/run_${tag}_forge.txt"; exit 1; }

key=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
for s in ValidityDisputeOnChain ValidityDisputeBatchOnChain RevealDisputeOnChain StateReadOnChain; do
    # The expiry needs blocks a second apart; auto-mining puts several in one second.
    if [ $s = ValidityDisputeOnChain ]; then pace="--block-time 1"; else pace=""; fi
    anvil --timestamp 5000 $pace --silent &
    node=$!
    for i in $(seq 1 50); do
        cast block-number --rpc-url http://127.0.0.1:8545 >/dev/null 2>&1 && break
        sleep 0.2
    done
    LOCAL_PK=$key forge script "script/$s.s.sol:$s" --rpc-url http://127.0.0.1:8545 --broadcast --slow --skip-simulation > "$hist/run_${tag}_$s.log" 2>&1 || { kill $node; tail -20 "$hist/run_${tag}_$s.log"; exit 1; }
    kill $node
    wait $node 2>/dev/null || true
    cp "broadcast/$s.s.sol/31337/run-latest.json" "$hist/receipts_${tag}_$s.json"
done

python3 - "$hist" "$tag" <<'PY' | tee "$hist/run_${tag}_gas.txt"
import json, sys
hist, tag = sys.argv[1], sys.argv[2]
for s in ("ValidityDisputeOnChain", "ValidityDisputeBatchOnChain", "RevealDisputeOnChain", "StateReadOnChain"):
    j = json.load(open(f"{hist}/receipts_{tag}_{s}.json"))
    print(s)
    posted = []
    for t, r in zip(j["transactions"], j["receipts"]):
        name = (t["function"] or ("deploy " + (t["contractName"] or ""))).split('(')[0]
        if name == "postProof":
            posted.append(int(r['gasUsed'], 16))
            continue
        print(f"  {name:<28} {int(r['gasUsed'], 16):>10,}")
    if posted:
        print(f"  {'postProof, all chunks':<28} {sum(posted):>10,}  in {len(posted)} transactions, the largest {max(posted):,}")
PY

python3 ../Analysis/posting_cost.py "$hist/receipts_${tag}_ValidityDisputeOnChain.json" | tee "$hist/run_${tag}_posting.txt"
