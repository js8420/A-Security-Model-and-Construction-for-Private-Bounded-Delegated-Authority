#!/bin/bash
# The fee analyses the paper cites, on the fee history fee_ratio.py fetched:
# the floors and factors, the deployed factors tested out of sample and on
# Ethereum from London to Dencun, and the blob way against the domain way.
# The fetch completes the history first; what is already there is kept.
# The blob comparison prices the stake and the bounty from the same tag's
# posting and bond runs. Usage: fee_runs.sh TAG DATA_DIR
set -euo pipefail
tag=${1:?tag}
data=${2:?data dir}
here=$(cd "$(dirname "$0")" && pwd)
hist=$(cd "$here/../../WorkingHistory" && pwd)
cd "$here"
price=$(grep -E 'ETH / USD, Chainlink' "$hist/run_${tag}_posting.txt" | awk '{print $NF}')
stake=$(grep -oE 'is less by the stake, [0-9]+\.[0-9]+' "$hist/run_${tag}_bond.txt" | awk '{print $NF}')
bounty=$(grep -oE 'bond plus the bounty, [0-9]+\.[0-9]+;' "$hist/run_${tag}_bond.txt" | tr -d ';' | awk '{print $NF}')
[ -n "$price" ] && [ -n "$stake" ] && [ -n "$bounty" ] || { echo "no price, stake or bounty in run_${tag}_posting.txt and run_${tag}_bond.txt"; exit 1; }
mkdir -p "$data"
python3 fee_ratio.py fetch "$data"
[ -f "$data/ethereum/meta.json" ] && [ -f "$data/base/meta.json" ] || { echo "no fetched fee history in $data"; exit 1; }
for mode in floors oos london settings denim datafee; do
    python3 fee_ratio.py $mode "$data" | tee "$hist/run_${tag}_$mode.txt"
done
python3 fee_ratio.py blobs "$data" "$price" "$stake" "$bounty" | tee "$hist/run_${tag}_blobs.txt"
