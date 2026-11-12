#!/bin/bash
# The fee analyses the paper cites, on the fee history fee_ratio.py fetched:
# the floors and factors, the deployed factors tested out of sample, and the
# blob way against the domain way. Usage: fee_runs.sh TAG DATA_DIR
set -euo pipefail
tag=${1:?tag}
data=${2:?data dir}
[ -f "$data/ethereum/meta.json" ] && [ -f "$data/base/meta.json" ] || { echo "no fetched fee history in $data"; exit 1; }
here=$(cd "$(dirname "$0")" && pwd)
hist=$(cd "$here/../../WorkingHistory" && pwd)
cd "$here"
for mode in floors oos blobs; do
    python3 fee_ratio.py $mode "$data" | tee "$hist/run_${tag}_$mode.txt"
done
