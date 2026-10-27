#!/bin/bash
# The compliance half against the same circuit with C9's binding removed,
# timed twice on n048, the node of the harness runs, so no other job shares its
# cores or memory bandwidth. Submit from this folder:
#   sbatch vacuity.sbatch
#SBATCH --job-name=vacuity
#SBATCH --partition=batch
#SBATCH --nodes=1
#SBATCH --exclusive
#SBATCH --nodelist=n048
#SBATCH --time=06:00:00
#SBATCH --output=vacuity_%j.log
set -euo pipefail
HERE=$SLURM_SUBMIT_DIR
source "$HERE/env.sh"
export CARGO_NET_OFFLINE=true
CIRCUITS="$HERE/../.."
OUT="$HERE/vacuity_$SLURM_JOB_ID"
mkdir -p "$OUT"
echo "job $SLURM_JOB_ID, node $(hostname), start $(date)"
lscpu | tee "$OUT/node.txt"
cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null | sed 's/^/governor /' | tee -a "$OUT/node.txt" || true
cat /sys/devices/system/cpu/intel_pstate/no_turbo 2>/dev/null | sed 's/^/no_turbo /' | tee -a "$OUT/node.txt" || true
cd "$CIRCUITS"
cargo build --release --locked 2>&1 | grep -e ^warning -e ^error -e Finished
for r in a b; do
  echo "run $r start $(date)"
  ./target/release/delegation-circuit vacuity-cost > "$OUT/run_$r.txt" 2>&1
  echo "run $r end $(date)"
done
cat "$OUT"/run_*.txt
echo "end $(date)"
