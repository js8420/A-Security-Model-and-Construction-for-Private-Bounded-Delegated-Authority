#!/bin/bash
# The full measurement harness twice, on one whole node, so no other job shares
# its cores or memory bandwidth. Submit from this folder:
#   sbatch harness.sbatch
#SBATCH --job-name=harness
#SBATCH --partition=batch
#SBATCH --nodes=1
#SBATCH --exclusive
#SBATCH --time=24:00:00
#SBATCH --output=harness_%j.log
set -euo pipefail
HERE=$SLURM_SUBMIT_DIR
source "$HERE/env.sh"
export CARGO_NET_OFFLINE=true
CIRCUITS="$HERE/../.."
OUT="$HERE/harness_$SLURM_JOB_ID"
mkdir -p "$OUT"
echo "job $SLURM_JOB_ID, node $(hostname), start $(date)"
lscpu | grep -e "Model name" -e "^CPU(s)" -e "MHz" -e "Thread" -e "Socket" | tee "$OUT/node.txt"
cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null | sed 's/^/governor /' | tee -a "$OUT/node.txt" || true
cat /sys/devices/system/cpu/intel_pstate/no_turbo 2>/dev/null | sed 's/^/no_turbo /' | tee -a "$OUT/node.txt" || true
cd "$CIRCUITS"
cargo build --release --locked 2>&1 | grep -e ^warning -e ^error -e Finished
for r in a b; do
  echo "run $r start $(date)"
  ./target/release/delegation-circuit > "$OUT/run_$r.txt" 2>&1
  echo "run $r end $(date)"
done
grep -h -e "one proof, grinding off" -e "controls," "$OUT"/run_*.txt
echo "end $(date)"
