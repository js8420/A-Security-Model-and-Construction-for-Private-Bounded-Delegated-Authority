#!/bin/bash
# One CPU Groth16 proof that the dispute verifier accepts the exported batch
# proof, on a bigmem node. Submit from this folder:
#   sbatch prove.sbatch            output folder out_<job id>
#   sbatch prove.sbatch batch_a    output folder out_batch_a
# The degree-5 proof is larger than the one measured before, whose slowest
# healthy run took under three hours, so the limit is twelve: a job on a node
# that stalls ends there rather than after two days.
# Add --mail-type=BEGIN,END,FAIL --mail-user=ADDRESS at submission for alerts.
#SBATCH --job-name=groth16
#SBATCH --partition=bigmem
#SBATCH --nodes=1
#SBATCH --ntasks=1
#SBATCH --cpus-per-task=32
#SBATCH --mem=700G
#SBATCH --time=12:00:00
#SBATCH --output=groth16_%j.log
set -euo pipefail
HERE=$SLURM_SUBMIT_DIR
source "$HERE/env.sh"
export RUST_LOG=info TMPDIR=/scratch/jshital/tmp
NAME=${1:-$SLURM_JOB_ID}
PROOF="$HERE/../../target/proof_keccak.bin"
OUT="$HERE/out_$NAME"
echo "job $SLURM_JOB_ID, node $(hostname), cpus $SLURM_CPUS_PER_TASK, out $OUT, start $(date)"
mkdir -p "$OUT"
lscpu | tee "$OUT/node.txt"
cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null | sed 's/^/governor /' | tee -a "$OUT/node.txt" || true
cat /sys/devices/system/cpu/intel_pstate/no_turbo 2>/dev/null | sed 's/^/no_turbo /' | tee -a "$OUT/node.txt" || true
grep MemTotal /proc/meminfo | tee -a "$OUT/node.txt"
sha256sum "$PROOF"
env | grep '^SP1_WORKER' || echo "SP1 worker settings: defaults"
TIMER=""
if [ -x /usr/bin/time ]; then TIMER="/usr/bin/time -v"; fi
$TIMER "$HERE/../script/target/release/prove" "$PROOF" "$OUT"
echo "end $(date)"
grep -v "^proof " "$OUT/onchain.txt"
