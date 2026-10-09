#!/bin/bash
# One CPU Groth16 proof on a bigmem node. Submit from this folder.
#SBATCH --job-name=groth16
#SBATCH --partition=bigmem
#SBATCH --nodes=1
#SBATCH --ntasks=1
#SBATCH --cpus-per-task=32
#SBATCH --mem=700G
#SBATCH --time=2-00:00:00
#SBATCH --output=groth16_%j.log
set -euo pipefail
HERE=$SLURM_SUBMIT_DIR
source "$HERE/env.sh"
export RUST_LOG=info TMPDIR=/scratch/jshital/tmp
OUT="$HERE/out_$SLURM_JOB_ID"
echo "node $(hostname), cpus $SLURM_CPUS_PER_TASK, start $(date)"
TIMER=""
if [ -x /usr/bin/time ]; then TIMER="/usr/bin/time -v"; fi
$TIMER "$HERE/../script/target/release/prove" "$HERE/../../target/proof_128.bin" "$OUT"
echo "end $(date)"
grep -v "^proof \|^public_values " "$OUT/onchain.txt"
