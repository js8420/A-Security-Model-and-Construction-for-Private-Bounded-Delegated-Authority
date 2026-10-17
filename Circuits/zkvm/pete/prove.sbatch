#!/bin/bash
# One CPU Groth16 proof that the dispute verifier accepts the exported batch
# proof, on a bigmem node. Submit from this folder:
#   sbatch prove.sbatch            output folder out_<job id>
#   sbatch prove.sbatch batch_a    output folder out_batch_a
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
NAME=${1:-$SLURM_JOB_ID}
PROOF="$HERE/../../target/proof_128_keccak.bin"
OUT="$HERE/out_$NAME"
echo "job $SLURM_JOB_ID, node $(hostname), cpus $SLURM_CPUS_PER_TASK, out $OUT, start $(date)"
sha256sum "$PROOF"
env | grep '^SP1_WORKER' || echo "SP1 worker settings: defaults"
TIMER=""
if [ -x /usr/bin/time ]; then TIMER="/usr/bin/time -v"; fi
$TIMER "$HERE/../script/target/release/prove" "$PROOF" "$OUT"
echo "end $(date)"
grep -v "^proof " "$OUT/onchain.txt"
