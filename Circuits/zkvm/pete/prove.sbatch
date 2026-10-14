#!/bin/bash
# One CPU Groth16 proof on a bigmem node. Submit from this folder:
#   sbatch prove.sbatch            the deployed Poseidon2 verifier
#   sbatch prove.sbatch keccak     the verifier for Keccak commitments
#   sbatch prove.sbatch batch 4    the batch verifier on the first 4 proofs
# A third argument names the output folder, out_<name>, in place of the job id:
#   sbatch prove.sbatch keccak 1 keccak_a
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
HASH=${1:-poseidon2}
N=${2:-}
NAME=${3:-$SLURM_JOB_ID}
case "$HASH" in
  keccak) PROOF="$HERE/../../target/proof_128_keccak.bin" ;;
  batch) PROOF="$HERE/../../target/proof_128_keccak_batch.bin" ;;
  *) PROOF="$HERE/../../target/proof_128.bin" ;;
esac
OUT="$HERE/out_$NAME"
echo "job $SLURM_JOB_ID, node $(hostname), cpus $SLURM_CPUS_PER_TASK, hash $HASH $N, out $OUT, start $(date)"
sha256sum "$PROOF"
env | grep '^SP1_WORKER' || echo "SP1 worker settings: defaults"
TIMER=""
if [ -x /usr/bin/time ]; then TIMER="/usr/bin/time -v"; fi
$TIMER "$HERE/../script/target/release/prove" "$PROOF" "$OUT" "$HASH" $N
echo "end $(date)"
grep -v "^proof \|^public_values " "$OUT/onchain.txt"
