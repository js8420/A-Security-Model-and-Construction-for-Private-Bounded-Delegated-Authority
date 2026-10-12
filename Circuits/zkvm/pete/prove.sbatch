#!/bin/bash
# One CPU Groth16 proof on a bigmem node. Submit from this folder:
#   sbatch prove.sbatch            the deployed Poseidon2 verifier
#   sbatch prove.sbatch keccak     the verifier for Keccak commitments
#   sbatch prove.sbatch batch 4    the batch verifier on the first 4 proofs
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
case "$HASH" in
  keccak) PROOF="$HERE/../../target/proof_128_keccak.bin" ;;
  batch) PROOF="$HERE/../../target/proof_128_keccak_batch.bin" ;;
  *) PROOF="$HERE/../../target/proof_128.bin" ;;
esac
OUT="$HERE/out_$SLURM_JOB_ID"
echo "node $(hostname), cpus $SLURM_CPUS_PER_TASK, hash $HASH $N, start $(date)"
sha256sum "$PROOF"
env | grep '^SP1_WORKER' || echo "SP1 worker settings: defaults"
TIMER=""
if [ -x /usr/bin/time ]; then TIMER="/usr/bin/time -v"; fi
$TIMER "$HERE/../script/target/release/prove" "$PROOF" "$OUT" "$HASH" $N
echo "end $(date)"
grep -v "^proof \|^public_values " "$OUT/onchain.txt"
