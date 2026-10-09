#!/bin/bash
# Tools and downloads for the Groth16 proof. Submit from this folder.
#SBATCH --job-name=setup-prove
#SBATCH --nodes=1
#SBATCH --ntasks=1
#SBATCH --cpus-per-task=8
#SBATCH --mem=32G
#SBATCH --time=02:00:00
#SBATCH --output=setup_%j.log
set -euo pipefail
HERE=$SLURM_SUBMIT_DIR
echo "node $(hostname), start $(date)"
if ! curl -fs -o /dev/null -r 0-0 --max-time 30 https://sp1-circuits.s3-us-east-2.amazonaws.com/v6.1.0-groth16.tar.gz; then
  echo "NO INTERNET ON THIS COMPUTE NODE"
  exit 3
fi
bash "$HERE/setup.sh"
echo "end $(date)"
