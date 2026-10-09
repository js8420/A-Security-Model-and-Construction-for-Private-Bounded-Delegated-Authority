#!/bin/bash
# Builds the prove program on a compute node, offline. Submit from this folder.
#SBATCH --job-name=build-prove
#SBATCH --nodes=1
#SBATCH --ntasks=1
#SBATCH --cpus-per-task=16
#SBATCH --mem=48G
#SBATCH --time=03:00:00
#SBATCH --output=build_%j.log
set -euo pipefail
HERE=$SLURM_SUBMIT_DIR
source "$HERE/env.sh"
export CARGO_NET_OFFLINE=true GOPROXY=off GOFLAGS=-mod=mod
export SP1_SKIP_PROGRAM_BUILD=true
echo "node $(hostname), start $(date)"
cd "$HERE/../script"
cargo build --release --locked --features prove --bin prove -j "$SLURM_CPUS_PER_TASK"
ls -l target/release/prove
./target/release/prove fetch
echo "end $(date)"
