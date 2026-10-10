#!/bin/bash
# Which GPU the bullet partition has, and whether SP1's GPU prover can use it.
#SBATCH --job-name=gpu-check
#SBATCH --partition=bullet
#SBATCH --gres=gpu:1
#SBATCH --cpus-per-task=1
#SBATCH --mem=2G
#SBATCH --time=00:05:00
#SBATCH --output=gpu_check_%j.log
echo "node $(hostname)"
nvidia-smi --query-gpu=name,compute_cap,memory.total,driver_version --format=csv || nvidia-smi -L
nvidia-smi | sed -n 1,12p
