#!/bin/bash
# Records the processor, clock policy and memory of the node it lands on.
# The Groth16 runs of r17 did not record them, so this is run once on each
# node they used:
#   for n in himem08 himem09 himem10 himem12; do sbatch -w $n node_cpu.sbatch; done
#SBATCH --job-name=node-cpu
#SBATCH --partition=bigmem
#SBATCH --nodes=1
#SBATCH --ntasks=1
#SBATCH --cpus-per-task=1
#SBATCH --mem=1G
#SBATCH --time=00:05:00
#SBATCH --output=node_cpu_%N_%j.txt
echo "job $SLURM_JOB_ID, node $(hostname), $(date)"
lscpu
cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null | sed 's/^/governor /' || true
cat /sys/devices/system/cpu/intel_pstate/no_turbo 2>/dev/null | sed 's/^/no_turbo /' || true
grep MemTotal /proc/meminfo
