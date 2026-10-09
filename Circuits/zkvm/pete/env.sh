# Shared settings for setup.sh and prove.sbatch on Pete.
if [ -f /scratch/jshital/.cargo/env ]; then source /scratch/jshital/.cargo/env; fi
export PATH=/scratch/jshital/go1.24/bin:/scratch/jshital/protoc/bin:/scratch/jshital/.cargo/bin:$PATH
export GOPATH=/scratch/jshital/gopath
export GOTOOLCHAIN=local
export PROTOC=$(command -v protoc || true)
if [ -z "${LIBCLANG_PATH:-}" ]; then
  d="$(python3 -c 'import site;print(site.getusersitepackages())' 2>/dev/null || true)/clang/native"
  if [ -f "$d/libclang.so" ]; then export LIBCLANG_PATH="$d"; fi
fi
true
