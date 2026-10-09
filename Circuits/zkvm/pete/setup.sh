#!/bin/bash
# Pete login node, once. Builds the Groth16 prover and downloads the circuit
# files, so the batch job needs no internet. Run from this folder:
#   bash setup.sh
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
SCRIPT="$HERE/../script"
ELF="$HERE/../program/target/elf-compilation/riscv64im-succinct-zkvm-elf/release/dispute-verifier"
PROOF="$HERE/../../target/proof_128.bin"
GO_DIR=/scratch/jshital/go1.24
source "$HERE/env.sh"

echo "== inputs"
ls -l "$ELF" "$PROOF"

echo "== Go 1.24 (gnark is written in Go)"
if [ ! -x "$GO_DIR/bin/go" ]; then
  mkdir -p "$GO_DIR"
  curl -fsSL https://go.dev/dl/go1.24.4.linux-amd64.tar.gz | tar -xz -C "$GO_DIR" --strip-components=1
fi
go version

echo "== protoc (reads SP1's message definitions)"
if [ -z "$PROTOC" ]; then
  mkdir -p /scratch/jshital/protoc && cd /scratch/jshital/protoc
  curl -fsSLO https://github.com/protocolbuffers/protobuf/releases/download/v28.3/protoc-28.3-linux-x86_64.zip
  python3 -c 'import zipfile;zipfile.ZipFile("protoc-28.3-linux-x86_64.zip").extractall(".")'
  chmod +x bin/protoc && cd "$HERE" && source "$HERE/env.sh"
fi
$PROTOC --version

echo "== libclang (reads gnark's C header)"
if [ -z "${LIBCLANG_PATH:-}" ]; then
  python3 -m pip install --user --quiet libclang==18.1.1
  echo "installed; env.sh finds it from now on"
  source "$HERE/env.sh"
fi
echo "LIBCLANG_PATH=$LIBCLANG_PATH"

echo "== build (the guest program is not rebuilt; the measured ELF is used)"
cd "$SCRIPT"
SP1_SKIP_PROGRAM_BUILD=true cargo build --release --features prove --bin prove

echo "== Groth16 circuit files"
./target/release/prove fetch
du -sh ~/.sp1/circuits/groth16/* 2>/dev/null || true
echo "setup done"
