#!/bin/bash
# Run by setup.sbatch on a compute node. Gets the tools and downloads
# everything the build and the proof need. Compiles nothing.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
ZKVM=$(cd "$HERE/.." && pwd)
ELF="$ZKVM/program/target/elf-compilation/riscv64im-succinct-zkvm-elf/release/dispute-verifier"
PROOF="$ZKVM/../target/proof_128.bin"
source "$HERE/env.sh"

echo "== inputs"
sha256sum "$ELF" "$PROOF"

echo "== tools: gcc 13, Go 1.24, clang 18, protoc (conda-forge, glibc 2.17 sysroot)"
if [ ! -x "$E/bin/go" ]; then
  rm -rf "$E"
  /scratch/jshital/miniforge3/bin/conda create -y -q -p "$E" -c conda-forge --override-channels \
    go=1.24.13 gcc=13 gxx=13 sysroot_linux-64=2.17 clang=18 libclang=18 libprotobuf=5.28
fi
$CC --version | sed -n 1p
go version
clang --version | sed -n 1p
$PROTOC --version
ls "$LIBCLANG_PATH"/libclang.so* | sed -n 1p
rustc --version

echo "== Rust packages"
(cd "$ZKVM/script" && cargo fetch --locked -q)
(cd "$ZKVM/program" && cargo fetch --locked -q)

echo "== Go modules for gnark"
CRATE=$(ls $CARGO_HOME/registry/cache/*/sp1-recursion-gnark-ffi-6.8.1.crate | sed -n 1p)
rm -rf /scratch/jshital/paper04/gnark-src && mkdir -p /scratch/jshital/paper04/gnark-src
tar -xzf "$CRATE" -C /scratch/jshital/paper04/gnark-src
(cd /scratch/jshital/paper04/gnark-src/sp1-recursion-gnark-ffi-6.8.1/go && go mod download)
echo "go modules cached in $GOPATH/pkg/mod"

echo "== Groth16 circuit files (SP1 circuit v6.1.0)"
G=$HOME/.sp1/circuits/groth16/v6.1.0
if [ ! -f "$G/.complete" ]; then
  rm -rf "$G" && mkdir -p "$G"
  curl -fL --progress-bar https://sp1-circuits.s3-us-east-2.amazonaws.com/v6.1.0-groth16.tar.gz -o "$G/artifacts.tar.gz"
  tar -Pxzf "$G/artifacts.tar.gz" -C "$G" && rm "$G/artifacts.tar.gz" && touch "$G/.complete"
fi
ls -la "$G"
du -sh "$G"
echo "setup done"
