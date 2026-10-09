# Shared settings for setup.sh, build.sbatch and prove.sbatch on Pete.
E=/scratch/jshital/conda-envs/gnark
export CARGO_HOME=/scratch/jshital/.cargo
if [ -f /scratch/jshital/.cargo/env ]; then source /scratch/jshital/.cargo/env; fi
export PATH=$E/bin:/scratch/jshital/.cargo/bin:$PATH
export CC=$E/bin/x86_64-conda-linux-gnu-gcc
export CXX=$E/bin/x86_64-conda-linux-gnu-g++
export AR=$E/bin/x86_64-conda-linux-gnu-ar
export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=$CC
export RUSTFLAGS="-C link-arg=-Wl,-rpath,$E/lib"
export LIBCLANG_PATH=$E/lib
export PROTOC=$E/bin/protoc
export GOPATH=/scratch/jshital/gopath
export GOTOOLCHAIN=local
export GOPROXY=https://proxy.golang.org,https://goproxy.cn,direct GOFLAGS= GOPRIVATE= GONOSUMDB=
true
