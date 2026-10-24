#!/bin/bash
# The zkVM program verifies with Plonky3 0.6.3's FRI verifier as vendored in
# vendor/p3-fri, whose reduced openings sum the part at the opening point once
# per proof instead of once per query. This runs the honest batch proof, the
# broken proofs and the deep faulty proofs through the native verifier, which
# is the published crate, and through the program in the zkVM, and prints both
# verdicts for every file. Usage: fri_equivalence.sh OUT [per-family]
set -euo pipefail
export PATH="$HOME/.cargo/bin:$PATH"
out=${1:?output file}
per=${2:-25}
here=$(cd "$(dirname "$0")" && pwd)
circuits=$(cd "$here/.." && pwd)
work=$(mktemp -d)
statement="$circuits/../SourceCode/Reserve/test/Statement.sol"
cp "$statement" "$work/Statement.sol"
trap 'cp "$work/Statement.sol" "$statement"; rm -rf "$work"' EXIT
(cd "$circuits" && cargo build --release 2>&1 | grep -E "^(warning|error)" && exit 1 || true)
(cd "$here/script" && cargo build --release --bin dispute-verifier-script 2>&1 | grep -E "^error" && exit 1 || true)
bin="$circuits/target/release/delegation-circuit"
mkdir -p "$work/broken" "$work/deep"
(cd "$circuits" && "$bin" export-keccak 256 >/dev/null && cp target/proof_keccak.bin "$work/honest.bin")
"$bin" export-broken "$work/broken" >/dev/null
for fam in draw codeword trace public grinding; do
    "$bin" deep-faults "$work/deep" "$fam" 0 "$per" >/dev/null
done
files=("$work/honest.bin" "$work"/broken/*.bin "$work"/deep/*.bin)
"$here/script/target/release/dispute-verifier-script" verdicts "${files[@]}" 2>/dev/null > "$work/guest.txt"
{
    echo "THE VENDORED FRI VERIFIER IN THE ZKVM AGAINST THE PUBLISHED ONE, NATIVE"
    echo "=============================================================================="
    same=0
    diff=0
    i=0
    while read -r g path; do
        n=$("$bin" verify-file "$path" < /dev/null 2>&1 || true)
        n=${n%%[[:space:]]*}
        [ "$n" = accept ] && na=accept || na=refuse
        if [ "$na" = "$g" ]; then same=$((same + 1)); else diff=$((diff + 1)); fi
        printf "  %-7s %-7s %s\n" "$na" "$g" "$(basename "$path")"
        i=$((i + 1))
    done < "$work/guest.txt"
    echo "  files $i, same verdict $same, different $diff"
} | tee "$out"
