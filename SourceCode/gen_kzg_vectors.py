"""Writes Reserve/test/KzgVectors.sol: one blob and real KZG openings of four
of its elements, against the mainnet trusted setup.

    pip install ckzg
    python gen_kzg_vectors.py trusted_setup.txt

The trusted setup is src/trusted_setup.txt in github.com/ethereum/c-kzg-4844.
"""
import hashlib
import os
import sys

import ckzg

R = 0x73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000001
P = 0xFFFFFFFF00000001


def rev12(x):
    return int(format(x, "012b")[::-1], 2)


def lanes(j):
    return [(j * 3 + l) * 0x9E3779B97F4A7C15 % P for l in range(3)]


def main(setup):
    ts = ckzg.load_trusted_setup(setup, 0)
    omega = pow(7, (R - 1) // 4096, R)
    vals = [a + (b << 64) + (c << 128) for a, b, c in (lanes(j) for j in range(4096))]
    blob = b"".join(v.to_bytes(32, "big") for v in vals)
    com = ckzg.blob_to_kzg_commitment(blob, ts)
    vh = b"\x01" + hashlib.sha256(com).digest()[1:]
    out = [
        "// SPDX-License-Identifier: MIT",
        "pragma solidity ^0.8.28;",
        "",
        "/// One real blob and KZG openings of four of its elements, produced by c-kzg",
        "/// 2.x against the mainnet trusted setup (SourceCode/gen_kzg_vectors.py).",
        "/// Element j holds three Goldilocks lanes, lane l being (3j + l) * 0x9E3779B97F4A7C15 mod p.",
        "library KzgVectors {",
        f"    bytes32 internal constant VERSIONED_HASH = 0x{vh.hex()};",
        f'    bytes internal constant COMMITMENT = hex"{com.hex()}";',
    ]
    for j in (0, 1, 777, 4095):
        z = pow(omega, rev12(j), R).to_bytes(32, "big")
        proof, y = ckzg.compute_kzg_proof(blob, z, ts)
        assert int.from_bytes(y, "big") == vals[j]
        assert ckzg.verify_kzg_proof(com, z, y, proof, ts)
        out.append(f"    uint256 internal constant Y_{j} = 0x{y.hex()};")
        out.append(f'    bytes internal constant PROOF_{j} = hex"{proof.hex()}";')
    out.append("")
    out.append("    function kzg(uint256 y, bytes memory proof) internal pure returns (bytes memory) {")
    out.append("        return abi.encodePacked(bytes32(y), COMMITMENT, proof);")
    out.append("    }")
    out.append("}")
    here = os.path.dirname(os.path.abspath(__file__))
    target = os.path.join(here, "Reserve", "test", "KzgVectors.sol")
    with open(target, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(out) + "\n")


if __name__ == "__main__":
    main(sys.argv[1])
