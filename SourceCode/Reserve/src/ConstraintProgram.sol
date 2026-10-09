// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// One constraint of the circuit, run at the out-of-domain point.
///
/// A program is the constraint's expression compiled by the circuit crate
/// (Circuits/src/leaf.rs): five bytes an operation, a kind and two slot
/// numbers, big-endian. Slots are the values read, then the constants, then
/// one per operation. Every value is an element of the degree-two extension
/// of Goldilocks, X^2 = 7, packed as lane 0 in the low 64 bits and lane 1 in
/// the next 64. The result is the slot the program names.
library ConstraintProgram {
    uint256 internal constant P = 0xFFFFFFFF00000001;
    uint256 internal constant W = 7;

    error BadProgram();
    error BadValue();

    function run(bytes memory prog, uint256[] memory inputs, uint256 out) internal pure returns (uint256 r) {
        uint256 n = prog.length / 5;
        if (prog.length != n * 5) revert BadProgram();
        uint256 base = inputs.length;
        if (out >= base + n) revert BadProgram();
        uint256[] memory v = new uint256[](base + n);
        for (uint256 i; i < base; ++i) {
            uint256 x = inputs[i];
            if (x >> 128 != 0 || x & 0xFFFFFFFFFFFFFFFF >= P || x >> 64 >= P) revert BadValue();
            v[i] = x;
        }
        bool bad;
        assembly ("memory-safe") {
            let vs := add(v, 0x20)
            let pp := add(prog, 0x20)
            let m := 0xFFFFFFFFFFFFFFFF
            for { let i := 0 } lt(i, n) { i := add(i, 1) } {
                let w := mload(add(pp, mul(i, 5)))
                let kind := byte(0, w)
                let a := and(shr(232, w), 0xFFFF)
                let b := and(shr(216, w), 0xFFFF)
                let slot := add(base, i)
                // An operation reads only slots written before it.
                if or(iszero(lt(a, slot)), iszero(lt(b, slot))) { bad := 1 }
                let x := mload(add(vs, mul(a, 0x20)))
                let y := mload(add(vs, mul(b, 0x20)))
                let x0 := and(x, m)
                let x1 := shr(64, x)
                let y0 := and(y, m)
                let y1 := shr(64, y)
                let c0 := 0
                let c1 := 0
                switch kind
                case 0 {
                    c0 := addmod(x0, y0, P)
                    c1 := addmod(x1, y1, P)
                }
                case 1 {
                    c0 := addmod(x0, sub(P, y0), P)
                    c1 := addmod(x1, sub(P, y1), P)
                }
                case 2 {
                    c0 := addmod(mulmod(x0, y0, P), mulmod(W, mulmod(x1, y1, P), P), P)
                    c1 := addmod(mulmod(x0, y1, P), mulmod(x1, y0, P), P)
                }
                case 3 {
                    c0 := mod(sub(P, x0), P)
                    c1 := mod(sub(P, x1), P)
                }
                default { bad := 1 }
                mstore(add(vs, mul(slot, 0x20)), or(c0, shl(64, c1)))
            }
            r := mload(add(vs, mul(out, 0x20)))
        }
        if (bad) revert BadProgram();
    }
}
