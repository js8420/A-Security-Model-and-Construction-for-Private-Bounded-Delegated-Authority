// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {Statement} from "./Statement.sol";

/// The Groth16 proofs Pete made of the dispute verifiers, read from the files
/// the prove binary wrote, and the statement of the payment proof they verify.
abstract contract Groth16Result is Test {
    string constant DIR = "../../WorkingHistory/groth16_s5b/";
    string constant SINGLE = "../../WorkingHistory/groth16_s5b/out_s5b_keccak_a/onchain.txt";
    uint256 constant VALUES = 19;

    bytes32 vkey;
    bytes publicValues;
    bytes proof;

    function _load() internal {
        vkey = vm.parseBytes32(_field(SINGLE, "vkey"));
        publicValues = vm.parseBytes(_field(SINGLE, "public_values"));
        proof = vm.parseBytes(_field(SINGLE, "proof"));
    }

    function _batchFile(uint256 k) internal pure returns (string memory) {
        if (k == 1) return string.concat(DIR, "out_s5b_batch1_a/onchain.txt");
        if (k == 2) return string.concat(DIR, "out_s5b_batch2_a/onchain.txt");
        return string.concat(DIR, "out_s5b_batch4_a/onchain.txt");
    }

    /// Reads the whole file at once: a line cursor is shared by every test
    /// running in parallel and gave one of them another's line.
    function _field(string memory file, string memory key) internal view returns (string memory) {
        string[] memory lines = vm.split(vm.readFile(file), "\n");
        for (uint256 i; i < lines.length; ++i) {
            string[] memory kv = vm.split(vm.replace(lines[i], "\r", ""), " ");
            if (kv.length == 2 && keccak256(bytes(kv[0])) == keccak256(bytes(key))) return kv[1];
        }
        revert(string.concat("no ", key, " in ", file));
    }

    /// Public value i, decoded from the little-endian bincode the guest commits.
    function _pv(uint256 i) internal view returns (uint64 x) {
        for (uint64 b = 0; b < 8; ++b) x |= uint64(uint8(publicValues[8 * (i + 1) + b])) << (8 * b);
    }

    /// Four public values from `first`, packed low lane first.
    function _lanes(uint256 first) internal view returns (bytes32) {
        uint256 w;
        for (uint256 j = 0; j < 4; ++j) w |= uint256(_pv(first + j)) << (64 * j);
        return bytes32(w);
    }

    /// The committed hash of the shares, from its four big-endian words.
    function _elemsHash() internal view returns (bytes32) {
        uint256 w;
        for (uint256 j = 0; j < 4; ++j) w |= uint256(_pv(15 + j)) << (192 - 64 * j);
        return bytes32(w);
    }

    /// The proof is of the exported statement and nothing else: same digest,
    /// amount, payee, time, and the hash of exactly the shares Statement.sol
    /// lists.
    function _checkStatement() internal view {
        uint256 a = uint160(Statement.PAYEE);
        require(_pv(0) == Statement.DIGEST, "digest");
        require(_pv(10) == Statement.AMOUNT, "amount");
        require(_pv(11) == a & ((1 << 56) - 1), "payee limb 0");
        require(_pv(12) == (a >> 56) & ((1 << 56) - 1), "payee limb 1");
        require(_pv(13) == a >> 112, "payee limb 2");
        require(_pv(14) == Statement.TIME, "time");
        require(_elemsHash() == Statement.ELEMS_HASH, "shares hash");
        require(keccak256(abi.encodePacked(Statement.elems())) == Statement.ELEMS_HASH, "shares");
    }
}
