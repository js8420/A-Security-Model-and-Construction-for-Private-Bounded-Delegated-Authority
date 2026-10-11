// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";

/// The Groth16 proof Pete made of the dispute verifier, read from the file the
/// prove binary wrote.
abstract contract Groth16Result is Test {
    string constant RESULT = "../../WorkingHistory/groth16_20261009/onchain.txt";

    bytes32 vkey;
    bytes publicValues;
    bytes proof;

    function _load() internal {
        vkey = vm.parseBytes32(_field("vkey"));
        publicValues = vm.parseBytes(_field("public_values"));
        proof = vm.parseBytes(_field("proof"));
    }

    /// Reads the whole file at once: a line cursor is shared by every test
    /// running in parallel and gave one of them another's line.
    function _field(string memory key) internal view returns (string memory) {
        string[] memory lines = vm.split(vm.readFile(RESULT), "\n");
        for (uint256 i; i < lines.length; ++i) {
            string[] memory kv = vm.split(vm.replace(lines[i], "\r", ""), " ");
            if (kv.length == 2 && keccak256(bytes(kv[0])) == keccak256(bytes(key))) return kv[1];
        }
        revert(string.concat("no ", key, " in onchain.txt"));
    }

    /// Public value i, decoded from the little-endian bincode the guest commits.
    function _pv(uint256 i) internal view returns (uint64 x) {
        for (uint64 b = 0; b < 8; ++b) x |= uint64(uint8(publicValues[8 * (i + 1) + b])) << (8 * b);
    }

    /// Four public values packed into one word, low lane first, as the reserve stores them.
    function _lanes(uint256 first) internal view returns (bytes32) {
        uint256 w;
        for (uint256 j = 0; j < 4; ++j) w |= uint256(_pv(first + j)) << (64 * j);
        return bytes32(w);
    }
}
