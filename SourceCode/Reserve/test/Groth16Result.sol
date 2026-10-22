// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {Statement} from "./Statement.sol";

/// The Groth16 proof Pete made of the dispute verifier on the exported batch
/// proof, read from the file the prove binary wrote, and the statements of the
/// batch's payments it commits to.
abstract contract Groth16Result is Test {
    string constant RESULT = "../../WorkingHistory/groth16_s7/out_s7_batch_a/onchain.txt";

    bytes32 vkey;
    bytes publicValues;
    bytes proof;

    function _load() internal {
        vkey = vm.parseBytes32(_field(RESULT, "vkey"));
        publicValues = vm.parseBytes(_field(RESULT, "public_values"));
        proof = vm.parseBytes(_field(RESULT, "proof"));
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

    /// The batch's statements, read once from Statement.sol into storage so
    /// that a test reading many payments does not copy the lists each time.
    uint64[] digests;
    uint64[] amounts;
    uint64[] times;
    address[] payees;
    mapping(uint256 => uint64[]) elemsOf;
    mapping(uint256 => uint64[]) leafOf;
    mapping(uint256 => bytes32[]) pathOf;

    function _cache() internal {
        Statement.Data memory d = Statement.load();
        for (uint256 i = 0; i < Statement.PAYMENTS; ++i) {
            digests.push(Statement.digest(d, i));
            amounts.push(Statement.amount(d, i));
            times.push(Statement.time(d, i));
            payees.push(Statement.payee(d, i));
            elemsOf[i] = Statement.elems(d, i);
            leafOf[i] = Statement.leaf(d, i);
            pathOf[i] = Statement.path(d, i);
        }
    }

    function _digest(uint256 i) internal view returns (uint64) {
        return digests[i];
    }

    function _amount(uint256 i) internal view returns (uint64) {
        return amounts[i];
    }

    function _time(uint256 i) internal view returns (uint64) {
        return times[i];
    }

    function _payee(uint256 i) internal view returns (address) {
        return payees[i];
    }

    function _elems(uint256 i) internal view returns (uint64[] memory) {
        return elemsOf[i];
    }

    function _leaf(uint256 i) internal view returns (uint64[] memory) {
        return leafOf[i];
    }

    function _path(uint256 i) internal view returns (bytes32[] memory) {
        return pathOf[i];
    }

    /// Four values of a leaf from `first`, packed low lane first.
    function _lanes(uint64[] memory leaf, uint256 first) internal pure returns (bytes32) {
        uint256 w;
        for (uint256 j = 0; j < 4; ++j) w |= uint256(leaf[first + j]) << (64 * j);
        return bytes32(w);
    }

    /// The delegation commitment and the revocation root every leaf carries.
    function _com() internal view returns (bytes32) {
        return _lanes(leafOf[0], 5);
    }

    function _root0() internal view returns (bytes32) {
        return _lanes(leafOf[0], 1);
    }

    /// The root the leaf of payment i reaches along its path.
    function _rootFrom(uint256 i) internal view returns (bytes32 h) {
        uint64[] memory l = leafOf[i];
        uint256[] memory w = new uint256[](l.length);
        for (uint256 j = 0; j < l.length; ++j) w[j] = l[j];
        h = keccak256(abi.encodePacked(w));
        bytes32[] memory p = pathOf[i];
        for (uint256 j = 0; j < p.length; ++j) {
            h = (i >> j) & 1 == 0 ? keccak256(abi.encodePacked(h, p[j])) : keccak256(abi.encodePacked(p[j], h));
        }
    }

    /// The proof commits the root of exactly the exported statements: every
    /// leaf carries its payment's digest, amount, time, the delegation's terms
    /// and the hash of exactly the shares Statement.sol lists, and reaches the
    /// root the proof commits. Reads the cache `_cache` fills.
    function _checkStatement() internal view {
        require(keccak256(publicValues) == keccak256(abi.encodePacked(Statement.ROOT)), "root");
        bytes32 com = _com();
        bytes32 root0 = _root0();
        for (uint256 i = 0; i < Statement.PAYMENTS; ++i) {
            uint64[] memory l = leafOf[i];
            require(l[0] == digests[i], "digest");
            require(l[10] == amounts[i], "amount");
            require(l[14] == times[i], "time");
            require(l[15] == Statement.UNIT && l[16] == Statement.RANGE_BASE && l[17] == Statement.RANGE_LEN, "terms");
            require(_lanes(l, 18) == Statement.SECRET_HASH, "secret hash");
            require(_lanes(l, 5) == com && _lanes(l, 1) == root0, "delegation");
            uint256 h = uint256(keccak256(abi.encodePacked(elemsOf[i])));
            for (uint256 j = 0; j < 4; ++j) require(l[22 + j] == (h >> (192 - 64 * j)) & 0xFFFFFFFFFFFFFFFF, "shares hash");
            require(_rootFrom(i) == Statement.ROOT, "path");
        }
    }
}
