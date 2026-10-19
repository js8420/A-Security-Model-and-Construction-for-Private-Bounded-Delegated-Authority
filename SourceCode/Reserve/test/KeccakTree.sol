// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {RevealDispute} from "../src/RevealDispute.sol";

/// Keccak Merkle trees as the reveal-on-dispute baseline reads them, built in memory.
library KeccakTree {
    function root(bytes32[] memory leaves) internal pure returns (bytes32) {
        bytes32[] memory level = leaves;
        while (level.length > 1) {
            bytes32[] memory up = new bytes32[](level.length / 2);
            for (uint256 i = 0; i < up.length; ++i) up[i] = keccak256(abi.encodePacked(level[2 * i], level[2 * i + 1]));
            level = up;
        }
        return level[0];
    }

    function path(bytes32[] memory leaves, uint256 index) internal pure returns (bytes32[] memory p) {
        uint256 depth;
        while ((uint256(1) << depth) < leaves.length) ++depth;
        p = new bytes32[](depth);
        bytes32[] memory level = leaves;
        for (uint256 j = 0; j < depth; ++j) {
            p[j] = level[index ^ 1];
            bytes32[] memory up = new bytes32[](level.length / 2);
            for (uint256 i = 0; i < up.length; ++i) up[i] = keccak256(abi.encodePacked(level[2 * i], level[2 * i + 1]));
            level = up;
            index >>= 1;
        }
    }

    /// 2^depth merchant leaves: merchant i paid at address 0x1000 + i.
    function merchants(uint256 depth) internal pure returns (bytes32[] memory l) {
        l = new bytes32[](uint256(1) << depth);
        for (uint64 i = 0; i < l.length; ++i) l[i] = keccak256(abi.encodePacked(i, payeeOf(i)));
    }

    function payeeOf(uint64 merchant) internal pure returns (address) {
        return address(uint160(0x1000) + merchant);
    }

    /// 2^depth category leaves: categories 0 to 2^depth - 1.
    function categories(uint256 depth) internal pure returns (bytes32[] memory l) {
        l = new bytes32[](uint256(1) << depth);
        for (uint64 i = 0; i < l.length; ++i) l[i] = keccak256(abi.encodePacked(i));
    }

    /// 2^depth revoked-range leaves, sorted: the sentinel at 0, then ranges of
    /// 4 units starting at 1000, 1010, 1020 and so on, then sentinels at 2^64 - 1.
    function revoked(uint256 depth, uint256 ranges) internal pure returns (bytes32[] memory l, uint64[] memory starts, uint64[] memory lengths) {
        uint256 n = uint256(1) << depth;
        l = new bytes32[](n);
        starts = new uint64[](n);
        lengths = new uint64[](n);
        for (uint256 i = 0; i < n; ++i) {
            if (i == 0) (starts[i], lengths[i]) = (0, 0);
            else if (i <= ranges) (starts[i], lengths[i]) = (uint64(1000 + 10 * (i - 1)), 4);
            else (starts[i], lengths[i]) = (type(uint64).max, 0);
            l[i] = keccak256(abi.encodePacked(starts[i], lengths[i]));
        }
    }

    function gap(bytes32[] memory l, uint64[] memory starts, uint64[] memory lengths, uint256 index)
        internal
        pure
        returns (RevealDispute.Gap memory g)
    {
        g.loStart = starts[index];
        g.loLength = lengths[index];
        g.hiStart = starts[index + 1];
        g.hiLength = lengths[index + 1];
        g.index = index;
        g.loPath = path(l, index);
        g.hiPath = path(l, index + 1);
    }
}
