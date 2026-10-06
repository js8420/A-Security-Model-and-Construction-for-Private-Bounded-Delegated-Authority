// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// A Merkle tree of 2^depth leaves, almost all zero, built the way
/// StepVerifier walks one: at each level an even index hashes (node, sibling).
library Sparse {
    function zero(uint256 level) internal pure returns (bytes32 z) {
        for (uint256 i = 0; i < level; ++i) z = keccak256(abi.encodePacked(z, z));
    }

    function node(uint256 level, uint256 pos, uint256[] memory idx, bytes32[] memory leaves)
        internal
        pure
        returns (bytes32)
    {
        bool any;
        for (uint256 i = 0; i < idx.length; ++i) {
            if (idx[i] >> level == pos) {
                if (level == 0) return leaves[i];
                any = true;
            }
        }
        if (!any) return zero(level);
        return keccak256(abi.encodePacked(
            node(level - 1, 2 * pos, idx, leaves), node(level - 1, 2 * pos + 1, idx, leaves)
        ));
    }

    function root(uint256 depth, uint256[] memory idx, bytes32[] memory leaves)
        internal
        pure
        returns (bytes32)
    {
        return node(depth, 0, idx, leaves);
    }

    function path(uint256 depth, uint256 at, uint256[] memory idx, bytes32[] memory leaves)
        internal
        pure
        returns (bytes32[] memory p)
    {
        p = new bytes32[](depth);
        for (uint256 l = 0; l < depth; ++l) {
            p[l] = node(l, (at >> l) ^ 1, idx, leaves);
        }
    }
}
