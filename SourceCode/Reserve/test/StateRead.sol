// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {RLPReader} from "./vendor/optimism/rlp/RLPReader.sol";
import {SecureMerkleTrie} from "./vendor/optimism/trie/SecureMerkleTrie.sol";

/// What one domain must verify to read a value another OP Stack domain holds,
/// with no proof system: an Ethereum block header the domain trusts, a
/// storage slot on Ethereum that holds the other domain's output root, the
/// output root's preimage, and the other domain's account and storage slot
/// under the state root it commits. Each proof is Ethereum's own Merkle
/// Patricia proof, checked with Optimism's libraries.
contract StateRead {
    struct Slot {
        address account;
        bytes[] accountProof;
        bytes32 key;
        bytes[] storageProof;
    }

    /// The Ethereum header and slot, and the other domain's output-root
    /// preimage and slot.
    struct Input {
        bytes header;
        bytes32 l1BlockHash;
        Slot l1;
        bytes32 l2StateRoot;
        bytes32 messagePasserRoot;
        bytes32 l2BlockHash;
        Slot l2;
    }

    error HeaderMismatch();

    /// The value of the Ethereum slot, the output root, and the value of the
    /// other domain's slot. A deployment would require the first to be the
    /// second; here, on unrelated real proofs, all three are returned.
    function read(Input calldata x) external pure returns (bytes32 l1Value, bytes32 outputRoot, bytes32 l2Value) {
        if (keccak256(x.header) != x.l1BlockHash) revert HeaderMismatch();
        bytes32 l1StateRoot = bytes32(RLPReader.readBytes(RLPReader.readList(x.header)[3]));
        l1Value = _slot(x.l1, l1StateRoot);
        outputRoot = keccak256(abi.encode(bytes32(0), x.l2StateRoot, x.messagePasserRoot, x.l2BlockHash));
        l2Value = _slot(x.l2, x.l2StateRoot);
    }

    function _slot(Slot calldata s, bytes32 stateRoot) private pure returns (bytes32 v) {
        bytes memory account = SecureMerkleTrie.get(abi.encodePacked(s.account), s.accountProof, stateRoot);
        bytes32 storageRoot = bytes32(RLPReader.readBytes(RLPReader.readList(account)[2]));
        bytes memory raw = RLPReader.readBytes(SecureMerkleTrie.get(abi.encodePacked(s.key), s.storageProof, storageRoot));
        v = bytes32(uint256(bytes32(raw)) >> (8 * (32 - raw.length)));
    }
}
