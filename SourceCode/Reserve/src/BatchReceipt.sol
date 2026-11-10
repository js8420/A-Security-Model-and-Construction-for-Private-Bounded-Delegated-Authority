// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// What an answerer signs on receiving a batch, besides the delegation and
/// the batch's root: the root of a tree of the payments' openings, each
/// sealed to the principal's key, in the batch's order; the hash of the
/// batch's proof as it is posted on the domain in chunks; the hash of the
/// blobs that carry the proof and the sealed openings on Ethereum; and when
/// it received them. Both hashes are fixed by the bytes, so either way of
/// posting is checked against the receipt without reading what was posted.
struct BatchReceipt {
    bytes32 sealedRoot;
    bytes32 proofHash;
    bytes32 blobsHash;
    uint64 receivedAt;
    bytes signature;
}
