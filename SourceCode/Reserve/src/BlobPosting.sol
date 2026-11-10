// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

interface ICrossDomainMessenger {
    function sendMessage(address target, bytes calldata message, uint32 minGasLimit) external payable;
}

/// On Ethereum: records a batch's postings carried as blobs, and tells the
/// posting contract on the domain through the domain's own messenger.
///
/// An answerer posts a batch's proof and its sealed openings as blobs, a few
/// to a transaction, each transaction calling `post` with how many blobs it
/// carries. The contract reads their versioned hashes, chains them in order,
/// and adds up what the transactions cost: the blob gas at the blob base fee
/// and the call's gas at the base fee, both as this block charged them. The
/// last transaction sends the chained hash, the cost and its block's time to
/// the posting contract. The message is a deposit, which the domain must
/// include within its sequencing window whatever its sequencer does, so a
/// censoring sequencer can delay the report but not keep it out, and the
/// posting counts from the time it carries.
///
/// The chained hash is the one the answerer's receipt names, and the hashes
/// are fixed by the bytes, so the domain checks what was posted without
/// reading it; anyone reads the blobs from Ethereum's nodes, which keep them
/// for 4,096 epochs, about 18 days.
contract BlobPosting {
    ICrossDomainMessenger public immutable messenger;
    address public immutable postings;
    /// Gas the message is given on the domain.
    uint32 public constant MESSAGE_GAS = 200_000;
    uint256 private constant GAS_PER_BLOB = 131_072;
    /// Gas a call spends after it measures, an upper bound.
    uint256 private constant TAIL_GAS = 60_000;

    /// One poster's postings for one batch so far.
    struct Run {
        bytes32 acc;
        uint256 blobs;
        uint256 cost;
    }

    mapping(address => mapping(uint256 => mapping(bytes32 => Run))) public runs;

    error NoBlobs();
    error WrongCount();

    /// Each call's blobs, so that a reader finds every transaction of a posting.
    event Carried(address indexed poster, uint256 indexed id, bytes32 indexed root, uint256 blobs);
    event Posted(address indexed poster, uint256 indexed id, bytes32 indexed root, bytes32 blobsHash, uint256 blobs, uint256 cost);

    constructor(address messenger_, address postings_) {
        messenger = ICrossDomainMessenger(messenger_);
        postings = postings_;
    }

    /// Records the `count` blobs this transaction carries for delegation
    /// `id`'s batch `root`; `last` closes the posting and tells the domain.
    function post(uint256 id, bytes32 root, uint256 count, bool last) external {
        uint256 g0 = gasleft();
        if (count == 0) revert NoBlobs();
        if (blobhash(count - 1) == bytes32(0) || blobhash(count) != bytes32(0)) revert WrongCount();
        Run storage r = runs[msg.sender][id][root];
        bytes32 acc = r.acc;
        for (uint256 i = 0; i < count; ++i) acc = keccak256(abi.encodePacked(acc, blobhash(i)));
        r.acc = acc;
        r.blobs += count;
        emit Carried(msg.sender, id, root, count);
        uint256 n = msg.data.length;
        uint256 exec = g0 - gasleft() + TAIL_GAS + (last ? MESSAGE_GAS : 0);
        uint256 data = 16 * n + exec > 40 * n ? 16 * n + exec : 40 * n;
        r.cost += count * GAS_PER_BLOB * block.blobbasefee + (21000 + data) * block.basefee;
        if (last) _close(id, root);
    }

    /// Sends the posting's chained hash, closed by its blob count, its cost
    /// and this block's time to the posting contract on the domain.
    function _close(uint256 id, bytes32 root) private {
        Run memory r = runs[msg.sender][id][root];
        delete runs[msg.sender][id][root];
        bytes32 blobsHash = keccak256(abi.encodePacked(r.acc, r.blobs));
        bytes memory call = abi.encodeWithSignature(
            "blobsPosted(address,uint256,bytes32,bytes32,uint256,uint64)", msg.sender, id, root, blobsHash, r.cost, uint64(block.timestamp)
        );
        messenger.sendMessage(postings, call, MESSAGE_GAS);
        emit Posted(msg.sender, id, root, blobsHash, r.blobs, r.cost);
    }
}
