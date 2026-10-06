// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

interface IReserveA {
    function settled(uint256 id, uint64 digest) external view returns (bytes32);
    function agentOf(uint256 id) external view returns (address);
    function forfeit(uint256 id) external;
}

/// Forces a settlement's proof into the open when someone asks for it.
///
/// In the honest case the agent sends the proof to the principal off chain and
/// nothing here is used. A principal that has not received it challenges, with
/// a bond, and the agent must then publish the proof as EIP-4844 blobs before
/// the window closes or lose its own bond. Once published, anyone can play the
/// dispute game against it, so the dispute no longer depends on the agent's
/// cooperation.
///
/// The EVM cannot read blob contents, only their versioned hashes, so the proof
/// commitment the agent signed at settlement is
///     keccak256(abi.encode(inputRoot, keccak256(abi.encodePacked(versionedHashes))))
/// and resolution checks the hashes of the blobs carried by the resolving
/// transactions against that list. A transaction carries at most six blobs, so
/// a proof of n blobs resolves over ceil(n / 6) calls.
///
/// After the pattern of the OP Stack's data-availability challenge: the bond
/// covers the cost of resolving. Here it goes to the agent on resolution, so an
/// honest agent is made whole and a principal gains nothing by challenging a
/// proof it already holds.
contract Availability {
    enum Status { None, Open, Resolved, Expired }

    struct Challenge {
        address challenger;
        uint64 deadline;
        Status status;
        uint16 count;
        uint256 published; // bitmap over blob positions
    }

    IReserveA public immutable reserve;
    uint64 public immutable resolveWindow;
    uint256 public immutable bond;

    mapping(bytes32 => Challenge) public challenges;

    error NotSettled();
    error AlreadyChallenged();
    error BondTooSmall();
    error NotOpen();
    error WrongCommitment();
    error WrongBlob();
    error TooLate();
    error TooEarly();
    error TooManyBlobs();

    event Challenged(uint256 indexed id, uint64 digest, address challenger);
    event Resolved(uint256 indexed id, uint64 digest);
    event Expired(uint256 indexed id, uint64 digest);

    constructor(address reserve_, uint64 window, uint256 bond_) {
        reserve = IReserveA(reserve_);
        resolveWindow = window;
        bond = bond_;
    }

    function key(uint256 id, uint64 digest) public pure returns (bytes32) {
        return keccak256(abi.encode(id, digest));
    }

    function challenge(uint256 id, uint64 digest) external payable {
        if (reserve.settled(id, digest) == bytes32(0)) revert NotSettled();
        if (msg.value != bond) revert BondTooSmall();
        bytes32 k = key(id, digest);
        if (challenges[k].status != Status.None) revert AlreadyChallenged();
        challenges[k] = Challenge({
            challenger: msg.sender,
            deadline: uint64(block.timestamp) + resolveWindow,
            status: Status.Open,
            count: 0,
            published: 0
        });
        emit Challenged(id, digest, msg.sender);
    }

    /// Publish part of the proof. Each blob this transaction carries is checked
    /// against its position in the signed list, starting at `offset`.
    function resolve(
        uint256 id,
        uint64 digest,
        bytes32 inputRoot,
        bytes32[] calldata versionedHashes,
        uint256 offset
    ) external {
        bytes32 k = key(id, digest);
        Challenge storage c = challenges[k];
        if (c.status != Status.Open) revert NotOpen();
        if (block.timestamp > c.deadline) revert TooLate();
        uint256 n = versionedHashes.length;
        if (n > 256) revert TooManyBlobs();
        bytes32 blobsHash = keccak256(abi.encodePacked(versionedHashes));
        if (keccak256(abi.encode(inputRoot, blobsHash)) != reserve.settled(id, digest)) {
            revert WrongCommitment();
        }

        uint256 bits = c.published;
        uint16 count = c.count;
        for (uint256 j = 0; ; ++j) {
            bytes32 h = blobhash(j);
            if (h == bytes32(0)) break;
            uint256 pos = offset + j;
            if (pos >= n || versionedHashes[pos] != h) revert WrongBlob();
            uint256 bit = uint256(1) << pos;
            if (bits & bit == 0) {
                bits |= bit;
                ++count;
            }
        }
        c.published = bits;
        c.count = count;

        if (count == n) {
            c.status = Status.Resolved;
            emit Resolved(id, digest);
            (bool ok, ) = payable(reserve.agentOf(id)).call{value: bond}("");
            require(ok, "refund");
        }
    }

    /// The window closed with the proof unpublished: the agent's bond goes to
    /// the principal and the challenger's comes back.
    function expire(uint256 id, uint64 digest) external {
        bytes32 k = key(id, digest);
        Challenge storage c = challenges[k];
        if (c.status != Status.Open) revert NotOpen();
        if (block.timestamp <= c.deadline) revert TooEarly();
        c.status = Status.Expired;
        emit Expired(id, digest);
        try reserve.forfeit(id) {} catch {}
        (bool ok, ) = payable(c.challenger).call{value: bond}("");
        require(ok, "refund");
    }
}
