// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ISP1Verifier} from "./sp1/ISP1Verifier.sol";

interface IReserveV {
    function settled(uint256 id, uint64 digest) external view returns (bytes32);
    function agentOf(uint256 id) external view returns (address);
    function forfeit(uint256 id) external;
    function domain() external view returns (uint64);
    function commitmentOf(uint256 id) external view returns (bytes32);
    function rootAt(uint256 id, uint64 epoch) external view returns (bytes32);
}

/// Challenge answered by a validity proof, never by the proof itself.
///
/// The settlement's STARK stays off chain. A challenger stakes a bond against
/// one settled digest. Before the deadline, anyone holding the STARK answers
/// with one SP1 Groth16 proof that the Plonky3 verifier, run inside SP1,
/// accepts a proof against this settlement's public values. The public values
/// are not taken from the answer: the contract rebuilds them from the
/// reserve's own record (the digest, the revocation root at the settlement's
/// epoch, the delegation commitment, the domain), so a proof of any other
/// statement fails the pairing check.
///
/// Many challenges. Three rules keep an honest agent answerable however many
/// challenges arrive. A settlement is challenged at most once, so it is proved
/// at most once. Each challenge against an agent is due at least `slot` after
/// that agent's previous one, so an agent that proves one answer per slot never
/// misses a deadline. One batch answer proves any number of open challenges,
/// of any agents, with one Groth16 proof and one pairing check.
///
/// Bonds. An answer credits each challenger's bond to the agent challenged,
/// which pays for the proving. No answer by the deadline credits the bond back
/// to the challenger and forfeits the agent's bond in the reserve to the
/// principal. Credits are withdrawn, never pushed, so no recipient can block
/// an answer or an expiry.
///
/// On Base the verifier is SP1's Groth16 gateway, which routes by the first
/// four bytes of the proof to the verifier of that circuit version.
contract ValidityDispute {
    enum Status { None, Open, Answered, Expired }

    struct Challenge {
        address challenger;
        uint64 deadline;
        uint64 epoch;
        Status status;
    }

    /// The circuit's public values, in its order: the payload digest, the
    /// revocation root's four lanes, the delegation commitment's four lanes,
    /// the settlement domain.
    uint256 public constant PUBLIC_VALUES = 10;
    uint256 private constant LANE = 0xFFFFFFFFFFFFFFFF;

    IReserveV public immutable reserve;
    ISP1Verifier public immutable verifier;
    /// The guest program for one settlement: the Plonky3 verifier with the
    /// circuit's own AIR, compiled for SP1.
    bytes32 public immutable programVKey;
    /// The guest program for any number of settlements, the same verifier run
    /// once per proof.
    bytes32 public immutable batchVKey;
    uint64 public immutable answerWindow;
    /// The least time between two deadlines of one agent: what proving one
    /// answer takes, with margin.
    uint64 public immutable slot;
    uint256 public immutable challengerBond;

    mapping(bytes32 => Challenge) private challenges;
    mapping(address => uint64) public lastDeadline;
    mapping(address => uint256) public credit;

    error BondTooSmall();
    error AlreadyChallenged();
    error WrongCommitment();
    error NotOpen();
    error TooLate();
    error TooEarly();
    error EmptyBatch();
    error LengthMismatch();
    error NothingToWithdraw();

    event Challenged(uint256 indexed id, uint64 digest, address challenger, uint64 deadline);
    event Answered(uint256 indexed id, uint64 digest);
    event Expired(uint256 indexed id, uint64 digest);

    constructor(
        address reserve_,
        address verifier_,
        bytes32 programVKey_,
        bytes32 batchVKey_,
        uint64 window,
        uint64 slot_,
        uint256 bond
    ) {
        reserve = IReserveV(reserve_);
        verifier = ISP1Verifier(verifier_);
        programVKey = programVKey_;
        batchVKey = batchVKey_;
        answerWindow = window;
        slot = slot_;
        challengerBond = bond;
    }

    function key(uint256 id, uint64 digest) public pure returns (bytes32) {
        return keccak256(abi.encode(id, digest));
    }

    function challengeOf(uint256 id, uint64 digest) external view returns (Challenge memory) {
        return challenges[key(id, digest)];
    }

    /// `commitment` and `epoch` open the reserve's record of the settlement:
    /// what the agent signed and the revocation epoch then in force.
    function open(uint256 id, uint64 digest, bytes32 commitment, uint64 epoch) external payable {
        if (msg.value != challengerBond) revert BondTooSmall();
        bytes32 k = key(id, digest);
        if (challenges[k].status != Status.None) revert AlreadyChallenged();
        if (keccak256(abi.encode(commitment, epoch)) != reserve.settled(id, digest)) {
            revert WrongCommitment();
        }
        address agent = reserve.agentOf(id);
        uint64 deadline = uint64(block.timestamp) + answerWindow;
        uint64 queued = lastDeadline[agent] + slot;
        if (queued > deadline) deadline = queued;
        lastDeadline[agent] = deadline;
        challenges[k] = Challenge({challenger: msg.sender, deadline: deadline, epoch: epoch, status: Status.Open});
        emit Challenged(id, digest, msg.sender, deadline);
    }

    function answer(uint256 id, uint64 digest, bytes calldata proof) external {
        Challenge storage c = _due(id, digest);
        verifier.verifyProof(programVKey, publicValues(id, digest, c.epoch), proof);
        _settle(c, id, digest);
    }

    /// One proof of the batch program over these settlements, in this order.
    function answerBatch(uint256[] calldata ids, uint64[] calldata digests, bytes calldata proof) external {
        uint256 n = ids.length;
        if (n == 0) revert EmptyBatch();
        if (digests.length != n) revert LengthMismatch();
        uint64[] memory epochs = new uint64[](n);
        for (uint256 i = 0; i < n; ++i) epochs[i] = _due(ids[i], digests[i]).epoch;
        verifier.verifyProof(batchVKey, batchPublicValues(ids, digests, epochs), proof);
        for (uint256 i = 0; i < n; ++i) {
            Challenge storage c = challenges[key(ids[i], digests[i])];
            // A settlement named twice is answered once; the second finds it closed.
            if (c.status != Status.Open) revert NotOpen();
            _settle(c, ids[i], digests[i]);
        }
    }

    function expire(uint256 id, uint64 digest) external {
        Challenge storage c = challenges[key(id, digest)];
        if (c.status != Status.Open) revert NotOpen();
        if (block.timestamp <= c.deadline) revert TooEarly();
        c.status = Status.Expired;
        credit[c.challenger] += challengerBond;
        emit Expired(id, digest);
        // A bond already taken by a claim or another challenge is simply gone.
        try reserve.forfeit(id) {} catch {}
    }

    function withdraw() external {
        uint256 amount = credit[msg.sender];
        if (amount == 0) revert NothingToWithdraw();
        credit[msg.sender] = 0;
        (bool ok, ) = payable(msg.sender).call{value: amount}("");
        require(ok, "withdraw");
    }

    function _due(uint256 id, uint64 digest) private view returns (Challenge storage c) {
        c = challenges[key(id, digest)];
        if (c.status != Status.Open) revert NotOpen();
        if (block.timestamp > c.deadline) revert TooLate();
    }

    function _settle(Challenge storage c, uint256 id, uint64 digest) private {
        c.status = Status.Answered;
        credit[reserve.agentOf(id)] += challengerBond;
        emit Answered(id, digest);
    }

    /// The bytes the single program commits: a bincode Vec<u64>, the length
    /// and then each value, little-endian.
    function publicValues(uint256 id, uint64 digest, uint64 epoch) public view returns (bytes memory pv) {
        pv = new bytes(8 * (PUBLIC_VALUES + 1));
        _le(pv, 0, PUBLIC_VALUES);
        _write(pv, 8, id, digest, epoch);
    }

    /// The bytes the batch program commits: one bincode Vec<u64> holding every
    /// settlement's values in turn.
    function batchPublicValues(uint256[] calldata ids, uint64[] calldata digests, uint64[] memory epochs)
        public
        view
        returns (bytes memory pv)
    {
        uint256 n = ids.length;
        pv = new bytes(8 * (PUBLIC_VALUES * n + 1));
        _le(pv, 0, PUBLIC_VALUES * n);
        for (uint256 i = 0; i < n; ++i) _write(pv, 8 + 8 * PUBLIC_VALUES * i, ids[i], digests[i], epochs[i]);
    }

    function _write(bytes memory pv, uint256 at, uint256 id, uint64 digest, uint64 epoch) private view {
        uint256 root = uint256(reserve.rootAt(id, epoch));
        uint256 com = uint256(reserve.commitmentOf(id));
        _le(pv, at, digest);
        for (uint256 j = 0; j < 4; ++j) {
            _le(pv, at + 8 * (1 + j), (root >> (64 * j)) & LANE);
            _le(pv, at + 8 * (5 + j), (com >> (64 * j)) & LANE);
        }
        _le(pv, at + 72, reserve.domain());
    }

    /// Writes the low eight bytes of x at `at`, least significant first.
    function _le(bytes memory out, uint256 at, uint256 x) private pure {
        assembly ("memory-safe") {
            let p := add(add(out, 32), at)
            for { let b := 0 } lt(b, 8) { b := add(b, 1) } { mstore8(add(p, b), shr(mul(8, b), x)) }
        }
    }
}
