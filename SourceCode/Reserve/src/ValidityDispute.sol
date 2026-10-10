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
/// one settled digest. Within the window, anyone holding the STARK answers
/// with one SP1 Groth16 proof that the deployed Plonky3 verifier, run inside
/// SP1, accepts a proof against this settlement's public values. The public
/// values are not taken from the answer: the contract rebuilds them from the
/// reserve's own record (the digest, the revocation root at the settlement's
/// epoch, the delegation commitment, the domain), so a proof of any other
/// statement fails the pairing check.
///
/// Bonds. An answer sends the challenger's bond to the agent, which pays for
/// the proving. No answer by the deadline returns the challenger's bond and
/// forfeits the agent's bond in the reserve to the principal.
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
    /// The guest program's verifying key: the deployed Plonky3 verifier with
    /// the circuit's own AIR, compiled for SP1.
    bytes32 public immutable programVKey;
    uint64 public immutable answerWindow;
    uint256 public immutable challengerBond;

    mapping(bytes32 => Challenge) private challenges;

    error BondTooSmall();
    error AlreadyChallenged();
    error WrongCommitment();
    error NotOpen();
    error TooLate();
    error TooEarly();

    event Challenged(uint256 indexed id, uint64 digest, address challenger, uint64 deadline);
    event Answered(uint256 indexed id, uint64 digest);
    event Expired(uint256 indexed id, uint64 digest);

    constructor(address reserve_, address verifier_, bytes32 programVKey_, uint64 window, uint256 bond) {
        reserve = IReserveV(reserve_);
        verifier = ISP1Verifier(verifier_);
        programVKey = programVKey_;
        answerWindow = window;
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
        uint64 deadline = uint64(block.timestamp) + answerWindow;
        challenges[k] = Challenge({challenger: msg.sender, deadline: deadline, epoch: epoch, status: Status.Open});
        emit Challenged(id, digest, msg.sender, deadline);
    }

    function answer(uint256 id, uint64 digest, bytes calldata proof) external {
        Challenge storage c = challenges[key(id, digest)];
        if (c.status != Status.Open) revert NotOpen();
        if (block.timestamp > c.deadline) revert TooLate();
        verifier.verifyProof(programVKey, publicValues(id, digest, c.epoch), proof);
        c.status = Status.Answered;
        emit Answered(id, digest);
        (bool ok, ) = payable(reserve.agentOf(id)).call{value: challengerBond}("");
        require(ok, "bond");
    }

    function expire(uint256 id, uint64 digest) external {
        Challenge storage c = challenges[key(id, digest)];
        if (c.status != Status.Open) revert NotOpen();
        if (block.timestamp <= c.deadline) revert TooEarly();
        c.status = Status.Expired;
        emit Expired(id, digest);
        // A bond already taken by a claim or another challenge is simply gone.
        try reserve.forfeit(id) {} catch {}
        (bool ok, ) = payable(c.challenger).call{value: challengerBond}("");
        require(ok, "bond");
    }

    /// The bytes the guest commits: a bincode Vec<u64>, the length and then
    /// each value, little-endian.
    function publicValues(uint256 id, uint64 digest, uint64 epoch) public view returns (bytes memory pv) {
        uint256 root = uint256(reserve.rootAt(id, epoch));
        uint256 com = uint256(reserve.commitmentOf(id));
        uint256[PUBLIC_VALUES] memory v;
        v[0] = digest;
        for (uint256 j = 0; j < 4; ++j) {
            v[1 + j] = (root >> (64 * j)) & LANE;
            v[5 + j] = (com >> (64 * j)) & LANE;
        }
        v[9] = reserve.domain();
        pv = new bytes(8 * (PUBLIC_VALUES + 1));
        _le(pv, 0, PUBLIC_VALUES);
        for (uint256 i = 0; i < PUBLIC_VALUES; ++i) _le(pv, 8 * (i + 1), v[i]);
    }

    /// Writes the low eight bytes of x at `at`, least significant first.
    function _le(bytes memory out, uint256 at, uint256 x) private pure {
        assembly ("memory-safe") {
            let p := add(add(out, 32), at)
            for { let b := 0 } lt(b, 8) { b := add(b, 1) } { mstore8(add(p, b), shr(mul(8, b), x)) }
        }
    }
}
