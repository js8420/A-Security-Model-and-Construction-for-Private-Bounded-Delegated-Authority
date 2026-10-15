// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ISP1Verifier} from "./sp1/ISP1Verifier.sol";
import {Settlement, SettlementHash} from "./Settlement.sol";

interface IReserveV {
    function settled(uint256 id, uint64 digest) external view returns (bytes32);
    function agentOf(uint256 id) external view returns (address);
    function principalOf(uint256 id) external view returns (address);
    function forfeit(uint256 id) external;
    function domain() external view returns (uint64);
    function commitmentOf(uint256 id) external view returns (bytes32);
    function rootAt(uint256 id, uint64 epoch) external view returns (bytes32);
    function termsOf(uint256 id) external view returns (uint64, uint64, uint64, bytes32);
}

/// Challenge answered by a validity proof, never by the proof itself.
///
/// The settlement's STARK stays off chain. Within the acceptance window after
/// a settlement, a challenger stakes a bond against it. Before the deadline,
/// anyone holding the STARK answers with one SP1 Groth16 proof that the
/// Plonky3 verifier, run inside SP1, accepts a proof of this settlement's
/// statement. The statement is not taken from the answer: the contract
/// rebuilds it from the reserve's records of the delegation and the settlement
/// (the digest, the revocation root at the settlement's epoch, the delegation
/// commitment, the domain, the amount paid, the payee, the signed time, the
/// unit size, the unit range, H(s), and the hash of the shares and nullifiers
/// published), so a proof of any other statement fails the pairing check. A settlement whose shares its proof did not compute
/// therefore cannot be answered.
///
/// Many challenges. A settlement is challenged at most once. Each agent has
/// two deadline queues, one for its principal's challenges and one for
/// everyone else's. Deadlines in one queue are two slots apart and the two
/// queues sit on alternate slot boundaries, so no two of an agent's deadlines
/// fall in one slot: an agent that proves one answer per slot never misses
/// one, and challenges anyone else opens, the agent's own included, cannot
/// push back the principal's. One batch answer proves any number of open
/// challenges with one Groth16 proof.
///
/// Bonds. An answer credits each challenger's bond to the agent challenged,
/// which pays for the proving. No answer by the deadline credits the bond back
/// to the challenger and forfeits the agent's bond in the reserve to the
/// principal. Credits are withdrawn, never pushed, so no recipient can block
/// an answer or an expiry.
///
/// The verifier is Succinct's Groth16 verifier for one circuit version,
/// called directly. Its routing gateway is not used: the gateway's owner can
/// add a route, and the prover picks the route with the first bytes of its
/// proof.
contract ValidityDispute {
    using SettlementHash for Settlement;

    enum Status { None, Open, Answered, Expired }

    struct Challenge {
        address challenger;
        uint64 deadline;
        Status status;
    }

    /// Values committed per settlement: the payload digest, the revocation
    /// root's four lanes, the delegation commitment's four lanes, the domain,
    /// the amount, the payee's three limbs, the time, the unit size, the
    /// range's base and length, H(s) in four lanes, and the shares' hash in
    /// four words.
    uint256 public constant PUBLIC_VALUES = 26;
    uint256 private constant LANE = 0xFFFFFFFFFFFFFFFF;
    uint256 private constant LIMB = 0xFFFFFFFFFFFFFF;

    IReserveV public immutable reserve;
    ISP1Verifier public immutable verifier;
    /// The guest program for one settlement: the Plonky3 verifier with the
    /// circuit's own AIR, compiled for SP1.
    bytes32 public immutable programVKey;
    /// The guest program for any number of settlements, the same verifier run
    /// once per proof.
    bytes32 public immutable batchVKey;
    /// How long after a settlement's signed time a challenge may be opened.
    uint64 public immutable acceptWindow;
    uint64 public immutable answerWindow;
    /// What proving one answer takes, with margin.
    uint64 public immutable slot;
    uint256 public immutable challengerBond;

    mapping(bytes32 => Challenge) private challenges;
    mapping(address => uint64) public lastPrincipalDeadline;
    mapping(address => uint64) public lastPublicDeadline;
    mapping(uint256 => uint256) public openCount;
    mapping(address => uint256) public credit;

    error BondTooSmall();
    error AlreadyChallenged();
    error WrongRecord();
    error WindowClosed();
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
        uint64 acceptWindow_,
        uint64 answerWindow_,
        uint64 slot_,
        uint256 bond
    ) {
        reserve = IReserveV(reserve_);
        verifier = ISP1Verifier(verifier_);
        programVKey = programVKey_;
        batchVKey = batchVKey_;
        acceptWindow = acceptWindow_;
        answerWindow = answerWindow_;
        slot = slot_;
        challengerBond = bond;
    }

    function key(uint256 id, uint64 digest) public pure returns (bytes32) {
        return keccak256(abi.encode(id, digest));
    }

    function challengeOf(uint256 id, uint64 digest) external view returns (Challenge memory) {
        return challenges[key(id, digest)];
    }

    /// `s` opens the reserve's record of the settlement.
    function open(uint256 id, uint64 digest, Settlement calldata s) external payable {
        if (msg.value != challengerBond) revert BondTooSmall();
        bytes32 k = key(id, digest);
        if (challenges[k].status != Status.None) revert AlreadyChallenged();
        _record(id, digest, s);
        if (block.timestamp > uint256(s.time) + acceptWindow) revert WindowClosed();
        uint64 deadline = _queue(reserve.agentOf(id), msg.sender == reserve.principalOf(id));
        challenges[k] = Challenge({challenger: msg.sender, deadline: deadline, status: Status.Open});
        openCount[id] += 1;
        emit Challenged(id, digest, msg.sender, deadline);
    }

    function answer(uint256 id, uint64 digest, Settlement calldata s, bytes calldata proof) external {
        Challenge storage c = _due(id, digest);
        _record(id, digest, s);
        verifier.verifyProof(programVKey, publicValues(id, digest, s), proof);
        _settle(c, id, digest);
    }

    /// One proof of the batch program over these settlements, in this order.
    function answerBatch(
        uint256[] calldata ids,
        uint64[] calldata digests,
        Settlement[] calldata ss,
        bytes calldata proof
    ) external {
        uint256 n = ids.length;
        if (n == 0) revert EmptyBatch();
        if (digests.length != n || ss.length != n) revert LengthMismatch();
        for (uint256 i = 0; i < n; ++i) {
            _due(ids[i], digests[i]);
            _record(ids[i], digests[i], ss[i]);
        }
        verifier.verifyProof(batchVKey, batchPublicValues(ids, digests, ss), proof);
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
        openCount[id] -= 1;
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

    /// The next deadline in one of the agent's two queues: at least the answer
    /// window away, at least two slots after that queue's previous deadline,
    /// and on that queue's own slot boundaries, even ones for the principal
    /// and odd ones for everyone else.
    function _queue(address agent, bool principal) private returns (uint64 d) {
        uint64 period = 2 * slot;
        uint64 phase = principal ? 0 : slot;
        uint64 x = uint64(block.timestamp) + answerWindow;
        uint64 last = principal ? lastPrincipalDeadline[agent] : lastPublicDeadline[agent];
        if (last != 0 && last + period > x) x = last + period;
        uint64 m = x % period;
        d = m <= phase ? x + (phase - m) : x + (period - m) + phase;
        if (principal) lastPrincipalDeadline[agent] = d;
        else lastPublicDeadline[agent] = d;
    }

    function _record(uint256 id, uint64 digest, Settlement calldata s) private view {
        if (s.hash() != reserve.settled(id, digest)) revert WrongRecord();
    }

    function _due(uint256 id, uint64 digest) private view returns (Challenge storage c) {
        c = challenges[key(id, digest)];
        if (c.status != Status.Open) revert NotOpen();
        if (block.timestamp > c.deadline) revert TooLate();
    }

    function _settle(Challenge storage c, uint256 id, uint64 digest) private {
        c.status = Status.Answered;
        openCount[id] -= 1;
        credit[reserve.agentOf(id)] += challengerBond;
        emit Answered(id, digest);
    }

    /// The bytes the single program commits: a bincode Vec<u64>, the length
    /// and then each value, little-endian.
    function publicValues(uint256 id, uint64 digest, Settlement calldata s) public view returns (bytes memory pv) {
        pv = new bytes(8 * (PUBLIC_VALUES + 1));
        _le(pv, 0, PUBLIC_VALUES);
        _write(pv, 8, id, digest, s);
    }

    /// The bytes the batch program commits: one bincode Vec<u64> holding every
    /// settlement's values in turn.
    function batchPublicValues(uint256[] calldata ids, uint64[] calldata digests, Settlement[] calldata ss)
        public
        view
        returns (bytes memory pv)
    {
        uint256 n = ids.length;
        pv = new bytes(8 * (PUBLIC_VALUES * n + 1));
        _le(pv, 0, PUBLIC_VALUES * n);
        for (uint256 i = 0; i < n; ++i) _write(pv, 8 + 8 * PUBLIC_VALUES * i, ids[i], digests[i], ss[i]);
    }

    function _write(bytes memory pv, uint256 at, uint256 id, uint64 digest, Settlement calldata s) private view {
        uint256 root = uint256(reserve.rootAt(id, s.epoch));
        uint256 com = uint256(reserve.commitmentOf(id));
        _le(pv, at, digest);
        for (uint256 j = 0; j < 4; ++j) {
            _le(pv, at + 8 * (1 + j), (root >> (64 * j)) & LANE);
            _le(pv, at + 8 * (5 + j), (com >> (64 * j)) & LANE);
        }
        _le(pv, at + 72, reserve.domain());
        _le(pv, at + 80, s.amount);
        uint256 a = uint160(s.payee);
        _le(pv, at + 88, a & LIMB);
        _le(pv, at + 96, (a >> 56) & LIMB);
        _le(pv, at + 104, a >> 112);
        _le(pv, at + 112, s.time);
        _terms(pv, at + 120, id);
        uint256 h = uint256(s.elems);
        for (uint256 j = 0; j < 4; ++j) _le(pv, at + 176 + 8 * j, (h >> (192 - 64 * j)) & LANE);
    }

    function _terms(bytes memory pv, uint256 at, uint256 id) private view {
        (uint64 unit, uint64 base, uint64 len, bytes32 hs) = reserve.termsOf(id);
        _le(pv, at, unit);
        _le(pv, at + 8, base);
        _le(pv, at + 16, len);
        for (uint256 j = 0; j < 4; ++j) _le(pv, at + 24 + 8 * j, (uint256(hs) >> (64 * j)) & LANE);
    }

    /// Writes the low eight bytes of x at `at`, least significant first.
    function _le(bytes memory out, uint256 at, uint256 x) private pure {
        assembly ("memory-safe") {
            let p := add(add(out, 32), at)
            for { let b := 0 } lt(b, 8) { b := add(b, 1) } { mstore8(add(p, b), shr(mul(8, b), x)) }
        }
    }
}
