// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {StepVerifier} from "./StepVerifier.sol";

interface IReserveD {
    function settled(uint256 id, uint64 digest) external view returns (bytes32);
    function agentOf(uint256 id) external view returns (address);
    function forfeit(uint256 id) external;
    function domain() external view returns (uint64);
    function commitmentOf(uint256 id) external view returns (bytes32);
    function rootAt(uint256 id, uint64 epoch) external view returns (bytes32);
}

/// Challenge by refereed bisection over the verifier's execution.
///
/// A state is keccak256(memory root, step index). Every game opens at the
/// empty memory, so the start is no party's choice: the proof enters through
/// the program's load steps, each checked against the blobs whose versioned
/// hashes the agent signed at settlement, and the public values enter from
/// the reserve's own record. The agent, as defender, first names the memory
/// root it claims verification ends in and proves the accept slot there
/// holds 1. The two then halve the
/// disputed interval until one step remains, and StepVerifier decides it.
///
/// Bisection needs somebody who can compute the true states, and that needs
/// the proof. The principal receives it point to point; failing that, the
/// Availability contract forces it into blobs. A challenger reasoning without
/// it cannot win against a defender that answers every round.
///
/// Bonds. The challenger stakes one to open. If the defender wins, by the step
/// or by the clock, the stake pays the defender for its gas. If the challenger
/// wins, the stake comes back and the agent's bond in the reserve goes to the
/// principal.
contract Dispute {
    enum Status { None, AwaitingFinal, Running, DefenderWon, ChallengerWon }

    struct Game {
        address defender;
        address challenger;
        uint256 reserveId;
        uint64 lo;
        uint64 hi;
        uint64 deadline;
        bool defenderToMove;
        Status status;
        bytes32 loState;
        bytes32 hiState;
        bytes32 midState;
        bytes32 blobsHash;
        uint64 digest;
        uint64 epoch;
    }

    /// The statement's public values, in the order the circuit takes them:
    /// the payload digest, the revocation root's four lanes, the delegation
    /// commitment's four lanes, and the settlement domain.
    uint256 public constant PUBLIC_VALUES = 10;

    /// Memory slot holding the verifier's verdict, 1 for accept.
    uint256 public constant ACCEPT_SLOT = 0;

    IReserveD public immutable reserve;
    StepVerifier public immutable verifier;
    /// The verifier's program, fixed by the circuit and the proof system.
    bytes32 public immutable programRoot;
    uint64 public immutable programDepth;
    uint64 public immutable steps;
    uint64 public immutable memDepth;
    uint64 public immutable responseWindow;
    uint256 public immutable challengerBond;
    bytes32 public immutable emptyRoot;

    mapping(bytes32 => Game) private games;

    function statusOf(bytes32 id) external view returns (Status) {
        return games[id].status;
    }

    function game(bytes32 id) external view returns (Game memory) {
        return games[id];
    }

    error NotYourMove();
    error GameNotRunning();
    error GameExists();
    error DeadlineNotPassed();
    error IntervalTooSmall();
    error BondTooSmall();
    error WrongCommitment();
    error NotAccepting();

    event Opened(bytes32 indexed id, uint256 reserveId, uint64 digest, address challenger);
    event Bisected(bytes32 indexed id, uint64 lo, uint64 hi);
    event Resolved(bytes32 indexed id, Status outcome);

    constructor(
        address reserve_,
        address verifier_,
        bytes32 programRoot_,
        uint64 programDepth_,
        uint64 steps_,
        uint64 memDepth_,
        uint64 window,
        uint256 bond
    ) {
        reserve = IReserveD(reserve_);
        verifier = StepVerifier(verifier_);
        programRoot = programRoot_;
        programDepth = programDepth_;
        steps = steps_;
        memDepth = memDepth_;
        responseWindow = window;
        challengerBond = bond;
        bytes32 z;
        for (uint256 i = 0; i < memDepth_; ++i) z = keccak256(abi.encodePacked(z, z));
        emptyRoot = z;
    }

    function state(bytes32 memRoot, uint64 k) public pure returns (bytes32) {
        return keccak256(abi.encode(memRoot, k));
    }

    function gameId(uint256 reserveId, uint64 digest) public pure returns (bytes32) {
        return keccak256(abi.encode(reserveId, digest));
    }

    function open(uint256 reserveId, uint64 digest, bytes32 blobsHash, uint64 epoch)
        external
        payable
    {
        if (msg.value != challengerBond) revert BondTooSmall();
        bytes32 id = gameId(reserveId, digest);
        if (games[id].status != Status.None) revert GameExists();
        if (keccak256(abi.encode(blobsHash, epoch)) != reserve.settled(reserveId, digest)) {
            revert WrongCommitment();
        }
        games[id] = Game({
            defender: reserve.agentOf(reserveId),
            challenger: msg.sender,
            reserveId: reserveId,
            lo: 0,
            hi: steps,
            deadline: uint64(block.timestamp) + responseWindow,
            defenderToMove: true,
            status: Status.AwaitingFinal,
            loState: state(emptyRoot, 0),
            hiState: bytes32(0),
            midState: bytes32(0),
            blobsHash: blobsHash,
            digest: digest,
            epoch: epoch
        });
        emit Opened(id, reserveId, digest, msg.sender);
    }

    /// The defender's claim: verification ends in this memory, which accepts.
    function postFinal(bytes32 id, bytes32 finalRoot, bytes32[] calldata acceptPath) external {
        Game storage g = games[id];
        if (g.status != Status.AwaitingFinal) revert GameNotRunning();
        if (msg.sender != g.defender) revert NotYourMove();
        if (verifier.rootOf(bytes32(uint256(1)), acceptPath, ACCEPT_SLOT) != finalRoot
            || acceptPath.length != memDepth) revert NotAccepting();
        g.hiState = state(finalRoot, steps);
        g.status = Status.Running;
        g.defenderToMove = true;
        g.deadline = uint64(block.timestamp) + responseWindow;
    }

    /// The defender names the state at the midpoint.
    function respond(bytes32 id, bytes32 midState) external {
        Game storage g = games[id];
        if (g.status != Status.Running) revert GameNotRunning();
        if (!g.defenderToMove || msg.sender != g.defender) revert NotYourMove();
        if (g.hi - g.lo < 2) revert IntervalTooSmall();
        g.midState = midState;
        g.defenderToMove = false;
        g.deadline = uint64(block.timestamp) + responseWindow;
    }

    /// The challenger says which half it still disputes. Agreeing with the
    /// midpoint moves the lower end up; disagreeing moves the upper end down.
    /// Neither branch lets the challenger write a state of its own.
    function choose(bytes32 id, bool agreeWithMid) external {
        Game storage g = games[id];
        if (g.status != Status.Running) revert GameNotRunning();
        if (g.defenderToMove || msg.sender != g.challenger) revert NotYourMove();
        uint64 mid = g.lo + (g.hi - g.lo) / 2;
        if (agreeWithMid) {
            g.lo = mid;
            g.loState = g.midState;
        } else {
            g.hi = mid;
            g.hiState = g.midState;
        }
        g.defenderToMove = true;
        g.deadline = uint64(block.timestamp) + responseWindow;
        emit Bisected(id, g.lo, g.hi);
    }

    /// One step remains. Anyone may submit it with true operands; the
    /// verifier reverts on false ones, so the outcome is the step's alone.
    function settleOneStep(
        bytes32 id,
        bytes32 loMemRoot,
        StepVerifier.StepInput calldata s,
        bytes32[] calldata blobs,
        bytes calldata kzg
    ) external {
        Game storage g = games[id];
        if (g.status != Status.Running) revert GameNotRunning();
        if (g.hi - g.lo != 1) revert IntervalTooSmall();
        if (state(loMemRoot, g.lo) != g.loState) revert WrongCommitment();
        bytes32 next = _next(g, loMemRoot, s, _context(g, s.kind, blobs, kzg));
        _end(id, g, state(next, g.hi) == g.hiState ? Status.DefenderWon : Status.ChallengerWon);
    }

    function _next(
        Game storage g,
        bytes32 loMemRoot,
        StepVerifier.StepInput calldata s,
        StepVerifier.Context memory c
    ) private view returns (bytes32) {
        StepVerifier.Frame memory f = StepVerifier.Frame({
            programRoot: programRoot,
            programDepth: programDepth,
            index: g.lo,
            memRoot: loMemRoot,
            depth: memDepth
        });
        return verifier.transition(f, s, c);
    }

    function _context(
        Game storage g,
        StepVerifier.Step kind,
        bytes32[] calldata blobs,
        bytes calldata kzg
    ) private view returns (StepVerifier.Context memory c) {
        if (kind == StepVerifier.Step.LoadBlob) {
            if (keccak256(abi.encodePacked(blobs)) != g.blobsHash) revert WrongCommitment();
            c.blobs = blobs;
            c.kzg = kzg;
        } else if (kind == StepVerifier.Step.LoadPublic) {
            c.pub = _publicValues(g);
        }
    }

    function _publicValues(Game storage g) private view returns (uint256[] memory pv) {
        pv = new uint256[](PUBLIC_VALUES);
        pv[0] = g.digest;
        uint256 root = uint256(reserve.rootAt(g.reserveId, g.epoch));
        uint256 com = uint256(reserve.commitmentOf(g.reserveId));
        for (uint256 j = 0; j < 4; ++j) {
            pv[1 + j] = (root >> (64 * j)) & 0xFFFFFFFFFFFFFFFF;
            pv[5 + j] = (com >> (64 * j)) & 0xFFFFFFFFFFFFFFFF;
        }
        pv[9] = reserve.domain();
    }

    function timeout(bytes32 id) external {
        Game storage g = games[id];
        if (g.status != Status.Running && g.status != Status.AwaitingFinal) revert GameNotRunning();
        if (block.timestamp <= g.deadline) revert DeadlineNotPassed();
        _end(id, g, g.defenderToMove ? Status.ChallengerWon : Status.DefenderWon);
    }

    function _end(bytes32 id, Game storage g, Status outcome) private {
        g.status = outcome;
        emit Resolved(id, outcome);
        address to = outcome == Status.ChallengerWon ? g.challenger : g.defender;
        // A bond already taken by Claim or by another game is simply gone.
        if (outcome == Status.ChallengerWon) {
            try reserve.forfeit(g.reserveId) {} catch {}
        }
        (bool ok, ) = payable(to).call{value: challengerBond}("");
        require(ok, "bond");
    }

    function rounds(uint64 n) external pure returns (uint64 r) {
        while (n > 1) {
            n = (n + 1) / 2;
            ++r;
        }
    }
}
