// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {StepVerifier} from "./StepVerifier.sol";

interface IReserveD {
    function settled(uint256 id, uint64 digest) external view returns (bytes32);
    function agentOf(uint256 id) external view returns (address);
    function forfeit(uint256 id) external;
}

/// Challenge by refereed bisection over the verifier's execution.
///
/// A state is keccak256(memory root, step index). The game opens at the state
/// the settlement committed to: the agent signed keccak256(inputRoot,
/// blobsHash), and inputRoot is the memory the verifier starts from. The
/// agent, as defender, first names the memory root it claims verification ends
/// in and proves the accept slot there holds 1. The two then halve the
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
    }

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

    mapping(bytes32 => Game) public games;

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
    }

    function state(bytes32 memRoot, uint64 k) public pure returns (bytes32) {
        return keccak256(abi.encode(memRoot, k));
    }

    function gameId(uint256 reserveId, uint64 digest) public pure returns (bytes32) {
        return keccak256(abi.encode(reserveId, digest));
    }

    function open(uint256 reserveId, uint64 digest, bytes32 inputRoot, bytes32 blobsHash)
        external
        payable
    {
        if (msg.value != challengerBond) revert BondTooSmall();
        bytes32 id = gameId(reserveId, digest);
        if (games[id].status != Status.None) revert GameExists();
        if (keccak256(abi.encode(inputRoot, blobsHash)) != reserve.settled(reserveId, digest)) {
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
            loState: state(inputRoot, 0),
            hiState: bytes32(0),
            midState: bytes32(0)
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
    function settleOneStep(bytes32 id, bytes32 loMemRoot, StepVerifier.StepInput calldata s)
        external
    {
        Game storage g = games[id];
        if (g.status != Status.Running) revert GameNotRunning();
        if (g.hi - g.lo != 1) revert IntervalTooSmall();
        if (state(loMemRoot, g.lo) != g.loState) revert WrongCommitment();
        bytes32 next = verifier.transition(programRoot, programDepth, g.lo, loMemRoot, memDepth, s);
        _end(id, g, state(next, g.hi) == g.hiState ? Status.DefenderWon : Status.ChallengerWon);
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
