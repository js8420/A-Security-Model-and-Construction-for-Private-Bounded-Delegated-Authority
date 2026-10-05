// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// Challenge by refereed bisection, so the reserve never carries the proof.
///
/// The reserve verifies no payment proof: at five megabytes a proof does not
/// fit in call data, and a settlement that recorded one would cost more than
/// the payment. The construction therefore leaves validity to a challenge, and
/// a challenge that must present the proof is a challenge nobody can raise.
///
/// Bisection removes that requirement. Verification is a deterministic
/// computation of N steps, and the agent commits to the state its execution
/// passes through. A challenger disputes the final state. The two then halve
/// the disputed interval until one step remains, which the chain adjudicates.
/// Nothing larger than a commitment ever crosses the chain, and the number of
/// messages is logarithmic in N.
///
/// What makes it work against an agent holding the only copy of the proof is
/// the clock: a party that does not move within the response window loses.
/// An agent that settled on a proof it cannot defend declines to play and
/// forfeits, which is the same outcome as losing, and it reaches that outcome
/// without anyone else ever holding the proof.
///
/// The one-step adjudicator is not implemented here. It is the verifier's
/// transition function for a single step, and its cost is a property of that
/// function rather than of this protocol; published interactive systems report
/// 200,000 to 500,000 gas for an equivalent step. What this contract measures
/// is everything around it: opening, each round of bisection, and the two ways
/// a game can end.
contract Dispute {
    enum Status { None, Running, DefenderWon, ChallengerWon }

    struct Game {
        address defender;
        address challenger;
        uint64 lo;            // first step both agree on
        uint64 hi;            // first step they disagree on
        bytes32 loState;      // committed state at lo
        bytes32 hiState;      // defender's claimed state at hi
        uint64 deadline;
        bool defenderToMove;
        Status status;
    }

    uint64 public immutable responseWindow;
    mapping(bytes32 => Game) public games;

    error NotYourMove();
    error GameNotRunning();
    error DeadlineNotPassed();
    error IntervalTooSmall();
    error MidpointOutOfRange();

    event Opened(bytes32 indexed id, address challenger, uint64 steps);
    event Bisected(bytes32 indexed id, uint64 lo, uint64 hi);
    event Resolved(bytes32 indexed id, Status outcome);

    constructor(uint64 window) {
        responseWindow = window;
    }

    /// A challenger disputes the final state of a settlement's verification.
    /// The defender is the agent that signed the payload.
    function open(
        bytes32 id,
        address defender,
        uint64 steps,
        bytes32 initialState,
        bytes32 claimedFinalState
    ) external {
        games[id] = Game({
            defender: defender,
            challenger: msg.sender,
            lo: 0,
            hi: steps,
            loState: initialState,
            hiState: claimedFinalState,
            deadline: uint64(block.timestamp) + responseWindow,
            defenderToMove: true,
            status: Status.Running
        });
        emit Opened(id, msg.sender, steps);
    }

    /// The defender names the state at the midpoint of the disputed interval.
    function respond(bytes32 id, bytes32 midState) external {
        Game storage g = games[id];
        if (g.status != Status.Running) revert GameNotRunning();
        if (!g.defenderToMove || msg.sender != g.defender) revert NotYourMove();
        if (g.hi - g.lo < 2) revert IntervalTooSmall();
        g.hiState = midState;
        g.defenderToMove = false;
        g.deadline = uint64(block.timestamp) + responseWindow;
    }

    /// The challenger picks the half it still disputes. `takeLower` keeps the
    /// midpoint as the new upper end; otherwise the midpoint becomes the new
    /// agreed lower end and the defender's earlier claim stands above it.
    function choose(bytes32 id, bool takeLower, bytes32 upperState) external {
        Game storage g = games[id];
        if (g.status != Status.Running) revert GameNotRunning();
        if (g.defenderToMove || msg.sender != g.challenger) revert NotYourMove();
        uint64 mid = g.lo + (g.hi - g.lo) / 2;
        if (mid <= g.lo || mid >= g.hi) revert MidpointOutOfRange();
        if (takeLower) {
            g.hi = mid;
        } else {
            g.lo = mid;
            g.loState = g.hiState;
            g.hiState = upperState;
        }
        g.defenderToMove = true;
        g.deadline = uint64(block.timestamp) + responseWindow;
        emit Bisected(id, g.lo, g.hi);
    }

    /// One step remains. The adjudicator for that step decides the game; here
    /// its verdict is supplied so the surrounding protocol can be measured
    /// without the verifier's transition function.
    function settleOneStep(bytes32 id, bool defenderCorrect) external {
        Game storage g = games[id];
        if (g.status != Status.Running) revert GameNotRunning();
        if (g.hi - g.lo != 1) revert IntervalTooSmall();
        g.status = defenderCorrect ? Status.DefenderWon : Status.ChallengerWon;
        emit Resolved(id, g.status);
    }

    /// A party that does not move in time loses. This is what makes the game
    /// playable against an agent that alone holds the proof.
    function timeout(bytes32 id) external {
        Game storage g = games[id];
        if (g.status != Status.Running) revert GameNotRunning();
        if (block.timestamp <= g.deadline) revert DeadlineNotPassed();
        g.status = g.defenderToMove ? Status.ChallengerWon : Status.DefenderWon;
        emit Resolved(id, g.status);
    }

    function rounds(uint64 steps) external pure returns (uint64 n) {
        while (steps > 1) {
            steps = (steps + 1) / 2;
            ++n;
        }
    }
}
