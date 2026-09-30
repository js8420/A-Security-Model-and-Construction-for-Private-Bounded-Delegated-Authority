// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// The scheme this construction is an alternative to.
///
/// The domain holds the cumulative total and refuses a payment that would carry
/// it past the budget. Nothing is extracted, no shares are published, and the
/// transcript holds only what a settlement needs. It is cheaper than the
/// accountable reserve in every dimension, and by Corollary 2 it cannot keep
/// the budget private: an adversary that offers payments and watches which are
/// served recovers the bound by binary search.
///
/// It is here to price that corollary. The difference between this contract and
/// Reserve.sol is what accountability costs on chain.
contract PreventiveReserve {
    struct Delegation {
        address principal;
        address agent;
        uint64 cap;
        uint64 budget;
        uint64 spent;
        uint64 velocityN;
        uint64 windowW;
    }

    struct Window {
        uint64 start;
        uint64 count;
    }

    mapping(uint256 => Delegation) public delegations;
    mapping(uint256 => Window) private windows;
    mapping(uint256 => mapping(uint64 => bool)) private indexSeen;

    uint256 public nextId;

    error IndexAlreadySettled();
    error AmountAboveCap();
    error VelocityExceeded();
    error BudgetExceeded();
    error NotAgent();

    event Settled(uint256 indexed id, uint64 index, uint64 amount);

    function register(
        address agent,
        uint64 cap,
        uint64 budget,
        uint64 velocityN,
        uint64 windowW
    ) external returns (uint256 id) {
        id = nextId++;
        delegations[id] = Delegation({
            principal: msg.sender,
            agent: agent,
            cap: cap,
            budget: budget,
            spent: 0,
            velocityN: velocityN,
            windowW: windowW
        });
    }

    /// The refusal Corollary 2 is about is the last of these four.
    function settle(uint256 id, uint64 amount, uint64 index) external {
        Delegation storage d = delegations[id];
        if (msg.sender != d.agent) revert NotAgent();
        if (indexSeen[id][index]) revert IndexAlreadySettled();
        if (amount > d.cap) revert AmountAboveCap();

        Window storage w = windows[id];
        uint64 nowTs = uint64(block.timestamp);
        if (nowTs >= w.start + d.windowW) {
            w.start = nowTs;
            w.count = 0;
        }
        if (w.count + 1 > d.velocityN) revert VelocityExceeded();
        w.count += 1;

        if (d.spent + amount > d.budget) revert BudgetExceeded();
        d.spent += amount;

        indexSeen[id][index] = true;
        emit Settled(id, index, amount);
    }
}
