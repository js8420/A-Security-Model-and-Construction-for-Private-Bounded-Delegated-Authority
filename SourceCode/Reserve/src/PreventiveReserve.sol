// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

interface IERC20P {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

/// The scheme this construction is an alternative to. The domain holds the
/// cumulative total and refuses a payment that would carry it past the budget.
/// Nothing is extracted and no shares are published, and by the probing
/// argument it cannot keep the budget private. It pays out of a deposit exactly
/// as Reserve does in Deposit mode, so the difference between the two is what
/// accountability costs and nothing else.
contract PreventiveReserve {
    struct Delegation {
        address principal;
        address agent;
        uint64 cap;
        uint64 budget;
        uint64 spent;
        uint64 velocityN;
        uint64 windowW;
        uint256 deposit;
    }

    struct Window {
        uint64 start;
        uint64 count;
    }

    IERC20P public immutable token;
    mapping(uint256 => Delegation) public delegations;
    mapping(uint256 => Window) private windows;
    mapping(uint256 => mapping(uint64 => bool)) private indexSeen;

    uint256 public nextId;

    error IndexAlreadySettled();
    error AmountAboveCap();
    error VelocityExceeded();
    error BudgetExceeded();
    error NotAgent();

    event Settled(uint256 indexed id, uint64 index, uint64 amount, address payee);

    constructor(address token_) {
        token = IERC20P(token_);
    }

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
            windowW: windowW,
            deposit: budget
        });
        require(token.transferFrom(msg.sender, address(this), budget), "deposit");
    }

    function settle(uint256 id, address payee, uint64 amount, uint64 index) external {
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
        d.deposit -= amount;

        indexSeen[id][index] = true;
        require(token.transfer(payee, amount), "transfer");
        emit Settled(id, index, amount, payee);
    }
}
