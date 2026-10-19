// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// The reveal-on-dispute baseline: the same challenge game with no proof
/// system. Every commitment is a Keccak hash. A challenged settlement is
/// answered by revealing its opening and every part of the principal's policy
/// that the checks need, and the contract checks the policy itself: the cap,
/// the merchant and its payee on the allowlist, the category on its list, the
/// validity window, the run inside the delegation's range and clear of every
/// revoked range, and the running total on this domain within the budget.
///
/// What it cannot check is the total across domains: this contract sees only
/// the settlements on its own chain. And an answer publishes the opening, the
/// budget, the cap, the validity window and one leaf of each list to every
/// reader of the chain.
contract RevealDispute {
    /// The principal's policy, committed at issuance with a salt.
    struct Policy {
        uint64 budget;
        uint64 cap;
        uint64 tStart;
        uint64 tExpiry;
        bytes32 merchants;
        bytes32 categories;
        bytes32 salt;
    }

    /// A payment's fields, as the agent commits them and the reserve records the commitment.
    struct Opening {
        bytes32 salt;
        uint64 amount;
        uint64 merchant;
        uint64 category;
        uint64 time;
        address payee;
        uint64 domain;
        uint64 nonce;
        uint64 runStart;
    }

    /// Two neighbouring leaves of the sorted revoked-range tree, the run lying between them.
    struct Gap {
        uint64 loStart;
        uint64 loLength;
        uint64 hiStart;
        uint64 hiLength;
        uint256 index;
        bytes32[] loPath;
        bytes32[] hiPath;
    }

    struct Delegation {
        address principal;
        bytes32 policy;
        bytes32 revoked;
        uint64 unitSize;
        uint64 rangeBase;
        uint64 rangeLen;
        uint64 spent;
        uint32 holds;
        bool frozen;
    }

    enum Status {
        None,
        Open,
        Answered,
        Expired
    }

    struct Challenge {
        address challenger;
        uint64 deadline;
        Status status;
    }

    uint256 public constant MAX_DEPTH = 16;

    uint64 public immutable domain;
    uint64 public immutable acceptWindow;
    uint64 public immutable answerWindow;
    uint256 public immutable challengerBond;

    uint256 public nextId;
    mapping(uint256 => Delegation) public delegations;
    /// A settlement's record: the hash of its amount, payee, time, opening
    /// commitment, and the running total on this domain after it.
    mapping(bytes32 => bytes32) public records;
    mapping(bytes32 => Challenge) public challenges;
    mapping(address => uint256) public credit;

    error NotPrincipal();
    error Held();
    error Frozen();
    error Duplicate();
    error BondTooSmall();
    error AlreadyChallenged();
    error WrongRecord();
    error WindowClosed();
    error NotOpen();
    error TooLate();
    error TooEarly();
    error OpeningMismatch();
    error PolicyMismatch();
    error AboveCap();
    error MerchantNotAllowed();
    error CategoryNotAllowed();
    error OutsideWindow();
    error OutsideRange();
    error Revoked();
    error OverBudget();
    error BadPath();
    error NothingToWithdraw();

    event Settled(uint256 indexed id, uint64 digest, uint64 amount, address payee, uint64 time, bytes32 opening);
    event Challenged(uint256 indexed id, uint64 digest, uint64 deadline);
    event Answered(uint256 indexed id, uint64 digest);
    event Expired(uint256 indexed id, uint64 digest);

    constructor(uint64 domain_, uint64 acceptWindow_, uint64 answerWindow_, uint256 bond) {
        domain = domain_;
        acceptWindow = acceptWindow_;
        answerWindow = answerWindow_;
        challengerBond = bond;
    }

    function register(bytes32 policy, bytes32 revoked, uint64 unitSize, uint64 rangeBase, uint64 rangeLen) external returns (uint256 id) {
        id = nextId++;
        delegations[id] = Delegation({
            principal: msg.sender, policy: policy, revoked: revoked, unitSize: unitSize, rangeBase: rangeBase,
            rangeLen: rangeLen, spent: 0, holds: 0, frozen: false
        });
    }

    function key(uint256 id, uint64 digest) public pure returns (bytes32) {
        return keccak256(abi.encode(id, digest));
    }

    function recordOf(uint64 amount, address payee, uint64 time, bytes32 opening, uint64 total) public pure returns (bytes32) {
        return keccak256(abi.encode(amount, payee, time, opening, total));
    }

    /// The record the reserve keeps. The agent's signature and the shares are
    /// the reserve's own business and are the same in both designs, so this
    /// baseline leaves them out.
    function settle(uint256 id, uint64 digest, uint64 amount, address payee, uint64 time, bytes32 opening) external {
        Delegation storage d = delegations[id];
        if (d.frozen) revert Frozen();
        if (d.holds != 0) revert Held();
        bytes32 k = key(id, digest);
        if (records[k] != bytes32(0)) revert Duplicate();
        d.spent += amount;
        records[k] = recordOf(amount, payee, time, opening, d.spent);
        emit Settled(id, digest, amount, payee, time, opening);
    }

    function open(uint256 id, uint64 digest, uint64 amount, address payee, uint64 time, bytes32 opening, uint64 total) external payable {
        if (msg.value != challengerBond) revert BondTooSmall();
        bytes32 k = key(id, digest);
        if (challenges[k].status != Status.None) revert AlreadyChallenged();
        if (records[k] != recordOf(amount, payee, time, opening, total)) revert WrongRecord();
        if (block.timestamp > uint256(time) + acceptWindow) revert WindowClosed();
        Delegation storage d = delegations[id];
        if (msg.sender != d.principal) revert NotPrincipal();
        uint64 deadline = uint64(block.timestamp) + answerWindow;
        challenges[k] = Challenge({challenger: msg.sender, deadline: deadline, status: Status.Open});
        d.holds += 1;
        emit Challenged(id, digest, deadline);
    }

    /// Everything an answer reveals.
    struct Answer {
        Opening o;
        uint64 total;
        Policy p;
        uint256 merchantIndex;
        bytes32[] merchantPath;
        uint256 categoryIndex;
        bytes32[] categoryPath;
        Gap gap;
    }

    function answer(uint256 id, uint64 digest, Answer calldata a) external {
        bytes32 k = key(id, digest);
        Challenge storage c = challenges[k];
        if (c.status != Status.Open) revert NotOpen();
        if (block.timestamp > c.deadline) revert TooLate();
        Delegation storage d = delegations[id];
        Opening calldata o = a.o;
        if (records[k] != recordOf(o.amount, o.payee, o.time, keccak256(abi.encode(o)), a.total) || o.domain != domain) {
            revert OpeningMismatch();
        }
        _policy(d.policy, a);
        uint256 end = uint256(o.runStart) + (uint256(o.amount) + d.unitSize - 1) / d.unitSize;
        if (o.runStart < d.rangeBase || end > uint256(d.rangeBase) + d.rangeLen) revert OutsideRange();
        _clear(d.revoked, o.runStart, end, a.gap);
        c.status = Status.Answered;
        d.holds -= 1;
        credit[msg.sender] += challengerBond;
        emit Answered(id, digest);
    }

    function _policy(bytes32 committed, Answer calldata a) private pure {
        Policy calldata p = a.p;
        Opening calldata o = a.o;
        if (keccak256(abi.encode(p)) != committed) revert PolicyMismatch();
        if (o.amount > p.cap) revert AboveCap();
        if (o.time < p.tStart || o.time > p.tExpiry) revert OutsideWindow();
        if (a.total > p.budget) revert OverBudget();
        if (_root(keccak256(abi.encodePacked(o.merchant, o.payee)), a.merchantIndex, a.merchantPath) != p.merchants) {
            revert MerchantNotAllowed();
        }
        if (_root(keccak256(abi.encodePacked(o.category)), a.categoryIndex, a.categoryPath) != p.categories) {
            revert CategoryNotAllowed();
        }
    }

    function expire(uint256 id, uint64 digest) external {
        Challenge storage c = challenges[key(id, digest)];
        if (c.status != Status.Open) revert NotOpen();
        if (block.timestamp <= c.deadline) revert TooEarly();
        c.status = Status.Expired;
        Delegation storage d = delegations[id];
        d.holds -= 1;
        d.frozen = true;
        credit[c.challenger] += challengerBond;
        emit Expired(id, digest);
    }

    function withdraw() external {
        uint256 amount = credit[msg.sender];
        if (amount == 0) revert NothingToWithdraw();
        credit[msg.sender] = 0;
        (bool ok, ) = payable(msg.sender).call{value: amount}("");
        require(ok, "withdraw");
    }

    /// The run [start, end) lies strictly between two neighbouring leaves of
    /// the revoked tree, whose leaves are the revoked ranges sorted by start,
    /// with an empty range at 0 and one at 2^64 - 1 as sentinels.
    function _clear(bytes32 root, uint64 start, uint256 end, Gap calldata g) private pure {
        if (_root(revokedLeaf(g.loStart, g.loLength), g.index, g.loPath) != root) revert BadPath();
        if (_root(revokedLeaf(g.hiStart, g.hiLength), g.index + 1, g.hiPath) != root) revert BadPath();
        if (uint256(g.loStart) + g.loLength > start || end > g.hiStart) revert Revoked();
    }

    function revokedLeaf(uint64 start, uint64 length) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(start, length));
    }

    /// The root a leaf reaches along `path` from position `index`; an inner node is the Keccak hash of its two children.
    function _root(bytes32 leaf, uint256 index, bytes32[] calldata path) private pure returns (bytes32 h) {
        uint256 depth = path.length;
        if (depth > MAX_DEPTH || index >> depth != 0) revert BadPath();
        h = leaf;
        for (uint256 j = 0; j < depth; ++j) {
            h = (index >> j) & 1 == 0 ? keccak256(abi.encodePacked(h, path[j])) : keccak256(abi.encodePacked(path[j], h));
        }
    }
}
