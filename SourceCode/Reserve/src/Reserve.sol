// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Settlement, SettlementHash} from "./Settlement.sol";

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

interface IDisputeCount {
    function openCount(uint256 id) external view returns (uint256);
    function acceptWindow() external view returns (uint64);
}

/// Uniswap Permit2, allowance mode. Only the call the reserve makes.
interface IAllowanceTransfer {
    function transferFrom(address from, address to, uint160 amount, address token) external;
}

/// The reserve of Section V on one settlement domain.
///
/// It verifies no payment proof. It records each settlement against its payload
/// digest, publishes the shares and nullifiers, refuses a digest it has already
/// settled, an amount above the public cap, a payment beyond the public
/// velocity bound, a stale or future time, or a payment after expiry, and moves
/// the payment itself. Value leaves the principal only through settle, so a
/// payment that moves money always publishes shares. The record keeps
/// everything the settlement paid and published, which is the statement a
/// challenge holds the agent to.
///
/// Two ways to fund a delegation, measured against each other:
///   Deposit  the principal deposits the declared range up front and the
///            reserve pays out of it;
///   Permit2  the money stays in the principal's wallet and the reserve pulls
///            each payment through a Permit2 allowance.
/// Either amount is public, so either must be sized to the declared range and
/// not to the budget.
contract Reserve {
    uint256 private constant PER_WORD = 4;

    enum Funding { Deposit, Permit2 }

    struct Delegation {
        address principal;
        address agent;
        uint64 cap;
        uint64 velocityN;
        uint64 windowW;
        Funding funding;
        bool bondPaid;
        bool closed;
        uint64 epoch;
        /// No settlement after this; the bond is released a delay later.
        uint64 expiry;
        /// The delegation's unit range, which revocations must lie inside.
        uint64 rangeBase;
        uint64 rangeLen;
        uint256 deposit;
        uint256 bond;
        bytes32 secretHash;
        /// The delegation commitment D.com, four Goldilocks lanes packed low
        /// lane first. A proof's public values must carry it.
        bytes32 commitment;
    }

    struct Window {
        uint64 start;
        uint64 count;
    }

    /// This domain's identifier, the second coordinate of every share index
    /// settled here. Never zero: a zero index would publish the secret itself.
    uint64 public immutable domain;
    IERC20 public immutable token;
    IAllowanceTransfer public immutable permit2;
    address private immutable deployer;
    /// How far a payment's signed time may be from the reserve's clock.
    uint64 public immutable maxAge;
    /// How long after expiry the bond stays: at least maxAge and the challenge
    /// window, and long enough for the principal to scan the transcript and claim.
    uint64 public immutable closeDelay;

    /// The contract allowed to forfeit a bond on an unanswered challenge. Set
    /// once, after both are deployed.
    address public dispute;

    mapping(uint256 => Delegation) private delegations;
    mapping(uint256 => Window) private windows;
    /// What each settled digest was settled against: the hash of its
    /// Settlement. Non-zero means settled, so the freshness check and the
    /// record a challenge needs share one slot.
    mapping(uint256 => mapping(uint64 => bytes32)) public settled;
    /// The revocation accumulator's root at each epoch, four lanes packed.
    mapping(uint256 => mapping(uint64 => bytes32)) public rootAt;
    mapping(uint256 => mapping(uint256 => uint256)) private transcript;
    mapping(uint256 => uint256) private transcriptLen;
    /// Each delegation's revoked ranges as (start, length), in insertion order.
    mapping(uint256 => uint64[2][]) private revoked;

    uint256 public nextId;

    error IndexAlreadySettled();
    error AmountAboveCap();
    error BadSignature();
    error VelocityExceeded();
    error BondAlreadyPaid();
    error SecretDoesNotOpen();
    error NotPrincipal();
    error NotArbiter();
    error AlreadySet();
    error DepositExhausted();
    error StaleTime();
    error Expired();
    error NotClosable();
    error RangeOutside();
    error RangeOverlaps();
    error LengthMismatch();

    event Settled(uint256 indexed id, uint64 digest, uint64 amount, address payee);
    event Transcript(uint256 indexed id, uint64 digest, uint64[] elems);
    event BondForfeited(uint256 indexed id, address to, uint256 amount);
    event Revoked(uint256 indexed id, uint64 start, uint64 length);
    event Closed(uint256 indexed id, uint256 deposit, uint256 bond);

    constructor(uint64 domainId, address token_, address permit2_, uint64 maxAge_, uint64 closeDelay_) {
        require(domainId != 0, "domain");
        domain = domainId;
        token = IERC20(token_);
        permit2 = IAllowanceTransfer(permit2_);
        deployer = msg.sender;
        maxAge = maxAge_;
        closeDelay = closeDelay_;
    }

    /// A bond must outlive every challenge that can still be opened. The last
    /// settlement is signed no later than maxAge after expiry and challenged
    /// no later than the acceptance window after that.
    function setDispute(address dispute_) external {
        if (msg.sender != deployer || dispute != address(0)) revert AlreadySet();
        require(uint256(IDisputeCount(dispute_).acceptWindow()) + maxAge <= closeDelay, "close delay");
        dispute = dispute_;
    }

    function register(
        address agent,
        uint64 cap,
        uint64 velocityN,
        uint64 windowW,
        bytes32 secretHash,
        Funding funding,
        uint256 deposit,
        bytes32 commitment,
        bytes32 revocationRoot,
        uint64 expiry,
        uint64 rangeBase,
        uint64 rangeLen
    ) external payable returns (uint256 id) {
        id = nextId++;
        delegations[id] = Delegation({
            principal: msg.sender,
            agent: agent,
            cap: cap,
            velocityN: velocityN,
            windowW: windowW,
            funding: funding,
            bondPaid: false,
            closed: false,
            epoch: 0,
            expiry: expiry,
            rangeBase: rangeBase,
            rangeLen: rangeLen,
            deposit: funding == Funding.Deposit ? deposit : 0,
            bond: msg.value,
            secretHash: secretHash,
            commitment: commitment
        });
        rootAt[id][0] = revocationRoot;
        if (funding == Funding.Deposit && deposit != 0) {
            require(token.transferFrom(msg.sender, address(this), deposit), "deposit");
        }
    }

    /// One payment, transcript stored. Called by whoever delivers the service,
    /// under the agent's signature over everything the agent answers for: the
    /// domain, the payee, the amount, the digest, the time and the shares. A
    /// payee holding a signed payload therefore cannot settle it with shares of
    /// its own.
    function settle(
        uint256 id,
        address payee,
        uint64 amount,
        uint64 digest,
        uint64 time,
        uint64[] calldata elems,
        bytes calldata signature
    ) external {
        bytes32 elemsHash = keccak256(abi.encodePacked(elems));
        _checkAgentSignature(id, payee, amount, digest, time, elemsHash, signature);
        _admit(id, payee, amount, digest, time, elemsHash);
        _append(id, elems);
        _pay(id, payee, amount);
        emit Settled(id, digest, amount, payee);
    }

    /// The same settlement with the transcript emitted rather than stored.
    function settleLogged(
        uint256 id,
        address payee,
        uint64 amount,
        uint64 digest,
        uint64 time,
        uint64[] calldata elems,
        bytes calldata signature
    ) external {
        bytes32 elemsHash = keccak256(abi.encodePacked(elems));
        _checkAgentSignature(id, payee, amount, digest, time, elemsHash, signature);
        _admit(id, payee, amount, digest, time, elemsHash);
        emit Transcript(id, digest, elems);
        _pay(id, payee, amount);
        emit Settled(id, digest, amount, payee);
    }

    function signedDigest(
        uint256 id,
        address payee,
        uint64 amount,
        uint64 digest,
        uint64 time,
        bytes32 elemsHash
    ) public view returns (bytes32) {
        return keccak256(
            abi.encode(block.chainid, address(this), domain, id, payee, amount, digest, time, elemsHash)
        );
    }

    function _checkAgentSignature(
        uint256 id,
        address payee,
        uint64 amount,
        uint64 digest,
        uint64 time,
        bytes32 elemsHash,
        bytes calldata signature
    ) private view {
        bytes32 h = signedDigest(id, payee, amount, digest, time, elemsHash);
        if (signature.length != 65) revert BadSignature();
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := calldataload(signature.offset)
            s := calldataload(add(signature.offset, 32))
            v := byte(0, calldataload(add(signature.offset, 64)))
        }
        if (uint256(s) > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0) {
            revert BadSignature();
        }
        address signer = ecrecover(h, v, r, s);
        if (signer == address(0) || signer != delegations[id].agent) revert BadSignature();
    }

    function _admit(uint256 id, address payee, uint64 amount, uint64 digest, uint64 time, bytes32 elemsHash)
        private
    {
        Delegation storage d = delegations[id];
        uint64 nowTs = uint64(block.timestamp);
        if (nowTs > d.expiry) revert Expired();
        if (time > nowTs + maxAge || nowTs > time + maxAge) revert StaleTime();
        if (settled[id][digest] != bytes32(0)) revert IndexAlreadySettled();
        if (amount > d.cap) revert AmountAboveCap();

        Window storage w = windows[id];
        if (nowTs >= w.start + d.windowW) {
            w.start = nowTs;
            w.count = 0;
        }
        if (w.count + 1 > d.velocityN) revert VelocityExceeded();
        w.count += 1;
        // The epoch is the reserve's, not the agent's: a proof against a root
        // revocation has since replaced is a proof the dispute rejects.
        settled[id][digest] = SettlementHash.hash(
            Settlement({elems: elemsHash, amount: amount, payee: payee, time: time, epoch: d.epoch})
        );
    }

    function _pay(uint256 id, address payee, uint64 amount) private {
        Delegation storage d = delegations[id];
        if (d.funding == Funding.Deposit) {
            if (d.deposit < amount) revert DepositExhausted();
            d.deposit -= amount;
            require(token.transfer(payee, amount), "transfer");
        } else {
            permit2.transferFrom(d.principal, payee, uint160(amount), address(token));
        }
    }

    function _append(uint256 id, uint64[] calldata elems) private {
        uint256 base = transcriptLen[id];
        uint256 n = elems.length;
        uint256 words = (n + PER_WORD - 1) / PER_WORD;
        for (uint256 i = 0; i < words; ++i) {
            uint256 packed;
            uint256 lo = i * PER_WORD;
            uint256 hi = lo + PER_WORD < n ? lo + PER_WORD : n;
            for (uint256 j = lo; j < hi; ++j) {
                packed |= uint256(elems[j]) << (64 * (j - lo));
            }
            transcript[id][base + i] = packed;
        }
        transcriptLen[id] = base + words;
    }

    /// Evidence of overdraft is a secret opening the committed hash. The bond
    /// goes to the principal, never to whoever presents the secret, or an agent
    /// could reclaim its own bond by overdrawing on purpose. keccak256 here; a
    /// deployment committing with Poseidon2 pays one on-chain permutation
    /// instead, measured in Poseidon2Gas.
    function claim(uint256 id, uint64[2] calldata secret) external {
        if (keccak256(abi.encodePacked(secret[0], secret[1])) != delegations[id].secretHash) {
            revert SecretDoesNotOpen();
        }
        _forfeit(id);
    }

    /// A challenge nobody answered.
    function forfeit(uint256 id) external {
        if (msg.sender != dispute) revert NotArbiter();
        _forfeit(id);
    }

    /// After expiry and the delay, with no challenge open, the deposit left
    /// goes back to the principal and the bond to the agent. Anyone may call
    /// it; the destinations are fixed.
    function close(uint256 id) external {
        Delegation storage d = delegations[id];
        if (d.closed || block.timestamp <= uint256(d.expiry) + closeDelay) revert NotClosable();
        if (dispute != address(0) && IDisputeCount(dispute).openCount(id) != 0) revert NotClosable();
        d.closed = true;
        uint256 dep = d.deposit;
        d.deposit = 0;
        uint256 bond = d.bondPaid ? 0 : d.bond;
        d.bondPaid = true;
        d.bond = 0;
        emit Closed(id, dep, bond);
        if (dep != 0) require(token.transfer(d.principal, dep), "deposit");
        if (bond != 0) {
            (bool ok, ) = payable(d.agent).call{value: bond}("");
            require(ok, "bond");
        }
    }

    function _forfeit(uint256 id) private {
        Delegation storage d = delegations[id];
        if (d.bondPaid) revert BondAlreadyPaid();
        d.bondPaid = true;
        uint256 amount = d.bond;
        d.bond = 0;
        emit BondForfeited(id, d.principal, amount);
        (bool ok, ) = payable(d.principal).call{value: amount}("");
        require(ok, "bond");
    }

    /// The principal computes the accumulator's new root off chain and the
    /// reserve records it; a wrong root misleads only the principal's own
    /// revocations. The ranges of one call are one update and one epoch. Each
    /// must lie inside the delegation's range and overlap no range already
    /// revoked or named earlier in the call, which is what lets C8 exhibit a
    /// single range.
    function revoke(uint256 id, uint64[] calldata starts, uint64[] calldata lengths, bytes32 newRoot) external {
        Delegation storage d = delegations[id];
        if (msg.sender != d.principal) revert NotPrincipal();
        uint256 n = starts.length;
        if (lengths.length != n || n == 0) revert LengthMismatch();
        uint64[2][] storage list = revoked[id];
        for (uint256 i = 0; i < n; ++i) {
            uint64 a = starts[i];
            uint64 l = lengths[i];
            if (l == 0 || a < d.rangeBase || uint256(a) + l > uint256(d.rangeBase) + d.rangeLen) {
                revert RangeOutside();
            }
            uint256 m = list.length;
            for (uint256 j = 0; j < m; ++j) {
                uint64[2] storage r = list[j];
                if (a < r[0] + r[1] && r[0] < a + l) revert RangeOverlaps();
            }
            list.push([a, l]);
            emit Revoked(id, a, l);
        }
        uint64 e = d.epoch + 1;
        d.epoch = e;
        rootAt[id][e] = newRoot;
    }

    function epochOf(uint256 id) external view returns (uint64) {
        return delegations[id].epoch;
    }

    function principalOf(uint256 id) external view returns (address) {
        return delegations[id].principal;
    }

    function commitmentOf(uint256 id) external view returns (bytes32) {
        return delegations[id].commitment;
    }

    function agentOf(uint256 id) external view returns (address) {
        return delegations[id].agent;
    }

    function transcriptWords(uint256 id) external view returns (uint256) {
        return transcriptLen[id];
    }

    function revokedCount(uint256 id) external view returns (uint256) {
        return revoked[id].length;
    }
}
