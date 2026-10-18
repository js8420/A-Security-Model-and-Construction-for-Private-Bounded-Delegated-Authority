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

/// The circuit's own permutation, which a claim needs to open H(s).
interface IPoseidon2 {
    function permute(uint256[8] memory s) external pure returns (uint256[8] memory);
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
        /// The principal's challenges still open. While any is, nothing settles.
        uint32 holds;
        /// No settlement ever again: set by a forfeit, a claim or the principal.
        bool frozen;
        uint64 cap;
        uint64 velocityN;
        uint64 windowW;
        Funding funding;
        bool bondPaid;
        bool closed;
        uint64 epoch;
        /// No settlement after this; the bond is released a delay later.
        uint64 expiry;
        /// When the delegation was frozen, if it was.
        uint64 frozenAt;
        /// The delegation's unit range, which revocations must lie inside.
        uint64 rangeBase;
        uint64 rangeLen;
        uint256 deposit;
        uint256 bond;
        /// The canonical unit size the budget is counted in.
        uint64 unitSize;
        /// H(s): lanes two to five of the circuit's permutation of the secret,
        /// packed low lane first. The proof's public values carry it.
        bytes32 secretHash;
        /// The delegation commitment D.com, four Goldilocks lanes packed low
        /// lane first. A proof's public values must carry it.
        bytes32 commitment;
        address monitor;
        /// Holds the agent's batch proofs and answers for it; zero if none.
        address answerer;
        /// What the answerer stakes, burnt if a challenge it could have
        /// answered expires.
        uint256 answererStake;
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
    IPoseidon2 public immutable poseidon;

    /// The separator the circuit hashes the secret under.
    uint256 private constant DOMAIN_SECRET = 6;
    uint256 private constant LANE = 0xFFFFFFFFFFFFFFFF;

    /// What the principal records at registration. Everything here is public
    /// except what the commitment hides; the unit size, the range and H(s) are
    /// the delegation's terms a proof is checked against.
    struct Terms {
        address agent;
        uint64 cap;
        uint64 velocityN;
        uint64 windowW;
        bytes32 secretHash;
        Funding funding;
        uint256 deposit;
        bytes32 commitment;
        bytes32 revocationRoot;
        uint64 expiry;
        uint64 unitSize;
        uint64 rangeBase;
        uint64 rangeLen;
        /// An address the principal's monitor sends from, if not the principal
        /// itself. Its challenges hold settlement and it may freeze. A principal
        /// that is a contract wallet needs one: a transaction forced in through
        /// L1 arrives from the sender's own address only when that is an EOA.
        address monitor;
        /// The agent's answerer, if it has one. An answer credits the
        /// challenger's bond to it rather than to the agent.
        address answerer;
    }

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
    /// Answerer stakes slashed, held here for good.
    uint256 public burnt;

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
    error WrongSlotCount();
    error Frozen();
    error Held();
    error NotFrozen();
    error NotAnswerer();
    error NotClosed();

    event Settled(uint256 indexed id, uint64 digest, uint64 amount, address payee);
    event Transcript(uint256 indexed id, uint64 digest, uint64[] elems);
    event BondForfeited(uint256 indexed id, address to, uint256 amount);
    event Revoked(uint256 indexed id, uint64 start, uint64 length);
    event Closed(uint256 indexed id, uint256 deposit, uint256 bond);
    event FrozenBy(uint256 indexed id, address by);
    event Reclaimed(uint256 indexed id, uint256 deposit);
    event AnswererStaked(uint256 indexed id, uint256 amount);
    event AnswererSlashed(uint256 indexed id, uint256 amount);

    constructor(
        uint64 domainId,
        address token_,
        address permit2_,
        address poseidon_,
        uint64 maxAge_,
        uint64 closeDelay_
    ) {
        require(domainId != 0, "domain");
        poseidon = IPoseidon2(poseidon_);
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

    function register(Terms calldata t) external payable returns (uint256 id) {
        if (t.unitSize == 0 || t.rangeLen == 0) revert RangeOutside();
        id = nextId++;
        delegations[id] = Delegation({
            principal: msg.sender,
            agent: t.agent,
            holds: 0,
            frozen: false,
            cap: t.cap,
            velocityN: t.velocityN,
            windowW: t.windowW,
            funding: t.funding,
            bondPaid: false,
            closed: false,
            epoch: 0,
            expiry: t.expiry,
            frozenAt: 0,
            rangeBase: t.rangeBase,
            rangeLen: t.rangeLen,
            deposit: t.funding == Funding.Deposit ? t.deposit : 0,
            bond: msg.value,
            unitSize: t.unitSize,
            secretHash: t.secretHash,
            commitment: t.commitment,
            monitor: t.monitor,
            answerer: t.answerer,
            answererStake: 0
        });
        rootAt[id][0] = t.revocationRoot;
        if (t.funding == Funding.Deposit && t.deposit != 0) {
            require(token.transferFrom(msg.sender, address(this), t.deposit), "deposit");
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
        _admit(id, payee, amount, digest, time, elemsHash, elems.length);
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
        _admit(id, payee, amount, digest, time, elemsHash, elems.length);
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

    /// A payment of amount a publishes the two share lanes and the nullifier
    /// of each of its ceil(a / u) units and nothing else. The amount is public,
    /// so padding to a fixed slot count would hide nothing.
    function _admit(
        uint256 id,
        address payee,
        uint64 amount,
        uint64 digest,
        uint64 time,
        bytes32 elemsHash,
        uint256 published
    ) private {
        Delegation storage d = delegations[id];
        if (d.frozen) revert Frozen();
        if (d.holds != 0) revert Held();
        uint256 u = d.unitSize;
        if (published != 3 * ((uint256(amount) + u - 1) / u)) revert WrongSlotCount();
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

    /// Evidence of overdraft is a secret opening the committed H(s), computed
    /// with the circuit's own permutation so that the secret the shares
    /// reconstruct is the one the record names. The bond goes to the
    /// principal, never to whoever presents the secret, or an agent could
    /// reclaim its own bond by overdrawing on purpose.
    function claim(uint256 id, uint64[2] calldata secret) external {
        uint256[8] memory st;
        st[0] = secret[0];
        st[1] = secret[1];
        st[2] = DOMAIN_SECRET;
        uint256[8] memory out = poseidon.permute(st);
        uint256 h = out[2] | (out[3] << 64) | (out[4] << 128) | (out[5] << 192);
        if (bytes32(h) != delegations[id].secretHash) revert SecretDoesNotOpen();
        _freeze(id);
        _forfeit(id);
    }

    /// A challenge nobody answered. The delegation freezes whether or not the
    /// bond is still there to pay.
    function forfeit(uint256 id) external {
        if (msg.sender != dispute) revert NotArbiter();
        _freeze(id);
        if (!delegations[id].bondPaid) _forfeit(id);
    }

    /// The answerer's stake, held until the delegation closes.
    function stakeAnswerer(uint256 id) external payable {
        Delegation storage d = delegations[id];
        if (d.answerer == address(0) || msg.sender != d.answerer) revert NotAnswerer();
        if (d.closed) revert NotClosable();
        d.answererStake += msg.value;
        emit AnswererStaked(id, msg.value);
    }

    /// An answerer that acknowledged a batch and let a challenge against it
    /// expire loses its stake. Whoever brings the receipt is paid a fixed
    /// bounty, so someone always has a reason to; the rest is burnt rather
    /// than paid to anyone: paid to the agent, an agent and principal acting
    /// together could knock the answerer offline and split it; paid to the
    /// principal, a bribe for silence would cost the principal nothing. The
    /// burnt part stays in this contract, which has no way to send it.
    function slashAnswerer(uint256 id, address caller, uint256 bounty) external {
        if (msg.sender != dispute) revert NotArbiter();
        Delegation storage d = delegations[id];
        uint256 amount = d.answererStake;
        d.answererStake = 0;
        uint256 paid = bounty < amount ? bounty : amount;
        burnt += amount - paid;
        emit AnswererSlashed(id, amount);
        if (paid != 0) {
            (bool ok, ) = payable(caller).call{value: paid}("");
            require(ok, "bounty");
        }
    }

    /// Pulled rather than paid at close, so an answerer cannot block a close.
    function unstakeAnswerer(uint256 id) external {
        Delegation storage d = delegations[id];
        if (msg.sender != d.answerer) revert NotAnswerer();
        if (!d.closed) revert NotClosed();
        uint256 amount = d.answererStake;
        d.answererStake = 0;
        if (amount != 0) {
            (bool ok, ) = payable(msg.sender).call{value: amount}("");
            require(ok, "stake");
        }
    }

    /// The principal's challenge holds settlement until it is answered.
    function hold(uint256 id) external {
        if (msg.sender != dispute) revert NotArbiter();
        delegations[id].holds += 1;
    }

    function release(uint256 id) external {
        if (msg.sender != dispute) revert NotArbiter();
        delegations[id].holds -= 1;
    }

    /// The principal stops the delegation at once, on every unit.
    function freeze(uint256 id) external {
        Delegation storage d = delegations[id];
        if (msg.sender != d.principal && (d.monitor == address(0) || msg.sender != d.monitor)) revert NotPrincipal();
        _freeze(id);
    }

    /// Once nothing can settle, the deposit left is the principal's at once.
    function reclaim(uint256 id) external {
        Delegation storage d = delegations[id];
        if (msg.sender != d.principal) revert NotPrincipal();
        if (!d.frozen) revert NotFrozen();
        uint256 dep = d.deposit;
        d.deposit = 0;
        emit Reclaimed(id, dep);
        if (dep != 0) require(token.transfer(d.principal, dep), "deposit");
    }

    function _freeze(uint256 id) private {
        Delegation storage d = delegations[id];
        if (d.frozen) return;
        d.frozen = true;
        d.frozenAt = uint64(block.timestamp);
        emit FrozenBy(id, msg.sender);
    }

    /// After expiry, or after a freeze, and the delay, with no challenge open,
    /// the deposit left goes back to the principal and the bond to the agent.
    /// Anyone may call it; the destinations are fixed.
    function close(uint256 id) external {
        Delegation storage d = delegations[id];
        uint256 end = d.frozen && d.frozenAt < d.expiry ? d.frozenAt : d.expiry;
        if (d.closed || block.timestamp <= end + closeDelay) revert NotClosable();
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

    /// The terms a proof's statement carries: the unit size, the range's base
    /// and declared length, and H(s).
    function termsOf(uint256 id) external view returns (uint64, uint64, uint64, bytes32) {
        Delegation storage d = delegations[id];
        return (d.unitSize, d.rangeBase, d.rangeLen, d.secretHash);
    }

    function epochOf(uint256 id) external view returns (uint64) {
        return delegations[id].epoch;
    }

    function frozenOf(uint256 id) external view returns (bool frozen, uint32 holds) {
        return (delegations[id].frozen, delegations[id].holds);
    }

    function monitorOf(uint256 id) external view returns (address) {
        return delegations[id].monitor;
    }

    function answererOf(uint256 id) external view returns (address, uint256) {
        return (delegations[id].answerer, delegations[id].answererStake);
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
