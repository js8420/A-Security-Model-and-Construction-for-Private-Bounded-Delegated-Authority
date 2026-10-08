// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

/// Uniswap Permit2, allowance mode. Only the call the reserve makes.
interface IAllowanceTransfer {
    function transferFrom(address from, address to, uint160 amount, address token) external;
}

/// The reserve of Section V on one settlement domain.
///
/// It verifies no payment proof. It records each settlement against its payload
/// digest, publishes the shares and nullifiers, refuses a digest it has already
/// settled, an amount above the public cap, or a payment beyond the public
/// velocity bound, and moves the payment itself. Value leaves the principal
/// only through settle, so a payment that moves money always publishes shares.
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
        uint64 epoch;
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

    /// The two contracts allowed to forfeit a bond: the dispute game and the
    /// availability challenge. Set once, after all three are deployed.
    address public dispute;
    address public availability;

    mapping(uint256 => Delegation) public delegations;
    mapping(uint256 => Window) private windows;
    /// What each settled digest was settled against: the hash of the agent's
    /// blob list together with the revocation epoch in force. Non-zero means
    /// settled, so the freshness check and the record a challenge needs share
    /// one slot.
    mapping(uint256 => mapping(uint64 => bytes32)) public settled;
    /// The revocation accumulator's root at each epoch, four lanes packed.
    mapping(uint256 => mapping(uint64 => bytes32)) public rootAt;
    mapping(uint256 => mapping(uint256 => uint256)) private transcript;
    mapping(uint256 => uint256) private transcriptLen;
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
    error ZeroCommitment();
    error DepositExhausted();

    event Settled(uint256 indexed id, uint64 digest, uint64 amount, address payee);
    event Transcript(uint256 indexed id, uint64 digest, uint64[] elems);
    event BondForfeited(uint256 indexed id, address to, uint256 amount);
    event Revoked(uint256 indexed id, uint64 start, uint64 length);

    constructor(uint64 domainId, address token_, address permit2_) {
        require(domainId != 0, "domain");
        domain = domainId;
        token = IERC20(token_);
        permit2 = IAllowanceTransfer(permit2_);
        deployer = msg.sender;
    }

    function setArbiters(address dispute_, address availability_) external {
        if (msg.sender != deployer || dispute != address(0)) revert AlreadySet();
        dispute = dispute_;
        availability = availability_;
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
        bytes32 revocationRoot
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
            epoch: 0,
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
    /// domain, the payee, the amount, the digest, the shares and the proof
    /// commitment. A payee holding a signed payload therefore cannot settle it
    /// with shares of its own.
    function settle(
        uint256 id,
        address payee,
        uint64 amount,
        uint64 digest,
        uint64[] calldata elems,
        bytes32 blobsHash,
        bytes calldata signature
    ) external {
        _checkAgentSignature(id, payee, amount, digest, elems, blobsHash, signature);
        _admit(id, amount, digest, blobsHash);
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
        uint64[] calldata elems,
        bytes32 blobsHash,
        bytes calldata signature
    ) external {
        _checkAgentSignature(id, payee, amount, digest, elems, blobsHash, signature);
        _admit(id, amount, digest, blobsHash);
        emit Transcript(id, digest, elems);
        _pay(id, payee, amount);
        emit Settled(id, digest, amount, payee);
    }

    function signedDigest(
        uint256 id,
        address payee,
        uint64 amount,
        uint64 digest,
        bytes32 elemsHash,
        bytes32 blobsHash
    ) public view returns (bytes32) {
        return keccak256(
            abi.encode(block.chainid, address(this), domain, id, payee, amount, digest,
                       elemsHash, blobsHash)
        );
    }

    function _checkAgentSignature(
        uint256 id,
        address payee,
        uint64 amount,
        uint64 digest,
        uint64[] calldata elems,
        bytes32 blobsHash,
        bytes calldata signature
    ) private view {
        bytes32 h = signedDigest(id, payee, amount, digest,
                                 keccak256(abi.encodePacked(elems)), blobsHash);
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

    function _admit(uint256 id, uint64 amount, uint64 digest, bytes32 blobsHash) private {
        Delegation storage d = delegations[id];
        if (blobsHash == bytes32(0)) revert ZeroCommitment();
        if (settled[id][digest] != bytes32(0)) revert IndexAlreadySettled();
        if (amount > d.cap) revert AmountAboveCap();

        Window storage w = windows[id];
        uint64 nowTs = uint64(block.timestamp);
        if (nowTs >= w.start + d.windowW) {
            w.start = nowTs;
            w.count = 0;
        }
        if (w.count + 1 > d.velocityN) revert VelocityExceeded();
        w.count += 1;
        // The epoch is the reserve's, not the agent's: a proof against a root
        // revocation has since replaced is a proof the dispute rejects.
        settled[id][digest] = keccak256(abi.encode(blobsHash, d.epoch));
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

    /// A lost dispute, or a proof the agent would not publish when challenged.
    function forfeit(uint256 id) external {
        if (msg.sender != dispute && msg.sender != availability) revert NotArbiter();
        _forfeit(id);
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
    /// revocations.
    function revoke(uint256 id, uint64 start, uint64 length, bytes32 newRoot) external {
        Delegation storage d = delegations[id];
        if (msg.sender != d.principal) revert NotPrincipal();
        revoked[id].push([start, length]);
        uint64 e = d.epoch + 1;
        d.epoch = e;
        rootAt[id][e] = newRoot;
        emit Revoked(id, start, length);
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
