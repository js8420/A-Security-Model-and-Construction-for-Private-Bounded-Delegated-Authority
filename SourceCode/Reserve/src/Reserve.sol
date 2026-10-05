// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// The reserve of Section V, as a settlement domain would deploy it.
///
/// It verifies no payment proof. It records settlements, appends the shares and
/// nullifiers submitted with them, refuses a payload index it has already
/// settled, refuses an amount above the public cap or a payment beyond the
/// public velocity bound, and pays the bond to the principal on a secret
/// matching the committed hash.
///
/// Challenge is deliberately absent. A challenge must carry the payment proof,
/// which is over nine megabytes; there is no call data budget for it on any
/// chain, so a function taking it would not be callable and measuring one would
/// report a number nobody can pay.
contract Reserve {
    /// Field elements packed four to a word. Goldilocks elements are under
    /// 2^64, so four fit and the transcript costs a quarter of the naive
    /// layout. This is the dominant cost of a settlement and the reason the
    /// slot cover is worth choosing carefully.
    uint256 private constant PER_WORD = 4;

    struct Delegation {
        address principal;
        address agent;
        uint64 cap;
        uint64 velocityN;
        uint64 windowW;
        uint256 bond;
        bytes32 secretHash;
        bool settled;
    }

    struct Window {
        uint64 start;
        uint64 count;
    }

    mapping(uint256 => Delegation) public delegations;
    mapping(uint256 => Window) private windows;
    mapping(uint256 => mapping(uint64 => bool)) private indexSeen;
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

    event Settled(uint256 indexed id, uint64 index, uint64 amount);

    /// The transcript as log data rather than storage. Extraction only reads
    /// the shares, and nothing in the contract compares against them, so a log
    /// serves the same purpose at a fraction of the price. The cost is that a
    /// log is not readable from inside the EVM: a future contract that wanted
    /// to check a share itself could not.
    event Transcript(uint256 indexed id, uint64 index, uint64[] elems);
    event BondForfeited(uint256 indexed id, address to, uint256 amount);
    event Revoked(uint256 indexed id, uint64 start, uint64 length);

    function register(
        address agent,
        uint64 cap,
        uint64 velocityN,
        uint64 windowW,
        bytes32 secretHash
    ) external payable returns (uint256 id) {
        id = nextId++;
        delegations[id] = Delegation({
            principal: msg.sender,
            agent: agent,
            cap: cap,
            velocityN: velocityN,
            windowW: windowW,
            bond: msg.value,
            secretHash: secretHash,
            settled: false
        });
    }

    /// One payment. `elems` is the flattened transcript the payment publishes:
    /// two share elements and one nullifier per slot, every slot, padded ones
    /// included, because a padded slot must be indistinguishable from a real
    /// one to anyone reading this.
    /// Called by the payee, under the agent's signature. The signature covers
    /// the shares and the proof commitment as well as the payload, so a payee
    /// holding a signed payload cannot settle it with shares of its own: it
    /// could otherwise consume the digest, block the real settlement, and
    /// leave the agent unable to defend a commitment it never made.
    function settle(
        uint256 id,
        uint64 amount,
        uint64 index,
        uint64[] calldata elems,
        bytes32 proofCommitment,
        bytes calldata signature
    ) external {
        _checkAgentSignature(id, amount, index, elems, proofCommitment, signature);
        _admit(id, amount, index);
        _append(id, elems);
        emit Settled(id, index, amount);
    }

    /// Everything the agent is answerable for, under one signature.
    function _checkAgentSignature(
        uint256 id,
        uint64 amount,
        uint64 index,
        uint64[] calldata elems,
        bytes32 proofCommitment,
        bytes calldata signature
    ) private view {
        bytes32 digest = keccak256(
            abi.encode(block.chainid, address(this), id, amount, index,
                       keccak256(abi.encodePacked(elems)), proofCommitment)
        );
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
        address signer = ecrecover(digest, v, r, s);
        if (signer == address(0) || signer != delegations[id].agent) revert BadSignature();
    }

    /// The three refusals the interface requires, all on public values.
    function _admit(uint256 id, uint64 amount, uint64 index) private {
        Delegation storage d = delegations[id];
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
        indexSeen[id][index] = true;
    }

    /// The transcript (I2) requires: every share and nullifier the payment
    /// published, padded slots included. This dominates the cost of a
    /// settlement.
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

    /// Evidence is a secret opening the committed hash. The transfer is to the
    /// principal and not to whoever presents it: a bearer payout would let the
    /// agent reclaim its own bond by overdrawing deliberately.
    ///
    /// The hash here is keccak256. The circuit commits under the algebraic hash
    /// the proof system uses, so a deployment must evaluate that hash on chain
    /// instead, which costs more. The figure this function reports is therefore
    /// a lower bound on Claim.
    function claim(uint256 id, uint64[2] calldata secret) external {
        Delegation storage d = delegations[id];
        if (d.settled) revert BondAlreadyPaid();
        if (keccak256(abi.encodePacked(secret[0], secret[1])) != d.secretHash) {
            revert SecretDoesNotOpen();
        }
        d.settled = true;
        uint256 amount = d.bond;
        d.bond = 0;
        emit BondForfeited(id, d.principal, amount);
        payable(d.principal).transfer(amount);
    }

    /// The same settlement with the transcript emitted instead of stored.
    /// Measured against `settle` so the choice is a number rather than an
    /// assumption.
    function settleLogged(
        uint256 id,
        uint64 amount,
        uint64 index,
        uint64[] calldata elems,
        bytes32 proofCommitment,
        bytes calldata signature
    ) external {
        _checkAgentSignature(id, amount, index, elems, proofCommitment, signature);
        _admit(id, amount, index);
        emit Transcript(id, index, elems);
        emit Settled(id, index, amount);
    }

    function revoke(uint256 id, uint64 start, uint64 length) external {
        revoked[id].push([start, length]);
        emit Revoked(id, start, length);
    }

    function transcriptWords(uint256 id) external view returns (uint256) {
        return transcriptLen[id];
    }

    function revokedCount(uint256 id) external view returns (uint256) {
        return revoked[id].length;
    }
}
