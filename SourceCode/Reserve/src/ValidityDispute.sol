// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ISP1Verifier} from "./sp1/ISP1Verifier.sol";
import {Settlement, SettlementHash} from "./Settlement.sol";

interface IReserveV {
    function settled(uint256 id, uint64 digest) external view returns (bytes32);
    function agentOf(uint256 id) external view returns (address);
    function principalOf(uint256 id) external view returns (address);
    function monitorOf(uint256 id) external view returns (address);
    function answererOf(uint256 id) external view returns (address, uint256);
    function slashAnswerer(uint256 id, address caller, uint256 bounty) external;
    function forfeit(uint256 id) external;
    function hold(uint256 id) external;
    function release(uint256 id) external;
    function domain() external view returns (uint64);
    function commitmentOf(uint256 id) external view returns (bytes32);
    function rootAt(uint256 id, uint64 epoch) external view returns (bytes32);
    function termsOf(uint256 id) external view returns (uint64, uint64, uint64, bytes32);
}

/// Challenge answered by a validity proof, never by the proof itself.
///
/// A STARK proves a batch of payments, one per row, and stays off chain.
/// Within the acceptance window after a settlement, a challenger stakes a bond
/// against it. Before the deadline, anyone holding the STARK answers with one
/// SP1 Groth16 proof that the Plonky3 verifier, run inside SP1, accepts it;
/// the program commits the Keccak root of the batch's statements. The
/// statement is not taken from the answer: the contract rebuilds the
/// settlement's leaf from the reserve's records of the delegation and the
/// settlement (the digest, the revocation root at the settlement's epoch, the
/// delegation commitment, the domain, the amount paid, the payee, the signed
/// time, the unit size, the unit range, H(s), and the hash of the shares and
/// nullifiers published), hashes it up the answer's path, and checks the proof
/// against that root, so a proof of any other statement fails the pairing
/// check. A settlement whose shares its proof did not compute therefore cannot
/// be answered.
///
/// Many challenges. A settlement is challenged at most once. Each agent has
/// two deadline queues, one for its principal's challenges and one for
/// everyone else's. Deadlines in one queue are two slots apart and the two
/// queues sit on alternate slot boundaries, so no two of an agent's deadlines
/// fall in one slot: an agent that proves one answer per slot never misses
/// one, and challenges anyone else opens, the agent's own included, cannot
/// push back the principal's. One answer proves every open challenge against
/// settlements of one batch with one Groth16 proof.
///
/// Bonds. An answer credits each challenger's bond to the agent challenged,
/// or to its answerer if it has one, whoever sends the answer, so copying an
/// answer gains nothing. No answer by the deadline credits the bond back to
/// the challenger and forfeits the agent's bond in the reserve to the
/// principal. Credits are withdrawn, never pushed, so no recipient can block
/// an answer or an expiry.
///
/// Answerers. An answerer signs a receipt for each batch it holds: the
/// batch's root, the root of a tree of the payments' openings, each sealed
/// to the principal's key, in the batch's order, and the hash of the batch's
/// proof as it is posted here in chunks. If a challenge against a
/// settlement in that batch then expires, and the receipt left the answerer a
/// full answer window, the receipt and the settlement's path to the root burn
/// the answerer's stake, less a bounty of one challenger's bond to whoever
/// brings them. A stake of at least the agent's bond plus that bounty leaves
/// a principal nothing to pay an answerer to stay silent with, and burning
/// the rest leaves nobody a reason to silence one.
///
/// Delivery. An answer to the principal's challenge is also its request for
/// what backs the settlement: within the delivery wait the sealed opening
/// must be posted here, at the settlement's position in the receipted tree,
/// and the batch's proof posted here in chunks whose chained hash is the one
/// the receipt names. The proof is too large for one transaction, so each
/// chunk is a transaction of its own, and only its hash is kept. If either
/// is missing at the wait's end, or the opening posted is not the one the
/// receipt names, the receipt slashes the stake in the same way, provided
/// the answerer held it before the answer.
///
/// The verifier is Succinct's Groth16 verifier for one circuit version,
/// called directly. Its routing gateway is not used: the gateway's owner can
/// add a route, and the prover picks the route with the first bytes of its
/// proof.
contract ValidityDispute {
    using SettlementHash for Settlement;

    enum Status { None, Open, Answered, Expired, Delivered }

    /// `deadline` is the answer's deadline while the challenge is open, and,
    /// once the principal's challenge is answered, the delivery's.
    struct Challenge {
        address challenger;
        uint64 deadline;
        Status status;
        bool byPrincipal;
    }

    /// Values in a settlement's leaf: the payload digest, the revocation
    /// root's four lanes, the delegation commitment's four lanes, the domain,
    /// the amount, the payee's three limbs, the time, the unit size, the
    /// range's base and length, H(s) in four lanes, and the shares' hash in
    /// four words. Each is one 32-byte word, as abi.encodePacked writes a
    /// uint64 array.
    uint256 public constant LEAF_VALUES = 26;
    /// A batch is at most one payment per trace row.
    uint256 public constant MAX_DEPTH = 7;
    uint256 private constant LANE = 0xFFFFFFFFFFFFFFFF;
    uint256 private constant LIMB = 0xFFFFFFFFFFFFFF;

    IReserveV public immutable reserve;
    ISP1Verifier public immutable verifier;
    /// The guest program: the Plonky3 verifier with the circuit's own AIR,
    /// compiled for SP1.
    bytes32 public immutable programVKey;
    /// How long after a settlement's signed time a challenge may be opened.
    uint64 public immutable acceptWindow;
    uint64 public immutable answerWindow;
    /// What proving one answer takes, with margin.
    uint64 public immutable slot;
    uint256 public immutable challengerBond;
    /// How long after answering the principal's challenge the sealed opening
    /// and the proof may be posted.
    uint64 public immutable deliveryWait;
    /// The size of every chunk of a posted proof but the last.
    uint256 public constant CHUNK = 262144;

    mapping(bytes32 => Challenge) private challenges;
    mapping(address => uint64) public lastPrincipalDeadline;
    mapping(address => uint64) public lastPublicDeadline;
    mapping(uint256 => uint256) public openCount;
    mapping(address => uint256) public credit;
    /// The sealed-opening root a delivery was made under.
    mapping(bytes32 => bytes32) public deliveredUnder;

    /// A proof being posted by one poster: the chained hash so far, the bytes
    /// and chunks taken. Kept per poster, so nobody can spoil another's.
    struct Posting {
        bytes32 acc;
        uint64 length;
        uint32 chunks;
    }

    mapping(address => mapping(uint256 => mapping(bytes32 => Posting))) private postings;
    /// When a proof with this hash was completely posted for a delegation.
    mapping(uint256 => mapping(bytes32 => uint64)) public postedAt;

    error BondTooSmall();
    error AlreadyChallenged();
    error WrongRecord();
    error WindowClosed();
    error NotOpen();
    error TooLate();
    error TooEarly();
    error EmptyBatch();
    error BadPath();
    error RootMismatch();
    error NothingToWithdraw();
    error NotExpired();
    error BadReceipt();
    error ReceiptTooLate();
    error NotDue();
    error NotWithheld();
    error BadChunk();
    error ProofMismatch();

    event Challenged(uint256 indexed id, uint64 digest, address challenger, uint64 deadline);
    event Answered(uint256 indexed id, uint64 digest);
    event Expired(uint256 indexed id, uint64 digest);
    event AnswererSlashed(uint256 indexed id, uint64 digest);
    event SealedDelivered(uint256 indexed id, uint64 digest, bytes opening);
    event ProofChunk(uint256 indexed id, bytes32 indexed proofHash, address indexed poster, uint256 index);
    event ProofPosted(uint256 indexed id, bytes32 indexed proofHash, address poster);

    constructor(
        address reserve_,
        address verifier_,
        bytes32 programVKey_,
        uint64 acceptWindow_,
        uint64 answerWindow_,
        uint64 slot_,
        uint256 bond,
        uint64 deliveryWait_
    ) {
        reserve = IReserveV(reserve_);
        verifier = ISP1Verifier(verifier_);
        programVKey = programVKey_;
        acceptWindow = acceptWindow_;
        answerWindow = answerWindow_;
        slot = slot_;
        challengerBond = bond;
        deliveryWait = deliveryWait_;
    }

    function key(uint256 id, uint64 digest) public pure returns (bytes32) {
        return keccak256(abi.encode(id, digest));
    }

    function challengeOf(uint256 id, uint64 digest) external view returns (Challenge memory) {
        return challenges[key(id, digest)];
    }

    /// `s` opens the reserve's record of the settlement.
    function open(uint256 id, uint64 digest, Settlement calldata s) external payable {
        if (msg.value != challengerBond) revert BondTooSmall();
        bytes32 k = key(id, digest);
        if (challenges[k].status != Status.None) revert AlreadyChallenged();
        _record(id, digest, s);
        if (block.timestamp > uint256(s.time) + acceptWindow) revert WindowClosed();
        bool principal = msg.sender == reserve.principalOf(id) || msg.sender == reserve.monitorOf(id);
        uint64 deadline = _queue(reserve.agentOf(id), principal);
        challenges[k] = Challenge({challenger: msg.sender, deadline: deadline, status: Status.Open, byPrincipal: principal});
        openCount[id] += 1;
        // The principal's challenge stops further settlement until it is
        // answered; anyone else's does not, or a stranger could halt an honest
        // agent for the price of a bond.
        if (principal) reserve.hold(id);
        emit Challenged(id, digest, msg.sender, deadline);
    }

    /// `index` and `path` place the settlement's leaf in the batch the proof
    /// proves: the siblings from the leaf to the root, lowest first.
    function answer(
        uint256 id,
        uint64 digest,
        Settlement calldata s,
        uint256 index,
        bytes32[] calldata path,
        bytes calldata proof
    ) external {
        Challenge storage c = _due(id, digest);
        _record(id, digest, s);
        verifier.verifyProof(programVKey, abi.encodePacked(rootOf(id, digest, s, index, path)), proof);
        _settle(c, id, digest);
    }

    /// A challenged settlement as an answer names it: the record, and its
    /// leaf's position and path in the batch the proof proves.
    struct Item {
        uint256 id;
        uint64 digest;
        Settlement s;
        uint256 index;
        bytes32[] path;
    }

    /// One proof answering challenges against settlements of one batch. Every
    /// path must reach the same root.
    function answerBatch(Item[] calldata items, bytes calldata proof) external {
        uint256 n = items.length;
        if (n == 0) revert EmptyBatch();
        bytes32 root;
        for (uint256 i = 0; i < n; ++i) {
            Item calldata it = items[i];
            _due(it.id, it.digest);
            _record(it.id, it.digest, it.s);
            bytes32 r = rootOf(it.id, it.digest, it.s, it.index, it.path);
            if (i == 0) root = r;
            else if (r != root) revert RootMismatch();
        }
        verifier.verifyProof(programVKey, abi.encodePacked(root), proof);
        for (uint256 i = 0; i < n; ++i) {
            Challenge storage c = challenges[key(items[i].id, items[i].digest)];
            // A settlement named twice is answered once; the second finds it closed.
            if (c.status != Status.Open) revert NotOpen();
            _settle(c, items[i].id, items[i].digest);
        }
    }

    function expire(uint256 id, uint64 digest) external {
        Challenge storage c = challenges[key(id, digest)];
        if (c.status != Status.Open) revert NotOpen();
        if (block.timestamp <= c.deadline) revert TooEarly();
        c.status = Status.Expired;
        openCount[id] -= 1;
        credit[c.challenger] += challengerBond;
        emit Expired(id, digest);
        if (c.byPrincipal) reserve.release(id);
        // Freezes the delegation and pays the bond if a claim has not already.
        reserve.forfeit(id);
    }

    /// What an answerer signs on receiving a batch: the delegation, the
    /// batch's root, the root of its sealed openings, and when it received
    /// them.
    function receiptDigest(uint256 id, bytes32 root, bytes32 sealedRoot, bytes32 proofHash, uint64 receivedAt)
        public
        view
        returns (bytes32)
    {
        return keccak256(abi.encode(block.chainid, address(this), id, root, sealedRoot, proofHash, receivedAt));
    }

    /// Posts, for delegation `id`, chunk `index` of the proof whose hash is
    /// `proofHash`: every chunk
    /// CHUNK bytes, the last at most that. The hash is the chained hash of
    /// the chunks, h = keccak(h, chunk) from zero, with the total length
    /// hashed in at the end. The chunks travel in the transactions' call
    /// data, which anyone can read back; only the chained hash is stored.
    function postProof(uint256 id, bytes32 proofHash, uint256 index, bytes calldata chunk, bool last) external {
        Posting storage p = postings[msg.sender][id][proofHash];
        if (postedAt[id][proofHash] != 0 || index != p.chunks) revert BadChunk();
        if (chunk.length == 0 || chunk.length > CHUNK || (!last && chunk.length != CHUNK)) revert BadChunk();
        p.acc = keccak256(abi.encodePacked(p.acc, chunk));
        p.length += uint64(chunk.length);
        p.chunks += 1;
        emit ProofChunk(id, proofHash, msg.sender, index);
        if (last) {
            if (keccak256(abi.encodePacked(p.acc, uint256(p.length))) != proofHash) revert ProofMismatch();
            postedAt[id][proofHash] = uint64(block.timestamp);
            emit ProofPosted(id, proofHash, msg.sender);
        }
    }

    /// A receipt as the answerer signed it.
    struct Receipt {
        bytes32 sealedRoot;
        bytes32 proofHash;
        uint64 receivedAt;
        bytes signature;
    }

    function slashAnswerer(
        uint256 id,
        uint64 digest,
        Settlement calldata s,
        uint256 index,
        bytes32[] calldata path,
        Receipt calldata r
    ) external {
        Challenge storage c = challenges[key(id, digest)];
        if (c.status != Status.Expired) revert NotExpired();
        _record(id, digest, s);
        if (uint256(r.receivedAt) + answerWindow > c.deadline) revert ReceiptTooLate();
        _receipt(id, rootOf(id, digest, s, index, path), r);
        emit AnswererSlashed(id, digest);
        reserve.slashAnswerer(id, msg.sender, challengerBond);
    }

    /// Posts a settlement's sealed opening after the principal's challenge of
    /// it was answered: the opening sits at the settlement's own position in
    /// the sealed tree the receipt names, so it is the one the answerer was
    /// handed for this settlement. Anyone may post it.
    function deliver(
        uint256 id,
        uint64 digest,
        Settlement calldata s,
        uint256 index,
        bytes32[] calldata path,
        Receipt calldata r,
        bytes calldata opening,
        bytes32[] calldata sealedPath
    ) external {
        bytes32 k = key(id, digest);
        Challenge storage c = challenges[k];
        if (c.status != Status.Answered || !c.byPrincipal) revert NotDue();
        if (block.timestamp > c.deadline) revert TooLate();
        _record(id, digest, s);
        _receipt(id, rootOf(id, digest, s, index, path), r);
        if (_up(keccak256(opening), index, sealedPath) != r.sealedRoot) revert BadPath();
        c.status = Status.Delivered;
        deliveredUnder[k] = r.sealedRoot;
        emit SealedDelivered(id, digest, opening);
    }

    /// Slashes the answerer that held a settlement's batch before the
    /// principal's challenge of it was answered, if by the end of the delivery
    /// wait the sealed opening or the proof its receipt names was not posted,
    /// or if the opening was posted under another sealed root than the
    /// receipt's.
    function slashWithholding(
        uint256 id,
        uint64 digest,
        Settlement calldata s,
        uint256 index,
        bytes32[] calldata path,
        Receipt calldata r
    ) external {
        bytes32 k = key(id, digest);
        Challenge storage c = challenges[k];
        _record(id, digest, s);
        _receipt(id, rootOf(id, digest, s, index, path), r);
        if (!c.byPrincipal || (c.status != Status.Answered && c.status != Status.Delivered)) revert NotWithheld();
        bool swapped = c.status == Status.Delivered && deliveredUnder[k] != r.sealedRoot;
        if (!swapped) {
            uint64 at = postedAt[id][r.proofHash];
            bool missing = c.status == Status.Answered || at == 0 || at > c.deadline;
            if (block.timestamp <= c.deadline || !missing) revert NotWithheld();
            if (uint256(r.receivedAt) + deliveryWait > c.deadline) revert ReceiptTooLate();
        }
        emit AnswererSlashed(id, digest);
        reserve.slashAnswerer(id, msg.sender, challengerBond);
    }

    function _receipt(uint256 id, bytes32 root, Receipt calldata r) private view {
        (address answerer, ) = reserve.answererOf(id);
        if (answerer == address(0) || _signer(receiptDigest(id, root, r.sealedRoot, r.proofHash, r.receivedAt), r.signature) != answerer) {
            revert BadReceipt();
        }
    }

    function _signer(bytes32 h, bytes calldata signature) private pure returns (address) {
        if (signature.length != 65) revert BadReceipt();
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := calldataload(signature.offset)
            s := calldataload(add(signature.offset, 32))
            v := byte(0, calldataload(add(signature.offset, 64)))
        }
        if (uint256(s) > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0) revert BadReceipt();
        return ecrecover(h, v, r, s);
    }

    function withdraw() external {
        uint256 amount = credit[msg.sender];
        if (amount == 0) revert NothingToWithdraw();
        credit[msg.sender] = 0;
        (bool ok, ) = payable(msg.sender).call{value: amount}("");
        require(ok, "withdraw");
    }

    /// The next deadline in one of the agent's two queues: at least the answer
    /// window away, at least two slots after that queue's previous deadline,
    /// and on that queue's own slot boundaries, even ones for the principal
    /// and odd ones for everyone else.
    function _queue(address agent, bool principal) private returns (uint64 d) {
        uint64 period = 2 * slot;
        uint64 phase = principal ? 0 : slot;
        uint64 x = uint64(block.timestamp) + answerWindow;
        uint64 last = principal ? lastPrincipalDeadline[agent] : lastPublicDeadline[agent];
        if (last != 0 && last + period > x) x = last + period;
        uint64 m = x % period;
        d = m <= phase ? x + (phase - m) : x + (period - m) + phase;
        if (principal) lastPrincipalDeadline[agent] = d;
        else lastPublicDeadline[agent] = d;
    }

    function _record(uint256 id, uint64 digest, Settlement calldata s) private view {
        if (s.hash() != reserve.settled(id, digest)) revert WrongRecord();
    }

    function _due(uint256 id, uint64 digest) private view returns (Challenge storage c) {
        c = challenges[key(id, digest)];
        if (c.status != Status.Open) revert NotOpen();
        if (block.timestamp > c.deadline) revert TooLate();
    }

    function _settle(Challenge storage c, uint256 id, uint64 digest) private {
        c.status = Status.Answered;
        openCount[id] -= 1;
        if (c.byPrincipal) {
            c.deadline = uint64(block.timestamp) + deliveryWait;
            reserve.release(id);
        }
        (address answerer, ) = reserve.answererOf(id);
        credit[answerer != address(0) ? answerer : reserve.agentOf(id)] += challengerBond;
        emit Answered(id, digest);
    }

    /// The root a settlement's leaf reaches along `path` from position
    /// `index`. An inner node is the Keccak hash of its two children.
    function rootOf(uint256 id, uint64 digest, Settlement calldata s, uint256 index, bytes32[] calldata path)
        public
        view
        returns (bytes32 h)
    {
        h = _up(leafHash(id, digest, s), index, path);
    }

    /// The root `leaf` reaches along `path` from position `index`.
    function _up(bytes32 leaf_, uint256 index, bytes32[] calldata path) private pure returns (bytes32 h) {
        uint256 depth = path.length;
        if (depth > MAX_DEPTH || index >> depth != 0) revert BadPath();
        h = leaf_;
        for (uint256 j = 0; j < depth; ++j) {
            h = (index >> j) & 1 == 0 ? keccak256(abi.encodePacked(h, path[j])) : keccak256(abi.encodePacked(path[j], h));
        }
    }

    /// The hash of the settlement's leaf, rebuilt from the reserve's records.
    function leafHash(uint256 id, uint64 digest, Settlement calldata s) public view returns (bytes32) {
        return keccak256(abi.encodePacked(leaf(id, digest, s)));
    }

    function leaf(uint256 id, uint64 digest, Settlement calldata s) public view returns (uint256[LEAF_VALUES] memory v) {
        uint256 root = uint256(reserve.rootAt(id, s.epoch));
        uint256 com = uint256(reserve.commitmentOf(id));
        v[0] = digest;
        for (uint256 j = 0; j < 4; ++j) {
            v[1 + j] = (root >> (64 * j)) & LANE;
            v[5 + j] = (com >> (64 * j)) & LANE;
        }
        v[9] = reserve.domain();
        v[10] = s.amount;
        uint256 a = uint160(s.payee);
        v[11] = a & LIMB;
        v[12] = (a >> 56) & LIMB;
        v[13] = a >> 112;
        v[14] = s.time;
        _terms(v, id);
        uint256 h = uint256(s.elems);
        for (uint256 j = 0; j < 4; ++j) v[22 + j] = (h >> (192 - 64 * j)) & LANE;
    }

    function _terms(uint256[LEAF_VALUES] memory v, uint256 id) private view {
        (uint64 unit, uint64 base, uint64 len, bytes32 hs) = reserve.termsOf(id);
        v[15] = unit;
        v[16] = base;
        v[17] = len;
        for (uint256 j = 0; j < 4; ++j) v[18 + j] = (uint256(hs) >> (64 * j)) & LANE;
    }
}
