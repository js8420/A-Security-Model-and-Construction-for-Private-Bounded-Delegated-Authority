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

/// OP Stack predeploys: the L1 data fee of a transaction's call data, and the
/// Ethereum base fee the domain last recorded.
interface IGasPriceOracle {
    function getL1Fee(bytes memory data) external view returns (uint256);
}

interface IL1Block {
    function basefee() external view returns (uint256);
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
/// Many challenges. A settlement is challenged at most once. Each agent has a
/// deadline queue for each principal it serves, which that principal's
/// challenges and its monitor's enter, and one for everyone else's.
/// Deadlines in one queue are two slots apart, and the principals' queues and
/// the other sit on alternate slot boundaries, so an agent that proves one
/// answer per slot for each principal and one more never misses one, and
/// challenges anyone else opens, the agent's own and those of its other
/// principals included, cannot push back a principal's. One answer proves
/// every open challenge against settlements of one batch with one Groth16
/// proof.
///
/// Bonds. An answer credits each challenger's bond to the agent challenged,
/// or to its answerer if it has one, whoever sends the answer, so copying an
/// answer gains nothing. No answer by the deadline credits the bond back to
/// the challenger and forfeits the agent's bond in the reserve to the
/// principal, which the principal withdraws from the reserve. Credits are
/// withdrawn, never pushed, so no recipient can block an answer or an expiry.
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
/// Joining. A settlement is challenged at most once, so a principal that
/// finds a settlement already challenged by someone else joins that
/// challenge. An open one holds settlement from then on, its deadline moves
/// into the principal's queue if that is sooner, and an answer to it carries
/// the principal's request below. An answered one carries the request from
/// the join. The principal therefore acts the same way whoever challenged
/// first, and whether or not that challenge was already answered.
///
/// Posting costs. A principal's challenge, or its join, carries a posting
/// deposit into the delegation's pool. While a delivery is due, the named
/// answerer's postings are refunded from the pool at the gas they cost: on
/// the domain at its base fee plus the L1 data fee, and for a posting forced
/// in through Ethereum, its call data and the portal's work at the Ethereum
/// base fee the domain records. If the pool runs out the duty lapses and no
/// withholding can be slashed; what is left once every delivery has fallen
/// due goes back to the principal. Which refund applies turns on the gas
/// price, so the answerer estimates gas at the price it pays: an estimate at
/// a zero price takes the branch of a forced posting and comes out low.
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
    uint256 public constant MAX_DEPTH = 8;
    uint256 private constant LANE = 0xFFFFFFFFFFFFFFFF;
    uint256 private constant LIMB = 0xFFFFFFFFFFFFFF;
    /// Gas the refund itself spends after it measures, an upper bound.
    uint256 private constant REFUND_GAS = 40_000;

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
    /// What a principal's challenge adds to the delegation's posting pool.
    uint256 public immutable postingDeposit;
    /// L1 gas of the portal's work for one forced posting, beyond its call
    /// data: measured on a fork of Ethereum, set at deployment.
    uint256 public immutable depositGas;
    address private constant GAS_PRICE_ORACLE = 0x420000000000000000000000000000000000000F;
    address private constant L1_BLOCK = 0x4200000000000000000000000000000000000015;
    /// The size of every chunk of a posted proof but the last.
    /// 96 KiB: a chunk's transaction stays below the 128 KiB a node's
    /// transaction pool admits and the 120,000 bytes of call data an OP Stack
    /// portal admits in a deposit, so a posting can be forced in through L1.
    uint256 public constant CHUNK = 98304;

    mapping(bytes32 => Challenge) private challenges;
    /// The last deadline in each principal's queue for an agent: keyed by the
    /// agent and the delegation's principal, so neither another principal of
    /// the same agent nor a delegation the agent issues itself lengthens it.
    mapping(address => mapping(address => uint64)) public lastPrincipalDeadline;
    mapping(address => uint64) public lastPublicDeadline;
    mapping(uint256 => uint256) public openCount;
    /// Posting deposits a delegation's principal has paid in and not yet spent.
    mapping(uint256 => uint256) public postingPool;
    /// The latest delivery deadline under a delegation.
    mapping(uint256 => uint64) public dutyUntil;
    /// Whether a refund found the pool empty while a delivery was due.
    mapping(uint256 => bool) public postingLapsed;
    /// Gas left when a refunded call began, kept for the call alone.
    uint256 private transient gasAtStart;
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
    error NotPrincipal();
    error NothingToReturn();

    event Challenged(uint256 indexed id, uint64 digest, address challenger, uint64 deadline);
    event Answered(uint256 indexed id, uint64 digest);
    event Expired(uint256 indexed id, uint64 digest);
    event AnswererSlashed(uint256 indexed id, uint64 digest);
    event SealedDelivered(uint256 indexed id, uint64 digest, bytes opening);
    event ProofChunk(uint256 indexed id, bytes32 indexed proofHash, address indexed poster, uint256 index);
    event ProofPosted(uint256 indexed id, bytes32 indexed proofHash, address poster);
    event Joined(uint256 indexed id, uint64 digest, uint64 deadline);
    event PostingRefunded(uint256 indexed id, address poster, uint256 amount);

    constructor(
        address reserve_,
        address verifier_,
        bytes32 programVKey_,
        uint64 acceptWindow_,
        uint64 answerWindow_,
        uint64 slot_,
        uint256 bond,
        uint64 deliveryWait_,
        uint256 postingDeposit_,
        uint256 depositGas_
    ) {
        reserve = IReserveV(reserve_);
        verifier = ISP1Verifier(verifier_);
        programVKey = programVKey_;
        acceptWindow = acceptWindow_;
        answerWindow = answerWindow_;
        slot = slot_;
        challengerBond = bond;
        deliveryWait = deliveryWait_;
        postingDeposit = postingDeposit_;
        depositGas = depositGas_;
    }

    function key(uint256 id, uint64 digest) public pure returns (bytes32) {
        return keccak256(abi.encode(id, digest));
    }

    function challengeOf(uint256 id, uint64 digest) external view returns (Challenge memory) {
        return challenges[key(id, digest)];
    }

    /// `s` opens the reserve's record of the settlement.
    function open(uint256 id, uint64 digest, Settlement calldata s) external payable {
        bytes32 k = key(id, digest);
        if (challenges[k].status != Status.None) revert AlreadyChallenged();
        _record(id, digest, s);
        if (block.timestamp > uint256(s.time) + acceptWindow) revert WindowClosed();
        address owner = reserve.principalOf(id);
        bool principal = msg.sender == owner || msg.sender == reserve.monitorOf(id);
        if (msg.value != challengerBond + (principal ? postingDeposit : 0)) revert BondTooSmall();
        if (principal) postingPool[id] += postingDeposit;
        uint64 deadline = _queue(reserve.agentOf(id), owner, principal);
        challenges[k] = Challenge({challenger: msg.sender, deadline: deadline, status: Status.Open, byPrincipal: principal});
        openCount[id] += 1;
        // The principal's challenge stops further settlement until it is
        // answered; anyone else's does not, or a stranger could halt an honest
        // agent for the price of a bond.
        if (principal) reserve.hold(id);
        emit Challenged(id, digest, msg.sender, deadline);
    }

    /// The principal, or its monitor address, joins a challenge someone else
    /// opened, within the acceptance window, with a posting deposit. An open
    /// challenge then holds settlement and falls due no later than the
    /// principal's own queue would place it. A challenge already answered
    /// stays answered, and the join is the principal's request for what backs
    /// the settlement, due within the delivery wait from the join.
    function join(uint256 id, uint64 digest, Settlement calldata s) external payable {
        Challenge storage c = challenges[key(id, digest)];
        if (c.status != Status.Open && c.status != Status.Answered) revert NotOpen();
        if (c.byPrincipal) revert AlreadyChallenged();
        _record(id, digest, s);
        if (block.timestamp > uint256(s.time) + acceptWindow) revert WindowClosed();
        address owner = reserve.principalOf(id);
        if (msg.sender != owner && msg.sender != reserve.monitorOf(id)) revert NotPrincipal();
        if (msg.value != postingDeposit) revert BondTooSmall();
        postingPool[id] += postingDeposit;
        c.byPrincipal = true;
        if (c.status == Status.Answered) {
            c.deadline = uint64(block.timestamp) + deliveryWait;
            if (c.deadline > dutyUntil[id]) dutyUntil[id] = c.deadline;
        } else {
            uint64 d = _queue(reserve.agentOf(id), owner, true);
            if (d < c.deadline) c.deadline = d;
            reserve.hold(id);
        }
        emit Joined(id, digest, c.deadline);
    }

    /// What is left of the posting pool goes back to the principal once no
    /// delivery under the delegation is still due.
    function returnPosting(uint256 id) external {
        if (block.timestamp <= dutyUntil[id]) revert TooEarly();
        if (openCount[id] != 0) revert TooEarly();
        uint256 left = postingPool[id];
        if (left == 0) revert NothingToReturn();
        postingPool[id] = 0;
        credit[reserve.principalOf(id)] += left;
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
    /// batch's root, the root of its sealed openings, the hash of the batch
    /// proof, and when it received them.
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
        uint256 g0 = gasleft();
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
        _refund(id, g0);
    }

    /// Refunds the named answerer's posting while a delivery under the
    /// delegation is due, from the principal's pool. The call data is
    /// charged as if every byte were non-zero, under EIP-7623's floor, which
    /// bounds what the transaction paid for it.
    function _refund(uint256 id, uint256 g0) private {
        (address answerer, ) = reserve.answererOf(id);
        if (msg.sender != answerer || block.timestamp > dutyUntil[id]) return;
        uint256 n = msg.data.length;
        uint256 fee;
        if (tx.gasprice != 0) {
            uint256 exec = g0 - gasleft() + REFUND_GAS;
            uint256 data = 16 * n + exec > 40 * n ? 16 * n + exec : 40 * n;
            fee = (21000 + data) * block.basefee;
            if (GAS_PRICE_ORACLE.code.length != 0) fee += IGasPriceOracle(GAS_PRICE_ORACLE).getL1Fee(msg.data);
        } else if (L1_BLOCK.code.length != 0) {
            // A deposit forced in through Ethereum pays no gas on the domain.
            fee = (21000 + 40 * n + depositGas) * IL1Block(L1_BLOCK).basefee();
        }
        uint256 pool = postingPool[id];
        if (fee > pool) {
            fee = pool;
            postingLapsed[id] = true;
        }
        postingPool[id] = pool - fee;
        credit[msg.sender] += fee;
        emit PostingRefunded(id, msg.sender, fee);
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
        gasAtStart = gasleft();
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
        _refund(id, gasAtStart);
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
            if (postingLapsed[id]) revert NotWithheld();
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
    function _queue(address agent, address owner, bool principal) private returns (uint64 d) {
        uint64 period = 2 * slot;
        uint64 phase = principal ? 0 : slot;
        uint64 x = uint64(block.timestamp) + answerWindow;
        uint64 last = principal ? lastPrincipalDeadline[agent][owner] : lastPublicDeadline[agent];
        if (last != 0 && last + period > x) x = last + period;
        uint64 m = x % period;
        d = m <= phase ? x + (phase - m) : x + (period - m) + phase;
        if (principal) lastPrincipalDeadline[agent][owner] = d;
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
            if (c.deadline > dutyUntil[id]) dutyUntil[id] = c.deadline;
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
