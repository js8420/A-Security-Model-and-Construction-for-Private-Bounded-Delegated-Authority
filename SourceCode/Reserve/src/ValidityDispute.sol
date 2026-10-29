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
    function getL1FeeUpperBound(uint256 unsignedTxSize) external view returns (uint256);
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
/// proof, and one answer may also speak for several batches at once.
///
/// Bonds. A challenger's bond is set when the challenge opens: the price of
/// proving one answer, fixed at deployment, plus what forcing the answer in
/// through Ethereum costs at the Ethereum base fee the domain records then,
/// times a fee factor. An answer credits each challenger's bond to the agent
/// challenged, or to its answerer if it has one, whoever sends the answer, so
/// copying an answer gains nothing. No answer by the deadline credits the bond
/// back to the challenger and forfeits the agent's bond in the reserve to the
/// principal, which the principal withdraws from the reserve. Credits are
/// withdrawn, never pushed, so no recipient can block an answer or an expiry.
///
/// Cancelling. The principal, or its monitor, withdraws its own challenge or
/// request once what backs the settlement reaches it some other way, as an
/// agent that delivers late hands it the batch proof. An open challenge it
/// opened is closed, the hold lifts and the bond goes back to it: nobody
/// proves, and lateness earns the agent nothing. A challenge it joined
/// reverts to the other party's alone. An answered challenge's request is
/// withdrawn, and nothing more is due under it.
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
/// Posting costs. A principal's challenge, or its join, tops the
/// delegation's posting pool up to one posting deposit: the domain gas of one
/// batch's postings at the domain's base fee then, plus their L1 data fee,
/// times the fee factor; anyone may add more. An answer records the root of
/// the batch it proves. The receipt for that root, brought by anyone with a
/// challenge of the principal's answered under it, binds the batch to the
/// proof hash it names, once; a delivery binds it too. While a request under
/// the batch is outstanding and a delivery is due, the named answerer's
/// binding, its deliveries and its first chunks of a bound proof, as many as
/// the deployed proof has, are refunded from the pool at what including them
/// on the domain costs: the gas at the domain's base fee plus the L1 data
/// fee. A posting forced in through Ethereum is refunded the same and no
/// more: what forcing adds is the answerer's, which it pays only when the
/// sequencer leaves it out, so forcing gains it nothing. Nothing else is
/// refunded, so no one can spend the pool on postings of anything but the
/// receipted proof. If the pool runs out during a batch's refunds, that
/// batch's duty lapses and no withholding can be slashed under it; other
/// batches keep theirs. What is left once every delivery has fallen due goes
/// back to the principal. A second receipt for a bound batch with another
/// proof hash, or another sealed root, is one the answerer signed besides
/// the first, and slashes it.
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

    enum Status { None, Open, Answered, Expired, Delivered, Cancelled }

    /// `deadline` is the answer's deadline while the challenge is open, and,
    /// once the principal's challenge is answered, the delivery's.
    struct Challenge {
        address challenger;
        uint64 deadline;
        Status status;
        bool byPrincipal;
        /// The batch the answer proved, as one more than its place in the
        /// delegation's list of answered roots; zero before the answer.
        uint16 batch;
        /// The challenger's bond, set when the challenge opened.
        uint128 bond;
        /// The principal joined another party's challenge.
        bool joined;
    }

    /// A batch's posting: the proof hash and sealed root its first receipt
    /// bound, and whether its refunds ran the pool out.
    struct Batch {
        bytes32 proofHash;
        bytes32 sealedRoot;
        bool lapsed;
        /// The principal's requests under the batch not yet withdrawn.
        uint32 due;
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
    /// The chunks of the deployed batch proof with its public values,
    /// 10,365,547 bytes: the most chunks of one posting that are refunded.
    uint256 public constant MAX_CHUNKS = 106;

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
    /// The price of proving one answer, in ether, with the margin the
    /// deployment chose; also the bounty a slash pays.
    uint256 public immutable provingBond;
    /// L1 gas of forcing one answer in through Ethereum: its call data at the
    /// floor price and the portal's work, measured on a fork of Ethereum.
    uint256 public immutable forceGas;
    /// What the bond's and the deposit's fee-dependent parts are multiplied
    /// by, to cover a rise in the fee between the challenge and the answer or
    /// the postings.
    uint256 public immutable feeFactor;
    /// How long after answering the principal's challenge the sealed opening
    /// and the proof may be posted.
    uint64 public immutable deliveryWait;
    /// Domain gas of one batch's postings: the binding, the batch proof's
    /// chunks and every sealed opening.
    uint256 public immutable postingGas;
    /// Call-data bytes of the same postings, for their L1 data fee.
    uint256 public immutable postingBytes;
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
    /// The roots answers have proved under each delegation, in order.
    mapping(uint256 => bytes32[]) private answeredRoots;
    mapping(uint256 => mapping(bytes32 => uint16)) private rootPlace;
    /// Each answered batch's posting, by its root.
    mapping(uint256 => mapping(bytes32 => Batch)) private batches;
    /// The batch a bound proof hash belongs to.
    mapping(uint256 => mapping(bytes32 => bytes32)) public boundRoot;
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
    error WrongBatch();
    error AlreadyBound();
    error TooManyBatches();
    error NotCancellable();

    event Challenged(uint256 indexed id, uint64 digest, address challenger, uint64 deadline);
    event Answered(uint256 indexed id, uint64 digest);
    event Expired(uint256 indexed id, uint64 digest);
    event AnswererSlashed(uint256 indexed id, uint64 digest);
    event SealedDelivered(uint256 indexed id, uint64 digest, bytes opening);
    event ProofChunk(uint256 indexed id, bytes32 indexed proofHash, address indexed poster, uint256 index);
    event ProofPosted(uint256 indexed id, bytes32 indexed proofHash, address poster);
    event Joined(uint256 indexed id, uint64 digest, uint64 deadline);
    event PostingRefunded(uint256 indexed id, address poster, uint256 amount);
    event PostingBound(uint256 indexed id, bytes32 root, bytes32 proofHash);
    event PostingLapsed(uint256 indexed id, bytes32 root);
    event Cancelled(uint256 indexed id, uint64 digest);

    /// The deployment's windows and prices.
    struct Params {
        uint64 acceptWindow;
        uint64 answerWindow;
        uint64 slot;
        uint64 deliveryWait;
        uint256 provingBond;
        uint256 forceGas;
        uint256 feeFactor;
        uint256 postingGas;
        uint256 postingBytes;
    }

    constructor(address reserve_, address verifier_, bytes32 programVKey_, Params memory p) {
        reserve = IReserveV(reserve_);
        verifier = ISP1Verifier(verifier_);
        programVKey = programVKey_;
        acceptWindow = p.acceptWindow;
        answerWindow = p.answerWindow;
        slot = p.slot;
        deliveryWait = p.deliveryWait;
        provingBond = p.provingBond;
        forceGas = p.forceGas;
        feeFactor = p.feeFactor;
        postingGas = p.postingGas;
        postingBytes = p.postingBytes;
    }

    /// The Ethereum base fee the domain last recorded, or zero off an OP Stack chain.
    function _l1BaseFee() private view returns (uint256) {
        return L1_BLOCK.code.length != 0 ? IL1Block(L1_BLOCK).basefee() : 0;
    }

    /// The bond a challenge opened now must carry.
    function challengeBond() public view returns (uint256) {
        return provingBond + feeFactor * forceGas * _l1BaseFee();
    }

    /// What one batch's postings cost to include on the domain now, times the
    /// fee factor: what a principal's challenge keeps in the pool.
    function postingDeposit() public view returns (uint256) {
        uint256 l1 = GAS_PRICE_ORACLE.code.length != 0 ? IGasPriceOracle(GAS_PRICE_ORACLE).getL1FeeUpperBound(postingBytes) : 0;
        return feeFactor * (postingGas * block.basefee + l1);
    }

    function key(uint256 id, uint64 digest) public pure returns (bytes32) {
        return keccak256(abi.encode(id, digest));
    }

    function challengeOf(uint256 id, uint64 digest) external view returns (Challenge memory) {
        return challenges[key(id, digest)];
    }

    /// The root a challenge's answer proved, or zero before the answer.
    function answeredRoot(uint256 id, uint64 digest) public view returns (bytes32) {
        uint16 b = challenges[key(id, digest)].batch;
        return b == 0 ? bytes32(0) : answeredRoots[id][b - 1];
    }

    function batchOf(uint256 id, bytes32 root) external view returns (Batch memory) {
        return batches[id][root];
    }

    /// What a principal's challenge or join adds to the posting pool: what
    /// brings it up to one deposit.
    function postingTopUp(uint256 id) public view returns (uint256) {
        uint256 pool = postingPool[id];
        uint256 target = postingDeposit();
        return pool >= target ? 0 : target - pool;
    }

    /// Adds to a delegation's posting pool, as a principal does when the
    /// postings of more than one batch are due at once.
    function fundPosting(uint256 id) external payable {
        postingPool[id] += msg.value;
    }

    /// `s` opens the reserve's record of the settlement. The call carries the
    /// bond, and from the principal also the posting pool's top-up.
    function open(uint256 id, uint64 digest, Settlement calldata s) external payable {
        bytes32 k = key(id, digest);
        if (challenges[k].status != Status.None) revert AlreadyChallenged();
        _record(id, digest, s);
        if (block.timestamp > uint256(s.time) + acceptWindow) revert WindowClosed();
        address owner = reserve.principalOf(id);
        bool principal = msg.sender == owner || msg.sender == reserve.monitorOf(id);
        // Both prices move with the fees between a reading and the block the
        // challenge lands in, so the call may send more: a principal's excess
        // joins the posting pool, which returns what is left, and anyone
        // else's is credited back.
        uint256 topUp = principal ? postingTopUp(id) : 0;
        uint256 bond = challengeBond();
        if (msg.value < bond + topUp) revert BondTooSmall();
        uint256 extra = msg.value - bond;
        if (principal) postingPool[id] += extra;
        else if (extra != 0) credit[msg.sender] += extra;
        uint64 deadline = _next(reserve.agentOf(id), owner, principal);
        _enter(reserve.agentOf(id), owner, principal, deadline);
        challenges[k] = Challenge({
            challenger: msg.sender,
            deadline: deadline,
            status: Status.Open,
            byPrincipal: principal,
            batch: 0,
            bond: uint128(bond),
            joined: false
        });
        openCount[id] += 1;
        // The principal's challenge stops further settlement until it is
        // answered; anyone else's does not, or a stranger could halt an honest
        // agent for the price of a bond.
        if (principal) reserve.hold(id);
        emit Challenged(id, digest, msg.sender, deadline);
    }

    /// The principal, or its monitor address, joins a challenge someone else
    /// opened, within the acceptance window, topping the posting pool up as a
    /// challenge does. An open challenge then holds settlement and falls due
    /// no later than the principal's own queue would place it; the queue
    /// takes that deadline only if the challenge does. A challenge already
    /// answered stays answered, and the join is the principal's request for
    /// what backs the settlement, due within the delivery wait from the join.
    function join(uint256 id, uint64 digest, Settlement calldata s) external payable {
        Challenge storage c = challenges[key(id, digest)];
        if (c.status != Status.Open && c.status != Status.Answered) revert NotOpen();
        if (c.byPrincipal) revert AlreadyChallenged();
        _record(id, digest, s);
        if (block.timestamp > uint256(s.time) + acceptWindow) revert WindowClosed();
        address owner = reserve.principalOf(id);
        if (msg.sender != owner && msg.sender != reserve.monitorOf(id)) revert NotPrincipal();
        if (msg.value < postingTopUp(id)) revert BondTooSmall();
        postingPool[id] += msg.value;
        c.byPrincipal = true;
        c.joined = true;
        if (c.status == Status.Answered) {
            c.deadline = uint64(block.timestamp) + deliveryWait;
            if (c.deadline > dutyUntil[id]) dutyUntil[id] = c.deadline;
            batches[id][answeredRoots[id][c.batch - 1]].due += 1;
        } else {
            address agent = reserve.agentOf(id);
            uint64 d = _next(agent, owner, true);
            if (d < c.deadline) {
                c.deadline = d;
                _enter(agent, owner, true, d);
            }
            reserve.hold(id);
        }
        emit Joined(id, digest, c.deadline);
    }

    /// The principal, or its monitor, withdraws its challenge or its request
    /// before the deadline, once what backs the settlement reached it another
    /// way. Its own open challenge closes with the bond back to it and the
    /// hold lifted; a joined one goes back to being the other party's alone,
    /// still open; an answered one's request is withdrawn, so no delivery is
    /// due and no posting is refunded under it.
    function cancel(uint256 id, uint64 digest) external {
        Challenge storage c = challenges[key(id, digest)];
        if (msg.sender != reserve.principalOf(id) && msg.sender != reserve.monitorOf(id)) revert NotPrincipal();
        if (!c.byPrincipal) revert NotCancellable();
        if (block.timestamp > c.deadline) revert TooLate();
        bool joined = c.joined;
        c.byPrincipal = false;
        c.joined = false;
        if (c.status == Status.Open) {
            reserve.release(id);
            if (!joined) {
                c.status = Status.Cancelled;
                openCount[id] -= 1;
                credit[c.challenger] += c.bond;
            }
        } else if (c.status == Status.Answered || c.status == Status.Delivered) {
            batches[id][answeredRoots[id][c.batch - 1]].due -= 1;
            if (!joined) c.status = Status.Cancelled;
        } else {
            revert NotCancellable();
        }
        emit Cancelled(id, digest);
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
        bytes32 root = rootOf(id, digest, s, index, path);
        verifier.verifyProof(programVKey, abi.encodePacked(root), proof);
        _settle(c, id, digest, _place(id, root));
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
        uint256 placed;
        uint16 place;
        for (uint256 i = 0; i < n; ++i) {
            Challenge storage c = challenges[key(items[i].id, items[i].digest)];
            // A settlement named twice is answered once; the second finds it closed.
            if (c.status != Status.Open) revert NotOpen();
            // The items may span delegations; the place is per delegation.
            if (i == 0 || items[i].id != placed) {
                placed = items[i].id;
                place = _place(placed, root);
            }
            _settle(c, items[i].id, items[i].digest, place);
        }
    }

    /// One proof answering challenges against settlements of several batches,
    /// of one delegation or of many: the program verifies every batch proof
    /// and commits their roots in order, which are `roots`; `which[i]` names
    /// the root the i-th settlement's path reaches.
    function answerBatches(Item[] calldata items, uint256[] calldata which, bytes32[] calldata roots, bytes calldata proof)
        external
    {
        uint256 n = items.length;
        if (n == 0 || which.length != n) revert EmptyBatch();
        for (uint256 i = 0; i < n; ++i) {
            Item calldata it = items[i];
            _due(it.id, it.digest);
            _record(it.id, it.digest, it.s);
            if (which[i] >= roots.length || rootOf(it.id, it.digest, it.s, it.index, it.path) != roots[which[i]]) {
                revert RootMismatch();
            }
        }
        verifier.verifyProof(programVKey, abi.encodePacked(roots), proof);
        for (uint256 i = 0; i < n; ++i) _settleItem(items[i], roots[which[i]]);
    }

    function _settleItem(Item calldata it, bytes32 root) private {
        Challenge storage c = challenges[key(it.id, it.digest)];
        // A settlement named twice is answered once; the second finds it closed.
        if (c.status != Status.Open) revert NotOpen();
        _settle(c, it.id, it.digest, _place(it.id, root));
    }

    function expire(uint256 id, uint64 digest) external {
        Challenge storage c = challenges[key(id, digest)];
        if (c.status != Status.Open) revert NotOpen();
        if (block.timestamp <= c.deadline) revert TooEarly();
        c.status = Status.Expired;
        openCount[id] -= 1;
        credit[c.challenger] += c.bond;
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
        bytes32 root = boundRoot[id][proofHash];
        if (root != bytes32(0) && index < MAX_CHUNKS) _refund(id, root, g0);
    }

    /// Binds the batch a principal's answered challenge was answered under to
    /// the proof hash and sealed root its receipt names, so that the
    /// answerer's postings of that proof are refunded. Anyone may bring the
    /// receipt, within the challenge's delivery wait; a batch is bound once.
    function bindPosting(
        uint256 id,
        uint64 digest,
        Settlement calldata s,
        uint256 index,
        bytes32[] calldata path,
        Receipt calldata r
    ) external {
        gasAtStart = gasleft();
        Challenge storage c = challenges[key(id, digest)];
        if (!c.byPrincipal || (c.status != Status.Answered && c.status != Status.Delivered)) revert NotDue();
        if (block.timestamp > c.deadline) revert TooLate();
        _record(id, digest, s);
        bytes32 root = _answeredUnder(id, digest, s, index, path);
        _receipt(id, root, r);
        if (batches[id][root].proofHash != bytes32(0)) revert AlreadyBound();
        _bind(id, root, r);
        _refund(id, root, gasAtStart);
    }

    function _bind(uint256 id, bytes32 root, Receipt calldata r) private {
        Batch storage b = batches[id][root];
        b.proofHash = r.proofHash;
        b.sealedRoot = r.sealedRoot;
        if (boundRoot[id][r.proofHash] == bytes32(0)) boundRoot[id][r.proofHash] = root;
        emit PostingBound(id, root, r.proofHash);
    }

    /// The root the settlement reaches along `path`, which must be the one
    /// the answer to its challenge proved.
    function _answeredUnder(uint256 id, uint64 digest, Settlement calldata s, uint256 index, bytes32[] calldata path)
        private
        view
        returns (bytes32 root)
    {
        root = rootOf(id, digest, s, index, path);
        if (root != answeredRoot(id, digest)) revert WrongBatch();
    }

    /// Refunds the named answerer's posting for batch `root` while a request
    /// under the batch is outstanding and a delivery under the delegation is
    /// due, from the principal's pool, at what including it on the domain
    /// costs however it was included. The call data is charged as if every
    /// byte were non-zero, under EIP-7623's floor, which bounds what a
    /// transaction on the domain pays for it.
    function _refund(uint256 id, bytes32 root, uint256 g0) private {
        (address answerer, ) = reserve.answererOf(id);
        if (msg.sender != answerer || block.timestamp > dutyUntil[id] || batches[id][root].due == 0) return;
        uint256 n = msg.data.length;
        uint256 exec = g0 - gasleft() + REFUND_GAS;
        uint256 data = 16 * n + exec > 40 * n ? 16 * n + exec : 40 * n;
        uint256 fee = (21000 + data) * block.basefee;
        if (GAS_PRICE_ORACLE.code.length != 0) fee += IGasPriceOracle(GAS_PRICE_ORACLE).getL1Fee(msg.data);
        uint256 pool = postingPool[id];
        if (fee > pool) {
            fee = pool;
            if (!batches[id][root].lapsed) {
                batches[id][root].lapsed = true;
                emit PostingLapsed(id, root);
            }
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
        reserve.slashAnswerer(id, msg.sender, provingBond);
    }

    /// Posts a settlement's sealed opening after the principal's challenge of
    /// it was answered: the opening sits at the settlement's own position in
    /// the sealed tree the receipt names, so it is the one the answerer was
    /// handed for this settlement, and the receipt is for the batch the
    /// answer proved. Anyone may post it. The first delivery under a batch
    /// binds it, as `bindPosting` does.
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
        bytes32 root = _answeredUnder(id, digest, s, index, path);
        _receipt(id, root, r);
        if (_up(keccak256(opening), index, sealedPath) != r.sealedRoot) revert BadPath();
        c.status = Status.Delivered;
        deliveredUnder[k] = r.sealedRoot;
        emit SealedDelivered(id, digest, opening);
        _bindAndRefund(id, root, r);
    }

    /// Binds the batch on its first delivery, and refunds a delivery under
    /// the bound receipt.
    function _bindAndRefund(uint256 id, bytes32 root, Receipt calldata r) private {
        Batch storage b = batches[id][root];
        if (b.proofHash == bytes32(0)) _bind(id, root, r);
        if (b.proofHash == r.proofHash && b.sealedRoot == r.sealedRoot) _refund(id, root, gasAtStart);
    }

    /// Slashes the answerer that held a settlement's batch before the
    /// principal's challenge of it was answered, if by the end of the delivery
    /// wait the sealed opening or the proof its receipt names was not posted,
    /// unless that batch's refunds ran the pool out; and at any time if the
    /// opening was posted under another sealed root than the receipt's, or the
    /// batch is bound to another proof hash or sealed root than the
    /// receipt's, either of which takes a second receipt for the batch.
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
        bytes32 root = rootOf(id, digest, s, index, path);
        _receipt(id, root, r);
        if (!c.byPrincipal || (c.status != Status.Answered && c.status != Status.Delivered)) revert NotWithheld();
        Batch storage b = batches[id][root];
        bool swapped = (c.status == Status.Delivered && deliveredUnder[k] != r.sealedRoot)
            || (b.proofHash != bytes32(0) && (b.proofHash != r.proofHash || b.sealedRoot != r.sealedRoot));
        if (!swapped) {
            if (b.lapsed) revert NotWithheld();
            uint64 at = postedAt[id][r.proofHash];
            bool missing = c.status == Status.Answered || at == 0 || at > c.deadline;
            if (block.timestamp <= c.deadline || !missing) revert NotWithheld();
            if (uint256(r.receivedAt) + deliveryWait > c.deadline) revert ReceiptTooLate();
        }
        emit AnswererSlashed(id, digest);
        reserve.slashAnswerer(id, msg.sender, provingBond);
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
    function _next(address agent, address owner, bool principal) private view returns (uint64 d) {
        uint64 period = 2 * slot;
        uint64 phase = principal ? 0 : slot;
        uint64 x = uint64(block.timestamp) + answerWindow;
        uint64 last = principal ? lastPrincipalDeadline[agent][owner] : lastPublicDeadline[agent];
        if (last != 0 && last + period > x) x = last + period;
        uint64 m = x % period;
        d = m <= phase ? x + (phase - m) : x + (period - m) + phase;
    }

    /// Records `d` as the queue's latest deadline.
    function _enter(address agent, address owner, bool principal, uint64 d) private {
        if (principal) lastPrincipalDeadline[agent][owner] = d;
        else lastPublicDeadline[agent] = d;
    }

    /// One more than the place of `root` in the delegation's answered roots,
    /// adding it if it is new.
    function _place(uint256 id, bytes32 root) private returns (uint16 place) {
        place = rootPlace[id][root];
        if (place != 0) return place;
        bytes32[] storage roots = answeredRoots[id];
        if (roots.length >= type(uint16).max) revert TooManyBatches();
        roots.push(root);
        place = uint16(roots.length);
        rootPlace[id][root] = place;
    }

    function _record(uint256 id, uint64 digest, Settlement calldata s) private view {
        if (s.hash() != reserve.settled(id, digest)) revert WrongRecord();
    }

    function _due(uint256 id, uint64 digest) private view returns (Challenge storage c) {
        c = challenges[key(id, digest)];
        if (c.status != Status.Open) revert NotOpen();
        if (block.timestamp > c.deadline) revert TooLate();
    }

    function _settle(Challenge storage c, uint256 id, uint64 digest, uint16 place) private {
        c.status = Status.Answered;
        c.batch = place;
        openCount[id] -= 1;
        if (c.byPrincipal) {
            c.deadline = uint64(block.timestamp) + deliveryWait;
            if (c.deadline > dutyUntil[id]) dutyUntil[id] = c.deadline;
            batches[id][answeredRoots[id][place - 1]].due += 1;
            reserve.release(id);
        }
        (address answerer, ) = reserve.answererOf(id);
        credit[answerer != address(0) ? answerer : reserve.agentOf(id)] += c.bond;
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
