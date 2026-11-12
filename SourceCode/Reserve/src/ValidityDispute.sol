// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ISP1Verifier} from "./sp1/ISP1Verifier.sol";
import {Settlement, SettlementHash} from "./Settlement.sol";
import {BatchReceipt} from "./BatchReceipt.sol";

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
    function earmark(uint256 id, uint256 target) external;
    function payProving(uint256 id, address to, uint256 amount) external;
    function releaseEarmark(uint256 id) external returns (uint256);
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

/// The posting duty, kept in a contract of its own.
interface IPostings {
    function request(uint256 id, bytes32 root) external;
    function withdrawRequest(uint256 id, bytes32 root) external;
    function receiptSigned(uint256 id, bytes32 root, BatchReceipt calldata r) external view returns (bool);
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
/// Bonds. Anyone but the principal challenges with a bond set when the
/// challenge opens: twice the price of proving one answer, fixed at
/// deployment, plus what forcing the answer in through Ethereum costs at the
/// Ethereum base fee the domain records then, times a fee factor. An answer
/// credits that bond to the agent challenged, or to its answerer if it has
/// one, whoever sends the answer, so copying an answer gains nothing.
///
/// The principal's challenges carry no bond, and hold settlement whatever the
/// principal holds in cash. An answer to them is paid what the answer costs
/// and no more: the price of proving one batch, in the reserve's token, once
/// for each batch of the delegation it proves, and the gas the answer spent,
/// measured as it runs. The price of proving comes from the principal's own
/// funds under the delegation: each challenge has the reserve set aside, from
/// the deposit or through the Permit2 allowance, that price for every batch
/// its open challenges could fall in, one for each 256 of them and one for
/// each delivery time their signed times span, and one more, as far as those
/// funds reach; the agent could not have spent what is set aside. The gas is
/// paid from the delegation's gas pool, which each challenge tops up with
/// the answer's gas at the fee factor, so the principal's challenge takes
/// gas money alone. An agent that delivers late therefore gains nothing from the
/// principal's challenges, and an honest agent the principal challenges
/// anyway is paid back what answering cost it. What is still set aside, and
/// what the gas pool holds, go back to the principal once no challenge of
/// the principal is open.
///
/// No answer by the deadline credits a bond back to its challenger and
/// forfeits the agent's bond in the reserve to the principal, which the
/// principal withdraws from the reserve. Credits are withdrawn, never pushed,
/// so no recipient can block an answer or an expiry.
///
/// Cancelling. The principal, or its monitor, withdraws its own challenge or
/// request once what backs the settlement reaches it some other way, as an
/// agent that delivers late hands it the batch proof, one at a time or a
/// whole batch's in one call. An open challenge it opened is closed and the
/// hold lifts: nobody proves. A challenge it joined
/// reverts to the other party's alone. An answered challenge's request is
/// withdrawn, and nothing more is due under it.
///
/// Answerers. An answerer signs a receipt for each batch it holds (BatchReceipt).
/// If a challenge against a settlement in that batch then expires, and the
/// receipt left the answerer a full answer window, the receipt and the
/// settlement's path to the root burn the answerer's stake, less a bounty of
/// the proving bond to whoever brings them. A stake of at least the agent's
/// bond plus that bounty leaves a principal nothing to pay an answerer to
/// stay silent with, and burning the rest leaves nobody a reason to silence
/// one.
///
/// Joining. A settlement is challenged at most once, so a principal that
/// finds a settlement already challenged by someone else joins that
/// challenge. An open one holds settlement from then on, its deadline moves
/// into the principal's queue if that is sooner, and an answer to it carries
/// the principal's request below. An answered one carries the request from
/// the join. The principal therefore acts the same way whoever challenged
/// first, and whether or not that challenge was already answered.
///
/// Delivery. An answer to the principal's challenge is also its request for
/// what backs the settlement, which a contract of its own, Postings, holds
/// the answerer to once the principal pays the deposit for the postings
/// there. An answer to the principal's challenge, or a join of an answered
/// one, files the request; a cancel withdraws it.
///
/// The verifier is Succinct's Groth16 verifier for one circuit version,
/// called directly. Its routing gateway is not used: the gateway's owner can
/// add a route, and the prover picks the route with the first bytes of its
/// proof.
contract ValidityDispute {
    using SettlementHash for Settlement;

    enum Status { None, Open, Answered, Expired, Cancelled }

    /// `deadline` is the answer's deadline while the challenge is open, and,
    /// once the principal's challenge is answered, when the request was
    /// filed: the answer, or the join of an answered challenge.
    struct Challenge {
        address challenger;
        uint64 deadline;
        Status status;
        bool byPrincipal;
        /// The batch the answer proved, as one more than its place in the
        /// delegation's list of answered roots; zero before the answer.
        uint16 batch;
        /// The challenger's bond, set when the challenge opened; zero for the
        /// principal's, which draw on the proving pool.
        uint128 bond;
        /// The principal joined another party's challenge.
        bool joined;
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
    /// Gas an answer spends on its own, its verifier call included, and gas
    /// and call-data bytes each settlement it names adds, upper bounds from
    /// the measured batch answers; the proving pool keeps this much at the
    /// fee factor.
    uint256 public constant ANSWER_GAS = 600_000;
    uint256 public constant ITEM_GAS = 60_000;
    uint256 public constant ITEM_BYTES = 1_024;
    /// The most payments one batch proof holds.
    uint256 public constant BATCH_SIZE = 256;
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
    /// deployment chose: the bond's fixed part for anyone but the principal,
    /// and the bounty a slash pays.
    uint256 public immutable provingBond;
    /// The price of proving one answer, in the reserve's token, without
    /// margin: what an answer to the principal's challenges is paid for each
    /// batch it proves.
    uint256 public immutable provingCost;
    /// The time an honest agent has to deliver a batch from its first
    /// payment, so the batches a set of settlements can fall in is bounded by
    /// the time their signed times span.
    uint64 public immutable deliveryTime;
    /// L1 gas of forcing one answer in through Ethereum: its call data at the
    /// floor price and the portal's work, measured on a fork of Ethereum.
    uint256 public immutable forceGas;
    /// What the fee-dependent parts of a bond or a deposit are multiplied by,
    /// to cover a rise in the fee between the challenge and the answer or the
    /// postings: one for Ethereum's fee and one for the domain's, each chosen
    /// from the measured history of that fee.
    uint256 public immutable l1Factor;
    uint256 public immutable l2Factor;
    /// The least fee a bond or a deposit is sized at, so a fee that has
    /// collapsed for a moment, as after the domain halts and restarts, does
    /// not size it near zero.
    uint256 public immutable l1FeeFloor;
    uint256 public immutable l2FeeFloor;
    /// How long the answerer has to post the sealed opening and the proof once
    /// the principal pays the posting deposit, and how long after the request
    /// the principal may pay it.
    uint64 public immutable deliveryWait;
    address private constant GAS_PRICE_ORACLE = 0x420000000000000000000000000000000000000F;
    address private constant L1_BLOCK = 0x4200000000000000000000000000000000000015;
    mapping(bytes32 => Challenge) private challenges;
    /// The last deadline in each principal's queue for an agent: keyed by the
    /// agent and the delegation's principal, so neither another principal of
    /// the same agent nor a delegation the agent issues itself lengthens it.
    mapping(address => mapping(address => uint64)) public lastPrincipalDeadline;
    mapping(address => uint64) public lastPublicDeadline;
    mapping(uint256 => uint256) public openCount;
    /// The principal's open challenges under a delegation, and the challenges
    /// it has opened since its proving pool last emptied: how many, and the
    /// earliest and latest signed time among them.
    mapping(uint256 => uint256) public openByPrincipal;
    struct Episode {
        uint256 count;
        uint64 first;
        uint64 last;
    }
    mapping(uint256 => Episode) public episode;
    /// Ether the principal holds against the gas of answers to its challenges.
    mapping(uint256 => uint256) public gasPool;
    /// Whether an answer to the principal's challenges was paid the price of
    /// proving a batch, by the delegation and the batch's root.
    mapping(uint256 => mapping(bytes32 => bool)) public provingPaid;
    /// The roots answers have proved under each delegation, in order.
    mapping(uint256 => bytes32[]) private answeredRoots;
    mapping(uint256 => mapping(bytes32 => uint16)) private rootPlace;
    /// Gas left when a refunded call began, kept for the call alone, and the
    /// principal's own challenges the call has answered so far.
    uint256 private transient gasAtStart;
    uint256 private transient ownAnswered;
    mapping(address => uint256) public credit;
    /// The contract that holds the posting duty, set once by the deployer.
    IPostings public postings;
    address private immutable deployer;
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
    error NotPrincipal();
    error NothingToReturn();
    error TooManyBatches();
    error NotCancellable();

    event Challenged(uint256 indexed id, uint64 digest, address challenger, uint64 deadline);
    event Answered(uint256 indexed id, uint64 digest);
    event Expired(uint256 indexed id, uint64 digest);
    event AnswererSlashed(uint256 indexed id, uint64 digest);
    event Joined(uint256 indexed id, uint64 digest, uint64 deadline);
    event Cancelled(uint256 indexed id, uint64 digest);

    /// The deployment's windows and prices.
    struct Params {
        uint64 acceptWindow;
        uint64 answerWindow;
        uint64 slot;
        uint64 deliveryWait;
        uint64 deliveryTime;
        uint256 provingBond;
        uint256 provingCost;
        uint256 forceGas;
        uint256 l1Factor;
        uint256 l2Factor;
        uint256 l1FeeFloor;
        uint256 l2FeeFloor;
    }

    constructor(address reserve_, address verifier_, bytes32 programVKey_, Params memory p) {
        reserve = IReserveV(reserve_);
        verifier = ISP1Verifier(verifier_);
        programVKey = programVKey_;
        acceptWindow = p.acceptWindow;
        answerWindow = p.answerWindow;
        slot = p.slot;
        deliveryWait = p.deliveryWait;
        deliveryTime = p.deliveryTime;
        provingBond = p.provingBond;
        provingCost = p.provingCost;
        forceGas = p.forceGas;
        l1Factor = p.l1Factor;
        l2Factor = p.l2Factor;
        l1FeeFloor = p.l1FeeFloor;
        l2FeeFloor = p.l2FeeFloor;
        deployer = msg.sender;
    }

    /// The Ethereum base fee the domain last recorded, or zero off an OP
    /// Stack chain, and never below the floor.
    function _l1Fee() private view returns (uint256 f) {
        f = L1_BLOCK.code.length != 0 ? IL1Block(L1_BLOCK).basefee() : 0;
        if (f < l1FeeFloor) f = l1FeeFloor;
    }

    /// The domain's base fee, never below the floor.
    function _l2Fee() private view returns (uint256 f) {
        f = block.basefee;
        if (f < l2FeeFloor) f = l2FeeFloor;
    }

    function _dataFee(uint256 bytes_) private view returns (uint256) {
        return GAS_PRICE_ORACLE.code.length != 0 ? IGasPriceOracle(GAS_PRICE_ORACLE).getL1FeeUpperBound(bytes_) : 0;
    }

    /// The bond anyone but the principal must carry to open a challenge now.
    function challengeBond() public view returns (uint256) {
        return provingBond + l1Factor * forceGas * _l1Fee();
    }

    /// The batches `count` settlements whose signed times span `first` to
    /// `last` can fall in, if each batch closes only when it holds BATCH_SIZE
    /// payments or the delivery time has passed since its first: a batch
    /// closed by time starts at least that long after the one before it.
    function batchBound(uint256 count, uint64 first, uint64 last) public view returns (uint256) {
        return count / BATCH_SIZE + (last - first) / deliveryTime + 1;
    }

    /// What the gas pool must hold for the answers to `count` challenges of
    /// the principal whose signed times span `first` to `last`.
    function gasNeed(uint256 count, uint64 first, uint64 last) public view returns (uint256) {
        uint256 gas = batchBound(count, first, last) * ANSWER_GAS + count * ITEM_GAS;
        return l2Factor * (gas * _l2Fee() + _dataFee(count * ITEM_BYTES));
    }

    /// The principal's open challenges once `count` more, signed from
    /// `first` to `last`, join them: how many, and the span of their times.
    function _episode(uint256 id, uint256 count, uint64 first, uint64 last) private view returns (uint256, uint64, uint64) {
        Episode memory e = episode[id];
        if (e.count != 0) {
            if (e.first < first) first = e.first;
            if (e.last > last) last = e.last;
        }
        return (e.count + count, first, last);
    }

    /// The ether a principal's challenges against settlements signed between
    /// `first` and `last`, `count` of them, must add to the gas pool now.
    function principalPrice(uint256 id, uint256 count, uint64 first, uint64 last) public view returns (uint256) {
        (uint256 n, uint64 a, uint64 b) = _episode(id, count, first, last);
        uint256 need = gasNeed(n, a, b);
        uint256 pool = gasPool[id];
        return need > pool ? need - pool : 0;
    }

    function key(uint256 id, uint64 digest) public pure returns (bytes32) {
        return keccak256(abi.encode(id, digest));
    }

    function challengeOf(uint256 id, uint64 digest) external view returns (Challenge memory) {
        return challenges[key(id, digest)];
    }

    /// The posting contract names this one, so it is deployed after it and
    /// set here once.
    function setPostings(address p) external {
        if (msg.sender != deployer || address(postings) != address(0)) revert NotPrincipal();
        postings = IPostings(p);
    }

    /// What the posting duty reads of a challenge: its status, whether the
    /// principal holds it, its deadline, the delivery's once answered, and
    /// the root the answer proved.
    function challengeState(uint256 id, uint64 digest)
        external
        view
        returns (uint8 status, bool byPrincipal, uint64 deadline, bytes32 root)
    {
        Challenge storage c = challenges[key(id, digest)];
        return (uint8(c.status), c.byPrincipal, c.deadline, c.batch == 0 ? bytes32(0) : answeredRoots[id][c.batch - 1]);
    }

    /// Slashes a delegation's answerer for the posting duty, which alone may
    /// ask, with the slash bounty to its caller.
    function slashFor(uint256 id, address caller) external {
        if (msg.sender != address(postings)) revert NotPrincipal();
        reserve.slashAnswerer(id, caller, provingBond);
    }

    /// The root a challenge's answer proved, or zero before the answer.
    function answeredRoot(uint256 id, uint64 digest) public view returns (bytes32) {
        uint16 b = challenges[key(id, digest)].batch;
        return b == 0 ? bytes32(0) : answeredRoots[id][b - 1];
    }

    /// `s` opens the reserve's record of the settlement. Anyone but the
    /// principal sends the bond; the principal, or its monitor, sends what
    /// `principalPrice` asks for the gas pool.
    function open(uint256 id, uint64 digest, Settlement calldata s) external payable {
        address owner = reserve.principalOf(id);
        if (msg.sender == owner || msg.sender == reserve.monitorOf(id)) {
            uint64[] memory d = new uint64[](1);
            d[0] = digest;
            Settlement[] memory one = new Settlement[](1);
            one[0] = s;
            _openPrincipal(id, owner, d, one);
            return;
        }
        bytes32 k = key(id, digest);
        if (challenges[k].status != Status.None) revert AlreadyChallenged();
        _record(id, digest, s);
        if (block.timestamp > uint256(s.time) + acceptWindow) revert WindowClosed();
        // The bond moves with Ethereum's fee between a reading and the block
        // the challenge lands in, so the call may send more; the excess is
        // credited back.
        uint256 bond = challengeBond();
        if (msg.value < bond) revert BondTooSmall();
        if (msg.value > bond) credit[msg.sender] += msg.value - bond;
        address agent = reserve.agentOf(id);
        uint64 deadline = _next(agent, owner, false);
        _enter(agent, owner, false, deadline);
        challenges[k] = Challenge({
            challenger: msg.sender,
            deadline: deadline,
            status: Status.Open,
            byPrincipal: false,
            batch: 0,
            bond: uint128(bond),
            joined: false
        });
        openCount[id] += 1;
        // Anyone else's challenge does not stop settlement, or a stranger
        // could halt an honest agent for the price of a bond.
        emit Challenged(id, digest, msg.sender, deadline);
    }

    /// The principal, or its monitor, challenges many settlements of one
    /// delegation in one call, as its monitor does at a decision time.
    function openMany(uint256 id, uint64[] calldata digests, Settlement[] calldata s) external payable {
        address owner = reserve.principalOf(id);
        if (msg.sender != owner && msg.sender != reserve.monitorOf(id)) revert NotPrincipal();
        if (digests.length == 0 || digests.length != s.length) revert EmptyBatch();
        _openPrincipal(id, owner, digests, s);
    }

    /// Opens the principal's challenges, which hold settlement until each is
    /// answered, cancelled or expired. They share one deadline, later than a
    /// single challenge's by two slots for each further batch they could fall
    /// in, so an agent that proves one batch a slot meets it.
    function _openPrincipal(uint256 id, address owner, uint64[] memory digests, Settlement[] memory s) private {
        uint256 n = digests.length;
        uint64 deadline = _fundAndSchedule(id, owner, s);
        for (uint256 i = 0; i < n; ++i) {
            bytes32 k = key(id, digests[i]);
            if (challenges[k].status != Status.None) revert AlreadyChallenged();
            if (s[i].hash() != reserve.settled(id, digests[i])) revert WrongRecord();
            if (block.timestamp > uint256(s[i].time) + acceptWindow) revert WindowClosed();
            challenges[k] = Challenge({
                challenger: msg.sender,
                deadline: deadline,
                status: Status.Open,
                byPrincipal: true,
                batch: 0,
                bond: 0,
                joined: false
            });
            reserve.hold(id);
            emit Challenged(id, digests[i], msg.sender, deadline);
        }
        openCount[id] += n;
        openByPrincipal[id] += n;
    }

    /// Takes the gas of answering the principal's challenges into the gas
    /// pool, has the reserve set the price of proving them aside, and returns
    /// their deadline.
    function _fundAndSchedule(uint256 id, address owner, Settlement[] memory s) private returns (uint64 deadline) {
        uint256 n = s.length;
        uint64 first = type(uint64).max;
        uint64 last = 0;
        for (uint256 i = 0; i < n; ++i) {
            if (s[i].time < first) first = s[i].time;
            if (s[i].time > last) last = s[i].time;
        }
        // The gas price moves with the domain's fee between a reading and the
        // block the challenges land in, so the call may send more: the excess
        // joins the gas pool, which returns what is left.
        if (msg.value < principalPrice(id, n, first, last)) revert BondTooSmall();
        gasPool[id] += msg.value;
        (uint256 count, uint64 a, uint64 b) = _episode(id, n, first, last);
        episode[id] = Episode({count: count, first: a, last: b});
        reserve.earmark(id, batchBound(count, a, b) * provingCost);
        address agent = reserve.agentOf(id);
        deadline = _next(agent, owner, true);
        uint256 nb = batchBound(n, first, last);
        for (uint256 j = 1; j < nb; ++j) deadline += 2 * slot;
        _enter(agent, owner, true, deadline);
    }

    /// The principal, or its monitor address, joins a challenge someone else
    /// opened, within the acceptance window, for nothing but its gas. An open
    /// challenge then holds settlement and falls due no later than the
    /// principal's own queue would place it; the queue takes that deadline
    /// only if the challenge does. A challenge already answered stays
    /// answered, and the join is the principal's request for what backs the
    /// settlement.
    function join(uint256 id, uint64 digest, Settlement calldata s) external {
        Challenge storage c = challenges[key(id, digest)];
        if (c.status != Status.Open && c.status != Status.Answered) revert NotOpen();
        if (c.byPrincipal) revert AlreadyChallenged();
        _record(id, digest, s);
        if (block.timestamp > uint256(s.time) + acceptWindow) revert WindowClosed();
        address owner = reserve.principalOf(id);
        if (msg.sender != owner && msg.sender != reserve.monitorOf(id)) revert NotPrincipal();
        c.byPrincipal = true;
        c.joined = true;
        if (c.status == Status.Answered) {
            c.deadline = uint64(block.timestamp);
            postings.request(id, answeredRoots[id][c.batch - 1]);
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

    /// The principal, or its monitor, withdraws its challenge before its
    /// deadline, or its request before the delivery falls due, once what
    /// backs the settlement reached it another way. Its own open challenge
    /// closes with the hold lifted, and what was set aside for it waits for
    /// the principal; a joined one goes back to being the other party's
    /// alone, still open; an answered one's request is withdrawn, so no
    /// delivery is due and no posting is refunded under it.
    function cancel(uint256 id, uint64 digest) external {
        if (msg.sender != reserve.principalOf(id) && msg.sender != reserve.monitorOf(id)) revert NotPrincipal();
        _cancel(id, digest);
    }

    /// Cancels several of the principal's challenges under one delegation in
    /// one call, as a monitor does once a late batch reaches it.
    function cancelMany(uint256 id, uint64[] calldata digests) external {
        if (msg.sender != reserve.principalOf(id) && msg.sender != reserve.monitorOf(id)) revert NotPrincipal();
        for (uint256 i = 0; i < digests.length; ++i) _cancel(id, digests[i]);
    }

    function _cancel(uint256 id, uint64 digest) private {
        Challenge storage c = challenges[key(id, digest)];
        if (!c.byPrincipal) revert NotCancellable();
        bool joined = c.joined;
        c.byPrincipal = false;
        c.joined = false;
        if (c.status == Status.Open) {
            if (block.timestamp > c.deadline) revert TooLate();
            reserve.release(id);
            if (!joined) {
                c.status = Status.Cancelled;
                openCount[id] -= 1;
                _closePrincipal(id);
            }
        } else if (c.status == Status.Answered) {
            postings.withdrawRequest(id, answeredRoots[id][c.batch - 1]);
            if (!joined) c.status = Status.Cancelled;
        } else {
            revert NotCancellable();
        }
        emit Cancelled(id, digest);
    }

    /// What is left of the gas pool, and what the reserve set aside for
    /// proving, go back to the principal once none of its challenges is open.
    function returnProving(uint256 id) external {
        if (openByPrincipal[id] != 0) revert TooEarly();
        uint256 left = gasPool[id];
        gasPool[id] = 0;
        credit[reserve.principalOf(id)] += left;
        if (reserve.releaseEarmark(id) == 0 && left == 0) revert NothingToReturn();
    }

    /// One of the principal's own challenges closed. Once none is open, the
    /// next challenge sizes the pool afresh.
    function _closePrincipal(uint256 id) private {
        uint256 n = openByPrincipal[id] - 1;
        openByPrincipal[id] = n;
        if (n == 0) delete episode[id];
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
        gasAtStart = gasleft();
        Challenge storage c = _due(id, digest);
        _record(id, digest, s);
        bytes32 root = rootOf(id, digest, s, index, path);
        verifier.verifyProof(programVKey, abi.encodePacked(root), proof);
        bool own = c.byPrincipal && !c.joined;
        _settle(c, id, digest, _place(id, root));
        if (own) {
            ownAnswered = 0;
            _pay(id, _spent());
        }
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
        gasAtStart = gasleft();
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
        _reimburse(items);
    }

    /// One proof answering challenges against settlements of several batches,
    /// of one delegation or of many: the program verifies every batch proof
    /// and commits their roots in order, which are `roots`; `which[i]` names
    /// the root the i-th settlement's path reaches.
    function answerBatches(Item[] calldata items, uint256[] calldata which, bytes32[] calldata roots, bytes calldata proof)
        external
    {
        gasAtStart = gasleft();
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
        _reimburse(items);
    }

    /// Pays the gas an answer spent, measured, shared among the principal's
    /// own challenges it answered, each from its delegation's proving pool.
    function _reimburse(Item[] calldata items) private {
        uint256 own = ownAnswered;
        if (own == 0) return;
        ownAnswered = 0;
        uint256 each = _spent() / own;
        for (uint256 i = 0; i < items.length; ++i) {
            Challenge storage c = challenges[key(items[i].id, items[i].digest)];
            if (c.byPrincipal && !c.joined) _pay(items[i].id, each);
        }
    }

    /// What the call has cost its sender so far: its gas at the domain's base
    /// fee, with the call data at the floor price, and the L1 data fee.
    function _spent() private view returns (uint256 fee) {
        uint256 n = msg.data.length;
        uint256 exec = gasAtStart - gasleft() + REFUND_GAS;
        uint256 data = 16 * n + exec > 40 * n ? 16 * n + exec : 40 * n;
        fee = (21000 + data) * block.basefee;
        if (GAS_PRICE_ORACLE.code.length != 0) fee += IGasPriceOracle(GAS_PRICE_ORACLE).getL1Fee(msg.data);
    }

    /// Pays the delegation's answerer, or its agent, the answer's gas from
    /// the gas pool, as far as the pool reaches.
    function _pay(uint256 id, uint256 amount) private {
        uint256 pool = gasPool[id];
        uint256 paid = amount > pool ? pool : amount;
        if (paid == 0) return;
        gasPool[id] = pool - paid;
        credit[_payee(id)] += paid;
    }

    /// Whom an answer under the delegation pays: its answerer, or its agent.
    function _payee(uint256 id) private view returns (address) {
        (address answerer, ) = reserve.answererOf(id);
        return answerer != address(0) ? answerer : reserve.agentOf(id);
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
        if (c.byPrincipal && !c.joined) _closePrincipal(id);
        else credit[c.challenger] += c.bond;
        emit Expired(id, digest);
        if (c.byPrincipal) reserve.release(id);
        // Freezes the delegation and pays the bond if a claim has not already.
        reserve.forfeit(id);
    }

    function slashAnswerer(
        uint256 id,
        uint64 digest,
        Settlement calldata s,
        uint256 index,
        bytes32[] calldata path,
        BatchReceipt calldata r
    ) external {
        Challenge storage c = challenges[key(id, digest)];
        if (c.status != Status.Expired) revert NotExpired();
        _record(id, digest, s);
        if (uint256(r.receivedAt) + answerWindow > c.deadline) revert ReceiptTooLate();
        if (!postings.receiptSigned(id, rootOf(id, digest, s, index, path), r)) revert BadReceipt();
        emit AnswererSlashed(id, digest);
        reserve.slashAnswerer(id, msg.sender, provingBond);
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
            c.deadline = uint64(block.timestamp);
            postings.request(id, answeredRoots[id][place - 1]);
            reserve.release(id);
        }
        if (c.byPrincipal && !c.joined) {
            // The principal's own challenge: the price of proving the batch,
            // once for the delegation, from what the reserve set aside, and
            // the gas, which the caller pays.
            _closePrincipal(id);
            bytes32 root = answeredRoots[id][place - 1];
            if (!provingPaid[id][root]) {
                provingPaid[id][root] = true;
                reserve.payProving(id, _payee(id), provingCost);
            }
            ownAnswered += 1;
        } else {
            credit[_payee(id)] += c.bond;
        }
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
