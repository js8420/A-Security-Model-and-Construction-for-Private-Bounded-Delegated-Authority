// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Settlement, SettlementHash} from "./Settlement.sol";
import {BatchReceipt} from "./BatchReceipt.sol";

interface IReserveP {
    function settled(uint256 id, uint64 digest) external view returns (bytes32);
    function answererOf(uint256 id) external view returns (address, uint256);
    function principalOf(uint256 id) external view returns (address);
}

/// What the posting duty reads of the dispute contract, and the one thing it
/// asks of it: to slash an answerer, which only the dispute contract may do.
interface IDisputeP {
    function challengeState(uint256 id, uint64 digest)
        external
        view
        returns (uint8 status, bool byPrincipal, uint64 deadline, bytes32 root);
    function rootOf(uint256 id, uint64 digest, Settlement calldata s, uint256 index, bytes32[] calldata path)
        external
        view
        returns (bytes32);
    function slashFor(uint256 id, address caller) external;
}

interface IGasPriceOracleP {
    function getL1Fee(bytes memory data) external view returns (uint256);
    function getL1FeeUpperBound(uint256 unsignedTxSize) external view returns (uint256);
}

interface IL2Messenger {
    function xDomainMessageSender() external view returns (address);
}

/// The answerer's duty to post what backs a principal's challenged
/// settlements, and the principal's deposit that pays for the postings.
///
/// An answer to the principal's challenge is also its request for what backs
/// the settlement. Within the delivery wait the answerer posts the batch's
/// proof and the settlement's sealed opening, at the settlement's position in
/// the tree its receipt names, one of two ways. On the domain: the opening by
/// `deliver`, and the proof in chunks of at most 96 KiB, each a transaction,
/// whose chained hash is the receipt's proof hash. Or on Ethereum: the proof
/// and every opening of the batch as blobs, recorded by the BlobPosting
/// contract there, whose message, a deposit the domain must include, gives
/// their chained hash, which is the receipt's blobs hash. If neither is done
/// by the wait's end, or what was posted is not what the receipt names, the
/// receipt slashes the answerer's stake, provided the answerer held it before
/// the answer.
///
/// Paying for the postings. A request costs the principal nothing when it is
/// filed. The duty starts when the principal, or anyone, pays the batch's
/// posting pool up to one posting deposit, which it may do within the
/// delivery wait of the latest request under the batch: what posting the
/// batch on the domain costs at the domain's fees then, at its fee factor,
/// and never below the fee floor. The delivery is then due within the
/// delivery wait. A request never paid for lapses: nothing is due under it.
/// A receipt binds its batch to the hashes it names, once. While a request
/// under the batch is outstanding and its delivery is due, the named
/// answerer's postings of what the receipt names are refunded from the
/// batch's pool at what they cost: on the domain at its base fee with the
/// call data at the floor price, plus the L1 data fee; on Ethereum at what
/// the BlobPosting contract measured, the blob gas at the blob base fee and
/// the calls' gas at the base fee, but never more, with what the batch was
/// already refunded, than posting it on the domain costs when the report
/// arrives. The blob way is for when the domain will not include the
/// answerer's postings; when it costs more than the domain way, the answerer
/// bears the excess, so the route it picks cannot drain the pool beyond what
/// the deposit was sized to. Once blobs were reported posted for a batch, no
/// later domain posting of it is refunded. A blob posting counts from the
/// Ethereum block it was made in, since its report may wait up to the
/// domain's inclusion wait; a withholding is slashed, and the pool returned,
/// only once that wait has passed too. If the pool cannot pay a blob refund,
/// that batch's duty lapses and no withholding can be slashed under it; a
/// shortfall on the domain lapses nothing, since the blob way remains.
/// Nothing else is refunded. What is left once the delivery is no longer due
/// goes back to the principal.
contract Postings {
    using SettlementHash for Settlement;

    uint8 private constant ANSWERED = 2;
    uint8 private constant EXPIRED = 3;

    /// A batch's posting: what its first receipt bound, whether its blob
    /// refunds ran the pool out, the principal's requests under it not yet
    /// withdrawn, when the latest was filed, when the postings were last
    /// paid for, when the delivery is due once paid for (zero before), the
    /// pool that pays for it and what it has refunded.
    struct Batch {
        bytes32 proofHash;
        bytes32 sealedRoot;
        bytes32 blobsHash;
        bool lapsed;
        uint32 due;
        uint64 requestedAt;
        uint64 paidAt;
        uint64 until;
        uint256 pool;
        uint256 refunded;
    }

    /// A proof being posted on the domain by one poster: the chained hash so
    /// far, the bytes and the chunks taken.
    struct Posting {
        bytes32 acc;
        uint64 length;
        uint32 chunks;
    }

    /// The deployment's prices for posting one batch.
    struct Params {
        /// Domain gas and call-data bytes of one batch's postings on the domain.
        uint256 postingGas;
        uint256 postingBytes;
        /// The fee factor for the domain's base fee, and the floor it is
        /// read at.
        uint256 l2Factor;
        uint256 l2FeeFloor;
        /// The domain's messenger from Ethereum.
        address messenger;
        /// How long after an Ethereum block the domain must include a deposit
        /// made in it, whatever its sequencer does: its sequencing window.
        uint64 inclusionWait;
    }

    /// 96 KiB: a chunk's transaction stays below the 128 KiB a node's
    /// transaction pool admits and the 120,000 bytes of call data an OP Stack
    /// portal admits in a deposit.
    uint256 public constant CHUNK = 98304;
    /// The chunks of the deployed batch proof with its public values,
    /// 10,365,547 bytes: the most chunks of one posting that are refunded.
    uint256 public constant MAX_CHUNKS = 106;
    /// Gas the refund itself spends after it measures, an upper bound.
    uint256 private constant REFUND_GAS = 40_000;
    address private constant GAS_PRICE_ORACLE = 0x420000000000000000000000000000000000000F;

    IReserveP public immutable reserve;
    IDisputeP public immutable dispute;
    uint256 public immutable postingGas;
    uint256 public immutable postingBytes;
    uint256 public immutable l2Factor;
    uint256 public immutable l2FeeFloor;
    address public immutable messenger;
    uint64 public immutable inclusionWait;
    /// The BlobPosting contract on Ethereum, set once by the deployer.
    address public blobPoster;
    address private immutable deployer;

    mapping(uint256 => mapping(bytes32 => Batch)) private batches;
    /// The batch a bound proof hash belongs to.
    mapping(uint256 => mapping(bytes32 => bytes32)) public boundRoot;
    mapping(address => mapping(uint256 => mapping(bytes32 => Posting))) private postings;
    /// When a proof with this hash was completely posted on the domain for a
    /// delegation, and when blobs with this hash were reported posted.
    mapping(uint256 => mapping(bytes32 => uint64)) public postedAt;
    mapping(uint256 => mapping(bytes32 => uint64)) public blobsPostedAt;
    /// The sealed-opening root a settlement's delivery was made under.
    mapping(bytes32 => bytes32) public deliveredUnder;
    mapping(address => uint256) public credit;
    uint256 private transient gasAtStart;

    error NotDispute();
    error NotDue();
    error TooLate();
    error TooEarly();
    error WrongRecord();
    error WrongBatch();
    error BadPath();
    error BadReceipt();
    error ReceiptTooLate();
    error NotWithheld();
    error BadChunk();
    error ProofMismatch();
    error AlreadyBound();
    error NothingToReturn();
    error NothingToWithdraw();
    error NotMessenger();
    error AlreadySet();
    error DepositTooSmall();

    event SealedDelivered(uint256 indexed id, uint64 digest, bytes opening);
    event ProofChunk(uint256 indexed id, bytes32 indexed proofHash, address indexed poster, uint256 index);
    event ProofPosted(uint256 indexed id, bytes32 indexed proofHash, address poster);
    event BlobsPosted(uint256 indexed id, bytes32 indexed root, bytes32 blobsHash, address poster);
    event PostingRefunded(uint256 indexed id, address poster, uint256 amount);
    event PostingBound(uint256 indexed id, bytes32 root, bytes32 proofHash);
    event PostingLapsed(uint256 indexed id, bytes32 root);
    event PostingPaid(uint256 indexed id, bytes32 root, uint64 until);
    event AnswererSlashed(uint256 indexed id, uint64 digest);

    constructor(address reserve_, address dispute_, Params memory p) {
        reserve = IReserveP(reserve_);
        dispute = IDisputeP(dispute_);
        postingGas = p.postingGas;
        postingBytes = p.postingBytes;
        l2Factor = p.l2Factor;
        l2FeeFloor = p.l2FeeFloor;
        messenger = p.messenger;
        inclusionWait = p.inclusionWait;
        deployer = msg.sender;
    }

    /// The BlobPosting contract is deployed on Ethereum after this one,
    /// since it names this one, so its address is set once afterwards.
    function setBlobPoster(address poster) external {
        if (msg.sender != deployer || blobPoster != address(0)) revert AlreadySet();
        blobPoster = poster;
    }

    modifier onlyDispute() {
        if (msg.sender != address(dispute)) revert NotDispute();
        _;
    }

    /// What posting one batch on the domain costs at the domain's fees now.
    function domainCost() public view returns (uint256 fee) {
        fee = postingGas * block.basefee;
        if (GAS_PRICE_ORACLE.code.length != 0) fee += IGasPriceOracleP(GAS_PRICE_ORACLE).getL1FeeUpperBound(postingBytes);
    }

    /// The posting deposit: what posting one batch on the domain costs now,
    /// with the base fee read no lower than its floor, times the fee factor.
    function postingDeposit() public view returns (uint256) {
        uint256 data = GAS_PRICE_ORACLE.code.length != 0 ? IGasPriceOracleP(GAS_PRICE_ORACLE).getL1FeeUpperBound(postingBytes) : 0;
        uint256 fee = block.basefee < l2FeeFloor ? l2FeeFloor : block.basefee;
        return l2Factor * (postingGas * fee + data);
    }

    /// What brings a batch's pool up to one deposit.
    function postingTopUp(uint256 id, bytes32 root) public view returns (uint256) {
        uint256 pool = batches[id][root].pool;
        uint256 target = postingDeposit();
        return pool >= target ? 0 : target - pool;
    }

    /// A principal's challenge answered under `root`, or joined once
    /// answered: a request, which binds the answerer once paid for.
    function request(uint256 id, bytes32 root) external onlyDispute {
        Batch storage b = batches[id][root];
        b.due += 1;
        b.requestedAt = uint64(block.timestamp);
    }

    /// Pays for the postings of batch `root`, within the delivery wait of
    /// the latest request under it: the pool must then hold one deposit, and
    /// the delivery falls due within the delivery wait from now. Anyone may
    /// pay; what is left goes back to the principal.
    function payPosting(uint256 id, bytes32 root) external payable {
        Batch storage b = batches[id][root];
        uint64 wait = IDisputeWait(address(dispute)).deliveryWait();
        if (b.due == 0) revert NotDue();
        if (block.timestamp > uint256(b.requestedAt) + wait) revert TooLate();
        uint256 pool = b.pool + msg.value;
        if (pool < postingDeposit()) revert DepositTooSmall();
        b.pool = pool;
        b.paidAt = uint64(block.timestamp);
        uint64 until = uint64(block.timestamp) + wait;
        if (until > b.until) b.until = until;
        emit PostingPaid(id, root, b.until);
    }

    /// The principal withdrew a request under `root`, before its delivery
    /// fell due.
    function withdrawRequest(uint256 id, bytes32 root) external onlyDispute {
        Batch storage b = batches[id][root];
        if (b.until != 0 && block.timestamp > b.until) revert TooLate();
        b.due -= 1;
    }

    function batchOf(uint256 id, bytes32 root) external view returns (Batch memory) {
        return batches[id][root];
    }

    /// What is left of a batch's pool goes back to the principal once its
    /// delivery is no longer due, and every report of blobs posted on
    /// Ethereum in time has reached the domain.
    function returnPosting(uint256 id, bytes32 root) external {
        Batch storage b = batches[id][root];
        if (block.timestamp <= uint256(b.until) + inclusionWait) revert TooEarly();
        uint256 left = b.pool;
        if (left == 0) revert NothingToReturn();
        b.pool = 0;
        credit[reserve.principalOf(id)] += left;
    }

    /// What an answerer signs on receiving a batch.
    function receiptDigest(uint256 id, bytes32 root, bytes32 sealedRoot, bytes32 proofHash, bytes32 blobsHash, uint64 receivedAt)
        public
        view
        returns (bytes32)
    {
        return keccak256(abi.encode(block.chainid, address(this), id, root, sealedRoot, proofHash, blobsHash, receivedAt));
    }

    /// Whether the delegation's named answerer signed this receipt for `root`.
    function receiptSigned(uint256 id, bytes32 root, BatchReceipt calldata r) public view returns (bool) {
        (address answerer, ) = reserve.answererOf(id);
        return answerer != address(0)
            && _signer(receiptDigest(id, root, r.sealedRoot, r.proofHash, r.blobsHash, r.receivedAt), r.signature) == answerer;
    }

    function _receipt(uint256 id, bytes32 root, BatchReceipt calldata r) private view {
        if (!receiptSigned(id, root, r)) revert BadReceipt();
    }

    function _signer(bytes32 h, bytes calldata signature) private pure returns (address) {
        if (signature.length != 65) return address(0);
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := calldataload(signature.offset)
            s := calldataload(add(signature.offset, 32))
            v := byte(0, calldataload(add(signature.offset, 64)))
        }
        if (uint256(s) > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0) return address(0);
        return ecrecover(h, v, r, s);
    }

    function _key(uint256 id, uint64 digest) private pure returns (bytes32) {
        return keccak256(abi.encode(id, digest));
    }

    function _record(uint256 id, uint64 digest, Settlement calldata s) private view {
        if (s.hash() != reserve.settled(id, digest)) revert WrongRecord();
    }

    /// The challenge of a principal's that was answered, whose delivery has
    /// not fallen due yet, and the root its answer proved.
    function _due(uint256 id, uint64 digest) private view returns (bytes32 root) {
        (uint8 status, bool byPrincipal, , bytes32 r) = dispute.challengeState(id, digest);
        if (status != ANSWERED || !byPrincipal) revert NotDue();
        uint64 until = batches[id][r].until;
        if (until != 0 && block.timestamp > until) revert TooLate();
        root = r;
    }

    /// The root the settlement reaches along `path`, which must be the one
    /// the answer to its challenge proved.
    function _answeredUnder(uint256 id, uint64 digest, Settlement calldata s, uint256 index, bytes32[] calldata path, bytes32 root)
        private
        view
    {
        _record(id, digest, s);
        if (dispute.rootOf(id, digest, s, index, path) != root) revert WrongBatch();
    }

    /// Posts, for delegation `id`, chunk `index` of the proof whose hash is
    /// `proofHash`: every chunk CHUNK bytes, the last at most that. The hash
    /// is the chained hash of the chunks, h = keccak(h, chunk) from zero, with
    /// the total length hashed in at the end. The chunks travel in the
    /// transactions' call data, which anyone can read back; only the chained
    /// hash is stored.
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
        if (root != bytes32(0) && index < MAX_CHUNKS) _refund(id, root, _spent(g0));
    }

    /// Binds the batch a principal's answered challenge was answered under to
    /// the hashes its receipt names, so that the answerer's postings of what
    /// they name are refunded. Anyone may bring the receipt, within the
    /// challenge's delivery wait; a batch is bound once.
    function bindPosting(uint256 id, uint64 digest, Settlement calldata s, uint256 index, bytes32[] calldata path, BatchReceipt calldata r)
        external
    {
        gasAtStart = gasleft();
        bytes32 root = _due(id, digest);
        _answeredUnder(id, digest, s, index, path, root);
        _receipt(id, root, r);
        if (batches[id][root].proofHash != bytes32(0)) revert AlreadyBound();
        _bind(id, root, r);
        _refund(id, root, _spent(gasAtStart));
    }

    function _bind(uint256 id, bytes32 root, BatchReceipt calldata r) private {
        Batch storage b = batches[id][root];
        b.proofHash = r.proofHash;
        b.sealedRoot = r.sealedRoot;
        b.blobsHash = r.blobsHash;
        if (boundRoot[id][r.proofHash] == bytes32(0)) boundRoot[id][r.proofHash] = root;
        emit PostingBound(id, root, r.proofHash);
    }

    /// Posts a settlement's sealed opening after the principal's challenge of
    /// it was answered: the opening sits at the settlement's own position in
    /// the sealed tree the receipt names, and the receipt is for the batch the
    /// answer proved. Anyone may post it. The first delivery under a batch
    /// binds it, as `bindPosting` does.
    function deliver(
        uint256 id,
        uint64 digest,
        Settlement calldata s,
        uint256 index,
        bytes32[] calldata path,
        BatchReceipt calldata r,
        bytes calldata opening,
        bytes32[] calldata sealedPath
    ) external {
        gasAtStart = gasleft();
        bytes32 k = _key(id, digest);
        if (deliveredUnder[k] != bytes32(0)) revert NotDue();
        bytes32 root = _due(id, digest);
        _answeredUnder(id, digest, s, index, path, root);
        _receipt(id, root, r);
        if (_up(keccak256(opening), index, sealedPath) != r.sealedRoot) revert BadPath();
        deliveredUnder[k] = r.sealedRoot;
        emit SealedDelivered(id, digest, opening);
        Batch storage b = batches[id][root];
        if (b.proofHash == bytes32(0)) _bind(id, root, r);
        if (b.proofHash == r.proofHash && b.sealedRoot == r.sealedRoot && b.blobsHash == r.blobsHash) {
            _refund(id, root, _spent(gasAtStart));
        }
    }

    /// The domain's messenger relays BlobPosting's report from Ethereum: the
    /// poster posted, for delegation `id`'s batch `root`, blobs whose chained
    /// hash is `blobsHash`, at a cost of `cost`, in an Ethereum block of time
    /// `at`. The report is a deposit, which a sequencer may hold back up to
    /// the inclusion wait, so the posting counts from `at`, not from when the
    /// report arrives.
    function blobsPosted(address poster, uint256 id, bytes32 root, bytes32 blobsHash, uint256 cost, uint64 at) external {
        if (msg.sender != messenger || IL2Messenger(messenger).xDomainMessageSender() != blobPoster || blobPoster == address(0)) {
            revert NotMessenger();
        }
        uint64 was = blobsPostedAt[id][blobsHash];
        if (was == 0 || at < was) blobsPostedAt[id][blobsHash] = at;
        emit BlobsPosted(id, root, blobsHash, poster);
        Batch storage b = batches[id][root];
        if (b.blobsHash == blobsHash && blobsHash != bytes32(0)) _pay(id, root, poster, cost, true, at);
    }

    /// What the call has cost its sender so far: its gas at the domain's base
    /// fee, with the call data at the floor price of EIP-7623, which bounds
    /// what a transaction on the domain pays for it, plus the L1 data fee.
    function _spent(uint256 g0) private view returns (uint256 fee) {
        uint256 n = msg.data.length;
        uint256 exec = g0 - gasleft() + REFUND_GAS;
        uint256 data = 16 * n + exec > 40 * n ? 16 * n + exec : 40 * n;
        fee = (21000 + data) * block.basefee;
        if (GAS_PRICE_ORACLE.code.length != 0) fee += IGasPriceOracleP(GAS_PRICE_ORACLE).getL1Fee(msg.data);
    }

    function _refund(uint256 id, bytes32 root, uint256 fee) private {
        _pay(id, root, msg.sender, fee, false, uint64(block.timestamp));
    }

    /// Refunds the named answerer's posting for batch `root` while a request
    /// under the batch is outstanding and paid for, and its delivery was not
    /// yet due at `at`, when the posting was made, from the batch's pool, as
    /// far as it reaches. A blob posting is refunded no more, with what the
    /// batch was already refunded, than the domain way costs now, and a
    /// domain posting after blobs were reported is not refunded. A blob
    /// refund the pool cannot pay lapses the batch's duty.
    function _pay(uint256 id, bytes32 root, address poster, uint256 fee, bool asBlobs, uint64 at) private {
        (address answerer, ) = reserve.answererOf(id);
        Batch storage b = batches[id][root];
        if (poster != answerer || b.until == 0 || at > b.until || b.due == 0) return;
        if (asBlobs) {
            uint256 cap = domainCost();
            cap = cap > b.refunded ? cap - b.refunded : 0;
            if (fee > cap) fee = cap;
        } else if (b.blobsHash != bytes32(0) && blobsPostedAt[id][b.blobsHash] != 0) {
            return;
        }
        uint256 pool = b.pool;
        if (fee > pool) {
            fee = pool;
            if (asBlobs && !b.lapsed) {
                b.lapsed = true;
                emit PostingLapsed(id, root);
            }
        }
        b.pool = pool - fee;
        b.refunded += fee;
        credit[poster] += fee;
        emit PostingRefunded(id, poster, fee);
    }

    /// Slashes the answerer that held a settlement's batch before the
    /// principal's request under it, if the request was paid for and by the
    /// time the delivery fell due neither way of posting delivered what its
    /// receipt names, unless that batch's duty lapsed; and at any time if the
    /// opening was delivered
    /// under another sealed root than the receipt's, or the batch is bound to
    /// other hashes than the receipt's, either of which takes a second
    /// receipt for the batch.
    function slashWithholding(uint256 id, uint64 digest, Settlement calldata s, uint256 index, bytes32[] calldata path, BatchReceipt calldata r)
        external
    {
        (uint8 status, bool byPrincipal, uint64 requestedAt, ) = dispute.challengeState(id, digest);
        _record(id, digest, s);
        bytes32 root = dispute.rootOf(id, digest, s, index, path);
        _receipt(id, root, r);
        if (!byPrincipal || status != ANSWERED) revert NotWithheld();
        bytes32 under = deliveredUnder[_key(id, digest)];
        if (!_swapped(id, root, under, r) && !_missed(id, root, under, r, requestedAt)) revert NotWithheld();
        emit AnswererSlashed(id, digest);
        dispute.slashFor(id, msg.sender);
    }

    /// The opening was delivered under another sealed root than the
    /// receipt's, or the batch is bound to other hashes than the receipt's.
    function _swapped(uint256 id, bytes32 root, bytes32 under, BatchReceipt calldata r) private view returns (bool) {
        Batch storage b = batches[id][root];
        return (under != bytes32(0) && under != r.sealedRoot)
            || (b.proofHash != bytes32(0) && (b.proofHash != r.proofHash || b.sealedRoot != r.sealedRoot || b.blobsHash != r.blobsHash));
    }

    /// The request was paid for after it was filed; the delivery wait is over, and so is the
    /// inclusion wait after it, by which any report of blobs posted in time
    /// has arrived; neither way of posting delivered what the receipt names;
    /// the duty did not lapse; and the receipt is dated no later than the
    /// request.
    function _missed(uint256 id, bytes32 root, bytes32 under, BatchReceipt calldata r, uint64 requestedAt) private view returns (bool) {
        Batch storage b = batches[id][root];
        uint64 until = b.until;
        if (until == 0 || requestedAt > b.paidAt || b.lapsed || block.timestamp <= uint256(until) + inclusionWait) return false;
        if (r.receivedAt > requestedAt) revert ReceiptTooLate();
        uint64 chunksAt = postedAt[id][r.proofHash];
        uint64 blobsAt = blobsPostedAt[id][r.blobsHash];
        bool onDomain = under != bytes32(0) && chunksAt != 0 && chunksAt <= until;
        bool asBlobs = blobsAt != 0 && blobsAt <= until;
        return !onDomain && !asBlobs;
    }

    function withdraw() external {
        uint256 amount = credit[msg.sender];
        if (amount == 0) revert NothingToWithdraw();
        credit[msg.sender] = 0;
        (bool ok, ) = payable(msg.sender).call{value: amount}("");
        require(ok, "withdraw");
    }

    /// The root `leaf` reaches along `path` from position `index`.
    function _up(bytes32 leaf_, uint256 index, bytes32[] calldata path) private pure returns (bytes32 h) {
        uint256 depth = path.length;
        if (depth > 8 || index >> depth != 0) revert BadPath();
        h = leaf_;
        for (uint256 j = 0; j < depth; ++j) {
            h = (index >> j) & 1 == 0 ? keccak256(abi.encodePacked(h, path[j])) : keccak256(abi.encodePacked(path[j], h));
        }
    }
}

interface IDisputeWait {
    function deliveryWait() external view returns (uint64);
}
