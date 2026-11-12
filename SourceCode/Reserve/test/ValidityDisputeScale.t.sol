// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test, console} from "forge-std/Test.sol";
import {Reserve} from "../src/Reserve.sol";
import {Poseidon2Goldilocks} from "../src/Poseidon2Goldilocks.sol";
import {TermsOf} from "./TermsOf.sol";
import {ValidityDispute} from "../src/ValidityDispute.sol";
import {Postings} from "../src/Postings.sol";
import {BatchReceipt} from "../src/BatchReceipt.sol";
import {ISP1Verifier} from "../src/sp1/ISP1Verifier.sol";
import {MockToken} from "./MockToken.sol";
import {Settlement} from "../src/Settlement.sol";
import {Statement} from "./Statement.sol";

/// Accepts a "proof" that is exactly the public values the contract built,
/// under the expected key, so these tests check what the contract asks the
/// verifier, not the pairing. The pairing is tested on Pete's real proof.
contract EchoVerifier is ISP1Verifier {
    bytes32 public immutable program;

    constructor(bytes32 program_) {
        program = program_;
    }

    function verifyProof(bytes32 vk, bytes calldata pv, bytes calldata proof) external view {
        require(vk == program, "key");
        require(keccak256(pv) == keccak256(proof), "values");
    }
}

contract FixedL1Block {
    function basefee() external pure returns (uint256) {
        return 3 gwei;
    }
}

/// The domain's messenger as the posting contract sees it: the sender on
/// Ethereum of the message it is relaying.
contract MockL2Messenger {
    address public immutable xDomainMessageSender;

    constructor(address sender) {
        xDomainMessageSender = sender;
    }
}

interface IPermit2Approve {
    function approve(address token, address spender, uint160 amount, uint48 expiration) external;
}

contract RefusesEther {
    function openOn(ValidityDispute vd, uint256 id, uint64 digest, Settlement calldata s) external payable {
        vd.open{value: msg.value}(id, digest, s);
    }
}

contract ValidityDisputeScaleTest is Test {
    /// Stands for the agent's commitment to a payment's hidden fields, which
    /// the reserve signs over and emits but never reads.
    bytes32 constant OPENING = keccak256("hidden fields");
    uint64 constant DOMAIN = 8453;
    uint256 constant AGENT_PK = 0xA6E47;
    uint256 constant OTHER_PK = 0xB0B;
    uint256 constant AGENT_BOND = 1 ether;
    uint256 constant BOND = 0.01 ether;
    /// What an answer to the principal's challenges is paid for each batch,
    /// in the reserve's token.
    uint256 constant COST = 4_000_000;
    /// An honest agent's delivery time, which bounds the batches a principal's
    /// challenges can fall in.
    uint64 constant WD = 8 hours;
    uint64 constant ACCEPT = 1 days;
    uint64 constant WINDOW = 1 days;
    uint64 constant SLOT = 2 hours;
    uint64 constant DELIVERY = 8 hours;
    uint256 constant POSTING = 0.25 ether;
    /// The fee factor, the forced answer's L1 gas, and the posting gas that
    /// makes one deposit POSTING at a domain base fee of 1 gwei.
    uint256 constant FACTOR = 2;
    uint256 constant FORCE_GAS = 572_345;
    uint256 constant POSTING_GAS = POSTING / (FACTOR * 1 gwei);
    uint256 constant POSTING_BYTES = 10_500_000;
    /// The domain's messenger, and BlobPosting's address on Ethereum.
    address constant MESSENGER = 0x4200000000000000000000000000000000000007;
    address constant BLOB_POSTER = address(0xB10B);
    uint64 constant LIFE = 30 days;
    bytes32 constant PROGRAM = bytes32(uint256(1));

    MockToken token;
    Reserve acc;
    ValidityDispute vd;
    Postings pd;
    address principal = address(0xA11CE);
    address payee = address(0xBEEF);
    address challenger = address(0xC14);
    mapping(bytes32 => Settlement) recs;
    uint64 nextDigest = 1000;

    function setUp() public {
        vm.warp(100 days);
        token = new MockToken();
        acc = new Reserve(DOMAIN, address(token), address(0), address(new Poseidon2Goldilocks()), 1 hours, ACCEPT + 1 hours);
        vm.fee(1 gwei);
        _deploy(_params(ACCEPT, WINDOW, SLOT, DELIVERY), _pparams());
        vm.deal(principal, 100 ether);
        vm.deal(challenger, 100 ether);
        token.mint(principal, 1e15);
        token.mint(payee, 1);
        vm.prank(principal);
        token.approve(address(acc), type(uint256).max);
    }

    function _params(uint64 w, uint64 wa, uint64 eta, uint64 wp) internal pure returns (ValidityDispute.Params memory) {
        return ValidityDispute.Params({
            acceptWindow: w,
            answerWindow: wa,
            slot: eta,
            deliveryWait: wp,
            deliveryTime: WD,
            provingBond: BOND,
            provingCost: COST,
            forceGas: FORCE_GAS,
            l1Factor: FACTOR,
            l2Factor: FACTOR,
            l1FeeFloor: 0,
            l2FeeFloor: 0
        });
    }

    /// One deposit is POSTING at a domain base fee of 1 gwei, and posting the
    /// batch on the domain then costs half of it.
    function _pparams() internal pure returns (Postings.Params memory) {
        return Postings.Params({
            postingGas: POSTING_GAS,
            postingBytes: POSTING_BYTES,
            l2Factor: FACTOR,
            l2FeeFloor: 0,
            messenger: MESSENGER,
            inclusionWait: 0
        });
    }

    /// Deploys the dispute and posting contracts on the current reserve.
    function _deploy(ValidityDispute.Params memory p, Postings.Params memory q) internal {
        vd = new ValidityDispute(address(acc), address(new EchoVerifier(PROGRAM)), PROGRAM, p);
        pd = new Postings(address(acc), address(vd), q);
        vd.setPostings(address(pd));
        pd.setBlobPoster(BLOB_POSTER);
        acc.setDispute(address(vd));
    }

    /// The agent accepts the delegation, posting the bond it names.
    function _accepted(uint256 r) internal returns (uint256) {
        address a = acc.agentOf(r);
        vm.deal(a, a.balance + AGENT_BOND);
        vm.prank(a);
        acc.accept{value: AGENT_BOND}(r);
        return r;
    }

    function _register(uint256 pk, uint256 tag) internal returns (uint256 r) {
        vm.prank(principal);
        r = _accepted(acc.register(TermsOf.make(vm.addr(pk), 1_000_000, 1_000, 86_400, Reserve.Funding.Deposit, 100_000_000, bytes32(tag), bytes32(tag + 1), uint64(block.timestamp) + LIFE)));
    }

    function _rec(uint256 r, uint64 d) internal view returns (Settlement memory) {
        return recs[keccak256(abi.encode(r, d))];
    }

    /// A payment of one unit, which publishes one slot: two share lanes and a
    /// nullifier.
    function _settle(uint256 pk, uint256 r, uint64 d) internal returns (Settlement memory s) {
        uint64[] memory e = new uint64[](3);
        e[0] = d;
        e[1] = d + 1;
        e[2] = d + 2;
        uint64 t = uint64(block.timestamp);
        bytes32 h = acc.signedDigest(r, payee, 1, d, t, keccak256(abi.encodePacked(e)), OPENING);
        (uint8 v, bytes32 rr, bytes32 ss) = vm.sign(pk, h);
        acc.settleLogged(r, payee, 1, d, t, e, OPENING, abi.encodePacked(rr, ss, v));
        s = Settlement({elems: keccak256(abi.encodePacked(e)), amount: 1, payee: payee, time: t, epoch: 0});
        recs[keccak256(abi.encode(r, d))] = s;
    }

    function _openBy(address who, uint256 r, uint64 d) internal {
        Settlement memory s = _rec(r, d);
        bool own = who == acc.principalOf(r) || who == acc.monitorOf(r);
        uint256 value = own ? vd.principalPrice(r, 1, s.time, s.time) : BOND;
        vm.prank(who);
        vd.open{value: value}(r, d, s);
    }

    /// k settlements of one delegation, each challenged by `who`.
    function _openMany(uint256 pk, uint256 r, uint256 k, address who)
        internal
        returns (uint256[] memory ids, uint64[] memory ds)
    {
        ids = new uint256[](k);
        ds = new uint64[](k);
        // All settle before any is challenged: a principal's challenge holds
        // the delegation's settlement until it is answered.
        for (uint64 i = 0; i < k; ++i) {
            ids[i] = r;
            ds[i] = nextDigest++;
            _settle(pk, r, ds[i]);
        }
        for (uint256 i = 0; i < k; ++i) _openBy(who, r, ds[i]);
    }

    function _recs(uint256[] memory ids, uint64[] memory ds) internal view returns (Settlement[] memory ss) {
        ss = new Settlement[](ids.length);
        for (uint256 i = 0; i < ids.length; ++i) ss[i] = _rec(ids[i], ds[i]);
    }

    function _deadline(uint256 r, uint64 d) internal view returns (uint64) {
        return vd.challengeOf(r, d).deadline;
    }

    /// A batch of one: the leaf is the root and the path is empty.
    function _answerAlone(uint256 r, uint64 d) internal {
        Settlement memory s = _rec(r, d);
        vd.answer(r, d, s, 0, new bytes32[](0), abi.encodePacked(vd.leafHash(r, d, s)));
    }

    /// The tree an answer to these settlements would commit, padded with zero
    /// leaves to a power of two, and each settlement's path in it.
    function _tree(uint256[] memory ids, uint64[] memory ds)
        internal
        view
        returns (bytes32 root, uint256[] memory at, bytes32[][] memory paths)
    {
        uint256 n = ids.length;
        uint256 width = 1;
        uint256 depth = 0;
        while (width < n) {
            width *= 2;
            depth += 1;
        }
        bytes32[][] memory levels = new bytes32[][](depth + 1);
        levels[0] = new bytes32[](width);
        for (uint256 i = 0; i < n; ++i) levels[0][i] = vd.leafHash(ids[i], ds[i], _rec(ids[i], ds[i]));
        for (uint256 l = 1; l <= depth; ++l) {
            levels[l] = new bytes32[](levels[l - 1].length / 2);
            for (uint256 i = 0; i < levels[l].length; ++i) {
                levels[l][i] = keccak256(abi.encodePacked(levels[l - 1][2 * i], levels[l - 1][2 * i + 1]));
            }
        }
        root = levels[depth][0];
        at = new uint256[](n);
        paths = new bytes32[][](n);
        for (uint256 i = 0; i < n; ++i) {
            at[i] = i;
            paths[i] = new bytes32[](depth);
            for (uint256 l = 0; l < depth; ++l) paths[i][l] = levels[l][(i >> l) ^ 1];
        }
    }

    /// Each queue's deadlines are two slots apart, on its own boundaries:
    /// even slot boundaries for the principal, odd for everyone else.
    function testQueuesAreSpacedAndOnAlternateSlots() public {
        uint256 r = _register(AGENT_PK, 10);
        (uint256[] memory a, uint64[] memory da) = _openMany(AGENT_PK, r, 4, challenger);
        (uint256[] memory b, uint64[] memory db) = _openMany(AGENT_PK, r, 3, principal);
        for (uint256 i = 0; i < 4; ++i) {
            uint64 d = _deadline(a[i], da[i]);
            assertEq(d % (2 * SLOT), SLOT);
            assertGe(d, uint64(block.timestamp) + WINDOW);
            if (i > 0) assertEq(d, _deadline(a[i - 1], da[i - 1]) + 2 * SLOT);
        }
        for (uint256 i = 0; i < 3; ++i) {
            uint64 d = _deadline(b[i], db[i]);
            assertEq(d % (2 * SLOT), 0);
            assertGe(d, uint64(block.timestamp) + WINDOW);
            if (i > 0) assertEq(d, _deadline(b[i - 1], db[i - 1]) + 2 * SLOT);
        }
    }

    /// The attack R5 describes: the agent challenges its own honest settlements
    /// to push the principal's challenge back. The principal's queue is its own.
    function testSelfChallengesDoNotDelayThePrincipal() public {
        uint256 r = _register(AGENT_PK, 10);
        address agent = vm.addr(AGENT_PK);
        vm.deal(agent, 100 ether);
        _openMany(AGENT_PK, r, 20, agent);
        _settle(AGENT_PK, r, 7);
        _openBy(principal, r, 7);
        assertLe(_deadline(r, 7), uint64(block.timestamp) + WINDOW + 2 * SLOT);
    }

    /// At most one deadline of an agent in any slot, so one answer per slot
    /// meets them all.
    function testNoTwoDeadlinesInOneSlot() public {
        uint256 r = _register(AGENT_PK, 10);
        (uint256[] memory a, uint64[] memory da) = _openMany(AGENT_PK, r, 5, challenger);
        (uint256[] memory b, uint64[] memory db) = _openMany(AGENT_PK, r, 5, principal);
        uint64[] memory all = new uint64[](10);
        for (uint256 i = 0; i < 5; ++i) {
            all[i] = _deadline(a[i], da[i]);
            all[5 + i] = _deadline(b[i], db[i]);
        }
        for (uint256 i = 0; i < 10; ++i) {
            for (uint256 j = i + 1; j < 10; ++j) {
                uint64 gap = all[i] > all[j] ? all[i] - all[j] : all[j] - all[i];
                assertGe(gap, SLOT);
            }
        }
    }

    function testOtherAgentsAreNotQueued() public {
        uint256 a = _register(AGENT_PK, 10);
        uint256 b = _register(OTHER_PK, 20);
        _openMany(AGENT_PK, a, 3, challenger);
        (uint256[] memory ids, uint64[] memory ds) = _openMany(OTHER_PK, b, 1, challenger);
        assertLe(_deadline(ids[0], ds[0]), uint64(block.timestamp) + WINDOW + 2 * SLOT);
    }

    function testQueueDrainsOverTime() public {
        uint256 r = _register(AGENT_PK, 10);
        _openMany(AGENT_PK, r, 3, challenger);
        vm.warp(block.timestamp + 10 days);
        _settle(AGENT_PK, r, 77);
        _openBy(challenger, r, 77);
        assertLe(_deadline(r, 77), uint64(block.timestamp) + WINDOW + 2 * SLOT);
    }

    function testChallengeAfterTheAcceptanceWindowRefused() public {
        uint256 r = _register(AGENT_PK, 10);
        _settle(AGENT_PK, r, 5);
        vm.warp(block.timestamp + ACCEPT + 1);
        Settlement memory s = _rec(r, 5);
        vm.prank(challenger);
        vm.expectRevert(ValidityDispute.WindowClosed.selector);
        vd.open{value: BOND}(r, 5, s);
    }

    /// A record that is not the reserve's cannot be opened or answered: here
    /// the shares' hash, the amount, the payee and the time each differ.
    function testWrongRecordRefused() public {
        uint256 r = _register(AGENT_PK, 10);
        Settlement memory s = _settle(AGENT_PK, r, 5);
        Settlement[4] memory bad;
        for (uint256 i = 0; i < 4; ++i) {
            bad[i] = Settlement({elems: s.elems, amount: s.amount, payee: s.payee, time: s.time, epoch: s.epoch});
        }
        bad[0].elems = keccak256("other shares");
        bad[1].amount = 2;
        bad[2].payee = address(0xBAD);
        bad[3].time = s.time - 1;
        for (uint256 i = 0; i < 4; ++i) {
            vm.prank(challenger);
            vm.expectRevert(ValidityDispute.WrongRecord.selector);
            vd.open{value: BOND}(r, 5, bad[i]);
        }
        _openBy(challenger, r, 5);
        vm.expectRevert(ValidityDispute.WrongRecord.selector);
        vd.answer(r, 5, bad[0], 0, new bytes32[](0), "");
    }

    /// A leaf carries the payee as three limbs and the shares' hash as four
    /// big-endian words, in the order the guest hashes them.
    function testLeafLayout() public {
        uint256 r = _register(AGENT_PK, 10);
        Settlement memory s = _settle(AGENT_PK, r, 5);
        s.payee = address(uint160(0x007a3f9c2e5b1d84f6a0c9e2b7d5f3a1c8e6b4d2f0));
        s.elems = 0x0102030405060708111213141516171821222324252627283132333435363738;
        uint256[26] memory v = vd.leaf(r, 5, s);
        assertEq(v[0], 5);
        assertEq(v[10], 1);
        assertEq(v[11], 68576303576830704);
        assertEq(v[12], 37425867368085461);
        assertEq(v[13], 134413621811997);
        assertEq(v[14], s.time);
        assertEq(v[15], Statement.UNIT);
        assertEq(v[16], Statement.RANGE_BASE);
        assertEq(v[17], Statement.RANGE_LEN);
        for (uint256 j = 0; j < 4; ++j) assertEq(v[18 + j], (uint256(Statement.SECRET_HASH) >> (64 * j)) & 0xFFFFFFFFFFFFFFFF);
        assertEq(v[22], 0x0102030405060708);
        assertEq(v[25], 0x3132333435363738);
        assertEq(vd.leafHash(r, 5, s), keccak256(abi.encodePacked(v)));
    }

    /// The circuit crate hashed each payment's published shares as the guest
    /// does; the reserve hashes them as Settle does. The two must agree, and
    /// each payment publishes exactly the slots its amount pays for.
    function testGuestAndReserveHashTheSharesAlike() public pure {
        Statement.Data memory d = Statement.load();
        for (uint256 i = 0; i < Statement.PAYMENTS; ++i) {
            uint64[] memory e = Statement.elems(d, i);
            uint64 a = Statement.amount(d, i);
            assertEq(e.length, 3 * ((a + Statement.UNIT - 1) / Statement.UNIT));
            uint256 h = uint256(keccak256(abi.encodePacked(e)));
            uint64[] memory l = Statement.leaf(d, i);
            for (uint256 j = 0; j < 4; ++j) assertEq(l[22 + j], (h >> (192 - 64 * j)) & 0xFFFFFFFFFFFFFFFF);
        }
    }

    /// The leaves the reserve rebuilds for the exported batch equal what the
    /// circuit crate computes the guest hashes, and reach the root it commits,
    /// before any proof exists.
    function testRebuiltLeavesReachTheRootTheGuestCommits() public {
        Statement.Data memory d = Statement.load();
        uint64[] memory c = Statement.leaf(d, 0);
        uint256 root;
        uint256 com;
        for (uint256 j = 0; j < 4; ++j) {
            root |= uint256(c[1 + j]) << (64 * j);
            com |= uint256(c[5 + j]) << (64 * j);
        }
        vm.prank(principal);
        uint256 r = _accepted(acc.register(TermsOf.make(vm.addr(AGENT_PK), 1_000_000, 1_000, 86_400, Reserve.Funding.Deposit, 100_000_000, bytes32(com), bytes32(root), uint64(block.timestamp) + LIFE)));
        for (uint256 i = 0; i < Statement.PAYMENTS; ++i) _rebuilt(d, r, i);
    }

    function _rebuilt(Statement.Data memory d, uint256 r, uint256 i) internal view {
        Settlement memory s = Settlement({
            elems: keccak256(abi.encodePacked(Statement.elems(d, i))), amount: Statement.amount(d, i),
            payee: Statement.payee(d, i), time: Statement.time(d, i), epoch: 0
        });
        uint64 dg = Statement.digest(d, i);
        uint256[26] memory v = vd.leaf(r, dg, s);
        uint64[] memory want = Statement.leaf(d, i);
        for (uint256 j = 0; j < 26; ++j) assertEq(v[j], want[j]);
        assertEq(vd.rootOf(r, dg, s, i, Statement.path(d, i)), Statement.ROOT);
    }

    function testBatchAnswersEveryChallengeAndCreditsEachAgent() public {
        uint256 a = _register(AGENT_PK, 10);
        uint256 b = _register(OTHER_PK, 20);
        (uint256[] memory ia, uint64[] memory da) = _openMany(AGENT_PK, a, 3, challenger);
        (uint256[] memory ib, uint64[] memory db) = _openMany(OTHER_PK, b, 2, challenger);
        uint256[] memory ids = new uint256[](5);
        uint64[] memory ds = new uint64[](5);
        for (uint256 i = 0; i < 3; ++i) (ids[i], ds[i]) = (ia[i], da[i]);
        for (uint256 i = 0; i < 2; ++i) (ids[3 + i], ds[3 + i]) = (ib[i], db[i]);
        Settlement[] memory ss = _recs(ids, ds);
        (bytes32 root, uint256[] memory at, bytes32[][] memory paths) = _tree(ids, ds);
        vd.answerBatch(_items(ids, ds, ss, at, paths), abi.encodePacked(root));
        for (uint256 i = 0; i < 5; ++i) {
            assertEq(uint256(vd.challengeOf(ids[i], ds[i]).status), uint256(ValidityDispute.Status.Answered));
        }
        assertEq(vd.credit(vm.addr(AGENT_PK)), 3 * BOND);
        assertEq(vd.credit(vm.addr(OTHER_PK)), 2 * BOND);
        assertEq(vd.openCount(a), 0);
        assertEq(vd.openCount(b), 0);
    }

    function testBatchWithWrongValuesFails() public {
        uint256 r = _register(AGENT_PK, 10);
        (uint256[] memory ids, uint64[] memory ds) = _openMany(AGENT_PK, r, 2, challenger);
        Settlement[] memory ss = _recs(ids, ds);
        (bytes32 root, uint256[] memory at, bytes32[][] memory paths) = _tree(ids, ds);
        vm.expectRevert(bytes("values"));
        vd.answerBatch(_items(ids, ds, ss, at, paths), abi.encodePacked(root ^ bytes32(uint256(1))));
        paths[1][0] ^= bytes32(uint256(1));
        vm.expectRevert(ValidityDispute.RootMismatch.selector);
        vd.answerBatch(_items(ids, ds, ss, at, paths), abi.encodePacked(root));
    }

    function testBatchNamingASettlementTwiceFails() public {
        uint256 r = _register(AGENT_PK, 10);
        (uint256[] memory one, uint64[] memory d1) = _openMany(AGENT_PK, r, 1, challenger);
        uint256[] memory ids = new uint256[](2);
        uint64[] memory ds = new uint64[](2);
        (ids[0], ds[0]) = (one[0], d1[0]);
        (ids[1], ds[1]) = (one[0], d1[0]);
        Settlement[] memory ss = _recs(ids, ds);
        (bytes32 root, uint256[] memory at, bytes32[][] memory paths) = _tree(ids, ds);
        vm.expectRevert(ValidityDispute.NotOpen.selector);
        vd.answerBatch(_items(ids, ds, ss, at, paths), abi.encodePacked(root));
    }

    function testBatchWithAnUnchallengedSettlementFails() public {
        uint256 r = _register(AGENT_PK, 10);
        (uint256[] memory one, uint64[] memory d1) = _openMany(AGENT_PK, r, 1, challenger);
        _settle(AGENT_PK, r, 999);
        uint256[] memory ids = new uint256[](2);
        uint64[] memory ds = new uint64[](2);
        (ids[0], ds[0]) = (one[0], d1[0]);
        (ids[1], ds[1]) = (r, 999);
        Settlement[] memory ss = _recs(ids, ds);
        (, uint256[] memory at, bytes32[][] memory paths) = _tree(ids, ds);
        vm.expectRevert(ValidityDispute.NotOpen.selector);
        vd.answerBatch(_items(ids, ds, ss, at, paths), "");
    }

    function testBatchAfterAnyDeadlineFails() public {
        uint256 r = _register(AGENT_PK, 10);
        (uint256[] memory ids, uint64[] memory ds) = _openMany(AGENT_PK, r, 2, challenger);
        vm.warp(_deadline(ids[0], ds[0]) + 1);
        Settlement[] memory ss = _recs(ids, ds);
        (bytes32 root, uint256[] memory at, bytes32[][] memory paths) = _tree(ids, ds);
        vm.expectRevert(ValidityDispute.TooLate.selector);
        vd.answerBatch(_items(ids, ds, ss, at, paths), abi.encodePacked(root));
    }

    function testEmptyBatchFails() public {
        vm.expectRevert(ValidityDispute.EmptyBatch.selector);
        vd.answerBatch(new ValidityDispute.Item[](0), "");
    }

    function testAnswerOfABatchOfOne() public {
        uint256 r = _register(AGENT_PK, 10);
        (uint256[] memory ids, uint64[] memory ds) = _openMany(AGENT_PK, r, 1, challenger);
        _answerAlone(ids[0], ds[0]);
        assertEq(uint256(vd.challengeOf(ids[0], ds[0]).status), uint256(ValidityDispute.Status.Answered));
    }

    function testAnsweredSettlementCannotBeChallengedAgain() public {
        uint256 r = _register(AGENT_PK, 10);
        (uint256[] memory ids, uint64[] memory ds) = _openMany(AGENT_PK, r, 1, challenger);
        Settlement memory s = _rec(ids[0], ds[0]);
        _answerAlone(ids[0], ds[0]);
        vm.prank(challenger);
        vm.expectRevert(ValidityDispute.AlreadyChallenged.selector);
        vd.open{value: BOND}(r, ds[0], s);
    }

    function testChallengerThatRefusesEtherCannotBlockForfeit() public {
        uint256 r = _register(AGENT_PK, 10);
        Settlement memory s = _settle(AGENT_PK, r, 42);
        RefusesEther bad = new RefusesEther();
        bad.openOn{value: BOND}(vd, r, 42, s);
        vm.warp(_deadline(r, 42) + 1);
        uint256 before = principal.balance;
        vd.expire(r, 42);
        assertEq(principal.balance, before);
        assertEq(acc.credit(principal), AGENT_BOND);
        assertEq(vd.credit(address(bad)), BOND);
    }

    function testWithdrawWithNoCreditFails() public {
        vm.expectRevert(ValidityDispute.NothingToWithdraw.selector);
        vd.withdraw();
    }

    /// R5: the bond cannot leave while a challenge is open, however late.
    function testCloseWaitsForOpenChallenges() public {
        uint256 r = _register(AGENT_PK, 10);
        address agent = vm.addr(AGENT_PK);
        _settle(AGENT_PK, r, 5);
        _openBy(principal, r, 5);
        vm.warp(block.timestamp + LIFE + ACCEPT + 1 hours + 1);
        vm.expectRevert(Reserve.NotClosable.selector);
        acc.close(r);
        vd.expire(r, 5);
        acc.close(r);
        assertEq(acc.credit(agent), 0);
        assertEq(acc.credit(principal), AGENT_BOND);
    }

    function testCloseAfterAnAnsweredChallengeReturnsTheBond() public {
        uint256 r = _register(AGENT_PK, 10);
        address agent = vm.addr(AGENT_PK);
        _settle(AGENT_PK, r, 5);
        _openBy(challenger, r, 5);
        _answerAlone(r, 5);
        vm.warp(block.timestamp + LIFE + ACCEPT + 1 hours + 1);
        acc.close(r);
        assertEq(acc.credit(agent), AGENT_BOND);
    }

    /// M1: an unanswered challenge forfeits the bond and freezes the
    /// delegation, and the principal takes the rest of the deposit at once.
    function testForfeitFreezesSettlementAndReleasesTheDeposit() public {
        uint256 r = _register(AGENT_PK, 10);
        _settle(AGENT_PK, r, 5);
        _openBy(challenger, r, 5);
        vm.warp(_deadline(r, 5) + 1);
        vd.expire(r, 5);
        (bool frozen,) = acc.frozenOf(r);
        assertTrue(frozen);
        vm.expectRevert(Reserve.Frozen.selector);
        this.settleAgain(AGENT_PK, r, 6);
        uint256 before = token.balanceOf(principal);
        vm.prank(principal);
        acc.reclaim(r);
        assertEq(token.balanceOf(principal), before + 100_000_000 - 1);
    }

    /// M4: the principal's challenge stops settlement when it is opened, not
    /// when it expires, and an answer lets settlement resume.
    function testPrincipalChallengeHoldsSettlementUntilAnswered() public {
        uint256 r = _register(AGENT_PK, 10);
        _settle(AGENT_PK, r, 5);
        _openBy(principal, r, 5);
        vm.expectRevert(Reserve.Held.selector);
        this.settleAgain(AGENT_PK, r, 6);
        _answerAlone(r, 5);
        _settle(AGENT_PK, r, 6);
    }

    /// A stranger's challenge costs it a bond and stops nothing.
    function testOtherChallengesDoNotHold() public {
        uint256 r = _register(AGENT_PK, 10);
        _settle(AGENT_PK, r, 5);
        _openBy(challenger, r, 5);
        _settle(AGENT_PK, r, 6);
        (, uint32 holds) = acc.frozenOf(r);
        assertEq(holds, 0);
    }

    /// M2: whole revocation stops settlement at once, whatever the proofs.
    function testFreezeByThePrincipalStopsSettlement() public {
        uint256 r = _register(AGENT_PK, 10);
        _settle(AGENT_PK, r, 5);
        vm.expectRevert(Reserve.NotPrincipal.selector);
        acc.freeze(r);
        vm.prank(principal);
        acc.freeze(r);
        vm.expectRevert(Reserve.Frozen.selector);
        this.settleAgain(AGENT_PK, r, 6);
        vm.expectRevert(Reserve.NotPrincipal.selector);
        acc.reclaim(r);
        vm.prank(principal);
        acc.reclaim(r);
        vm.warp(block.timestamp + ACCEPT + 1 hours + 1);
        address agent = vm.addr(AGENT_PK);
        acc.close(r);
        assertEq(acc.credit(agent), AGENT_BOND);
    }

    /// A principal that is a contract wallet monitors from an EOA: that
    /// address's challenges hold settlement and it may freeze, and nobody
    /// else's do.
    function testMonitorAddressHoldsAndFreezes() public {
        address mon = address(0xA11CE);
        vm.deal(mon, 10 ether);
        Reserve.Terms memory t = TermsOf.make(vm.addr(AGENT_PK), 1_000_000, 1_000, 86_400, Reserve.Funding.Deposit, 100_000_000, bytes32(uint256(10)), bytes32(uint256(11)), uint64(block.timestamp) + LIFE);
        t.monitor = mon;
        vm.prank(principal);
        uint256 r = _accepted(acc.register(t));
        assertEq(acc.monitorOf(r), mon);
        _settle(AGENT_PK, r, 5);
        _openBy(mon, r, 5);
        (, uint32 holds) = acc.frozenOf(r);
        assertEq(holds, 1);
        vm.expectRevert(Reserve.Held.selector);
        this.settleAgain(AGENT_PK, r, 6);
        _answerAlone(r, 5);
        _settle(AGENT_PK, r, 6);
        vm.expectRevert(Reserve.NotPrincipal.selector);
        vm.prank(challenger);
        acc.freeze(r);
        vm.prank(mon);
        acc.freeze(r);
        vm.expectRevert(Reserve.Frozen.selector);
        this.settleAgain(AGENT_PK, r, 7);
    }

    /// With no monitor recorded, the zero address cannot freeze.
    function testNoMonitorMeansOnlyThePrincipal() public {
        uint256 r = _register(AGENT_PK, 10);
        assertEq(acc.monitorOf(r), address(0));
        vm.expectRevert(Reserve.NotPrincipal.selector);
        vm.prank(address(0));
        acc.freeze(r);
    }

    uint256 constant ANSWERER_PK = 0xA45E;

    function _registerWithAnswerer() internal returns (uint256 r, address ans) {
        ans = vm.addr(ANSWERER_PK);
        vm.deal(ans, 10 ether);
        Reserve.Terms memory t = TermsOf.make(vm.addr(AGENT_PK), 1_000_000, 1_000, 86_400, Reserve.Funding.Deposit, 100_000_000, bytes32(uint256(10)), bytes32(uint256(11)), uint64(block.timestamp) + LIFE);
        t.answerer = ans;
        vm.prank(principal);
        r = _accepted(acc.register(t));
        vm.prank(ans);
        acc.stakeAnswerer{value: AGENT_BOND}(r);
    }

    /// Stands for the root of a batch's sealed openings in tests that do not deliver one.
    bytes32 constant SEALED_ROOT = keccak256("sealed openings");
    /// Stands for the chained hash of a batch's blobs.
    bytes32 constant BLOBS_HASH = keccak256("blobs");

    function _receipt(uint256 pk, uint256 r, bytes32 root, uint64 at) internal view returns (BatchReceipt memory) {
        return _receiptOver(pk, r, root, SEALED_ROOT, at);
    }

    function _receiptOver(uint256 pk, uint256 r, bytes32 root, bytes32 sealedRoot, uint64 at)
        internal
        view
        returns (BatchReceipt memory)
    {
        return _receiptFor(pk, r, root, sealedRoot, _proofHash(_proof(100)), at);
    }

    function _receiptFor(uint256 pk, uint256 r, bytes32 root, bytes32 sealedRoot, bytes32 ph, uint64 at)
        internal
        view
        returns (BatchReceipt memory)
    {
        return _receiptBlobs(pk, r, root, sealedRoot, ph, BLOBS_HASH, at);
    }

    function _receiptBlobs(uint256 pk, uint256 r, bytes32 root, bytes32 sealedRoot, bytes32 ph, bytes32 bh, uint64 at)
        internal
        view
        returns (BatchReceipt memory)
    {
        (uint8 v, bytes32 rr, bytes32 ss) = vm.sign(pk, pd.receiptDigest(r, root, sealedRoot, ph, bh, at));
        return BatchReceipt({sealedRoot: sealedRoot, proofHash: ph, blobsHash: bh, receivedAt: at, signature: abi.encodePacked(rr, ss, v)});
    }

    /// Stands for a batch proof of `n` bytes.
    function _proof(uint256 n) internal pure returns (bytes memory b) {
        b = new bytes(n);
        for (uint256 i = 0; i < n; i += 32) {
            bytes32 w = keccak256(abi.encode("proof", i));
            for (uint256 j = 0; j < 32 && i + j < n; ++j) b[i + j] = w[j];
        }
    }

    function _slice(bytes memory b, uint256 from, uint256 to) internal pure returns (bytes memory c) {
        c = new bytes(to - from);
        for (uint256 i = from; i < to; ++i) c[i - from] = b[i];
    }

    /// The chained hash postProof checks: chunk by chunk from zero, then the length.
    function _proofHash(bytes memory b) internal view returns (bytes32 h) {
        uint256 size = pd.CHUNK();
        for (uint256 at = 0; at < b.length; at += size) {
            uint256 end = at + size < b.length ? at + size : b.length;
            h = keccak256(abi.encodePacked(h, _slice(b, at, end)));
        }
        h = keccak256(abi.encodePacked(h, b.length));
    }

    function _post(uint256 r, bytes memory b) internal {
        bytes32 h = _proofHash(b);
        uint256 size = pd.CHUNK();
        uint256 i;
        for (uint256 at = 0; at < b.length; at += size) {
            uint256 end = at + size < b.length ? at + size : b.length;
            pd.postProof(r, h, i++, _slice(b, at, end), end == b.length);
        }
    }

    /// An answer pays the registered answerer, whoever sends it.
    function testAnswerCreditsTheAnswererWhoeverSendsIt() public {
        (uint256 r, address ans) = _registerWithAnswerer();
        _settle(AGENT_PK, r, 5);
        _openBy(principal, r, 5);
        vm.prank(challenger);
        _answerAlone(r, 5);
        // The principal's challenge pays the proving cost, in the reserve's
        // token from what was set aside, and the answer's gas, in ether.
        assertEq(acc.tokenCredit(ans), COST);
        assertGt(vd.credit(ans), 0);
        assertLt(vd.credit(ans), 0.002 ether);
        assertEq(vd.credit(vm.addr(AGENT_PK)), 0);
        assertEq(acc.tokenCredit(vm.addr(AGENT_PK)), 0);
        assertEq(vd.credit(challenger), 0);
        uint256 b0 = token.balanceOf(ans);
        vm.prank(ans);
        acc.withdrawToken();
        assertEq(token.balanceOf(ans), b0 + COST);
    }

    /// The answerer acknowledged the batch and stayed silent: the principal
    /// still gets the agent's bond, whoever brings the receipt is paid one
    /// challenger's bond, and the rest of the stake is burnt.
    function testSilentAnswererLosesItsStake() public {
        (uint256 r, address ans) = _registerWithAnswerer();
        _settle(AGENT_PK, r, 5);
        Settlement memory s = _rec(r, 5);
        uint64 at = uint64(block.timestamp);
        BatchReceipt memory rc = _receipt(ANSWERER_PK, r, vd.leafHash(r, 5, s), at);
        _openBy(principal, r, 5);
        vm.warp(_deadline(r, 5) + 1);
        vd.expire(r, 5);
        assertEq(acc.credit(principal), AGENT_BOND);
        address agent = vm.addr(AGENT_PK);
        vm.prank(challenger);
        vd.slashAnswerer(r, 5, s, 0, new bytes32[](0), rc);
        assertEq(acc.credit(agent), 0);
        assertEq(acc.credit(principal), AGENT_BOND);
        assertEq(acc.credit(challenger), BOND);
        (, uint256 left) = acc.answererOf(r);
        assertEq(left, 0);
        assertEq(acc.burnt(), AGENT_BOND - BOND);
        vm.warp(block.timestamp + ACCEPT + 1 hours + 1);
        acc.close(r);
        vm.warp(block.timestamp + ACCEPT + 1 hours + 2 * DELIVERY + 1);
        uint256 b0 = ans.balance;
        vm.prank(ans);
        acc.unstakeAnswerer(r);
        assertEq(ans.balance, b0);
        assertGe(address(acc).balance, acc.burnt() + acc.credit(principal) + acc.credit(challenger));
    }

    function testSlashBeforeExpiryRefused() public {
        (uint256 r, ) = _registerWithAnswerer();
        _settle(AGENT_PK, r, 5);
        Settlement memory s = _rec(r, 5);
        uint64 at = uint64(block.timestamp);
        BatchReceipt memory rc = _receipt(ANSWERER_PK, r, vd.leafHash(r, 5, s), at);
        _openBy(principal, r, 5);
        vm.expectRevert(ValidityDispute.NotExpired.selector);
        vd.slashAnswerer(r, 5, s, 0, new bytes32[](0), rc);
        _answerAlone(r, 5);
        vm.expectRevert(ValidityDispute.NotExpired.selector);
        vd.slashAnswerer(r, 5, s, 0, new bytes32[](0), rc);
    }

    function _expired() internal returns (uint256 r, Settlement memory s, uint64 at) {
        (r, ) = _registerWithAnswerer();
        _settle(AGENT_PK, r, 5);
        s = _rec(r, 5);
        at = uint64(block.timestamp);
        _openBy(principal, r, 5);
        vm.warp(_deadline(r, 5) + 1);
        vd.expire(r, 5);
    }

    /// A receipt signed by anyone but the registered answerer moves nothing.
    function testReceiptByAnotherKeyRefused() public {
        (uint256 r, Settlement memory s, uint64 at) = _expired();
        BatchReceipt memory rc = _receipt(OTHER_PK, r, vd.leafHash(r, 5, s), at);
        vm.expectRevert(ValidityDispute.BadReceipt.selector);
        vd.slashAnswerer(r, 5, s, 0, new bytes32[](0), rc);
    }

    /// A receipt for a batch the settlement is not in moves nothing.
    function testReceiptForAnotherBatchRefused() public {
        (uint256 r, Settlement memory s, uint64 at) = _expired();
        bytes32[] memory path = new bytes32[](1);
        path[0] = keccak256("other");
        BatchReceipt memory rc = _receipt(ANSWERER_PK, r, keccak256("another root"), at);
        vm.expectRevert(ValidityDispute.BadReceipt.selector);
        vd.slashAnswerer(r, 5, s, 0, path, rc);
        vm.expectRevert(ValidityDispute.BadReceipt.selector);
        vd.slashAnswerer(r, 5, s, 0, new bytes32[](0), rc);
    }

    /// An answerer handed the proof with less than an answer window left is
    /// not to blame.
    function testReceiptWithoutAFullWindowRefused() public {
        (uint256 r, Settlement memory s, ) = _expired();
        uint64 late = _deadline(r, 5) - WINDOW + 1;
        BatchReceipt memory rc = _receipt(ANSWERER_PK, r, vd.leafHash(r, 5, s), late);
        vm.expectRevert(ValidityDispute.ReceiptTooLate.selector);
        vd.slashAnswerer(r, 5, s, 0, new bytes32[](0), rc);
    }

    /// A receipt with a different time than the one signed moves nothing.
    function testReceiptTimeIsSigned() public {
        (uint256 r, Settlement memory s, uint64 at) = _expired();
        BatchReceipt memory rc = _receipt(ANSWERER_PK, r, vd.leafHash(r, 5, s), at);
        rc.receivedAt = at - 1;
        vm.expectRevert(ValidityDispute.BadReceipt.selector);
        vd.slashAnswerer(r, 5, s, 0, new bytes32[](0), rc);
        rc = _receipt(ANSWERER_PK, r, vd.leafHash(r, 5, s), at);
        rc.sealedRoot = keccak256("other openings");
        vm.expectRevert(ValidityDispute.BadReceipt.selector);
        vd.slashAnswerer(r, 5, s, 0, new bytes32[](0), rc);
    }

    /// One sealed opening, 349 bytes as every one is, standing for a
    /// ciphertext the contract never reads.
    function _sealed(uint256 tag) internal pure returns (bytes memory b) {
        b = new bytes(349);
        for (uint256 i = 0; i < 349; i += 32) {
            bytes32 w = keccak256(abi.encode(tag, i));
            for (uint256 j = 0; j < 32 && i + j < 349; ++j) b[i + j] = w[j];
        }
    }

    /// The principal pays for the postings of the batch settlement `d`'s
    /// answer proved.
    function _payPosting(uint256 r, uint64 d) internal {
        bytes32 root = vd.answeredRoot(r, d);
        uint256 v = pd.postingTopUp(r, root);
        vm.prank(principal);
        pd.payPosting{value: v}(r, root);
    }

    /// The pool of the batch settlement `d`'s answer proved.
    function _pool(uint256 r, uint64 d) internal view returns (uint256) {
        return pd.batchOf(r, vd.answeredRoot(r, d)).pool;
    }

    /// A settlement of a batch of one, receipted with its sealed opening,
    /// challenged by the principal and answered, its postings paid for.
    function _answered() internal returns (uint256 r, Settlement memory s, BatchReceipt memory rc) {
        (r, ) = _registerWithAnswerer();
        _settle(AGENT_PK, r, 5);
        s = _rec(r, 5);
        rc = _receiptOver(ANSWERER_PK, r, vd.leafHash(r, 5, s), keccak256(_sealed(5)), uint64(block.timestamp));
        _openBy(principal, r, 5);
        _answerAlone(r, 5);
        _payPosting(r, 5);
    }

    /// Answering the principal's challenge files a request, and once the
    /// principal pays for the postings the delivery is due one delivery wait
    /// later; answering anyone else's challenge files nothing.
    function testAnswerToThePrincipalAsksForTheSealedOpening() public {
        (uint256 r, , BatchReceipt memory rc) = _answered();
        ValidityDispute.Challenge memory c = vd.challengeOf(r, 5);
        assertEq(uint256(c.status), uint256(ValidityDispute.Status.Answered));
        assertEq(c.deadline, uint64(block.timestamp));
        Postings.Batch memory b = pd.batchOf(r, vd.answeredRoot(r, 5));
        assertEq(b.due, 1);
        assertEq(b.until, uint64(block.timestamp) + DELIVERY);
        assertEq(b.pool, POSTING);
        _settle(AGENT_PK, r, 6);
        _openBy(challenger, r, 6);
        _answerAlone(r, 6);
        Settlement memory s6 = _rec(r, 6);
        BatchReceipt memory rc6 = _receiptOver(ANSWERER_PK, r, vd.leafHash(r, 6, s6), keccak256(_sealed(6)), rc.receivedAt);
        vm.expectRevert(Postings.NotDue.selector);
        pd.deliver(r, 6, s6, 0, new bytes32[](0), rc6, _sealed(6), new bytes32[](0));
    }

    /// The receipted opening and proof, posted in time, end the duty: the
    /// opening is delivered once and the receipt can no longer slash.
    function testDeliveredOpeningIsPostedAndEndsTheDuty() public {
        (uint256 r, Settlement memory s, BatchReceipt memory rc) = _answered();
        vm.expectEmit(true, false, false, true, address(pd));
        emit Postings.SealedDelivered(r, 5, _sealed(5));
        pd.deliver(r, 5, s, 0, new bytes32[](0), rc, _sealed(5), new bytes32[](0));
        assertEq(pd.deliveredUnder(vd.key(r, 5)), rc.sealedRoot);
        vm.expectRevert(Postings.NotDue.selector);
        pd.deliver(r, 5, s, 0, new bytes32[](0), rc, _sealed(5), new bytes32[](0));
        _post(r + 1, _proof(100));
        assertEq(pd.postedAt(r, _proofHash(_proof(100))), 0);
        _post(r, _proof(100));
        vm.warp(block.timestamp + DELIVERY + 1);
        vm.expectRevert(Postings.NotWithheld.selector);
        pd.slashWithholding(r, 5, s, 0, new bytes32[](0), rc);
    }

    /// The opening was posted but the proof was not: the receipt slashes.
    function testWithheldProofSlashesTheStake() public {
        (uint256 r, Settlement memory s, BatchReceipt memory rc) = _answered();
        pd.deliver(r, 5, s, 0, new bytes32[](0), rc, _sealed(5), new bytes32[](0));
        vm.warp(block.timestamp + DELIVERY + 1);
        vm.prank(challenger);
        pd.slashWithholding(r, 5, s, 0, new bytes32[](0), rc);
        (, uint256 left) = acc.answererOf(r);
        assertEq(left, 0);
    }

    /// A proof posted after the wait came too late, and the receipt slashes.
    function testProofPostedLateSlashes() public {
        (uint256 r, Settlement memory s, BatchReceipt memory rc) = _answered();
        pd.deliver(r, 5, s, 0, new bytes32[](0), rc, _sealed(5), new bytes32[](0));
        vm.warp(block.timestamp + DELIVERY + 1);
        _post(r, _proof(100));
        vm.prank(challenger);
        pd.slashWithholding(r, 5, s, 0, new bytes32[](0), rc);
        (, uint256 left) = acc.answererOf(r);
        assertEq(left, 0);
    }

    /// A proof of three chunks is accepted only in order, with full chunks
    /// before the last, and only if its chained hash is the one named; a
    /// second poster's wrong chunks spoil nothing for the first.
    function testProofPostedInChunks() public {
        bytes memory b = _proof(2 * pd.CHUNK() + 1000);
        bytes32 h = _proofHash(b);
        uint256 size = pd.CHUNK();
        vm.expectRevert(Postings.BadChunk.selector);
        pd.postProof(7, h, 1, _slice(b, size, 2 * size), false);
        vm.expectRevert(Postings.BadChunk.selector);
        pd.postProof(7, h, 0, _slice(b, 0, size - 1), false);
        vm.prank(challenger);
        pd.postProof(7, h, 0, _slice(b, size, 2 * size), false);
        pd.postProof(7, h, 0, _slice(b, 0, size), false);
        pd.postProof(7, h, 1, _slice(b, size, 2 * size), false);
        vm.expectRevert(Postings.ProofMismatch.selector);
        pd.postProof(7, h, 2, _slice(b, 2 * size, 2 * size + 999), true);
        assertEq(pd.postedAt(7, h), 0);
        pd.postProof(7, h, 2, _slice(b, 2 * size, 2 * size + 1000), true);
        assertEq(pd.postedAt(7, h), uint64(block.timestamp));
        assertEq(pd.postedAt(8, h), 0);
        vm.expectRevert(Postings.BadChunk.selector);
        pd.postProof(7, h, 3, _slice(b, 0, 10), true);
    }

    /// Only the opening the receipt names, at the settlement's own position,
    /// can be delivered.
    function testOtherOpeningCannotBeDelivered() public {
        (uint256 r, Settlement memory s, BatchReceipt memory rc) = _answered();
        vm.expectRevert(ValidityDispute.BadPath.selector);
        pd.deliver(r, 5, s, 0, new bytes32[](0), rc, _sealed(6), new bytes32[](0));
        BatchReceipt memory other = _receiptOver(OTHER_PK, r, vd.leafHash(r, 5, s), keccak256(_sealed(6)), rc.receivedAt);
        vm.expectRevert(ValidityDispute.BadReceipt.selector);
        pd.deliver(r, 5, s, 0, new bytes32[](0), other, _sealed(6), new bytes32[](0));
    }

    function testDeliveryAfterTheWaitRefused() public {
        (uint256 r, Settlement memory s, BatchReceipt memory rc) = _answered();
        vm.warp(block.timestamp + DELIVERY + 1);
        vm.expectRevert(ValidityDispute.TooLate.selector);
        pd.deliver(r, 5, s, 0, new bytes32[](0), rc, _sealed(5), new bytes32[](0));
    }

    /// Nothing posted within the wait: the receipt burns the stake less the
    /// bounty, and the agent keeps its bond, since the challenge was answered.
    function testWithheldOpeningSlashesTheStake() public {
        (uint256 r, Settlement memory s, BatchReceipt memory rc) = _answered();
        vm.expectRevert(Postings.NotWithheld.selector);
        pd.slashWithholding(r, 5, s, 0, new bytes32[](0), rc);
        vm.warp(block.timestamp + DELIVERY + 1);
        address agent = vm.addr(AGENT_PK);
        uint256 a0 = agent.balance;
        vm.prank(challenger);
        uint256 g0 = gasleft();
        pd.slashWithholding(r, 5, s, 0, new bytes32[](0), rc);
        console.log("slash for withholding, batch of one", g0 - gasleft());
        assertEq(acc.credit(challenger), BOND);
        assertEq(agent.balance, a0);
        (, uint256 left) = acc.answererOf(r);
        assertEq(left, 0);
        assertEq(acc.burnt(), AGENT_BOND - BOND);
    }

    /// An answerer handed the batch only after the answer is not to blame.
    function testReceiptAfterTheAnswerCannotSlashWithholding() public {
        (uint256 r, Settlement memory s, ) = _answered();
        BatchReceipt memory late = _receiptOver(ANSWERER_PK, r, vd.leafHash(r, 5, s), keccak256(_sealed(5)), uint64(block.timestamp) + 1);
        vm.warp(block.timestamp + DELIVERY + 1);
        vm.expectRevert(Postings.ReceiptTooLate.selector);
        pd.slashWithholding(r, 5, s, 0, new bytes32[](0), late);
    }

    /// Delivering under a second receipt with other openings is caught by the
    /// first: two sealed roots for one batch are the answerer's own signatures.
    function testDeliveryUnderAnotherReceiptSlashes() public {
        (uint256 r, Settlement memory s, BatchReceipt memory rc) = _answered();
        BatchReceipt memory swapped = _receiptOver(ANSWERER_PK, r, vd.leafHash(r, 5, s), keccak256(_sealed(9)), rc.receivedAt);
        pd.deliver(r, 5, s, 0, new bytes32[](0), swapped, _sealed(9), new bytes32[](0));
        vm.expectRevert(Postings.NotWithheld.selector);
        pd.slashWithholding(r, 5, s, 0, new bytes32[](0), swapped);
        vm.prank(challenger);
        pd.slashWithholding(r, 5, s, 0, new bytes32[](0), rc);
        (, uint256 left) = acc.answererOf(r);
        assertEq(left, 0);
    }

    /// Gas of delivering one sealed opening of a batch of 256, whose two
    /// paths have eight siblings each.
    function testDeliveryGas() public {
        (uint256 r, ) = _registerWithAnswerer();
        _settle(AGENT_PK, r, 5);
        Settlement memory s = _rec(r, 5);
        uint256 index = 77;
        bytes32[] memory path = new bytes32[](8);
        bytes32[] memory sealedPath = new bytes32[](8);
        for (uint256 j = 0; j < 8; ++j) {
            path[j] = keccak256(abi.encode("statement sibling", j));
            sealedPath[j] = keccak256(abi.encode("sealed sibling", j));
        }
        bytes32 root = _climb(vd.leafHash(r, 5, s), index, path);
        bytes32 sealedRoot = _climb(keccak256(_sealed(5)), index, sealedPath);
        BatchReceipt memory rc = _receiptOver(ANSWERER_PK, r, root, sealedRoot, uint64(block.timestamp));
        _openBy(principal, r, 5);
        vd.answer(r, 5, s, index, path, abi.encodePacked(root));
        _payPosting(r, 5);
        bytes memory opening = _sealed(5);
        uint256 g0 = gasleft();
        pd.deliver(r, 5, s, index, path, rc, opening, sealedPath);
        console.log("deliver sealed opening, batch of 256", g0 - gasleft());
    }

    function _climb(bytes32 h, uint256 index, bytes32[] memory path) internal pure returns (bytes32) {
        for (uint256 j = 0; j < path.length; ++j) {
            h = (index >> j) & 1 == 0 ? keccak256(abi.encodePacked(h, path[j])) : keccak256(abi.encodePacked(path[j], h));
        }
        return h;
    }

    /// Only the registered answerer stakes, and it takes its stake back only
    /// after the close.
    function testAnswererStakeLifecycle() public {
        (uint256 r, address ans) = _registerWithAnswerer();
        vm.deal(challenger, 10 ether);
        vm.prank(challenger);
        vm.expectRevert(Reserve.NotAnswerer.selector);
        acc.stakeAnswerer{value: 1}(r);
        vm.prank(ans);
        vm.expectRevert(Reserve.NotClosed.selector);
        acc.unstakeAnswerer(r);
        vm.prank(principal);
        acc.freeze(r);
        vm.warp(block.timestamp + ACCEPT + 1 hours + 1);
        acc.close(r);
        vm.prank(challenger);
        vm.expectRevert(Reserve.NotAnswerer.selector);
        acc.unstakeAnswerer(r);
        vm.prank(ans);
        vm.expectRevert(Reserve.NotClosed.selector);
        acc.unstakeAnswerer(r);
        vm.warp(block.timestamp + ACCEPT + 1 hours + 2 * DELIVERY);
        vm.prank(ans);
        vm.expectRevert(Reserve.NotClosed.selector);
        acc.unstakeAnswerer(r);
        vm.warp(block.timestamp + 1);
        uint256 b0 = ans.balance;
        vm.prank(ans);
        acc.unstakeAnswerer(r);
        assertEq(ans.balance, b0 + AGENT_BOND);
        vm.prank(ans);
        vm.expectRevert(Reserve.NotClosable.selector);
        acc.stakeAnswerer{value: 1}(r);
    }

    /// Gas of the answerer's two calls: staking, and the slash a silent
    /// answerer's receipt brings.
    function testAnswererGas() public {
        address ans = vm.addr(ANSWERER_PK);
        vm.deal(ans, 10 ether);
        Reserve.Terms memory t = TermsOf.make(vm.addr(AGENT_PK), 1_000_000, 1_000, 86_400, Reserve.Funding.Deposit, 100_000_000, bytes32(uint256(10)), bytes32(uint256(11)), uint64(block.timestamp) + LIFE);
        t.answerer = ans;
        vm.prank(principal);
        uint256 r = _accepted(acc.register(t));
        vm.prank(ans);
        uint256 g0 = gasleft();
        acc.stakeAnswerer{value: AGENT_BOND}(r);
        console.log("stake answerer", g0 - gasleft());
        _settle(AGENT_PK, r, 5);
        Settlement memory s = _rec(r, 5);
        uint64 at = uint64(block.timestamp);
        BatchReceipt memory rc = _receipt(ANSWERER_PK, r, vd.leafHash(r, 5, s), at);
        _openBy(principal, r, 5);
        vm.warp(_deadline(r, 5) + 1);
        vd.expire(r, 5);
        vm.prank(challenger);
        g0 = gasleft();
        vd.slashAnswerer(r, 5, s, 0, new bytes32[](0), rc);
        console.log("slash answerer, batch of one", g0 - gasleft());
    }

    /// Without an answerer the agent is credited, as before, and nobody can
    /// stake.
    function testNoAnswererCreditsTheAgent() public {
        uint256 r = _register(AGENT_PK, 10);
        _settle(AGENT_PK, r, 5);
        _openBy(principal, r, 5);
        _answerAlone(r, 5);
        assertEq(acc.tokenCredit(vm.addr(AGENT_PK)), COST);
        assertGt(vd.credit(vm.addr(AGENT_PK)), 0);
        assertLt(vd.credit(vm.addr(AGENT_PK)), 0.002 ether);
        vm.prank(address(0));
        vm.expectRevert(Reserve.NotAnswerer.selector);
        acc.stakeAnswerer(r);
    }

    function testReclaimNeedsAFreeze() public {
        uint256 r = _register(AGENT_PK, 10);
        vm.prank(principal);
        vm.expectRevert(Reserve.NotFrozen.selector);
        acc.reclaim(r);
    }

    function settleAgain(uint256 pk, uint256 r, uint64 d) external {
        _settle(pk, r, d);
    }

    /// The windows the paper sets for Base: w = 36.5 h, theta = 1 h,
    /// w_a = 32 h, eta = 4 h and w_p = 30 h. The monitor's challenge at its
    /// decision time, ten hours after the signed time, is admitted; another
    /// party's at w is too, and one a second later is refused. The principal's
    /// challenge falls due between w_a and w_a + 2 eta after it opens, an answer
    /// in its last second is accepted, the principal pays for the postings
    /// then, which starts a posting wait of w_p, and once that wait has
    /// passed with nothing posted the receipt slashes the stake. Another party's challenge left unanswered expires and freezes.
    function testWindowsOfTheBaseDeployment() public {
        uint64 w = 36 hours + 30 minutes;
        uint64 wa = 32 hours;
        uint64 eta = 4 hours;
        uint64 wp = 30 hours;
        acc = new Reserve(DOMAIN, address(token), address(0), address(new Poseidon2Goldilocks()), 1 hours, w + 1 hours);
        _deploy(_params(w, wa, eta, wp), _pparams());
        vm.prank(principal);
        token.approve(address(acc), type(uint256).max);

        (uint256 r, ) = _registerWithAnswerer();
        uint64 signed = uint64(block.timestamp);
        _settle(AGENT_PK, r, 5);
        _settle(AGENT_PK, r, 6);
        _settle(AGENT_PK, r, 7);
        Settlement memory s5 = _rec(r, 5);
        BatchReceipt memory rc = _receiptOver(ANSWERER_PK, r, vd.leafHash(r, 5, s5), keccak256(_sealed(5)), signed);

        vm.warp(signed + w - 14 hours - 12 hours - 30 minutes);
        _openBy(principal, r, 5);
        uint64 opened = uint64(block.timestamp);
        uint64 due = _deadline(r, 5);
        assertGe(due, opened + wa);
        assertLe(due, opened + wa + 2 * eta);

        vm.warp(signed + w);
        _openBy(challenger, r, 6);
        vm.warp(signed + w + 1);
        Settlement memory s7 = _rec(r, 7);
        vm.prank(challenger);
        vm.expectRevert(ValidityDispute.WindowClosed.selector);
        vd.open{value: BOND}(r, 7, s7);

        vm.warp(due);
        _answerAlone(r, 5);
        _payPosting(r, 5);
        assertEq(pd.batchOf(r, vd.answeredRoot(r, 5)).until, due + wp);
        vm.warp(due + wp);
        vm.expectRevert(Postings.NotWithheld.selector);
        pd.slashWithholding(r, 5, s5, 0, new bytes32[](0), rc);
        vm.warp(due + wp + 1);
        vm.prank(challenger);
        pd.slashWithholding(r, 5, s5, 0, new bytes32[](0), rc);
        (, uint256 left) = acc.answererOf(r);
        assertEq(left, 0);

        vm.warp(_deadline(r, 6) + 1);
        vd.expire(r, 6);
        (bool frozen,) = acc.frozenOf(r);
        assertTrue(frozen);
    }

    /// A settlement someone else challenged first: the principal joins that
    /// challenge for its gas alone, and the challenge then holds settlement,
    /// moves into the principal's queue, and on its answer asks for the
    /// sealed opening.
    function testPrincipalJoinsAChallengeSomeoneElseOpened() public {
        uint256 r = _register(AGENT_PK, 10);
        _settle(AGENT_PK, r, 5);
        _openBy(challenger, r, 5);
        (, uint32 before) = acc.frozenOf(r);
        assertEq(before, 0);
        Settlement memory s = _rec(r, 5);
        vm.prank(principal);
        uint256 g0 = gasleft();
        vd.join(r, 5, s);
        console.log("join another party's challenge", g0 - gasleft());
        (, uint32 held) = acc.frozenOf(r);
        assertEq(held, 1);
        assertLe(_deadline(r, 5), uint64(block.timestamp) + WINDOW + 2 * SLOT);
        vm.expectRevert(Reserve.Held.selector);
        this.settleAgain(AGENT_PK, r, 6);
        _answerAlone(r, 5);
        (, uint32 after_) = acc.frozenOf(r);
        assertEq(after_, 0);
        assertEq(vd.challengeOf(r, 5).deadline, uint64(block.timestamp));
        assertEq(pd.batchOf(r, vd.answeredRoot(r, 5)).due, 1);
        assertEq(pd.batchOf(r, vd.answeredRoot(r, 5)).until, 0);
    }

    function testOnlyThePrincipalJoins() public {
        uint256 r = _register(AGENT_PK, 10);
        _settle(AGENT_PK, r, 5);
        _openBy(challenger, r, 5);
        Settlement memory s = _rec(r, 5);
        vm.prank(address(0xD00D));
        vm.expectRevert(ValidityDispute.NotPrincipal.selector);
        vd.join(r, 5, s);
        vm.prank(principal);
        vd.join(r, 5, s);
        vm.prank(principal);
        vm.expectRevert(ValidityDispute.AlreadyChallenged.selector);
        vd.join(r, 5, s);
    }

    /// Someone else challenged and the answerer answered before the
    /// principal's decision time: the principal joins the answered challenge,
    /// nothing is held, and the join asks for the sealed opening and the
    /// proof, due within the delivery wait from the payment for the postings
    /// and slashable after.
    function testPrincipalJoinsAnAnsweredChallenge() public {
        (uint256 r, ) = _registerWithAnswerer();
        _settle(AGENT_PK, r, 5);
        Settlement memory s = _rec(r, 5);
        BatchReceipt memory rc = _receiptOver(ANSWERER_PK, r, vd.leafHash(r, 5, s), keccak256(_sealed(5)), uint64(block.timestamp));
        _openBy(challenger, r, 5);
        _answerAlone(r, 5);
        vm.expectRevert(Postings.NotDue.selector);
        pd.deliver(r, 5, s, 0, new bytes32[](0), rc, _sealed(5), new bytes32[](0));
        vm.warp(block.timestamp + 3600);
        vm.prank(principal);
        vd.join(r, 5, s);
        _payPosting(r, 5);
        (, uint32 held) = acc.frozenOf(r);
        assertEq(held, 0);
        assertEq(uint256(vd.challengeOf(r, 5).status), uint256(ValidityDispute.Status.Answered));
        assertEq(vd.challengeOf(r, 5).deadline, uint64(block.timestamp));
        assertEq(pd.batchOf(r, vd.answeredRoot(r, 5)).until, uint64(block.timestamp) + DELIVERY);
        vm.prank(principal);
        vm.expectRevert(ValidityDispute.AlreadyChallenged.selector);
        vd.join(r, 5, s);
        vm.warp(block.timestamp + DELIVERY + 1);
        vm.prank(challenger);
        pd.slashWithholding(r, 5, s, 0, new bytes32[](0), rc);
        (, uint256 left) = acc.answererOf(r);
        assertEq(left, 0);
    }

    /// The same, with the answerer delivering after the join: the duty ends.
    function testAnsweredChallengeJoinedThenDelivered() public {
        (uint256 r, ) = _registerWithAnswerer();
        _settle(AGENT_PK, r, 5);
        Settlement memory s = _rec(r, 5);
        BatchReceipt memory rc = _receiptOver(ANSWERER_PK, r, vd.leafHash(r, 5, s), keccak256(_sealed(5)), uint64(block.timestamp));
        _openBy(challenger, r, 5);
        _answerAlone(r, 5);
        vm.prank(principal);
        vd.join(r, 5, s);
        _payPosting(r, 5);
        pd.deliver(r, 5, s, 0, new bytes32[](0), rc, _sealed(5), new bytes32[](0));
        _post(r, _proof(100));
        assertEq(pd.deliveredUnder(vd.key(r, 5)), rc.sealedRoot);
        vm.warp(block.timestamp + DELIVERY + 1);
        vm.expectRevert(Postings.NotWithheld.selector);
        pd.slashWithholding(r, 5, s, 0, new bytes32[](0), rc);
    }

    function testJoinAfterTheAcceptanceWindowRefused() public {
        uint256 r = _register(AGENT_PK, 10);
        _settle(AGENT_PK, r, 5);
        _openBy(challenger, r, 5);
        Settlement memory s = _rec(r, 5);
        vm.warp(block.timestamp + ACCEPT + 1);
        vm.prank(principal);
        vm.expectRevert(ValidityDispute.WindowClosed.selector);
        vd.join(r, 5, s);
    }

    /// The named answerer's postings of the receipted proof, once its batch
    /// is bound, are refunded from the pool at the domain's base fee;
    /// anyone else's are not, nor the answerer's own before the binding.
    function testPostingIsRefundedFromThePool() public {
        (uint256 r, Settlement memory s, BatchReceipt memory rc) = _answered();
        vm.fee(1 gwei);
        vm.txGasPrice(2 gwei);
        address ans = vm.addr(ANSWERER_PK);
        uint256 base = pd.credit(ans);
        vm.startPrank(ans);
        _post(r, _proof(200));
        vm.stopPrank();
        assertEq(pd.credit(ans), base);
        vm.prank(address(0xD00D));
        pd.bindPosting(r, 5, s, 0, new bytes32[](0), rc);
        assertEq(_pool(r, 5), POSTING);
        vm.prank(address(0xD00D));
        pd.postProof(r, rc.proofHash, 0, _proof(pd.CHUNK()), false);
        assertEq(pd.credit(address(0xD00D)), 0);
        assertEq(_pool(r, 5), POSTING);
        vm.startPrank(ans);
        _post(r, _proof(100));
        vm.stopPrank();
        uint256 paid = pd.credit(ans) - base;
        assertGt(paid, 0);
        assertEq(_pool(r, 5), POSTING - paid);
        assertFalse(pd.batchOf(r, vd.answeredRoot(r, 5)).lapsed);
    }

    /// Chunks under a hash no receipt bound are not refunded, so the answerer
    /// cannot spend the pool on junk and lapse its own duty.
    function testJunkPostingIsNotRefunded() public {
        (uint256 r, Settlement memory s, BatchReceipt memory rc) = _answered();
        address ans = vm.addr(ANSWERER_PK);
        vm.prank(ans);
        pd.bindPosting(r, 5, s, 0, new bytes32[](0), rc);
        uint256 pool = _pool(r, 5);
        vm.fee(1e18);
        vm.txGasPrice(1e18);
        bytes memory chunk = _proof(pd.CHUNK());
        vm.prank(ans);
        pd.postProof(r, keccak256("junk"), 0, chunk, false);
        assertEq(_pool(r, 5), pool);
        assertFalse(pd.batchOf(r, vd.answeredRoot(r, 5)).lapsed);
        vm.fee(0);
        vm.txGasPrice(0);
        vm.warp(block.timestamp + DELIVERY + 1);
        vm.prank(challenger);
        pd.slashWithholding(r, 5, s, 0, new bytes32[](0), rc);
        (, uint256 left) = acc.answererOf(r);
        assertEq(left, 0);
    }

    /// A domain refund the pool cannot pay empties it but lapses nothing: the
    /// blob way remains, so the answerer is still slashed if it posts neither.
    function testAnEmptyPoolOnTheDomainLapsesNothing() public {
        (uint256 r, Settlement memory s, BatchReceipt memory rc) = _answered();
        vm.prank(vm.addr(ANSWERER_PK));
        pd.bindPosting(r, 5, s, 0, new bytes32[](0), rc);
        vm.fee(1e18);
        vm.txGasPrice(1e18);
        bytes memory chunk = _proof(pd.CHUNK());
        vm.prank(vm.addr(ANSWERER_PK));
        pd.postProof(r, rc.proofHash, 0, chunk, false);
        assertEq(_pool(r, 5), 0);
        assertFalse(pd.batchOf(r, vd.answeredRoot(r, 5)).lapsed);
        vm.fee(0);
        vm.txGasPrice(0);
        vm.warp(block.timestamp + DELIVERY + 1);
        vm.prank(challenger);
        pd.slashWithholding(r, 5, s, 0, new bytes32[](0), rc);
        (, uint256 left) = acc.answererOf(r);
        assertEq(left, 0);
    }

    /// The domain's messenger relays BlobPosting's report, as a deposit from
    /// Ethereum does.
    function _blobsPosted(address poster, uint256 r, bytes32 root, bytes32 bh, uint256 cost, uint64 at) internal {
        vm.etch(MESSENGER, address(new MockL2Messenger(BLOB_POSTER)).code);
        vm.prank(MESSENGER);
        pd.blobsPosted(poster, r, root, bh, cost, at);
    }

    /// The answerer's blobs, reported in time, are refunded what BlobPosting
    /// measured and end the duty, with the opening never posted on the
    /// domain; a report from anyone but the messenger relaying BlobPosting
    /// is refused, and a report of other blobs, or another poster's, pays
    /// nothing and ends nothing.
    function testBlobsPostedEndTheDutyAndAreRefunded() public {
        (uint256 r, Settlement memory s, BatchReceipt memory rc) = _answered();
        address ans = vm.addr(ANSWERER_PK);
        bytes32 root = vd.answeredRoot(r, 5);
        pd.bindPosting(r, 5, s, 0, new bytes32[](0), rc);
        uint256 pool = _pool(r, 5);
        vm.expectRevert(Postings.NotMessenger.selector);
        pd.blobsPosted(ans, r, root, BLOBS_HASH, 1 ether, uint64(block.timestamp));
        vm.etch(MESSENGER, address(new MockL2Messenger(address(0xBAD))).code);
        vm.prank(MESSENGER);
        vm.expectRevert(Postings.NotMessenger.selector);
        pd.blobsPosted(ans, r, root, BLOBS_HASH, 1 ether, uint64(block.timestamp));
        _blobsPosted(ans, r, root, keccak256("other blobs"), 0.01 ether, uint64(block.timestamp));
        _blobsPosted(challenger, r, root, BLOBS_HASH, 0.01 ether, uint64(block.timestamp));
        assertEq(_pool(r, 5), pool);
        assertEq(pd.credit(ans), 0);
        _blobsPosted(ans, r, root, BLOBS_HASH, 0.01 ether, uint64(block.timestamp));
        assertEq(pd.credit(ans), 0.01 ether);
        assertEq(_pool(r, 5), pool - 0.01 ether);
        vm.warp(block.timestamp + DELIVERY + 1);
        vm.expectRevert(Postings.NotWithheld.selector);
        pd.slashWithholding(r, 5, s, 0, new bytes32[](0), rc);
    }

    /// A blob refund the pool cannot pay empties it and lapses that batch's
    /// duty: the answerer is not slashed for what it was not paid to post.
    /// The pool falls short only when the domain's fee has risen beyond the
    /// factor since the payment, since a blob refund is never more than the
    /// domain way costs.
    function testAnEmptyPoolForBlobsLapsesTheDuty() public {
        (uint256 r, Settlement memory s, BatchReceipt memory rc) = _answered();
        address ans = vm.addr(ANSWERER_PK);
        bytes32 root = vd.answeredRoot(r, 5);
        pd.bindPosting(r, 5, s, 0, new bytes32[](0), rc);
        uint256 pool = _pool(r, 5);
        vm.fee(3 gwei);
        assertGt(pd.domainCost(), pool);
        vm.expectEmit(true, false, false, true, address(pd));
        emit Postings.PostingLapsed(r, root);
        _blobsPosted(ans, r, root, BLOBS_HASH, pool + 1, uint64(block.timestamp));
        assertTrue(pd.batchOf(r, root).lapsed);
        assertEq(_pool(r, 5), 0);
        assertEq(pd.credit(ans), pool);
        vm.warp(block.timestamp + DELIVERY + 1);
        vm.expectRevert(Postings.NotWithheld.selector);
        pd.slashWithholding(r, 5, s, 0, new bytes32[](0), rc);
    }

    /// A blob posting is refunded no more than posting the batch on the
    /// domain costs when the report arrives, so the answerer's choice of way
    /// cannot take more from the pool than the deposit was sized to; and
    /// once blobs were reported, the domain way is no longer refunded.
    function testBlobRefundIsCappedAtTheDomainWay() public {
        (uint256 r, Settlement memory s, BatchReceipt memory rc) = _answered();
        address ans = vm.addr(ANSWERER_PK);
        bytes32 root = vd.answeredRoot(r, 5);
        pd.bindPosting(r, 5, s, 0, new bytes32[](0), rc);
        uint256 cap = pd.domainCost();
        assertEq(cap, POSTING / 2);
        _blobsPosted(ans, r, root, BLOBS_HASH, 1 ether, uint64(block.timestamp));
        assertEq(pd.credit(ans), cap);
        assertEq(_pool(r, 5), POSTING - cap);
        assertEq(pd.batchOf(r, root).refunded, cap);
        assertFalse(pd.batchOf(r, root).lapsed);
        vm.txGasPrice(1 gwei);
        vm.prank(ans);
        pd.postProof(r, rc.proofHash, 0, _proof(pd.CHUNK()), false);
        assertEq(pd.credit(ans), cap);
        vm.warp(block.timestamp + DELIVERY + 1);
        vm.expectRevert(Postings.NotWithheld.selector);
        pd.slashWithholding(r, 5, s, 0, new bytes32[](0), rc);
    }

    /// A lapse is the batch's alone: another batch of the delegation, whose
    /// postings the pool still covers, keeps its duty.
    function testLapseIsPerBatch() public {
        (uint256 r, ) = _registerWithAnswerer();
        _settle(AGENT_PK, r, 5);
        _settle(AGENT_PK, r, 6);
        Settlement memory s5 = _rec(r, 5);
        Settlement memory s6 = _rec(r, 6);
        uint64 at = uint64(block.timestamp);
        BatchReceipt memory rc5 = _receiptOver(ANSWERER_PK, r, vd.leafHash(r, 5, s5), keccak256(_sealed(5)), at);
        BatchReceipt memory rc6 =
            _receiptBlobs(ANSWERER_PK, r, vd.leafHash(r, 6, s6), keccak256(_sealed(6)), keccak256("other proof"), keccak256("other blobs"), at);
        _openBy(principal, r, 5);
        _answerAlone(r, 5);
        _payPosting(r, 5);
        _openBy(principal, r, 6);
        _answerAlone(r, 6);
        _payPosting(r, 6);
        address ans = vm.addr(ANSWERER_PK);
        pd.bindPosting(r, 5, s5, 0, new bytes32[](0), rc5);
        vm.fee(3 gwei);
        _blobsPosted(ans, r, vd.answeredRoot(r, 5), BLOBS_HASH, _pool(r, 5) + 1, at);
        vm.fee(1 gwei);
        assertTrue(pd.batchOf(r, vd.answeredRoot(r, 5)).lapsed);
        assertEq(_pool(r, 6), POSTING);
        pd.bindPosting(r, 6, s6, 0, new bytes32[](0), rc6);
        assertFalse(pd.batchOf(r, vd.answeredRoot(r, 6)).lapsed);
        vm.warp(block.timestamp + DELIVERY + 1);
        vm.expectRevert(Postings.NotWithheld.selector);
        pd.slashWithholding(r, 5, s5, 0, new bytes32[](0), rc5);
        vm.prank(challenger);
        pd.slashWithholding(r, 6, s6, 0, new bytes32[](0), rc6);
        (, uint256 left) = acc.answererOf(r);
        assertEq(left, 0);
    }

    /// A sequencer that holds the report back delays it, but the posting
    /// counts from the Ethereum block it was made in: the report may arrive
    /// after the deadline and still end the duty and be refunded. Until the
    /// inclusion wait after the deadline has passed, nothing can be slashed
    /// and the pool does not return.
    function testCensoredReportStillCounts() public {
        _redeploy(_withInclusion(12 hours));
        (uint256 r, Settlement memory s, BatchReceipt memory rc) = _answered();
        address ans = vm.addr(ANSWERER_PK);
        bytes32 root = vd.answeredRoot(r, 5);
        uint64 due = pd.batchOf(r, root).until;
        pd.bindPosting(r, 5, s, 0, new bytes32[](0), rc);
        vm.warp(due + 1);
        vm.expectRevert(Postings.NotWithheld.selector);
        pd.slashWithholding(r, 5, s, 0, new bytes32[](0), rc);
        vm.expectRevert(Postings.TooEarly.selector);
        pd.returnPosting(r, root);
        vm.warp(due + 11 hours);
        _blobsPosted(ans, r, root, BLOBS_HASH, 0.01 ether, due - 1);
        assertEq(pd.credit(ans), 0.01 ether);
        vm.warp(due + 12 hours + 1);
        vm.expectRevert(Postings.NotWithheld.selector);
        pd.slashWithholding(r, 5, s, 0, new bytes32[](0), rc);
        pd.returnPosting(r, root);
    }

    /// The same delay with blobs posted after the deadline: the report pays
    /// nothing, and once the inclusion wait is over the receipt slashes.
    function testBlobsPostedLateSlash() public {
        _redeploy(_withInclusion(12 hours));
        (uint256 r, Settlement memory s, BatchReceipt memory rc) = _answered();
        address ans = vm.addr(ANSWERER_PK);
        bytes32 root = vd.answeredRoot(r, 5);
        uint64 due = pd.batchOf(r, root).until;
        pd.bindPosting(r, 5, s, 0, new bytes32[](0), rc);
        vm.warp(due + 2 hours);
        _blobsPosted(ans, r, root, BLOBS_HASH, 0.01 ether, due + 1);
        assertEq(pd.credit(ans), 0);
        vm.warp(due + 12 hours);
        vm.expectRevert(Postings.NotWithheld.selector);
        pd.slashWithholding(r, 5, s, 0, new bytes32[](0), rc);
        vm.warp(due + 12 hours + 1);
        vm.prank(challenger);
        pd.slashWithholding(r, 5, s, 0, new bytes32[](0), rc);
        (, uint256 left) = acc.answererOf(r);
        assertEq(left, 0);
    }

    /// A fresh reserve and dispute, since a reserve takes its dispute once.
    function _redeploy(Postings.Params memory q) internal {
        acc = new Reserve(DOMAIN, address(token), address(0), address(new Poseidon2Goldilocks()), 1 hours, ACCEPT + 1 hours);
        _deploy(_params(ACCEPT, WINDOW, SLOT, DELIVERY), q);
        vm.prank(principal);
        token.approve(address(acc), type(uint256).max);
    }

    function _withInclusion(uint64 wait) internal pure returns (Postings.Params memory q) {
        q = _pparams();
        q.inclusionWait = wait;
    }

    /// A batch binds once, only to a receipt for the root its answer proved,
    /// and only after the principal's challenge is answered.
    function testBindingNeedsTheAnsweredBatch() public {
        (uint256 r, ) = _registerWithAnswerer();
        _settle(AGENT_PK, r, 5);
        Settlement memory s = _rec(r, 5);
        BatchReceipt memory rc = _receiptOver(ANSWERER_PK, r, vd.leafHash(r, 5, s), keccak256(_sealed(5)), uint64(block.timestamp));
        _openBy(principal, r, 5);
        vm.expectRevert(Postings.NotDue.selector);
        pd.bindPosting(r, 5, s, 0, new bytes32[](0), rc);
        _answerAlone(r, 5);
        _payPosting(r, 5);
        bytes32[] memory path = new bytes32[](1);
        path[0] = keccak256("sibling");
        BatchReceipt memory other = _receiptOver(ANSWERER_PK, r, _climb(vd.leafHash(r, 5, s), 0, path), keccak256(_sealed(5)), rc.receivedAt);
        vm.expectRevert(Postings.WrongBatch.selector);
        pd.bindPosting(r, 5, s, 0, path, other);
        vm.expectEmit(true, false, false, true, address(pd));
        emit Postings.PostingBound(r, vd.leafHash(r, 5, s), rc.proofHash);
        pd.bindPosting(r, 5, s, 0, new bytes32[](0), rc);
        vm.expectRevert(Postings.AlreadyBound.selector);
        pd.bindPosting(r, 5, s, 0, new bytes32[](0), rc);
        vm.warp(block.timestamp + DELIVERY + 1);
        vm.expectRevert(Postings.TooLate.selector);
        pd.deliver(r, 5, s, 0, new bytes32[](0), rc, _sealed(5), new bytes32[](0));
    }

    /// A second receipt for a bound batch naming another proof is the
    /// answerer's second signature for one batch, and slashes it at once.
    function testSecondReceiptForABoundBatchSlashes() public {
        (uint256 r, Settlement memory s, BatchReceipt memory rc) = _answered();
        BatchReceipt memory junk = _receiptFor(ANSWERER_PK, r, vd.leafHash(r, 5, s), keccak256(_sealed(5)), keccak256("junk"), rc.receivedAt);
        vm.prank(vm.addr(ANSWERER_PK));
        pd.bindPosting(r, 5, s, 0, new bytes32[](0), junk);
        vm.prank(challenger);
        pd.slashWithholding(r, 5, s, 0, new bytes32[](0), rc);
        (, uint256 left) = acc.answererOf(r);
        assertEq(left, 0);
    }

    /// The principal's challenges send ether for the answers' gas alone; the
    /// price of proving is set aside from the deposit, once for each batch
    /// the challenges could fall in. A challenge short of the gas is refused;
    /// one carrying more, as a monitor sends against a fee that moves, adds
    /// the excess to the gas pool, and another party's excess over its bond
    /// is credited back to it.
    function testPrincipalChallengesCarryOnlyGas() public {
        uint256 r = _register(AGENT_PK, 10);
        _settle(AGENT_PK, r, 40);
        _settle(AGENT_PK, r, 41);
        Settlement memory s = _rec(r, 40);
        _openMany(AGENT_PK, r, 3, principal);
        assertEq(acc.earmarked(r), COST);
        uint256 price = vd.principalPrice(r, 1, s.time, s.time);
        assertLt(price, 0.002 ether);
        uint256 before = vd.gasPool(r);
        vm.prank(principal);
        vm.expectRevert(ValidityDispute.BondTooSmall.selector);
        vd.open{value: price - 1}(r, 40, s);
        vm.prank(principal);
        vd.open{value: price + 7}(r, 40, s);
        assertEq(vd.gasPool(r), before + price + 7);
        assertEq(acc.earmarked(r), COST);
        vm.prank(challenger);
        vd.open{value: BOND + 5}(r, 41, _rec(r, 41));
        assertEq(vd.credit(challenger), 5);
    }

    /// A challenge holds settlement whatever the principal has left: with
    /// less left in the deposit than one batch's proving, the reserve sets
    /// aside what there is, the hold stands, and the answer is paid that.
    function testHoldNeedsNoFunds() public {
        vm.prank(principal);
        uint256 r = _accepted(acc.register(TermsOf.make(vm.addr(AGENT_PK), 1_000_000, 1_000, 86_400, Reserve.Funding.Deposit, 3, bytes32(uint256(40)), bytes32(uint256(41)), uint64(block.timestamp) + LIFE)));
        _settle(AGENT_PK, r, 5);
        _openBy(principal, r, 5);
        assertEq(acc.earmarked(r), 2);
        vm.expectRevert(Reserve.Held.selector);
        this.settleAgain(AGENT_PK, r, 6);
        _answerAlone(r, 5);
        assertEq(acc.tokenCredit(vm.addr(AGENT_PK)), 2);
        assertEq(acc.earmarked(r), 0);
    }

    /// Funded through Permit2, the money stays in the principal's wallet, and
    /// the reserve sets the proving price aside from it through the
    /// allowance; with the allowance withdrawn it sets nothing aside, and the
    /// challenge still holds.
    function testEarmarkThroughPermit2() public {
        bytes memory code = vm.getCode("lib/permit2/out/Permit2.sol/Permit2.json");
        address permit2;
        assembly {
            permit2 := create(0, add(code, 32), mload(code))
        }
        acc = new Reserve(DOMAIN, address(token), permit2, address(new Poseidon2Goldilocks()), 1 hours, ACCEPT + 1 hours);
        _deploy(_params(ACCEPT, WINDOW, SLOT, DELIVERY), _pparams());
        vm.startPrank(principal);
        token.approve(permit2, type(uint256).max);
        IPermit2Approve(permit2).approve(address(token), address(acc), type(uint160).max, type(uint48).max);
        uint256 r = acc.register(TermsOf.make(vm.addr(AGENT_PK), 1_000_000, 1_000, 86_400, Reserve.Funding.Permit2, 0, bytes32(uint256(50)), bytes32(uint256(51)), uint64(block.timestamp) + LIFE));
        vm.stopPrank();
        _accepted(r);
        _settle(AGENT_PK, r, 5);
        _settle(AGENT_PK, r, 6);
        uint256 t0 = token.balanceOf(principal);
        _openBy(principal, r, 5);
        assertEq(acc.earmarked(r), COST);
        assertEq(token.balanceOf(principal), t0 - COST);
        _answerAlone(r, 5);
        assertEq(acc.tokenCredit(vm.addr(AGENT_PK)), COST);
        vm.prank(principal);
        IPermit2Approve(permit2).approve(address(token), address(acc), 0, type(uint48).max);
        _openBy(principal, r, 6);
        assertEq(acc.earmarked(r), 0);
        vm.expectRevert(Reserve.Held.selector);
        this.settleAgain(AGENT_PK, r, 7);
    }

    /// A request nobody pays for binds no one: nothing is refunded, nothing
    /// is slashed, and the payment is refused once the delivery wait after
    /// the request has passed.
    function testUnpaidRequestLapses() public {
        (uint256 r, ) = _registerWithAnswerer();
        _settle(AGENT_PK, r, 5);
        Settlement memory s = _rec(r, 5);
        BatchReceipt memory rc = _receiptOver(ANSWERER_PK, r, vd.leafHash(r, 5, s), keccak256(_sealed(5)), uint64(block.timestamp));
        _openBy(principal, r, 5);
        _answerAlone(r, 5);
        bytes32 root = vd.answeredRoot(r, 5);
        assertEq(pd.batchOf(r, root).until, 0);
        uint256 v = pd.postingTopUp(r, root);
        vm.prank(principal);
        vm.expectRevert(Postings.DepositTooSmall.selector);
        pd.payPosting{value: v - 1}(r, root);
        vm.warp(block.timestamp + DELIVERY + 1);
        vm.prank(principal);
        vm.expectRevert(Postings.TooLate.selector);
        pd.payPosting{value: v}(r, root);
        vm.warp(block.timestamp + DELIVERY + 1);
        vm.expectRevert(Postings.NotWithheld.selector);
        pd.slashWithholding(r, 5, s, 0, new bytes32[](0), rc);
        vm.expectRevert(Postings.NothingToReturn.selector);
        pd.returnPosting(r, root);
    }

    /// A payment covers the requests filed before it: a later join of
    /// another settlement of the batch binds the answerer only once the
    /// principal pays again.
    function testLaterRequestNeedsItsOwnPayment() public {
        (uint256 r, ) = _registerWithAnswerer();
        uint256[] memory ids = new uint256[](2);
        uint64[] memory ds = new uint64[](2);
        Settlement[] memory ss = new Settlement[](2);
        for (uint256 i = 0; i < 2; ++i) {
            ids[i] = r;
            ds[i] = uint64(5 + i);
            ss[i] = _settle(AGENT_PK, r, ds[i]);
        }
        (bytes32 root, uint256[] memory at, bytes32[][] memory paths) = _tree(ids, ds);
        BatchReceipt memory rc = _receiptOver(ANSWERER_PK, r, root, keccak256(_sealed(5)), uint64(block.timestamp));
        _openBy(principal, r, 5);
        _openBy(challenger, r, 6);
        vd.answerBatch(_items(ids, ds, ss, at, paths), abi.encodePacked(root));
        _payPosting(r, 5);
        vm.warp(block.timestamp + 1 hours);
        vm.prank(principal);
        vd.join(r, 6, ss[1]);
        vm.warp(block.timestamp + DELIVERY + 1);
        vm.expectRevert(Postings.NotWithheld.selector);
        pd.slashWithholding(r, 6, ss[1], at[1], paths[1], rc);
        vm.prank(challenger);
        pd.slashWithholding(r, 5, ss[0], at[0], paths[0], rc);
        (, uint256 left) = acc.answererOf(r);
        assertEq(left, 0);
    }

    /// A join whose challenge keeps its own, earlier deadline leaves the
    /// principal's queue where it was.
    function testJoinKeepingItsDeadlineLeavesTheQueue() public {
        uint256 r = _register(AGENT_PK, 10);
        _settle(AGENT_PK, r, 5);
        _settle(AGENT_PK, r, 6);
        _openBy(principal, r, 5);
        _openBy(challenger, r, 6);
        address agent = vm.addr(AGENT_PK);
        uint64 last = vd.lastPrincipalDeadline(agent, principal);
        uint64 before = _deadline(r, 6);
        assertLt(before, last + 2 * SLOT);
        vm.prank(principal);
        vd.join(r, 6, _rec(r, 6));
        assertEq(_deadline(r, 6), before);
        assertEq(vd.lastPrincipalDeadline(agent, principal), last);
    }

    /// A posting forced in through Ethereum is refunded what including it on
    /// the domain costs, the same as one sent there, and nothing at the
    /// Ethereum base fee: forcing is the answerer's own cost.
    function testForcedPostingIsRefundedAtTheDomainFee() public {
        (uint256 r, Settlement memory s, BatchReceipt memory rc) = _answered();
        address ans = vm.addr(ANSWERER_PK);
        vm.prank(ans);
        pd.bindPosting(r, 5, s, 0, new bytes32[](0), rc);
        uint256 c0 = pd.credit(ans);
        vm.etch(0x4200000000000000000000000000000000000015, address(new FixedL1Block()).code);
        vm.fee(1 gwei);
        vm.txGasPrice(0);
        bytes memory chunk = _proof(pd.CHUNK());
        bytes32 h = rc.proofHash;
        vm.prank(ans);
        pd.postProof(r, h, 0, chunk, false);
        uint256 n = abi.encodeCall(Postings.postProof, (r, h, 0, chunk, false)).length;
        uint256 paid = pd.credit(ans) - c0;
        assertGe(paid, (21000 + 40 * n) * 1 gwei);
        assertLt(paid, (21000 + 40 * n) * 2 gwei);
    }

    /// Once no delivery is due, what is left of the pool is the principal's.
    function testUnspentPostingReturnsToThePrincipal() public {
        (uint256 r, , ) = _answered();
        bytes32 root = vd.answeredRoot(r, 5);
        vm.expectRevert(Postings.TooEarly.selector);
        pd.returnPosting(r, root);
        vm.warp(block.timestamp + DELIVERY + 1);
        pd.returnPosting(r, root);
        assertEq(pd.credit(principal), POSTING);
        vm.expectRevert(Postings.NothingToReturn.selector);
        pd.returnPosting(r, root);
    }

    /// One proof answers challenges against batches of two delegations: each
    /// settlement's path must reach the root the call names for it, and the
    /// proof is checked against all the roots at once.
    function testOneAnswerForSeveralBatches() public {
        uint256 a = _register(AGENT_PK, 10);
        uint256 b = _register(AGENT_PK, 20);
        _settle(AGENT_PK, a, 5);
        _settle(AGENT_PK, b, 6);
        _openBy(principal, a, 5);
        _openBy(challenger, b, 6);
        ValidityDispute.Item[] memory items = new ValidityDispute.Item[](2);
        items[0] = ValidityDispute.Item({id: a, digest: 5, s: _rec(a, 5), index: 0, path: new bytes32[](0)});
        items[1] = ValidityDispute.Item({id: b, digest: 6, s: _rec(b, 6), index: 0, path: new bytes32[](0)});
        bytes32[] memory roots = new bytes32[](2);
        roots[0] = vd.leafHash(a, 5, _rec(a, 5));
        roots[1] = vd.leafHash(b, 6, _rec(b, 6));
        uint256[] memory which = new uint256[](2);
        which[1] = 1;
        uint256[] memory swapped = new uint256[](2);
        swapped[0] = 1;
        vm.expectRevert(ValidityDispute.RootMismatch.selector);
        vd.answerBatches(items, swapped, roots, abi.encodePacked(roots));
        vm.expectRevert(bytes("values"));
        vd.answerBatches(items, which, roots, abi.encodePacked(roots[0]));
        uint256 g = gasleft();
        vd.answerBatches(items, which, roots, abi.encodePacked(roots));
        console.log("answer for two batches of two delegations", g - gasleft());
        assertEq(uint256(vd.challengeOf(a, 5).status), uint256(ValidityDispute.Status.Answered));
        assertEq(uint256(vd.challengeOf(b, 6).status), uint256(ValidityDispute.Status.Answered));
        assertEq(vd.answeredRoot(a, 5), roots[0]);
        assertEq(vd.answeredRoot(b, 6), roots[1]);
        // The principal's challenge is paid at cost, the other party's its bond.
        assertGt(vd.credit(vm.addr(AGENT_PK)), BOND + COST);
        assertLt(vd.credit(vm.addr(AGENT_PK)), BOND + COST + 0.002 ether);
    }

    /// A delegation is the agent's only once it accepts it: nothing settles
    /// before, and nobody else can accept for it or post another bond.
    function testNothingSettlesBeforeTheAgentAccepts() public {
        address agent = vm.addr(AGENT_PK);
        vm.prank(principal);
        uint256 r = acc.register(TermsOf.make(agent, 1_000_000, 1_000, 86_400, Reserve.Funding.Deposit, 100_000_000, bytes32(uint256(10)), bytes32(uint256(11)), uint64(block.timestamp) + LIFE));
        vm.expectRevert(Reserve.NotAccepted.selector);
        this.settleAgain(AGENT_PK, r, 5);
        vm.prank(principal);
        vm.expectRevert(Reserve.NotAgent.selector);
        acc.accept{value: AGENT_BOND}(r);
        vm.deal(agent, 3 ether);
        vm.prank(agent);
        vm.expectRevert(Reserve.WrongBond.selector);
        acc.accept{value: AGENT_BOND - 1}(r);
        assertFalse(acc.serves(agent, principal));
        vm.prank(agent);
        acc.accept{value: AGENT_BOND}(r);
        assertTrue(acc.serves(agent, principal));
        vm.prank(agent);
        vm.expectRevert(Reserve.NotAcceptable.selector);
        acc.accept{value: AGENT_BOND}(r);
        _settle(AGENT_PK, r, 5);
    }

    /// An agent that declared its capacity accepts no principal beyond it,
    /// and delegations it never accepted count for nothing: a stranger
    /// registering to it fills no place.
    function testAgentCapacityLimitsItsPrincipals() public {
        address agent = vm.addr(AGENT_PK);
        vm.prank(agent);
        acc.declareCapacity(1);
        Reserve.Terms memory t = TermsOf.make(agent, 1_000_000, 1_000, 86_400, Reserve.Funding.Deposit, 0, bytes32(uint256(1)), bytes32(uint256(2)), uint64(block.timestamp) + LIFE);
        for (uint160 i = 1; i <= 5; ++i) {
            vm.prank(address(0x5B1100 + i));
            acc.register(t);
        }
        assertEq(acc.servedCount(agent), 0);
        _register(AGENT_PK, 10);
        assertEq(acc.servedCount(agent), 1);
        _register(AGENT_PK, 20);
        assertEq(acc.servedCount(agent), 1);
        vm.prank(address(0xB0B5));
        uint256 other = acc.register(t);
        vm.deal(agent, 2 ether);
        vm.prank(agent);
        vm.expectRevert(Reserve.OverCapacity.selector);
        acc.accept{value: AGENT_BOND}(other);
        vm.prank(agent);
        vm.expectRevert(Reserve.OverCapacity.selector);
        acc.declareCapacity(0);
    }

    /// Principals accepted before the agent declared are counted, so the
    /// agent cannot declare fewer than it already serves.
    function testPrincipalsBeforeTheDeclarationCount() public {
        address agent = vm.addr(AGENT_PK);
        _register(AGENT_PK, 10);
        vm.prank(address(0xB0B5));
        _accepted(acc.register(TermsOf.make(agent, 1_000_000, 1_000, 86_400, Reserve.Funding.Deposit, 0, bytes32(uint256(1)), bytes32(uint256(2)), uint64(block.timestamp) + LIFE)));
        assertEq(acc.servedCount(agent), 2);
        assertTrue(acc.serves(agent, address(0xB0B5)));
        vm.prank(agent);
        vm.expectRevert(Reserve.OverCapacity.selector);
        acc.declareCapacity(1);
        vm.prank(agent);
        acc.declareCapacity(2);
        vm.prank(address(0xCAFE));
        uint256 third = acc.register(TermsOf.make(agent, 1_000_000, 1_000, 86_400, Reserve.Funding.Deposit, 0, bytes32(uint256(1)), bytes32(uint256(2)), uint64(block.timestamp) + LIFE));
        vm.deal(agent, 2 ether);
        vm.prank(agent);
        vm.expectRevert(Reserve.OverCapacity.selector);
        acc.accept{value: AGENT_BOND}(third);
    }

    /// The principal cancels its own open challenge once the late batch has
    /// reached it: the hold lifts, the gas pool comes back to it and what was
    /// set aside goes back to the deposit, the agent earns nothing, and the
    /// challenge can be neither answered nor expired.
    function testCancelLiftsTheHoldAndThePoolReturns() public {
        uint256 r = _register(AGENT_PK, 10);
        _settle(AGENT_PK, r, 5);
        _openBy(principal, r, 5);
        vm.expectRevert(Reserve.Held.selector);
        this.settleAgain(AGENT_PK, r, 6);
        vm.prank(principal);
        vm.expectEmit(true, false, false, true, address(vd));
        emit ValidityDispute.Cancelled(r, 5);
        vd.cancel(r, 5);
        assertEq(uint256(vd.challengeOf(r, 5).status), uint256(ValidityDispute.Status.Cancelled));
        assertEq(vd.credit(vm.addr(AGENT_PK)), 0);
        assertEq(vd.openCount(r), 0);
        assertEq(vd.openByPrincipal(r), 0);
        uint256 pool = vd.gasPool(r);
        assertGt(pool, 0);
        assertEq(acc.earmarked(r), COST);
        vd.returnProving(r);
        assertEq(vd.credit(principal), pool);
        assertEq(vd.gasPool(r), 0);
        assertEq(acc.earmarked(r), 0);
        _settle(AGENT_PK, r, 6);
        Settlement memory s = _rec(r, 5);
        bytes memory proof = abi.encodePacked(vd.leafHash(r, 5, s));
        vm.expectRevert(ValidityDispute.NotOpen.selector);
        vd.answer(r, 5, s, 0, new bytes32[](0), proof);
        vm.warp(_deadline(r, 5) + 1);
        vm.expectRevert(ValidityDispute.NotOpen.selector);
        vd.expire(r, 5);
        uint256 t0 = token.balanceOf(principal);
        vm.prank(principal);
        acc.freeze(r);
        vm.prank(principal);
        acc.reclaim(r);
        assertEq(token.balanceOf(principal), t0 + 100_000_000 - 2);
    }

    /// A whole batch's challenges cancel in one call: every one closes, the
    /// hold lifts once the last does, and nobody but the principal or its
    /// monitor can cancel them.
    function testCancelManyCancelsEach() public {
        uint256 r = _register(AGENT_PK, 10);
        _settle(AGENT_PK, r, 5);
        _settle(AGENT_PK, r, 6);
        _settle(AGENT_PK, r, 7);
        uint64[] memory ds = new uint64[](3);
        Settlement[] memory ss = new Settlement[](3);
        for (uint256 i = 0; i < 3; ++i) {
            ds[i] = uint64(5 + i);
            ss[i] = _rec(r, ds[i]);
        }
        uint256 price = vd.principalPrice(r, 3, ss[0].time, ss[2].time);
        vm.prank(principal);
        vd.openMany{value: price}(r, ds, ss);
        assertEq(vd.openByPrincipal(r), 3);
        vm.prank(challenger);
        vm.expectRevert(ValidityDispute.NotPrincipal.selector);
        vd.cancelMany(r, ds);
        vm.prank(principal);
        vd.cancelMany(r, ds);
        for (uint256 i = 0; i < 3; ++i) assertEq(uint256(vd.challengeOf(r, ds[i]).status), uint256(ValidityDispute.Status.Cancelled));
        assertEq(vd.openByPrincipal(r), 0);
        assertEq(vd.openCount(r), 0);
        _settle(AGENT_PK, r, 8);
        uint256 before = vd.credit(principal);
        vd.returnProving(r);
        assertEq(vd.credit(principal) - before, price);
        assertEq(acc.earmarked(r), 0);
    }

    /// The monitor address cancels as the principal does; nobody else can,
    /// and no one cancels after the deadline.
    function testOnlyThePrincipalSideCancelsInTime() public {
        address mon = address(0x3011);
        vm.deal(mon, 10 ether);
        Reserve.Terms memory t = TermsOf.make(vm.addr(AGENT_PK), 1_000_000, 1_000, 86_400, Reserve.Funding.Deposit, 100_000_000, bytes32(uint256(10)), bytes32(uint256(11)), uint64(block.timestamp) + LIFE);
        t.monitor = mon;
        vm.prank(principal);
        uint256 r = _accepted(acc.register(t));
        _settle(AGENT_PK, r, 5);
        _settle(AGENT_PK, r, 6);
        _openBy(mon, r, 5);
        _openBy(mon, r, 6);
        vm.prank(challenger);
        vm.expectRevert(ValidityDispute.NotPrincipal.selector);
        vd.cancel(r, 5);
        vm.prank(vm.addr(AGENT_PK));
        vm.expectRevert(ValidityDispute.NotPrincipal.selector);
        vd.cancel(r, 5);
        vm.prank(principal);
        vd.cancel(r, 5);
        assertEq(vd.credit(mon), 0);
        assertEq(vd.openByPrincipal(r), 1);
        vm.warp(_deadline(r, 6) + 1);
        vm.prank(mon);
        vm.expectRevert(ValidityDispute.TooLate.selector);
        vd.cancel(r, 6);
    }

    /// Another party's challenge is not the principal's to cancel. Once the
    /// principal joined it, cancelling withdraws the join alone: the hold
    /// lifts and the challenge stays open, still the other party's.
    function testCancellingAJoinLeavesTheOtherChallenge() public {
        uint256 r = _register(AGENT_PK, 10);
        _settle(AGENT_PK, r, 5);
        _openBy(challenger, r, 5);
        vm.prank(principal);
        vm.expectRevert(ValidityDispute.NotCancellable.selector);
        vd.cancel(r, 5);
        Settlement memory s = _rec(r, 5);
        vm.prank(principal);
        vd.join(r, 5, s);
        vm.expectRevert(Reserve.Held.selector);
        this.settleAgain(AGENT_PK, r, 6);
        vm.prank(principal);
        vd.cancel(r, 5);
        ValidityDispute.Challenge memory c = vd.challengeOf(r, 5);
        assertEq(uint256(c.status), uint256(ValidityDispute.Status.Open));
        assertFalse(c.byPrincipal);
        assertEq(vd.credit(principal), 0);
        _settle(AGENT_PK, r, 6);
        _answerAlone(r, 5);
        assertEq(vd.credit(vm.addr(AGENT_PK)), BOND);
    }

    /// Cancelling an answered challenge withdraws its request: nothing is due
    /// under it, the batch is no longer refunded for postings, and the
    /// answerer cannot be slashed for posting nothing.
    function testCancelWithdrawsTheRequest() public {
        (uint256 r, Settlement memory s, BatchReceipt memory rc) = _answered();
        address ans = vm.addr(ANSWERER_PK);
        vm.prank(ans);
        pd.bindPosting(r, 5, s, 0, new bytes32[](0), rc);
        uint256 pool = _pool(r, 5);
        vm.prank(principal);
        vd.cancel(r, 5);
        assertEq(uint256(vd.challengeOf(r, 5).status), uint256(ValidityDispute.Status.Cancelled));
        assertEq(pd.batchOf(r, vd.answeredRoot(r, 5)).due, 0);
        vm.fee(1 gwei);
        bytes memory chunk = _proof(100);
        vm.prank(ans);
        pd.postProof(r, rc.proofHash, 0, chunk, true);
        assertEq(_pool(r, 5), pool);
        vm.expectRevert(Postings.NotDue.selector);
        pd.deliver(r, 5, s, 0, new bytes32[](0), rc, _sealed(5), new bytes32[](0));
        vm.warp(block.timestamp + DELIVERY + 1);
        vm.expectRevert(Postings.NotWithheld.selector);
        pd.slashWithholding(r, 5, s, 0, new bytes32[](0), rc);
        vm.prank(principal);
        vm.expectRevert(ValidityDispute.NotCancellable.selector);
        vd.cancel(r, 5);
    }

    /// The bond follows the Ethereum base fee the domain records when the
    /// challenge opens, times the fee factor, and the challenge keeps the bond
    /// it opened with: the answer is credited that amount.
    function testBondFollowsTheEthereumFee() public {
        uint256 r = _register(AGENT_PK, 10);
        _settle(AGENT_PK, r, 5);
        _settle(AGENT_PK, r, 6);
        assertEq(vd.challengeBond(), BOND);
        vm.etch(0x4200000000000000000000000000000000000015, address(new FixedL1Block()).code);
        uint256 bond = BOND + FACTOR * FORCE_GAS * 3 gwei;
        assertEq(vd.challengeBond(), bond);
        Settlement memory s = _rec(r, 5);
        vm.prank(challenger);
        vm.expectRevert(ValidityDispute.BondTooSmall.selector);
        vd.open{value: BOND}(r, 5, s);
        vm.prank(challenger);
        vd.open{value: bond}(r, 5, s);
        assertEq(vd.challengeOf(r, 5).bond, bond);
        vm.etch(0x4200000000000000000000000000000000000015, "");
        _answerAlone(r, 5);
        assertEq(vd.credit(vm.addr(AGENT_PK)), bond);
    }

    /// The deposit follows the domain's base fee when the principal pays for
    /// the postings, times the fee factor.
    function testDepositFollowsTheDomainFee() public {
        assertEq(pd.postingDeposit(), POSTING);
        vm.fee(3 gwei);
        assertEq(pd.postingDeposit(), 3 * POSTING);
        uint256 r = _register(AGENT_PK, 10);
        _settle(AGENT_PK, r, 5);
        _openBy(principal, r, 5);
        _answerAlone(r, 5);
        _payPosting(r, 5);
        assertEq(_pool(r, 5), 3 * POSTING);
    }

    function testDisputeWindowMustFitTheCloseDelay() public {
        Reserve short = new Reserve(DOMAIN, address(token), address(0), address(new Poseidon2Goldilocks()), 1 hours, ACCEPT);
        vm.expectRevert(bytes("close delay"));
        short.setDispute(address(vd));
    }

    function _items(
        uint256[] memory ids,
        uint64[] memory ds,
        Settlement[] memory ss,
        uint256[] memory at,
        bytes32[][] memory paths
    ) internal pure returns (ValidityDispute.Item[] memory items) {
        items = new ValidityDispute.Item[](ids.length);
        for (uint256 i = 0; i < ids.length; ++i) {
            items[i] = ValidityDispute.Item({id: ids[i], digest: ds[i], s: ss[i], index: at[i], path: paths[i]});
        }
    }

    /// A challenge expiring after the close delay lets anyone close at once,
    /// but the answerer's stake waits a further close delay and delivery wait,
    /// so the agent's receipt still burns it.
    function testStakeStaysForASlashAfterTheClose() public {
        (uint256 r, address ans) = _registerWithAnswerer();
        vm.warp(block.timestamp + LIFE - 10 minutes);
        _settle(AGENT_PK, r, 5);
        Settlement memory s = _rec(r, 5);
        BatchReceipt memory rc = _receipt(ANSWERER_PK, r, vd.leafHash(r, 5, s), uint64(block.timestamp));
        _openBy(principal, r, 5);
        vm.warp(_deadline(r, 5) + 1);
        vd.expire(r, 5);
        vm.warp(block.timestamp + ACCEPT + 1 hours + 1);
        acc.close(r);
        vm.prank(ans);
        vm.expectRevert(Reserve.NotClosed.selector);
        acc.unstakeAnswerer(r);
        vm.prank(challenger);
        vd.slashAnswerer(r, 5, s, 0, new bytes32[](0), rc);
        (, uint256 left) = acc.answererOf(r);
        assertEq(left, 0);
        assertEq(acc.credit(challenger), BOND);
    }

    /// The same for a delivery that falls due after an answer: an answer ends
    /// the challenge's count, so the close comes first, and the withholding
    /// slash still lands.
    function testWithholdingSlashesAfterTheClose() public {
        (uint256 r, ) = _registerWithAnswerer();
        vm.warp(block.timestamp + LIFE - 10 minutes);
        _settle(AGENT_PK, r, 5);
        Settlement memory s = _rec(r, 5);
        BatchReceipt memory rc = _receiptOver(ANSWERER_PK, r, vd.leafHash(r, 5, s), keccak256(_sealed(5)), uint64(block.timestamp));
        _openBy(principal, r, 5);
        _answerAlone(r, 5);
        _payPosting(r, 5);
        vm.warp(block.timestamp + ACCEPT + 1 hours + DELIVERY + 1);
        acc.close(r);
        vm.prank(challenger);
        pd.slashWithholding(r, 5, s, 0, new bytes32[](0), rc);
        (, uint256 left) = acc.answererOf(r);
        assertEq(left, 0);
    }

    /// Each principal of an agent has a queue of its own: another principal's
    /// challenges, or those under a delegation the agent issued to itself, do
    /// not push back this principal's deadline.
    function testAnotherPrincipalDoesNotDelayTheQueue() public {
        address other = address(0xB0B0);
        vm.deal(other, 100 ether);
        token.mint(other, 1e15);
        vm.prank(other);
        token.approve(address(acc), type(uint256).max);
        vm.prank(other);
        uint256 o = _accepted(acc.register(TermsOf.make(vm.addr(AGENT_PK), 1_000_000, 1_000, 86_400, Reserve.Funding.Deposit, 100_000_000, bytes32(uint256(20)), bytes32(uint256(21)), uint64(block.timestamp) + LIFE)));
        uint256 r = _register(AGENT_PK, 10);
        for (uint64 d = 1; d <= 6; ++d) _settle(AGENT_PK, o, d);
        for (uint64 d = 1; d <= 6; ++d) _openBy(other, o, d);
        _settle(AGENT_PK, r, 50);
        _openBy(principal, r, 50);
        assertLe(_deadline(r, 50), uint64(block.timestamp) + WINDOW + 2 * SLOT);
        assertGt(_deadline(o, 6), _deadline(r, 50) + 8 * SLOT);
    }

    /// The reserve credits ether rather than sending it, so an agent that
    /// refuses ether cannot block the close that returns the deposit.
    function testAgentThatRefusesEtherCannotBlockClose() public {
        RefusesEther bad = new RefusesEther();
        vm.prank(principal);
        uint256 r = _accepted(acc.register(TermsOf.make(address(bad), 1_000_000, 1_000, 86_400, Reserve.Funding.Deposit, 100_000_000, bytes32(uint256(30)), bytes32(uint256(31)), uint64(block.timestamp) + LIFE)));
        vm.warp(block.timestamp + LIFE + ACCEPT + 1 hours + 1);
        uint256 before = token.balanceOf(principal);
        acc.close(r);
        assertEq(token.balanceOf(principal), before + 100_000_000);
        assertEq(acc.credit(address(bad)), AGENT_BOND);
    }

    /// One late batch: the principal's challenges of all its settlements, in
    /// one call, are answered by one proof, which is paid the proving cost
    /// once and the gas it spent, not a bond for each settlement.
    function testLateBatchIsPaidOnceAtCost() public {
        uint256 r = _register(AGENT_PK, 10);
        uint256 k = 8;
        uint256[] memory ids = new uint256[](k);
        uint64[] memory ds = new uint64[](k);
        Settlement[] memory ss = new Settlement[](k);
        for (uint256 i = 0; i < k; ++i) {
            ids[i] = r;
            ds[i] = nextDigest++;
            ss[i] = _settle(AGENT_PK, r, ds[i]);
        }
        uint256 price = vd.principalPrice(r, k, ss[0].time, ss[k - 1].time);
        vm.prank(principal);
        vd.openMany{value: price}(r, ds, ss);
        assertEq(vd.openByPrincipal(r), k);
        uint256 pool = vd.gasPool(r);
        (bytes32 root, uint256[] memory at, bytes32[][] memory paths) = _tree(ids, ds);
        vd.answerBatch(_items(ids, ds, ss, at, paths), abi.encodePacked(root));
        uint256 paid = vd.credit(vm.addr(AGENT_PK));
        assertGt(paid, 0);
        assertLt(paid, 0.002 ether);
        assertEq(acc.tokenCredit(vm.addr(AGENT_PK)), COST);
        assertTrue(vd.provingPaid(r, root));
        assertEq(vd.openByPrincipal(r), 0);
        vd.returnProving(r);
        assertEq(vd.credit(principal), pool - paid);
        assertEq(acc.earmarked(r), 0);
    }

    /// A batch's proving is paid once, even when its settlements are
    /// challenged apart and answered apart; the second answer gets its gas.
    function testBatchIsPaidOnceAcrossAnswers() public {
        uint256 r = _register(AGENT_PK, 10);
        uint256[] memory ids = new uint256[](2);
        uint64[] memory ds = new uint64[](2);
        Settlement[] memory ss = new Settlement[](2);
        for (uint256 i = 0; i < 2; ++i) {
            ids[i] = r;
            ds[i] = nextDigest++;
            ss[i] = _settle(AGENT_PK, r, ds[i]);
        }
        _openBy(principal, r, ds[0]);
        _openBy(principal, r, ds[1]);
        (bytes32 root, uint256[] memory at, bytes32[][] memory paths) = _tree(ids, ds);
        ValidityDispute.Item[] memory all = _items(ids, ds, ss, at, paths);
        ValidityDispute.Item[] memory one = new ValidityDispute.Item[](1);
        one[0] = all[0];
        vd.answerBatch(one, abi.encodePacked(root));
        uint256 first = vd.credit(vm.addr(AGENT_PK));
        assertGt(first, 0);
        assertEq(acc.tokenCredit(vm.addr(AGENT_PK)), COST);
        one[0] = all[1];
        vd.answerBatch(one, abi.encodePacked(root));
        assertGt(vd.credit(vm.addr(AGENT_PK)), first);
        assertEq(acc.tokenCredit(vm.addr(AGENT_PK)), COST);
    }

    /// What is set aside covers every batch the challenged settlements could
    /// fall in, and their shared deadline adds two slots for each further
    /// batch.
    function testPoolAndDeadlineFollowTheBatchBound() public {
        assertEq(vd.batchBound(1, 0, 0), 1);
        assertEq(vd.batchBound(256, 0, 0), 2);
        assertEq(vd.batchBound(2, 0, WD), 2);
        assertEq(vd.batchBound(2, 0, WD - 1), 1);
        uint256 r = _register(AGENT_PK, 10);
        uint64[] memory ds = new uint64[](2);
        Settlement[] memory ss = new Settlement[](2);
        ds[0] = nextDigest++;
        ss[0] = _settle(AGENT_PK, r, ds[0]);
        vm.warp(block.timestamp + WD);
        ds[1] = nextDigest++;
        ss[1] = _settle(AGENT_PK, r, ds[1]);
        assertGt(vd.gasNeed(2, ss[0].time, ss[1].time), vd.gasNeed(2, ss[0].time, ss[0].time));
        uint256 price = vd.principalPrice(r, 2, ss[0].time, ss[1].time);
        vm.prank(principal);
        vm.expectRevert(ValidityDispute.BondTooSmall.selector);
        vd.openMany{value: price - 1}(r, ds, ss);
        vm.prank(principal);
        vd.openMany{value: price}(r, ds, ss);
        assertEq(acc.earmarked(r), 2 * COST);
        uint64 d = _deadline(r, ds[0]);
        assertEq(d, _deadline(r, ds[1]));
        assertEq(d % (2 * SLOT), 0);
        assertGe(d, uint64(block.timestamp) + WINDOW + 2 * SLOT);
    }

    function testOnlyThePrincipalOpensMany() public {
        uint256 r = _register(AGENT_PK, 10);
        uint64[] memory ds = new uint64[](1);
        Settlement[] memory ss = new Settlement[](1);
        ds[0] = nextDigest++;
        ss[0] = _settle(AGENT_PK, r, ds[0]);
        vm.prank(challenger);
        vm.expectRevert(ValidityDispute.NotPrincipal.selector);
        vd.openMany{value: 1 ether}(r, ds, ss);
        vm.prank(principal);
        vm.expectRevert(ValidityDispute.EmptyBatch.selector);
        vd.openMany{value: 1 ether}(r, new uint64[](0), new Settlement[](0));
    }

    /// An unanswered challenge of the principal forfeits the agent's bond and
    /// pays nobody, and the gas pool and what was set aside go back to the
    /// principal: here, the delegation frozen by the forfeit, to the deposit
    /// it reclaims.
    function testExpiredPrincipalChallengeReturnsThePool() public {
        uint256 r = _register(AGENT_PK, 10);
        _settle(AGENT_PK, r, 5);
        _openBy(principal, r, 5);
        uint256 pool = vd.gasPool(r);
        vm.warp(_deadline(r, 5) + 1);
        vd.expire(r, 5);
        assertEq(vd.openByPrincipal(r), 0);
        assertEq(vd.credit(vm.addr(AGENT_PK)), 0);
        assertEq(acc.tokenCredit(vm.addr(AGENT_PK)), 0);
        vd.returnProving(r);
        assertEq(vd.credit(principal), pool);
        assertEq(acc.earmarked(r), 0);
        uint256 t0 = token.balanceOf(principal);
        vm.prank(principal);
        acc.reclaim(r);
        assertEq(token.balanceOf(principal), t0 + 100_000_000 - 1);
    }

    /// What is set aside after the close goes to the principal as tokens
    /// owed, since the deposit has already been paid out.
    function testEarmarkAfterTheCloseIsOwedToThePrincipal() public {
        uint256 r = _register(AGENT_PK, 10);
        _settle(AGENT_PK, r, 5);
        _openBy(principal, r, 5);
        vm.prank(principal);
        vd.cancel(r, 5);
        vm.prank(principal);
        acc.freeze(r);
        vm.warp(block.timestamp + ACCEPT + 1 hours + 1);
        acc.close(r);
        vd.returnProving(r);
        assertEq(acc.tokenCredit(principal), COST);
        uint256 t0 = token.balanceOf(principal);
        vm.prank(principal);
        acc.withdrawToken();
        assertEq(token.balanceOf(principal), t0 + COST);
    }

    /// The pool is returned only once no challenge of the principal is open.
    function testProvingPoolWaitsForOpenChallenges() public {
        uint256 r = _register(AGENT_PK, 10);
        _settle(AGENT_PK, r, 5);
        _openBy(principal, r, 5);
        vm.expectRevert(ValidityDispute.TooEarly.selector);
        vd.returnProving(r);
    }

    /// A fee that has collapsed for a moment, as after a halt, does not size
    /// the bond or the deposit below the deployment's floors.
    function testFloorsSizeTheBondAndTheDeposit() public {
        ValidityDispute.Params memory p = _params(ACCEPT, WINDOW, SLOT, DELIVERY);
        p.l1FeeFloor = 2 gwei;
        p.l2FeeFloor = 3 gwei;
        ValidityDispute f = new ValidityDispute(address(acc), address(new EchoVerifier(PROGRAM)), PROGRAM, p);
        Postings.Params memory q = _pparams();
        q.l2FeeFloor = 3 gwei;
        Postings g = new Postings(address(acc), address(f), q);
        vm.fee(1 wei);
        assertEq(f.challengeBond(), BOND + FACTOR * FORCE_GAS * 2 gwei);
        assertEq(g.postingDeposit(), 3 * POSTING);
        vm.fee(5 gwei);
        assertEq(g.postingDeposit(), 5 * POSTING);
    }


}
