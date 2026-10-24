// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test, console} from "forge-std/Test.sol";
import {Reserve} from "../src/Reserve.sol";
import {Poseidon2Goldilocks} from "../src/Poseidon2Goldilocks.sol";
import {TermsOf} from "./TermsOf.sol";
import {ValidityDispute} from "../src/ValidityDispute.sol";
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
    uint64 constant ACCEPT = 1 days;
    uint64 constant WINDOW = 1 days;
    uint64 constant SLOT = 2 hours;
    uint64 constant DELIVERY = 8 hours;
    uint256 constant POSTING = 0.25 ether;
    uint64 constant LIFE = 30 days;
    bytes32 constant PROGRAM = bytes32(uint256(1));

    MockToken token;
    Reserve acc;
    ValidityDispute vd;
    address principal = address(0xA11CE);
    address payee = address(0xBEEF);
    address challenger = address(0xC14);
    mapping(bytes32 => Settlement) recs;
    uint64 nextDigest = 1000;

    function setUp() public {
        vm.warp(100 days);
        token = new MockToken();
        acc = new Reserve(DOMAIN, address(token), address(0), address(new Poseidon2Goldilocks()), 1 hours, ACCEPT + 1 hours);
        vd = new ValidityDispute(address(acc), address(new EchoVerifier(PROGRAM)), PROGRAM, ACCEPT, WINDOW, SLOT, BOND, DELIVERY, POSTING, 0);
        acc.setDispute(address(vd));
        vm.deal(principal, 100 ether);
        vm.deal(challenger, 100 ether);
        token.mint(principal, 1e15);
        token.mint(payee, 1);
        vm.prank(principal);
        token.approve(address(acc), type(uint256).max);
    }

    function _register(uint256 pk, uint256 tag) internal returns (uint256 r) {
        vm.prank(principal);
        r = acc.register{value: AGENT_BOND}(TermsOf.make(vm.addr(pk), 1_000_000, 1_000, 86_400, Reserve.Funding.Deposit, 100_000_000, bytes32(tag), bytes32(tag + 1), uint64(block.timestamp) + LIFE));
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
        vm.prank(who);
        vd.open{value: BOND + (own ? POSTING : 0)}(r, d, s);
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
        uint256 r = acc.register{value: AGENT_BOND}(TermsOf.make(vm.addr(AGENT_PK), 1_000_000, 1_000, 86_400, Reserve.Funding.Deposit, 100_000_000, bytes32(com), bytes32(root), uint64(block.timestamp) + LIFE));
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
        uint256 r = acc.register{value: AGENT_BOND}(t);
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
        r = acc.register{value: AGENT_BOND}(t);
        vm.prank(ans);
        acc.stakeAnswerer{value: AGENT_BOND}(r);
    }

    /// Stands for the root of a batch's sealed openings in tests that do not deliver one.
    bytes32 constant SEALED_ROOT = keccak256("sealed openings");

    function _receipt(uint256 pk, uint256 r, bytes32 root, uint64 at) internal view returns (ValidityDispute.Receipt memory) {
        return _receiptOver(pk, r, root, SEALED_ROOT, at);
    }

    function _receiptOver(uint256 pk, uint256 r, bytes32 root, bytes32 sealedRoot, uint64 at)
        internal
        view
        returns (ValidityDispute.Receipt memory)
    {
        bytes32 ph = _proofHash(_proof(100));
        (uint8 v, bytes32 rr, bytes32 ss) = vm.sign(pk, vd.receiptDigest(r, root, sealedRoot, ph, at));
        return ValidityDispute.Receipt({sealedRoot: sealedRoot, proofHash: ph, receivedAt: at, signature: abi.encodePacked(rr, ss, v)});
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
        uint256 size = vd.CHUNK();
        for (uint256 at = 0; at < b.length; at += size) {
            uint256 end = at + size < b.length ? at + size : b.length;
            h = keccak256(abi.encodePacked(h, _slice(b, at, end)));
        }
        h = keccak256(abi.encodePacked(h, b.length));
    }

    function _post(uint256 r, bytes memory b) internal {
        bytes32 h = _proofHash(b);
        uint256 size = vd.CHUNK();
        uint256 i;
        for (uint256 at = 0; at < b.length; at += size) {
            uint256 end = at + size < b.length ? at + size : b.length;
            vd.postProof(r, h, i++, _slice(b, at, end), end == b.length);
        }
    }

    /// An answer pays the registered answerer, whoever sends it.
    function testAnswerCreditsTheAnswererWhoeverSendsIt() public {
        (uint256 r, address ans) = _registerWithAnswerer();
        _settle(AGENT_PK, r, 5);
        _openBy(principal, r, 5);
        vm.prank(challenger);
        _answerAlone(r, 5);
        assertEq(vd.credit(ans), BOND);
        assertEq(vd.credit(vm.addr(AGENT_PK)), 0);
        assertEq(vd.credit(challenger), 0);
    }

    /// The answerer acknowledged the batch and stayed silent: the principal
    /// still gets the agent's bond, whoever brings the receipt is paid one
    /// challenger's bond, and the rest of the stake is burnt.
    function testSilentAnswererLosesItsStake() public {
        (uint256 r, address ans) = _registerWithAnswerer();
        _settle(AGENT_PK, r, 5);
        Settlement memory s = _rec(r, 5);
        uint64 at = uint64(block.timestamp);
        ValidityDispute.Receipt memory rc = _receipt(ANSWERER_PK, r, vd.leafHash(r, 5, s), at);
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
        vm.warp(block.timestamp + ACCEPT + 1 hours + DELIVERY + 1);
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
        ValidityDispute.Receipt memory rc = _receipt(ANSWERER_PK, r, vd.leafHash(r, 5, s), at);
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
        ValidityDispute.Receipt memory rc = _receipt(OTHER_PK, r, vd.leafHash(r, 5, s), at);
        vm.expectRevert(ValidityDispute.BadReceipt.selector);
        vd.slashAnswerer(r, 5, s, 0, new bytes32[](0), rc);
    }

    /// A receipt for a batch the settlement is not in moves nothing.
    function testReceiptForAnotherBatchRefused() public {
        (uint256 r, Settlement memory s, uint64 at) = _expired();
        bytes32[] memory path = new bytes32[](1);
        path[0] = keccak256("other");
        ValidityDispute.Receipt memory rc = _receipt(ANSWERER_PK, r, keccak256("another root"), at);
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
        ValidityDispute.Receipt memory rc = _receipt(ANSWERER_PK, r, vd.leafHash(r, 5, s), late);
        vm.expectRevert(ValidityDispute.ReceiptTooLate.selector);
        vd.slashAnswerer(r, 5, s, 0, new bytes32[](0), rc);
    }

    /// A receipt with a different time than the one signed moves nothing.
    function testReceiptTimeIsSigned() public {
        (uint256 r, Settlement memory s, uint64 at) = _expired();
        ValidityDispute.Receipt memory rc = _receipt(ANSWERER_PK, r, vd.leafHash(r, 5, s), at);
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

    /// A settlement of a batch of one, receipted with its sealed opening,
    /// challenged by the principal and answered.
    function _answered() internal returns (uint256 r, Settlement memory s, ValidityDispute.Receipt memory rc) {
        (r, ) = _registerWithAnswerer();
        _settle(AGENT_PK, r, 5);
        s = _rec(r, 5);
        rc = _receiptOver(ANSWERER_PK, r, vd.leafHash(r, 5, s), keccak256(_sealed(5)), uint64(block.timestamp));
        _openBy(principal, r, 5);
        _answerAlone(r, 5);
    }

    /// Answering the principal's challenge opens a delivery due one delivery
    /// wait later; answering anyone else's does not.
    function testAnswerToThePrincipalAsksForTheSealedOpening() public {
        (uint256 r, , ValidityDispute.Receipt memory rc) = _answered();
        ValidityDispute.Challenge memory c = vd.challengeOf(r, 5);
        assertEq(uint256(c.status), uint256(ValidityDispute.Status.Answered));
        assertEq(c.deadline, uint64(block.timestamp) + DELIVERY);
        _settle(AGENT_PK, r, 6);
        _openBy(challenger, r, 6);
        _answerAlone(r, 6);
        Settlement memory s6 = _rec(r, 6);
        ValidityDispute.Receipt memory rc6 = _receiptOver(ANSWERER_PK, r, vd.leafHash(r, 6, s6), keccak256(_sealed(6)), rc.receivedAt);
        vm.expectRevert(ValidityDispute.NotDue.selector);
        vd.deliver(r, 6, s6, 0, new bytes32[](0), rc6, _sealed(6), new bytes32[](0));
    }

    /// The receipted opening and proof, posted in time, end the duty: the
    /// opening is delivered once and the receipt can no longer slash.
    function testDeliveredOpeningIsPostedAndEndsTheDuty() public {
        (uint256 r, Settlement memory s, ValidityDispute.Receipt memory rc) = _answered();
        vm.expectEmit(true, false, false, true, address(vd));
        emit ValidityDispute.SealedDelivered(r, 5, _sealed(5));
        vd.deliver(r, 5, s, 0, new bytes32[](0), rc, _sealed(5), new bytes32[](0));
        assertEq(uint256(vd.challengeOf(r, 5).status), uint256(ValidityDispute.Status.Delivered));
        vm.expectRevert(ValidityDispute.NotDue.selector);
        vd.deliver(r, 5, s, 0, new bytes32[](0), rc, _sealed(5), new bytes32[](0));
        _post(r + 1, _proof(100));
        assertEq(vd.postedAt(r, _proofHash(_proof(100))), 0);
        _post(r, _proof(100));
        vm.warp(block.timestamp + DELIVERY + 1);
        vm.expectRevert(ValidityDispute.NotWithheld.selector);
        vd.slashWithholding(r, 5, s, 0, new bytes32[](0), rc);
    }

    /// The opening was posted but the proof was not: the receipt slashes.
    function testWithheldProofSlashesTheStake() public {
        (uint256 r, Settlement memory s, ValidityDispute.Receipt memory rc) = _answered();
        vd.deliver(r, 5, s, 0, new bytes32[](0), rc, _sealed(5), new bytes32[](0));
        vm.warp(block.timestamp + DELIVERY + 1);
        vm.prank(challenger);
        vd.slashWithholding(r, 5, s, 0, new bytes32[](0), rc);
        (, uint256 left) = acc.answererOf(r);
        assertEq(left, 0);
    }

    /// A proof posted after the wait came too late, and the receipt slashes.
    function testProofPostedLateSlashes() public {
        (uint256 r, Settlement memory s, ValidityDispute.Receipt memory rc) = _answered();
        vd.deliver(r, 5, s, 0, new bytes32[](0), rc, _sealed(5), new bytes32[](0));
        vm.warp(block.timestamp + DELIVERY + 1);
        _post(r, _proof(100));
        vm.prank(challenger);
        vd.slashWithholding(r, 5, s, 0, new bytes32[](0), rc);
        (, uint256 left) = acc.answererOf(r);
        assertEq(left, 0);
    }

    /// A proof of three chunks is accepted only in order, with full chunks
    /// before the last, and only if its chained hash is the one named; a
    /// second poster's wrong chunks spoil nothing for the first.
    function testProofPostedInChunks() public {
        bytes memory b = _proof(2 * vd.CHUNK() + 1000);
        bytes32 h = _proofHash(b);
        uint256 size = vd.CHUNK();
        vm.expectRevert(ValidityDispute.BadChunk.selector);
        vd.postProof(7, h, 1, _slice(b, size, 2 * size), false);
        vm.expectRevert(ValidityDispute.BadChunk.selector);
        vd.postProof(7, h, 0, _slice(b, 0, size - 1), false);
        vm.prank(challenger);
        vd.postProof(7, h, 0, _slice(b, size, 2 * size), false);
        vd.postProof(7, h, 0, _slice(b, 0, size), false);
        vd.postProof(7, h, 1, _slice(b, size, 2 * size), false);
        vm.expectRevert(ValidityDispute.ProofMismatch.selector);
        vd.postProof(7, h, 2, _slice(b, 2 * size, 2 * size + 999), true);
        assertEq(vd.postedAt(7, h), 0);
        vd.postProof(7, h, 2, _slice(b, 2 * size, 2 * size + 1000), true);
        assertEq(vd.postedAt(7, h), uint64(block.timestamp));
        assertEq(vd.postedAt(8, h), 0);
        vm.expectRevert(ValidityDispute.BadChunk.selector);
        vd.postProof(7, h, 3, _slice(b, 0, 10), true);
    }

    /// Only the opening the receipt names, at the settlement's own position,
    /// can be delivered.
    function testOtherOpeningCannotBeDelivered() public {
        (uint256 r, Settlement memory s, ValidityDispute.Receipt memory rc) = _answered();
        vm.expectRevert(ValidityDispute.BadPath.selector);
        vd.deliver(r, 5, s, 0, new bytes32[](0), rc, _sealed(6), new bytes32[](0));
        ValidityDispute.Receipt memory other = _receiptOver(OTHER_PK, r, vd.leafHash(r, 5, s), keccak256(_sealed(6)), rc.receivedAt);
        vm.expectRevert(ValidityDispute.BadReceipt.selector);
        vd.deliver(r, 5, s, 0, new bytes32[](0), other, _sealed(6), new bytes32[](0));
    }

    function testDeliveryAfterTheWaitRefused() public {
        (uint256 r, Settlement memory s, ValidityDispute.Receipt memory rc) = _answered();
        vm.warp(block.timestamp + DELIVERY + 1);
        vm.expectRevert(ValidityDispute.TooLate.selector);
        vd.deliver(r, 5, s, 0, new bytes32[](0), rc, _sealed(5), new bytes32[](0));
    }

    /// Nothing posted within the wait: the receipt burns the stake less the
    /// bounty, and the agent keeps its bond, since the challenge was answered.
    function testWithheldOpeningSlashesTheStake() public {
        (uint256 r, Settlement memory s, ValidityDispute.Receipt memory rc) = _answered();
        vm.expectRevert(ValidityDispute.NotWithheld.selector);
        vd.slashWithholding(r, 5, s, 0, new bytes32[](0), rc);
        vm.warp(block.timestamp + DELIVERY + 1);
        address agent = vm.addr(AGENT_PK);
        uint256 a0 = agent.balance;
        vm.prank(challenger);
        uint256 g0 = gasleft();
        vd.slashWithholding(r, 5, s, 0, new bytes32[](0), rc);
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
        ValidityDispute.Receipt memory late = _receiptOver(ANSWERER_PK, r, vd.leafHash(r, 5, s), keccak256(_sealed(5)), uint64(block.timestamp) + 1);
        vm.warp(block.timestamp + DELIVERY + 1);
        vm.expectRevert(ValidityDispute.ReceiptTooLate.selector);
        vd.slashWithholding(r, 5, s, 0, new bytes32[](0), late);
    }

    /// Delivering under a second receipt with other openings is caught by the
    /// first: two sealed roots for one batch are the answerer's own signatures.
    function testDeliveryUnderAnotherReceiptSlashes() public {
        (uint256 r, Settlement memory s, ValidityDispute.Receipt memory rc) = _answered();
        ValidityDispute.Receipt memory swapped = _receiptOver(ANSWERER_PK, r, vd.leafHash(r, 5, s), keccak256(_sealed(9)), rc.receivedAt);
        vd.deliver(r, 5, s, 0, new bytes32[](0), swapped, _sealed(9), new bytes32[](0));
        vm.expectRevert(ValidityDispute.NotWithheld.selector);
        vd.slashWithholding(r, 5, s, 0, new bytes32[](0), swapped);
        vm.prank(challenger);
        vd.slashWithholding(r, 5, s, 0, new bytes32[](0), rc);
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
        ValidityDispute.Receipt memory rc = _receiptOver(ANSWERER_PK, r, root, sealedRoot, uint64(block.timestamp));
        _openBy(principal, r, 5);
        vd.answer(r, 5, s, index, path, abi.encodePacked(root));
        bytes memory opening = _sealed(5);
        uint256 g0 = gasleft();
        vd.deliver(r, 5, s, index, path, rc, opening, sealedPath);
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
        vm.warp(block.timestamp + ACCEPT + 1 hours + DELIVERY + 1);
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
        uint256 r = acc.register{value: AGENT_BOND}(t);
        vm.prank(ans);
        uint256 g0 = gasleft();
        acc.stakeAnswerer{value: AGENT_BOND}(r);
        console.log("stake answerer", g0 - gasleft());
        _settle(AGENT_PK, r, 5);
        Settlement memory s = _rec(r, 5);
        uint64 at = uint64(block.timestamp);
        ValidityDispute.Receipt memory rc = _receipt(ANSWERER_PK, r, vd.leafHash(r, 5, s), at);
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
        assertEq(vd.credit(vm.addr(AGENT_PK)), BOND);
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
    /// in its last second is accepted and starts a posting wait of w_p, and
    /// once that wait has passed with nothing posted the receipt slashes the
    /// stake. Another party's challenge left unanswered expires and freezes.
    function testWindowsOfTheBaseDeployment() public {
        uint64 w = 36 hours + 30 minutes;
        uint64 wa = 32 hours;
        uint64 eta = 4 hours;
        uint64 wp = 30 hours;
        acc = new Reserve(DOMAIN, address(token), address(0), address(new Poseidon2Goldilocks()), 1 hours, w + 1 hours);
        vd = new ValidityDispute(address(acc), address(new EchoVerifier(PROGRAM)), PROGRAM, w, wa, eta, BOND, wp, POSTING, 0);
        acc.setDispute(address(vd));
        vm.prank(principal);
        token.approve(address(acc), type(uint256).max);

        (uint256 r, ) = _registerWithAnswerer();
        uint64 signed = uint64(block.timestamp);
        _settle(AGENT_PK, r, 5);
        _settle(AGENT_PK, r, 6);
        _settle(AGENT_PK, r, 7);
        Settlement memory s5 = _rec(r, 5);
        ValidityDispute.Receipt memory rc = _receiptOver(ANSWERER_PK, r, vd.leafHash(r, 5, s5), keccak256(_sealed(5)), signed);

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
        assertEq(vd.challengeOf(r, 5).deadline, due + wp);
        vm.warp(due + wp);
        vm.expectRevert(ValidityDispute.NotWithheld.selector);
        vd.slashWithholding(r, 5, s5, 0, new bytes32[](0), rc);
        vm.warp(due + wp + 1);
        vm.prank(challenger);
        vd.slashWithholding(r, 5, s5, 0, new bytes32[](0), rc);
        (, uint256 left) = acc.answererOf(r);
        assertEq(left, 0);

        vm.warp(_deadline(r, 6) + 1);
        vd.expire(r, 6);
        (bool frozen,) = acc.frozenOf(r);
        assertTrue(frozen);
    }

    /// A settlement someone else challenged first: the principal joins that
    /// challenge, which then holds settlement, moves into the principal's
    /// queue, and on its answer asks for the sealed opening.
    function testPrincipalJoinsAChallengeSomeoneElseOpened() public {
        uint256 r = _register(AGENT_PK, 10);
        _settle(AGENT_PK, r, 5);
        _openBy(challenger, r, 5);
        (, uint32 before) = acc.frozenOf(r);
        assertEq(before, 0);
        Settlement memory s = _rec(r, 5);
        vm.prank(principal);
        uint256 g0 = gasleft();
        vd.join{value: POSTING}(r, 5, s);
        console.log("join another party's challenge", g0 - gasleft());
        (, uint32 held) = acc.frozenOf(r);
        assertEq(held, 1);
        assertLe(_deadline(r, 5), uint64(block.timestamp) + WINDOW + 2 * SLOT);
        vm.expectRevert(Reserve.Held.selector);
        this.settleAgain(AGENT_PK, r, 6);
        _answerAlone(r, 5);
        (, uint32 after_) = acc.frozenOf(r);
        assertEq(after_, 0);
        assertEq(vd.challengeOf(r, 5).deadline, uint64(block.timestamp) + DELIVERY);
        assertEq(vd.postingPool(r), POSTING);
    }

    function testOnlyThePrincipalJoinsAndOnlyWithTheDeposit() public {
        uint256 r = _register(AGENT_PK, 10);
        _settle(AGENT_PK, r, 5);
        _openBy(challenger, r, 5);
        Settlement memory s = _rec(r, 5);
        vm.deal(address(0xD00D), 1 ether);
        vm.prank(address(0xD00D));
        vm.expectRevert(ValidityDispute.NotPrincipal.selector);
        vd.join{value: POSTING}(r, 5, s);
        vm.prank(principal);
        vm.expectRevert(ValidityDispute.BondTooSmall.selector);
        vd.join{value: POSTING - 1}(r, 5, s);
        vm.prank(principal);
        vd.join{value: POSTING}(r, 5, s);
        vm.prank(principal);
        vm.expectRevert(ValidityDispute.AlreadyChallenged.selector);
        vd.join{value: POSTING}(r, 5, s);
    }

    /// Someone else challenged and the answerer answered before the
    /// principal's decision time: the principal joins the answered challenge,
    /// nothing is held, and the join asks for the sealed opening and the
    /// proof, due within the delivery wait from the join and slashable after.
    function testPrincipalJoinsAnAnsweredChallenge() public {
        (uint256 r, ) = _registerWithAnswerer();
        _settle(AGENT_PK, r, 5);
        Settlement memory s = _rec(r, 5);
        ValidityDispute.Receipt memory rc = _receiptOver(ANSWERER_PK, r, vd.leafHash(r, 5, s), keccak256(_sealed(5)), uint64(block.timestamp));
        _openBy(challenger, r, 5);
        _answerAlone(r, 5);
        vm.expectRevert(ValidityDispute.NotDue.selector);
        vd.deliver(r, 5, s, 0, new bytes32[](0), rc, _sealed(5), new bytes32[](0));
        vm.warp(block.timestamp + 3600);
        vm.prank(principal);
        vd.join{value: POSTING}(r, 5, s);
        (, uint32 held) = acc.frozenOf(r);
        assertEq(held, 0);
        assertEq(uint256(vd.challengeOf(r, 5).status), uint256(ValidityDispute.Status.Answered));
        assertEq(vd.challengeOf(r, 5).deadline, uint64(block.timestamp) + DELIVERY);
        vm.prank(principal);
        vm.expectRevert(ValidityDispute.AlreadyChallenged.selector);
        vd.join{value: POSTING}(r, 5, s);
        vm.warp(block.timestamp + DELIVERY + 1);
        vm.prank(challenger);
        vd.slashWithholding(r, 5, s, 0, new bytes32[](0), rc);
        (, uint256 left) = acc.answererOf(r);
        assertEq(left, 0);
    }

    /// The same, with the answerer delivering after the join: the duty ends.
    function testAnsweredChallengeJoinedThenDelivered() public {
        (uint256 r, ) = _registerWithAnswerer();
        _settle(AGENT_PK, r, 5);
        Settlement memory s = _rec(r, 5);
        ValidityDispute.Receipt memory rc = _receiptOver(ANSWERER_PK, r, vd.leafHash(r, 5, s), keccak256(_sealed(5)), uint64(block.timestamp));
        _openBy(challenger, r, 5);
        _answerAlone(r, 5);
        vm.prank(principal);
        vd.join{value: POSTING}(r, 5, s);
        vd.deliver(r, 5, s, 0, new bytes32[](0), rc, _sealed(5), new bytes32[](0));
        _post(r, _proof(100));
        assertEq(uint256(vd.challengeOf(r, 5).status), uint256(ValidityDispute.Status.Delivered));
        vm.warp(block.timestamp + DELIVERY + 1);
        vm.expectRevert(ValidityDispute.NotWithheld.selector);
        vd.slashWithholding(r, 5, s, 0, new bytes32[](0), rc);
    }

    function testJoinAfterTheAcceptanceWindowRefused() public {
        uint256 r = _register(AGENT_PK, 10);
        _settle(AGENT_PK, r, 5);
        _openBy(challenger, r, 5);
        Settlement memory s = _rec(r, 5);
        vm.warp(block.timestamp + ACCEPT + 1);
        vm.prank(principal);
        vm.expectRevert(ValidityDispute.WindowClosed.selector);
        vd.join{value: POSTING}(r, 5, s);
    }

    /// The named answerer's postings after an answer to the principal's
    /// challenge are refunded from the pool at the domain's base fee; anyone
    /// else's are not.
    function testPostingIsRefundedFromThePool() public {
        (uint256 r, , ) = _answered();
        vm.fee(1 gwei);
        vm.txGasPrice(2 gwei);
        address ans = vm.addr(ANSWERER_PK);
        bytes memory b = _proof(vd.CHUNK() + 100);
        vm.startPrank(address(0xD00D));
        _post(r, b);
        vm.stopPrank();
        assertEq(vd.credit(address(0xD00D)), 0);
        assertEq(vd.postingPool(r), POSTING);
        vm.startPrank(ans);
        _post(r, _proof(200));
        vm.stopPrank();
        uint256 paid = vd.credit(ans) - BOND;
        assertGt(paid, 0);
        assertEq(vd.postingPool(r), POSTING - paid);
        assertFalse(vd.postingLapsed(r));
    }

    /// A posting the pool cannot pay for empties it and lapses the duty: the
    /// answerer is not slashed for what it was not paid to post.
    function testAnEmptyPoolLapsesTheDuty() public {
        (uint256 r, Settlement memory s, ValidityDispute.Receipt memory rc) = _answered();
        vm.fee(1e18);
        vm.txGasPrice(1e18);
        bytes memory chunk = _proof(vd.CHUNK());
        vm.prank(vm.addr(ANSWERER_PK));
        vd.postProof(r, keccak256("partial"), 0, chunk, false);
        assertTrue(vd.postingLapsed(r));
        assertEq(vd.postingPool(r), 0);
        vm.fee(0);
        vm.txGasPrice(0);
        vm.warp(block.timestamp + DELIVERY + 1);
        vm.expectRevert(ValidityDispute.NotWithheld.selector);
        vd.slashWithholding(r, 5, s, 0, new bytes32[](0), rc);
    }

    /// A posting forced in through Ethereum pays nothing on the domain; it is
    /// refunded at the Ethereum base fee the domain records.
    function testForcedPostingIsRefundedAtTheEthereumFee() public {
        (uint256 r, , ) = _answered();
        vm.etch(0x4200000000000000000000000000000000000015, address(new FixedL1Block()).code);
        vm.txGasPrice(0);
        address ans = vm.addr(ANSWERER_PK);
        bytes memory chunk = _proof(300);
        bytes32 h = _proofHash(chunk);
        vm.prank(ans);
        vd.postProof(r, h, 0, chunk, true);
        uint256 n = abi.encodeCall(ValidityDispute.postProof, (r, h, 0, chunk, true)).length;
        assertEq(vd.credit(ans) - BOND, (21000 + 40 * n) * 3 gwei);
    }

    /// Once no delivery is due, what is left of the pool is the principal's.
    function testUnspentPostingReturnsToThePrincipal() public {
        (uint256 r, , ) = _answered();
        vm.expectRevert(ValidityDispute.TooEarly.selector);
        vd.returnPosting(r);
        vm.warp(block.timestamp + DELIVERY + 1);
        vd.returnPosting(r);
        assertEq(vd.credit(principal), POSTING);
        vm.expectRevert(ValidityDispute.NothingToReturn.selector);
        vd.returnPosting(r);
    }

    /// An agent that has declared its capacity is registered to only by the
    /// principals it took on, and takes on no more than it declared.
    function testAgentCapacityLimitsItsPrincipals() public {
        address agent = vm.addr(AGENT_PK);
        vm.startPrank(agent);
        acc.declareCapacity(1);
        acc.servePrincipal(principal);
        vm.expectRevert(Reserve.OverCapacity.selector);
        acc.servePrincipal(address(0xB0B5));
        vm.expectRevert(Reserve.OverCapacity.selector);
        acc.declareCapacity(0);
        vm.stopPrank();
        _register(AGENT_PK, 10);
        vm.prank(address(0xB0B5));
        vm.expectRevert(Reserve.NotServed.selector);
        acc.register(TermsOf.make(agent, 1_000_000, 1_000, 86_400, Reserve.Funding.Deposit, 0, bytes32(uint256(1)), bytes32(uint256(2)), uint64(block.timestamp) + LIFE));
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
        ValidityDispute.Receipt memory rc = _receipt(ANSWERER_PK, r, vd.leafHash(r, 5, s), uint64(block.timestamp));
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
        ValidityDispute.Receipt memory rc = _receiptOver(ANSWERER_PK, r, vd.leafHash(r, 5, s), keccak256(_sealed(5)), uint64(block.timestamp));
        _openBy(principal, r, 5);
        _answerAlone(r, 5);
        vm.warp(block.timestamp + ACCEPT + 1 hours + DELIVERY + 1);
        acc.close(r);
        vm.prank(challenger);
        vd.slashWithholding(r, 5, s, 0, new bytes32[](0), rc);
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
        uint256 o = acc.register{value: AGENT_BOND}(TermsOf.make(vm.addr(AGENT_PK), 1_000_000, 1_000, 86_400, Reserve.Funding.Deposit, 100_000_000, bytes32(uint256(20)), bytes32(uint256(21)), uint64(block.timestamp) + LIFE));
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
        uint256 r = acc.register{value: AGENT_BOND}(TermsOf.make(address(bad), 1_000_000, 1_000, 86_400, Reserve.Funding.Deposit, 100_000_000, bytes32(uint256(30)), bytes32(uint256(31)), uint64(block.timestamp) + LIFE));
        vm.warp(block.timestamp + LIFE + ACCEPT + 1 hours + 1);
        uint256 before = token.balanceOf(principal);
        acc.close(r);
        assertEq(token.balanceOf(principal), before + 100_000_000);
        assertEq(acc.credit(address(bad)), AGENT_BOND);
    }
}
