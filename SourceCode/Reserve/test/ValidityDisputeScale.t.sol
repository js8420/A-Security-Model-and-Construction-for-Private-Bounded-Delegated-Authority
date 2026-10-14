// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {Reserve} from "../src/Reserve.sol";
import {ValidityDispute} from "../src/ValidityDispute.sol";
import {ISP1Verifier} from "../src/sp1/ISP1Verifier.sol";
import {MockToken} from "./MockToken.sol";
import {Settlement} from "../src/Settlement.sol";
import {Statement} from "./Statement.sol";

/// Accepts a "proof" that is exactly the public values the contract built,
/// under the expected key, so these tests check what the contract asks the
/// verifier, not the pairing. The pairing is tested on Pete's real proofs.
contract EchoVerifier is ISP1Verifier {
    bytes32 public immutable single;
    bytes32 public immutable batch;

    constructor(bytes32 single_, bytes32 batch_) {
        single = single_;
        batch = batch_;
    }

    function verifyProof(bytes32 vk, bytes calldata pv, bytes calldata proof) external view {
        require(vk == single || vk == batch, "key");
        require(keccak256(pv) == keccak256(proof), "values");
    }
}

contract RefusesEther {
    function openOn(ValidityDispute vd, uint256 id, uint64 digest, Settlement calldata s) external payable {
        vd.open{value: msg.value}(id, digest, s);
    }
}

contract ValidityDisputeScaleTest is Test {
    uint64 constant DOMAIN = 8453;
    uint256 constant AGENT_PK = 0xA6E47;
    uint256 constant OTHER_PK = 0xB0B;
    uint256 constant AGENT_BOND = 1 ether;
    uint256 constant BOND = 0.01 ether;
    uint64 constant ACCEPT = 1 days;
    uint64 constant WINDOW = 1 days;
    uint64 constant SLOT = 2 hours;
    uint64 constant LIFE = 30 days;
    bytes32 constant SINGLE = bytes32(uint256(1));
    bytes32 constant BATCH = bytes32(uint256(2));

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
        acc = new Reserve(DOMAIN, address(token), address(0), 1 hours, ACCEPT + 1 hours);
        vd = new ValidityDispute(
            address(acc), address(new EchoVerifier(SINGLE, BATCH)), SINGLE, BATCH, ACCEPT, WINDOW, SLOT, BOND
        );
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
        r = acc.register{value: AGENT_BOND}(
            vm.addr(pk), 1_000_000, 1_000, 86_400, keccak256(abi.encodePacked(uint64(7), uint64(11))),
            Reserve.Funding.Deposit, 100_000_000, bytes32(tag), bytes32(tag + 1),
            uint64(block.timestamp) + LIFE, 0, 1 << 16
        );
    }

    function _rec(uint256 r, uint64 d) internal view returns (Settlement memory) {
        return recs[keccak256(abi.encode(r, d))];
    }

    function _settle(uint256 pk, uint256 r, uint64 d) internal returns (Settlement memory s) {
        uint64[] memory e = new uint64[](1);
        e[0] = d;
        uint64 t = uint64(block.timestamp);
        bytes32 h = acc.signedDigest(r, payee, 1, d, t, keccak256(abi.encodePacked(e)));
        (uint8 v, bytes32 rr, bytes32 ss) = vm.sign(pk, h);
        acc.settleLogged(r, payee, 1, d, t, e, abi.encodePacked(rr, ss, v));
        s = Settlement({elems: keccak256(abi.encodePacked(e)), amount: 1, payee: payee, time: t, epoch: 0});
        recs[keccak256(abi.encode(r, d))] = s;
    }

    function _openBy(address who, uint256 r, uint64 d) internal {
        Settlement memory s = _rec(r, d);
        vm.prank(who);
        vd.open{value: BOND}(r, d, s);
    }

    /// k settlements of one delegation, each challenged by `who`.
    function _openMany(uint256 pk, uint256 r, uint256 k, address who)
        internal
        returns (uint256[] memory ids, uint64[] memory ds)
    {
        ids = new uint256[](k);
        ds = new uint64[](k);
        for (uint64 i = 0; i < k; ++i) {
            ids[i] = r;
            ds[i] = nextDigest++;
            _settle(pk, r, ds[i]);
            _openBy(who, r, ds[i]);
        }
    }

    function _recs(uint256[] memory ids, uint64[] memory ds) internal view returns (Settlement[] memory ss) {
        ss = new Settlement[](ids.length);
        for (uint256 i = 0; i < ids.length; ++i) ss[i] = _rec(ids[i], ds[i]);
    }

    function _deadline(uint256 r, uint64 d) internal view returns (uint64) {
        return vd.challengeOf(r, d).deadline;
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
        bytes memory pv = vd.publicValues(r, 5, bad[0]);
        vm.expectRevert(ValidityDispute.WrongRecord.selector);
        vd.answer(r, 5, bad[0], pv);
    }

    /// The statement carries the payee as three limbs and the shares' hash as
    /// four big-endian words, in the order the guest commits them.
    function testStatementLayout() public {
        uint256 r = _register(AGENT_PK, 10);
        Settlement memory s = _settle(AGENT_PK, r, 5);
        s.payee = address(uint160(0x007a3f9c2e5b1d84f6a0c9e2b7d5f3a1c8e6b4d2f0));
        s.elems = 0x0102030405060708111213141516171821222324252627283132333435363738;
        bytes memory pv = vd.publicValues(r, 5, s);
        assertEq(pv.length, 8 + 8 * 19);
        assertEq(_word(pv, 10), 1);
        assertEq(_word(pv, 11), 68576303576830704);
        assertEq(_word(pv, 12), 37425867368085461);
        assertEq(_word(pv, 13), 134413621811997);
        assertEq(_word(pv, 14), s.time);
        assertEq(_word(pv, 15), 0x0102030405060708);
        assertEq(_word(pv, 18), 0x3132333435363738);
    }

    /// The circuit crate hashed the exported shares as the guest does; the
    /// reserve hashes them as Settle does. The two must agree.
    function testGuestAndReserveHashTheSharesAlike() public pure {
        uint64[] memory e = Statement.elems();
        assertEq(e.length, 192);
        assertEq(keccak256(abi.encodePacked(e)), Statement.ELEMS_HASH);
    }

    /// The bytes the reserve rebuilds for the exported payment equal what the
    /// circuit crate computes the guest will commit, before any proof exists.
    function testRebuiltStatementIsWhatTheGuestCommits() public {
        uint64[] memory c = Statement.committed();
        assertEq(c.length, 19);
        uint256 root;
        uint256 com;
        for (uint256 j = 0; j < 4; ++j) {
            root |= uint256(c[1 + j]) << (64 * j);
            com |= uint256(c[5 + j]) << (64 * j);
        }
        vm.prank(principal);
        uint256 r = acc.register{value: AGENT_BOND}(
            vm.addr(AGENT_PK), 1_000_000, 1_000, 86_400, keccak256(abi.encodePacked(uint64(7), uint64(11))),
            Reserve.Funding.Deposit, 100_000_000, bytes32(com), bytes32(root), uint64(block.timestamp) + LIFE, 0, 1 << 16
        );
        Settlement memory s = Settlement({
            elems: Statement.ELEMS_HASH, amount: Statement.AMOUNT, payee: Statement.PAYEE, time: Statement.TIME,
            epoch: 0
        });
        bytes memory want = new bytes(8 + 8 * c.length);
        want[0] = bytes1(uint8(c.length));
        for (uint256 i = 0; i < c.length; ++i) {
            for (uint256 b = 0; b < 8; ++b) want[8 + 8 * i + b] = bytes1(uint8(c[i] >> (8 * b)));
        }
        assertEq(vd.publicValues(r, Statement.DIGEST, s), want);
    }

    function _word(bytes memory pv, uint256 i) internal pure returns (uint256 x) {
        for (uint256 b = 0; b < 8; ++b) x |= uint256(uint8(pv[8 * (i + 1) + b])) << (8 * b);
    }

    function testBatchValuesAreTheSingleValuesInOrder() public {
        uint256 a = _register(AGENT_PK, 10);
        uint256 b = _register(OTHER_PK, 20);
        _settle(AGENT_PK, a, 5);
        _settle(OTHER_PK, b, 6);
        uint256[] memory ids = new uint256[](2);
        uint64[] memory ds = new uint64[](2);
        ids[0] = a; ds[0] = 5;
        ids[1] = b; ds[1] = 6;
        bytes memory pv = vd.batchPublicValues(ids, ds, _recs(ids, ds));
        bytes memory one = vd.publicValues(a, 5, _rec(a, 5));
        bytes memory two = vd.publicValues(b, 6, _rec(b, 6));
        assertEq(pv.length, 8 + 2 * 152);
        assertEq(uint8(pv[0]), 38);
        for (uint256 i = 0; i < 152; ++i) {
            assertEq(pv[8 + i], one[8 + i]);
            assertEq(pv[160 + i], two[8 + i]);
        }
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
        vd.answerBatch(ids, ds, ss, vd.batchPublicValues(ids, ds, ss));
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
        bytes memory pv = vd.batchPublicValues(ids, ds, ss);
        pv[pv.length - 1] ^= 0x01;
        vm.expectRevert(bytes("values"));
        vd.answerBatch(ids, ds, ss, pv);
    }

    function testBatchNamingASettlementTwiceFails() public {
        uint256 r = _register(AGENT_PK, 10);
        (uint256[] memory one, uint64[] memory d1) = _openMany(AGENT_PK, r, 1, challenger);
        uint256[] memory ids = new uint256[](2);
        uint64[] memory ds = new uint64[](2);
        (ids[0], ds[0]) = (one[0], d1[0]);
        (ids[1], ds[1]) = (one[0], d1[0]);
        Settlement[] memory ss = _recs(ids, ds);
        bytes memory pv = vd.batchPublicValues(ids, ds, ss);
        vm.expectRevert(ValidityDispute.NotOpen.selector);
        vd.answerBatch(ids, ds, ss, pv);
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
        vm.expectRevert(ValidityDispute.NotOpen.selector);
        vd.answerBatch(ids, ds, ss, "");
    }

    function testBatchAfterAnyDeadlineFails() public {
        uint256 r = _register(AGENT_PK, 10);
        (uint256[] memory ids, uint64[] memory ds) = _openMany(AGENT_PK, r, 2, challenger);
        vm.warp(_deadline(ids[0], ds[0]) + 1);
        Settlement[] memory ss = _recs(ids, ds);
        bytes memory pv = vd.batchPublicValues(ids, ds, ss);
        vm.expectRevert(ValidityDispute.TooLate.selector);
        vd.answerBatch(ids, ds, ss, pv);
    }

    function testEmptyAndUnevenBatchesFail() public {
        uint256[] memory none = new uint256[](0);
        uint64[] memory noneD = new uint64[](0);
        Settlement[] memory noneS = new Settlement[](0);
        vm.expectRevert(ValidityDispute.EmptyBatch.selector);
        vd.answerBatch(none, noneD, noneS, "");
        uint256 r = _register(AGENT_PK, 10);
        (uint256[] memory ids, uint64[] memory ds) = _openMany(AGENT_PK, r, 1, challenger);
        vm.expectRevert(ValidityDispute.LengthMismatch.selector);
        vd.answerBatch(ids, noneD, noneS, "");
        vm.expectRevert(ValidityDispute.LengthMismatch.selector);
        vd.answerBatch(ids, ds, noneS, "");
    }

    function testSingleAnswerUsesTheSingleKey() public {
        uint256 r = _register(AGENT_PK, 10);
        (uint256[] memory ids, uint64[] memory ds) = _openMany(AGENT_PK, r, 1, challenger);
        Settlement memory s = _rec(ids[0], ds[0]);
        vd.answer(ids[0], ds[0], s, vd.publicValues(ids[0], ds[0], s));
        assertEq(uint256(vd.challengeOf(ids[0], ds[0]).status), uint256(ValidityDispute.Status.Answered));
    }

    function testAnsweredSettlementCannotBeChallengedAgain() public {
        uint256 r = _register(AGENT_PK, 10);
        (uint256[] memory ids, uint64[] memory ds) = _openMany(AGENT_PK, r, 1, challenger);
        Settlement memory s = _rec(ids[0], ds[0]);
        vd.answer(ids[0], ds[0], s, vd.publicValues(ids[0], ds[0], s));
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
        assertEq(principal.balance, before + AGENT_BOND);
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
        uint256 before = agent.balance;
        acc.close(r);
        assertEq(agent.balance, before);
    }

    function testCloseAfterAnAnsweredChallengeReturnsTheBond() public {
        uint256 r = _register(AGENT_PK, 10);
        address agent = vm.addr(AGENT_PK);
        Settlement memory s = _settle(AGENT_PK, r, 5);
        _openBy(challenger, r, 5);
        vd.answer(r, 5, s, vd.publicValues(r, 5, s));
        vm.warp(block.timestamp + LIFE + ACCEPT + 1 hours + 1);
        uint256 before = agent.balance;
        acc.close(r);
        assertEq(agent.balance, before + AGENT_BOND);
    }

    function testDisputeWindowMustFitTheCloseDelay() public {
        Reserve short = new Reserve(DOMAIN, address(token), address(0), 1 hours, ACCEPT);
        vm.expectRevert(bytes("close delay"));
        short.setDispute(address(vd));
    }
}
