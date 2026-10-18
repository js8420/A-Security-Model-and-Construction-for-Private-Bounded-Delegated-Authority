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
        vd = new ValidityDispute(address(acc), address(new EchoVerifier(PROGRAM)), PROGRAM, ACCEPT, WINDOW, SLOT, BOND);
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
        _settle(AGENT_PK, r, 5);
        _openBy(challenger, r, 5);
        _answerAlone(r, 5);
        vm.warp(block.timestamp + LIFE + ACCEPT + 1 hours + 1);
        uint256 before = agent.balance;
        acc.close(r);
        assertEq(agent.balance, before + AGENT_BOND);
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
        uint256 bond = agent.balance;
        acc.close(r);
        assertEq(agent.balance, bond + AGENT_BOND);
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

    function _receipt(uint256 pk, uint256 r, bytes32 root, uint64 at) internal view returns (bytes memory) {
        (uint8 v, bytes32 rr, bytes32 ss) = vm.sign(pk, vd.receiptDigest(r, root, at));
        return abi.encodePacked(rr, ss, v);
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
    /// still gets the agent's bond, and the agent gets the answerer's stake.
    function testSilentAnswererPaysTheAgent() public {
        (uint256 r, address ans) = _registerWithAnswerer();
        _settle(AGENT_PK, r, 5);
        Settlement memory s = _rec(r, 5);
        uint64 at = uint64(block.timestamp);
        bytes memory rc = _receipt(ANSWERER_PK, r, vd.leafHash(r, 5, s), at);
        _openBy(principal, r, 5);
        vm.warp(_deadline(r, 5) + 1);
        uint256 p0 = principal.balance;
        vd.expire(r, 5);
        assertEq(principal.balance, p0 + AGENT_BOND);
        address agent = vm.addr(AGENT_PK);
        uint256 a0 = agent.balance;
        vd.slashAnswerer(r, 5, s, 0, new bytes32[](0), at, rc);
        assertEq(agent.balance, a0 + AGENT_BOND);
        (, uint256 left) = acc.answererOf(r);
        assertEq(left, 0);
        assertEq(ans.balance, 10 ether - AGENT_BOND);
    }

    function testSlashBeforeExpiryRefused() public {
        (uint256 r, ) = _registerWithAnswerer();
        _settle(AGENT_PK, r, 5);
        Settlement memory s = _rec(r, 5);
        uint64 at = uint64(block.timestamp);
        bytes memory rc = _receipt(ANSWERER_PK, r, vd.leafHash(r, 5, s), at);
        _openBy(principal, r, 5);
        vm.expectRevert(ValidityDispute.NotExpired.selector);
        vd.slashAnswerer(r, 5, s, 0, new bytes32[](0), at, rc);
        _answerAlone(r, 5);
        vm.expectRevert(ValidityDispute.NotExpired.selector);
        vd.slashAnswerer(r, 5, s, 0, new bytes32[](0), at, rc);
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
        bytes memory rc = _receipt(OTHER_PK, r, vd.leafHash(r, 5, s), at);
        vm.expectRevert(ValidityDispute.BadReceipt.selector);
        vd.slashAnswerer(r, 5, s, 0, new bytes32[](0), at, rc);
    }

    /// A receipt for a batch the settlement is not in moves nothing.
    function testReceiptForAnotherBatchRefused() public {
        (uint256 r, Settlement memory s, uint64 at) = _expired();
        bytes32[] memory path = new bytes32[](1);
        path[0] = keccak256("other");
        bytes memory rc = _receipt(ANSWERER_PK, r, keccak256("another root"), at);
        vm.expectRevert(ValidityDispute.BadReceipt.selector);
        vd.slashAnswerer(r, 5, s, 0, path, at, rc);
        vm.expectRevert(ValidityDispute.BadReceipt.selector);
        vd.slashAnswerer(r, 5, s, 0, new bytes32[](0), at, rc);
    }

    /// An answerer handed the proof with less than an answer window left is
    /// not to blame.
    function testReceiptWithoutAFullWindowRefused() public {
        (uint256 r, Settlement memory s, ) = _expired();
        uint64 late = _deadline(r, 5) - WINDOW + 1;
        bytes memory rc = _receipt(ANSWERER_PK, r, vd.leafHash(r, 5, s), late);
        vm.expectRevert(ValidityDispute.ReceiptTooLate.selector);
        vd.slashAnswerer(r, 5, s, 0, new bytes32[](0), late, rc);
    }

    /// A receipt with a different time than the one signed moves nothing.
    function testReceiptTimeIsSigned() public {
        (uint256 r, Settlement memory s, uint64 at) = _expired();
        bytes memory rc = _receipt(ANSWERER_PK, r, vd.leafHash(r, 5, s), at);
        vm.expectRevert(ValidityDispute.BadReceipt.selector);
        vd.slashAnswerer(r, 5, s, 0, new bytes32[](0), at - 1, rc);
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
        bytes memory rc = _receipt(ANSWERER_PK, r, vd.leafHash(r, 5, s), at);
        _openBy(principal, r, 5);
        vm.warp(_deadline(r, 5) + 1);
        vd.expire(r, 5);
        g0 = gasleft();
        vd.slashAnswerer(r, 5, s, 0, new bytes32[](0), at, rc);
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
}
