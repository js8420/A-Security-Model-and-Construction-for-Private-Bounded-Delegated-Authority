// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test, console} from "forge-std/Test.sol";
import {RevealDispute} from "../src/RevealDispute.sol";
import {KeccakTree} from "./KeccakTree.sol";

/// The reveal-on-dispute baseline: an honest answer passes, each broken rule
/// is refused, an unanswered challenge freezes, and an overspend split across
/// two domains passes on both.
contract RevealDisputeTest is Test {
    uint64 constant DOMAIN = 8453;
    uint64 constant UNIT = 10_000;
    uint64 constant BUDGET = 100_000;
    uint64 constant T0 = 5_000;
    address constant AGENT = address(0xA6E47);

    struct Setup {
        RevealDispute rd;
        uint256 id;
        RevealDispute.Policy p;
        bytes32[] merchants;
        bytes32[] categories;
        bytes32[] revoked;
        uint64[] starts;
        uint64[] lengths;
    }

    function _setup(uint64 domain, uint256 depth) internal returns (Setup memory s) {
        vm.warp(T0);
        s.rd = new RevealDispute(domain, 1 days, 2 hours, 0.01 ether);
        s.merchants = KeccakTree.merchants(depth);
        s.categories = KeccakTree.categories(depth);
        (s.revoked, s.starts, s.lengths) = KeccakTree.revoked(depth, 3);
        s.p = RevealDispute.Policy({
            budget: BUDGET, cap: 50_000, tStart: 0, tExpiry: T0 + 30 days,
            merchants: KeccakTree.root(s.merchants), categories: KeccakTree.root(s.categories), salt: keccak256("policy salt")
        });
        s.id = s.rd.register(keccak256(abi.encode(s.p)), KeccakTree.root(s.revoked), UNIT, 0, 4096, AGENT);
    }

    function _opening(uint64 domain, uint64 amount, uint64 merchant, uint64 category, uint64 runStart, uint64 nonce)
        internal
        pure
        returns (RevealDispute.Opening memory)
    {
        return RevealDispute.Opening({
            salt: keccak256(abi.encode("salt", nonce)), amount: amount, merchant: merchant, category: category, time: T0,
            payee: KeccakTree.payeeOf(merchant), domain: domain, nonce: nonce, runStart: runStart
        });
    }

    /// Settles the opening and opens the principal's challenge. Returns the running total recorded with it.
    function _settleAndChallenge(Setup memory s, uint64 digest, RevealDispute.Opening memory o) internal returns (uint64 total) {
        s.rd.settle(s.id, digest, o.amount, o.payee, o.time, keccak256(abi.encode(o)));
        (, , , , , , total, , , ) = s.rd.delegations(s.id);
        s.rd.open{value: 0.01 ether}(s.id, digest, o.amount, o.payee, o.time, keccak256(abi.encode(o)), total);
    }

    function _answer(Setup memory s, uint64 digest, RevealDispute.Opening memory o, uint64 total, uint256 gapAt)
        internal
        returns (uint256 gas)
    {
        RevealDispute.Gap memory g = KeccakTree.gap(s.revoked, s.starts, s.lengths, gapAt);
        bytes32[] memory mp = KeccakTree.path(s.merchants, o.merchant);
        bytes32[] memory cp = KeccakTree.path(s.categories, o.category);
        RevealDispute.Answer memory a = RevealDispute.Answer(o, total, s.p, o.merchant, mp, o.category, cp, g);
        uint256 before = gasleft();
        s.rd.answer(s.id, digest, a);
        gas = before - gasleft();
    }

    function _status(Setup memory s, uint64 digest) internal view returns (RevealDispute.Status st) {
        (, , st) = s.rd.challenges(s.rd.key(s.id, digest));
    }

    function testHonestAnswerReleasesTheHold() public {
        Setup memory s = _setup(DOMAIN, 7);
        RevealDispute.Opening memory o = _opening(DOMAIN, 20_000, 5, 3, 0, 1);
        uint64 total = _settleAndChallenge(s, 1, o);
        vm.expectRevert(RevealDispute.Held.selector);
        s.rd.settle(s.id, 2, 1, address(1), T0, bytes32(0));
        _answer(s, 1, o, total, 0);
        assertEq(uint256(_status(s, 1)), uint256(RevealDispute.Status.Answered));
        s.rd.settle(s.id, 2, 1, address(1), T0, bytes32(0));
    }

    function testRunBetweenTwoRevokedRangesPasses() public {
        Setup memory s = _setup(DOMAIN, 7);
        RevealDispute.Opening memory o = _opening(DOMAIN, 20_000, 5, 3, 1004, 1);
        uint64 total = _settleAndChallenge(s, 1, o);
        _answer(s, 1, o, total, 1);
        assertEq(uint256(_status(s, 1)), uint256(RevealDispute.Status.Answered));
    }

    function _refused(RevealDispute.Opening memory o, bytes4 why, uint256 gapAt) internal {
        Setup memory s = _setup(DOMAIN, 7);
        uint64 total = _settleAndChallenge(s, 1, o);
        RevealDispute.Gap memory g = KeccakTree.gap(s.revoked, s.starts, s.lengths, gapAt);
        bytes32[] memory mp = KeccakTree.path(s.merchants, o.merchant % 128);
        bytes32[] memory cp = KeccakTree.path(s.categories, o.category % 128);
        vm.expectRevert(why);
        s.rd.answer(s.id, 1, RevealDispute.Answer(o, total, s.p, o.merchant % 128, mp, o.category % 128, cp, g));
    }

    function testAboveCapRefused() public {
        _refused(_opening(DOMAIN, 50_001, 5, 3, 0, 1), RevealDispute.AboveCap.selector, 0);
    }

    function testMerchantPaidElsewhereRefused() public {
        RevealDispute.Opening memory o = _opening(DOMAIN, 20_000, 5, 3, 0, 1);
        o.payee = address(0xBAD);
        _refused(o, RevealDispute.MerchantNotAllowed.selector, 0);
    }

    function testMerchantOutsideTheListRefused() public {
        _refused(_opening(DOMAIN, 20_000, 200, 3, 0, 1), RevealDispute.MerchantNotAllowed.selector, 0);
    }

    function testCategoryOutsideTheListRefused() public {
        _refused(_opening(DOMAIN, 20_000, 5, 300, 0, 1), RevealDispute.CategoryNotAllowed.selector, 0);
    }

    function testOutsideTheValidityWindowRefused() public {
        Setup memory s = _setup(DOMAIN, 7);
        s.p.tStart = T0 + 1;
        RevealDispute.Policy memory p = s.p;
        uint256 id = s.rd.register(keccak256(abi.encode(p)), KeccakTree.root(s.revoked), UNIT, 0, 4096, AGENT);
        s.id = id;
        RevealDispute.Opening memory o = _opening(DOMAIN, 20_000, 5, 3, 0, 1);
        uint64 total = _settleAndChallenge(s, 1, o);
        RevealDispute.Gap memory g = KeccakTree.gap(s.revoked, s.starts, s.lengths, 0);
        bytes32[] memory mp = KeccakTree.path(s.merchants, 5);
        bytes32[] memory cp = KeccakTree.path(s.categories, 3);
        vm.expectRevert(RevealDispute.OutsideWindow.selector);
        s.rd.answer(s.id, 1, RevealDispute.Answer(o, total, p, 5, mp, 3, cp, g));
    }

    function testRevokedRunRefused() public {
        _refused(_opening(DOMAIN, 20_000, 5, 3, 1002, 1), RevealDispute.Revoked.selector, 1);
    }

    function testRunOutsideTheRangeRefused() public {
        _refused(_opening(DOMAIN, 20_000, 5, 3, 4095, 1), RevealDispute.OutsideRange.selector, 3);
    }

    function testOpeningOfAnotherDomainRefused() public {
        _refused(_opening(10, 20_000, 5, 3, 0, 1), RevealDispute.OpeningMismatch.selector, 0);
    }

    function testWrongPolicyRefused() public {
        Setup memory s = _setup(DOMAIN, 7);
        RevealDispute.Opening memory o = _opening(DOMAIN, 20_000, 5, 3, 0, 1);
        uint64 total = _settleAndChallenge(s, 1, o);
        s.p.budget += 1;
        RevealDispute.Gap memory g = KeccakTree.gap(s.revoked, s.starts, s.lengths, 0);
        bytes32[] memory mp = KeccakTree.path(s.merchants, 5);
        bytes32[] memory cp = KeccakTree.path(s.categories, 3);
        vm.expectRevert(RevealDispute.PolicyMismatch.selector);
        s.rd.answer(s.id, 1, RevealDispute.Answer(o, total, s.p, 5, mp, 3, cp, g));
    }

    function testOverspendOnOneDomainRefused() public {
        Setup memory s = _setup(DOMAIN, 7);
        for (uint64 i = 0; i < 2; ++i) {
            RevealDispute.Opening memory a = _opening(DOMAIN, 50_000, 5, 3, 5 * i, 10 + i);
            s.rd.settle(s.id, 10 + i, a.amount, a.payee, a.time, keccak256(abi.encode(a)));
        }
        RevealDispute.Opening memory o = _opening(DOMAIN, 10_000, 5, 3, 10, 1);
        uint64 total = _settleAndChallenge(s, 1, o);
        assertEq(total, 110_000);
        RevealDispute.Gap memory g = KeccakTree.gap(s.revoked, s.starts, s.lengths, 0);
        bytes32[] memory mp = KeccakTree.path(s.merchants, 5);
        bytes32[] memory cp = KeccakTree.path(s.categories, 3);
        vm.expectRevert(RevealDispute.OverBudget.selector);
        s.rd.answer(s.id, 1, RevealDispute.Answer(o, total, s.p, 5, mp, 3, cp, g));
    }

    /// 60,000 on each of two domains, 120,000 in all against a budget of
    /// 100,000: each domain's contract sees only its own 60,000, so both
    /// answers pass and the overspend goes unseen.
    function testOverspendAcrossTwoDomainsPassesOnBoth() public {
        Setup memory a = _setup(DOMAIN, 7);
        Setup memory b = _setup(10, 7);
        RevealDispute.Opening memory oa = _opening(DOMAIN, 50_000, 5, 3, 0, 1);
        RevealDispute.Opening memory ob = _opening(10, 50_000, 5, 3, 5, 2);
        a.rd.settle(a.id, 7, 10_000, oa.payee, T0, keccak256("first on A"));
        b.rd.settle(b.id, 8, 10_000, ob.payee, T0, keccak256("first on B"));
        uint64 ta = _settleAndChallenge(a, 1, oa);
        uint64 tb = _settleAndChallenge(b, 2, ob);
        _answer(a, 1, oa, ta, 0);
        _answer(b, 2, ob, tb, 0);
        assertEq(uint256(ta) + tb, 120_000);
        assertEq(uint256(_status(a, 1)), uint256(RevealDispute.Status.Answered));
        assertEq(uint256(_status(b, 2)), uint256(RevealDispute.Status.Answered));
    }

    function testUnansweredChallengeFreezes() public {
        Setup memory s = _setup(DOMAIN, 7);
        RevealDispute.Opening memory o = _opening(DOMAIN, 20_000, 5, 3, 0, 1);
        _settleAndChallenge(s, 1, o);
        vm.expectRevert(RevealDispute.TooEarly.selector);
        s.rd.expire(s.id, 1);
        vm.warp(block.timestamp + 2 hours + 1);
        s.rd.expire(s.id, 1);
        vm.expectRevert(RevealDispute.Frozen.selector);
        s.rd.settle(s.id, 2, 1, address(1), T0, bytes32(0));
    }

    function testChallengeAfterTheAcceptanceWindowRefused() public {
        Setup memory s = _setup(DOMAIN, 7);
        RevealDispute.Opening memory o = _opening(DOMAIN, 20_000, 5, 3, 0, 1);
        s.rd.settle(s.id, 1, o.amount, o.payee, o.time, keccak256(abi.encode(o)));
        vm.warp(T0 + 1 days + 1);
        vm.expectRevert(RevealDispute.WindowClosed.selector);
        s.rd.open{value: 0.01 ether}(s.id, 1, o.amount, o.payee, o.time, keccak256(abi.encode(o)), o.amount);
    }

    /// The principal, holding the late opening off chain, cancels: the hold
    /// lifts, the bond comes back to it, the late agent earns nothing, and
    /// nothing is revealed.
    function testCancelReleasesTheHoldAndReturnsTheBond() public {
        Setup memory s = _setup(DOMAIN, 7);
        RevealDispute.Opening memory o = _opening(DOMAIN, 20_000, 5, 3, 0, 1);
        _settleAndChallenge(s, 1, o);
        vm.expectRevert(RevealDispute.Held.selector);
        s.rd.settle(s.id, 2, 1, address(1), T0, bytes32(0));
        s.rd.cancel(s.id, 1);
        assertEq(uint256(_status(s, 1)), uint256(RevealDispute.Status.Cancelled));
        assertEq(s.rd.credit(AGENT), 0);
        assertEq(s.rd.credit(address(this)), 0.01 ether);
        s.rd.settle(s.id, 2, 1, address(1), T0, bytes32(0));
        vm.expectRevert(RevealDispute.NotOpen.selector);
        _answer(s, 1, o, o.amount, 0);
        vm.warp(block.timestamp + 2 hours + 1);
        vm.expectRevert(RevealDispute.NotOpen.selector);
        s.rd.expire(s.id, 1);
    }

    function testOnlyThePrincipalCancels() public {
        Setup memory s = _setup(DOMAIN, 7);
        RevealDispute.Opening memory o = _opening(DOMAIN, 20_000, 5, 3, 0, 1);
        _settleAndChallenge(s, 1, o);
        vm.prank(AGENT);
        vm.expectRevert(RevealDispute.NotPrincipal.selector);
        s.rd.cancel(s.id, 1);
    }

    function testCancelAfterTheDeadlineRefused() public {
        Setup memory s = _setup(DOMAIN, 7);
        RevealDispute.Opening memory o = _opening(DOMAIN, 20_000, 5, 3, 0, 1);
        _settleAndChallenge(s, 1, o);
        vm.warp(block.timestamp + 2 hours + 1);
        vm.expectRevert(RevealDispute.TooLate.selector);
        s.rd.cancel(s.id, 1);
    }

    /// Execution gas of one answer, warm, by list depth: lists of 2^depth
    /// merchants, categories and revoked ranges.
    function testAnswerGasByDepth() public {
        uint256[4] memory depths = [uint256(1), 4, 7, 10];
        for (uint256 i = 0; i < depths.length; ++i) {
            Setup memory s = _setup(DOMAIN, depths[i]);
            RevealDispute.Opening memory o = _opening(DOMAIN, 20_000, 1, 1, 0, 1);
            uint64 total = _settleAndChallenge(s, 1, o);
            console.log("reveal answer, list depth", depths[i], "execution gas", _answer(s, 1, o, total, 0));
        }
    }
}
