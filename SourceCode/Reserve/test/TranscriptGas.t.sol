// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {console} from "forge-std/Test.sol";
import {Reserve} from "../src/Reserve.sol";
import {Statement} from "./Statement.sol";
import {Fixture} from "./Fixture.sol";

/// What a settlement costs, now that it moves the payment as well as
/// publishing its evidence. Every figure is the settle call alone, warmed by
/// one earlier settlement on the same delegation.
contract TranscriptGas is Fixture {
    uint64 constant B0 = Statement.RANGE_BASE;

    function setUp() public {
        _base();
    }

    /// A payment publishes three values per unit it consumes, so the cost
    /// follows the units, from one unit to the 64 a slot cover allows.
    function testStoredAgainstLogged() public {
        uint16[6] memory covers = [uint16(1), 3, 8, 14, 30, 64];
        for (uint256 k = 0; k < covers.length; ++k) {
            uint256 a = _reg(Reserve.Funding.Deposit);
            uint256 b = _reg(Reserve.Funding.Deposit);
            _settle(a, 1, _elems(covers[k], 1), false);
            uint256 stored = _settle(a, 2, _elems(covers[k], 2), false);
            _settle(b, 1, _elems(covers[k], 1), true);
            uint256 logged = _settle(b, 2, _elems(covers[k], 2), true);
            console.log("units", covers[k]);
            console.log("  stored", stored);
            console.log("  logged", logged);
            console.log("  ratio x100", (stored * 100) / logged);
        }
    }

    /// The two ways of funding a delegation, at the cover the paper uses.
    function testDepositAgainstPermit2() public {
        uint256 a = _reg(Reserve.Funding.Deposit);
        uint256 b = _reg(Reserve.Funding.Permit2);
        _settle(a, 1, _elems(64, 1), true);
        uint256 dep = _settle(a, 2, _elems(64, 2), true);
        _settle(b, 1, _elems(64, 1), true);
        uint256 p2 = _settle(b, 2, _elems(64, 2), true);
        console.log("settle logged, 64 units, deposit", dep);
        console.log("settle logged, 64 units, permit2", p2);
        console.log("  permit2 minus deposit", p2 - dep);
        assertEq(token.balanceOf(payee), 1 + 4 * 64 * Statement.UNIT);
    }

    function testAllOperationsOneWarming() public {
        uint256 g0 = gasleft();
        uint256 id = _reg(Reserve.Funding.Deposit);
        console.log("Open, deposit", g0 - gasleft());
        uint256 g1 = gasleft();
        _reg(Reserve.Funding.Permit2);
        console.log("Open, permit2", g1 - gasleft());

        _settle(id, 1, _elems(64, 1), true);
        console.log("Settle logged, 64 units", _settle(id, 2, _elems(64, 2), true));

        uint64[] memory s1 = _one(B0);
        uint64[] memory s2 = _one(B0 + 128);
        uint64[] memory l64 = _one(64);
        vm.prank(principal);
        uint256 g2 = gasleft();
        acc.revoke(id, s1, l64, keccak256("root1"));
        console.log("Revoke, first range", g2 - gasleft());
        vm.prank(principal);
        uint256 g3 = gasleft();
        acc.revoke(id, s2, l64, keccak256("root2"));
        console.log("Revoke, later range", g3 - gasleft());

        uint64[2] memory secret = [Statement.SECRET0, Statement.SECRET1];
        uint256 g4 = gasleft();
        acc.claim(id, secret);
        console.log("Claim", g4 - gasleft());
    }

    function testLoggedAgainstPreventive() public {
        uint256 a = _reg(Reserve.Funding.Deposit);
        vm.prank(principal);
        uint256 p = prev.register(agent, CAP, BUDGET, VELOCITY, WINDOW);

        _settle(a, 1, _elems(64, 1), true);
        vm.prank(agent);
        prev.settle(p, payee, 64 * Statement.UNIT, 1);

        uint256 logged = _settle(a, 2, _elems(64, 2), true);
        vm.prank(agent);
        uint256 g1 = gasleft();
        prev.settle(p, payee, 64 * Statement.UNIT, 2);
        uint256 preventive = g1 - gasleft();

        console.log("accountable, logged, 64 units", logged);
        console.log("preventive", preventive);
        console.log("ratio x100", (logged * 100) / preventive);
    }

    /// Call data alone, at 16 gas a non-zero byte, for presenting the batch
    /// proof of 128 payments the harness measures. Not a call: it exceeds the
    /// per-transaction cap.
    function testChallengeCallDataBudget() public pure {
        uint256 proofBytes = 5_378_237;
        console.log("challenge call data alone, gas", proofBytes * 16);
        console.log("proof bytes", proofBytes);
        console.log("over the 2^24 per-transaction cap x100", proofBytes * 16 * 100 / (1 << 24));
    }

    function testRevokeIsThePrincipals() public {
        uint256 id = _reg(Reserve.Funding.Deposit);
        uint64[] memory st = _one(B0);
        uint64[] memory ln = _one(64);
        vm.expectRevert(Reserve.NotPrincipal.selector);
        acc.revoke(id, st, ln, keccak256("root1"));
    }

    /// (I6): a revoked range lies inside the delegation's range and overlaps
    /// no range already revoked, including one named earlier in the same call.
    function testRevokeRangeRules() public {
        uint256 id = _reg(Reserve.Funding.Deposit);
        vm.startPrank(principal);
        vm.expectRevert(Reserve.RangeOutside.selector);
        acc.revoke(id, _one(B0 + Statement.RANGE_LEN - 10), _one(64), keccak256("r"));
        vm.expectRevert(Reserve.RangeOutside.selector);
        acc.revoke(id, _one(B0 - 1), _one(2), keccak256("r"));
        vm.expectRevert(Reserve.RangeOutside.selector);
        acc.revoke(id, _one(B0 + 5), _one(0), keccak256("r"));
        acc.revoke(id, _one(B0 + 100), _one(50), keccak256("r1"));
        vm.expectRevert(Reserve.RangeOverlaps.selector);
        acc.revoke(id, _one(B0 + 149), _one(10), keccak256("r2"));
        vm.expectRevert(Reserve.RangeOverlaps.selector);
        acc.revoke(id, _one(B0 + 60), _one(41), keccak256("r2"));
        uint64[] memory st = new uint64[](2);
        uint64[] memory ln = new uint64[](2);
        st[0] = B0 + 300; ln[0] = 20;
        st[1] = B0 + 310; ln[1] = 20;
        vm.expectRevert(Reserve.RangeOverlaps.selector);
        acc.revoke(id, st, ln, keccak256("r2"));
        st[1] = B0 + 320;
        acc.revoke(id, st, ln, keccak256("r2"));
        vm.stopPrank();
        assertEq(acc.revokedCount(id), 3);
        assertEq(acc.epochOf(id), 2);
    }

    /// The signature covers the payee, so a settlement redirected to anyone
    /// else does not verify.
    function testPayeeIsBound() public {
        uint256 id = _reg(Reserve.Funding.Deposit);
        uint64[] memory e = _elems(14, 1);
        bytes memory sg = _sign(id, _amount(e), 1, _now(), e);
        vm.expectRevert(Reserve.BadSignature.selector);
        acc.settleLogged(id, address(0xBAD), _amount(e), 1, _now(), e, OPENING, sg);
    }

    /// The signature covers the commitment to the hidden fields, so no one can
    /// settle the payment under an opening the agent did not sign.
    function testOpeningIsBound() public {
        uint256 id = _reg(Reserve.Funding.Deposit);
        uint64[] memory e = _elems(14, 1);
        bytes memory sg = _sign(id, _amount(e), 1, _now(), e);
        vm.expectRevert(Reserve.BadSignature.selector);
        acc.settleLogged(id, payee, _amount(e), 1, _now(), e, keccak256("other fields"), sg);
    }

    /// The record the monitor reads carries the signed time and the opening.
    function testSettledCarriesTimeAndOpening() public {
        uint256 id = _reg(Reserve.Funding.Deposit);
        uint64[] memory e = _elems(14, 1);
        uint64 t = _now();
        bytes memory sg = _sign(id, _amount(e), 1, t, e);
        vm.expectEmit(true, false, false, true, address(acc));
        emit Reserve.Settled(id, 1, _amount(e), payee, t, OPENING);
        acc.settleLogged(id, payee, _amount(e), 1, t, e, OPENING, sg);
    }

    function testDigestSettlesOnce() public {
        uint256 id = _reg(Reserve.Funding.Deposit);
        _settle(id, 1, _elems(14, 1), true);
        uint64[] memory e = _elems(14, 2);
        bytes memory sg = _sign(id, _amount(e), 1, _now(), e);
        vm.expectRevert(Reserve.IndexAlreadySettled.selector);
        acc.settleLogged(id, payee, _amount(e), 1, _now(), e, OPENING, sg);
    }

    /// The signed time must be within maxAge of the reserve's clock either way.
    function testStaleOrFutureTimeRefused() public {
        uint256 id = _reg(Reserve.Funding.Deposit);
        vm.warp(10 days);
        uint64[] memory e = _elems(14, 1);
        uint64 old = _now() - MAX_AGE - 1;
        bytes memory sg = _sign(id, _amount(e), 1, old, e);
        vm.expectRevert(Reserve.StaleTime.selector);
        acc.settleLogged(id, payee, _amount(e), 1, old, e, OPENING, sg);
        uint64 ahead = _now() + MAX_AGE + 1;
        sg = _sign(id, _amount(e), 1, ahead, e);
        vm.expectRevert(Reserve.StaleTime.selector);
        acc.settleLogged(id, payee, _amount(e), 1, ahead, e, OPENING, sg);
        uint64 edge = _now() - MAX_AGE;
        sg = _sign(id, _amount(e), 1, edge, e);
        acc.settleLogged(id, payee, _amount(e), 1, edge, e, OPENING, sg);
    }

    /// A payment publishes exactly the slots its amount pays for: one more or
    /// one fewer is refused, and the boundary amounts of a unit count pass.
    function testSlotCountFollowsTheAmount() public {
        uint256 id = _reg(Reserve.Funding.Deposit);
        uint64[] memory e = _elems(3, 1);
        uint64 u = Statement.UNIT;
        uint64[3] memory bad = [2 * u, 3 * u + 1, 0];
        for (uint256 i = 0; i < bad.length; ++i) {
            bytes memory sg = _sign(id, bad[i], 1, _now(), e);
            vm.expectRevert(Reserve.WrongSlotCount.selector);
            acc.settleLogged(id, payee, bad[i], 1, _now(), e, OPENING, sg);
        }
        bytes memory ok = _sign(id, 2 * u + 1, 1, _now(), e);
        acc.settleLogged(id, payee, 2 * u + 1, 1, _now(), e, OPENING, ok);
        ok = _sign(id, 3 * u, 2, _now(), e);
        acc.settleLogged(id, payee, 3 * u, 2, _now(), e, OPENING, ok);
    }

    function testNoSettlementAfterExpiry() public {
        uint256 id = _reg(Reserve.Funding.Deposit);
        vm.warp(block.timestamp + LIFE + 1);
        uint64[] memory e = _elems(14, 1);
        bytes memory sg = _sign(id, _amount(e), 1, _now(), e);
        vm.expectRevert(Reserve.Expired.selector);
        acc.settleLogged(id, payee, _amount(e), 1, _now(), e, OPENING, sg);
    }

    /// With no dispute contract, close waits only for expiry and the delay,
    /// then returns the deposit left to the principal and the bond to the agent.
    function testCloseReturnsDepositAndBond() public {
        uint256 id = _reg(Reserve.Funding.Deposit);
        _settle(id, 1, _elems(14, 1), true);
        vm.warp(block.timestamp + LIFE + CLOSE_DELAY);
        vm.expectRevert(Reserve.NotClosable.selector);
        acc.close(id);
        vm.warp(block.timestamp + 1);
        uint256 tokens = token.balanceOf(principal);
        uint256 bond = agent.balance;
        acc.close(id);
        assertEq(token.balanceOf(principal), tokens + BUDGET - 14 * Statement.UNIT);
        assertEq(agent.balance, bond + 1 ether);
        vm.expectRevert(Reserve.NotClosable.selector);
        acc.close(id);
        vm.expectRevert(Reserve.BondAlreadyPaid.selector);
        acc.claim(id, [Statement.SECRET0, Statement.SECRET1]);
    }

    /// A claim opens H(s) with the circuit's permutation: any other secret,
    /// including the right one with a lane changed, is refused.
    function testWrongSecretCannotClaim() public {
        uint256 id = _reg(Reserve.Funding.Deposit);
        vm.expectRevert(Reserve.SecretDoesNotOpen.selector);
        acc.claim(id, [Statement.SECRET0, Statement.SECRET1 + 1]);
    }

    function testClaimedBondIsNotReturnedAtClose() public {
        uint256 id = _reg(Reserve.Funding.Deposit);
        acc.claim(id, [Statement.SECRET0, Statement.SECRET1]);
        uint64[] memory e = _elems(1, 1);
        bytes memory sg = _sign(id, _amount(e), 1, _now(), e);
        vm.expectRevert(Reserve.Frozen.selector);
        acc.settleLogged(id, payee, _amount(e), 1, _now(), e, OPENING, sg);
        vm.warp(block.timestamp + LIFE + CLOSE_DELAY + 1);
        uint256 bond = agent.balance;
        acc.close(id);
        assertEq(agent.balance, bond);
    }
}
