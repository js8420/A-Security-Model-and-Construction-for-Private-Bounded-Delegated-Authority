// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {console} from "forge-std/Test.sol";
import {Reserve} from "../src/Reserve.sol";
import {Fixture} from "./Fixture.sol";

/// What a settlement costs, now that it moves the payment as well as
/// publishing its evidence. Every figure is the settle call alone, warmed by
/// one earlier settlement on the same delegation.
contract TranscriptGas is Fixture {
    function setUp() public {
        _base();
    }

    function testStoredAgainstLogged() public {
        uint16[4] memory covers = [uint16(14), 30, 64, 128];
        for (uint256 k = 0; k < covers.length; ++k) {
            uint256 a = _reg(Reserve.Funding.Deposit);
            uint256 b = _reg(Reserve.Funding.Deposit);
            _settle(a, 1, _elems(covers[k], 1), false);
            uint256 stored = _settle(a, 2, _elems(covers[k], 2), false);
            _settle(b, 1, _elems(covers[k], 1), true);
            uint256 logged = _settle(b, 2, _elems(covers[k], 2), true);
            console.log("cover", covers[k]);
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
        console.log("settle logged, cover 64, deposit", dep);
        console.log("settle logged, cover 64, permit2", p2);
        console.log("  permit2 minus deposit", p2 - dep);
        assertEq(token.balanceOf(payee), 1 + 4 * 1000);
    }

    function testAllOperationsOneWarming() public {
        uint256 g0 = gasleft();
        uint256 id = _reg(Reserve.Funding.Deposit);
        console.log("Open, deposit", g0 - gasleft());
        uint256 g1 = gasleft();
        _reg(Reserve.Funding.Permit2);
        console.log("Open, permit2", g1 - gasleft());

        _settle(id, 1, _elems(64, 1), true);
        console.log("Settle logged, cover 64", _settle(id, 2, _elems(64, 2), true));

        vm.prank(principal);
        uint256 g2 = gasleft();
        acc.revoke(id, 0, 64);
        console.log("Revoke, first range", g2 - gasleft());
        vm.prank(principal);
        uint256 g3 = gasleft();
        acc.revoke(id, 128, 64);
        console.log("Revoke, later range", g3 - gasleft());

        uint64[2] memory secret = [uint64(7), uint64(11)];
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
        prev.settle(p, payee, 1000, 1);

        uint256 logged = _settle(a, 2, _elems(64, 2), true);
        vm.prank(agent);
        uint256 g1 = gasleft();
        prev.settle(p, payee, 1000, 2);
        uint256 preventive = g1 - gasleft();

        console.log("accountable, logged, cover 64", logged);
        console.log("preventive", preventive);
        console.log("ratio x100", (logged * 100) / preventive);
    }

    /// Call data alone, at 16 gas a non-zero byte, for presenting the proof
    /// the harness measures. Not a call: it exceeds the per-transaction cap.
    function testChallengeCallDataBudget() public pure {
        uint256 proofBytes = 5_137_181;
        console.log("challenge call data alone, gas", proofBytes * 16);
        console.log("proof bytes", proofBytes);
        console.log("over the 2^24 per-transaction cap x100", proofBytes * 16 * 100 / (1 << 24));
    }

    function testRevokeIsThePrincipals() public {
        uint256 id = _reg(Reserve.Funding.Deposit);
        vm.expectRevert(Reserve.NotPrincipal.selector);
        acc.revoke(id, 0, 64);
    }

    /// The signature covers the payee, so a settlement redirected to anyone
    /// else does not verify.
    function testPayeeIsBound() public {
        uint256 id = _reg(Reserve.Funding.Deposit);
        uint64[] memory e = _elems(14, 1);
        bytes32 c = _commit(id, 1);
        bytes memory sg = _sign(id, 1000, 1, e, c);
        vm.expectRevert(Reserve.BadSignature.selector);
        acc.settleLogged(id, address(0xBAD), 1000, 1, e, c, sg);
    }

    function testDigestSettlesOnce() public {
        uint256 id = _reg(Reserve.Funding.Deposit);
        _settle(id, 1, _elems(14, 1), true);
        uint64[] memory e = _elems(14, 2);
        bytes32 c = _commit(id, 1);
        bytes memory sg = _sign(id, 1000, 1, e, c);
        vm.expectRevert(Reserve.IndexAlreadySettled.selector);
        acc.settleLogged(id, payee, 1000, 1, e, c, sg);
    }
}
