// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test, console} from "forge-std/Test.sol";
import {Dispute} from "../src/Dispute.sol";

/// What a challenge costs when it does not carry the proof.
///
/// The settlement figures elsewhere in this folder are per payment; these are
/// per dispute, and a dispute is rare. The question the paper needs answered
/// is whether the protocol around the one-step adjudicator is affordable, and
/// how it scales with the length of the verification it disputes.
contract DisputeGas is Test {
    Dispute d;
    address defender = address(0xB0B);
    address challenger = address(0xC14);
    // funded in setUp so a challenger can post its bond

    function setUp() public {
        d = new Dispute(7 days, 0.01 ether);
        vm.deal(challenger, 1 ether);
    }

    function _play(uint64 steps) internal returns (uint256 total, uint64 n) {
        bytes32 id = keccak256(abi.encodePacked(steps));
        uint256 g = gasleft();
        vm.prank(challenger);
        d.open{value: 0.01 ether}(id, defender, steps, bytes32(uint256(1)), bytes32(uint256(2)));
        total = g - gasleft();

        uint64 lo = 0;
        uint64 hi = steps;
        while (hi - lo > 1) {
            uint64 mid = lo + (hi - lo) / 2;
            uint256 a = gasleft();
            vm.prank(defender);
            d.respond(id, keccak256(abi.encodePacked(mid)));
            total += a - gasleft();

            uint256 b = gasleft();
            vm.prank(challenger);
            d.choose(id, true, bytes32(0));
            total += b - gasleft();

            hi = mid;
            ++n;
        }

        uint256 c = gasleft();
        d.settleOneStep(id, false);
        total += c - gasleft();
    }

    function testCostByVerificationLength() public {
        uint64[5] memory steps = [uint64(1024), 16384, 262144, 1048576, 16777216];
        for (uint256 i = 0; i < steps.length; ++i) {
            (uint256 total, uint64 n) = _play(steps[i]);
            console.log("steps", steps[i]);
            console.log("  rounds", n);
            console.log("  total gas, excluding the one-step adjudicator", total);
        }
    }

    /// The case that matters for an agent holding the only copy of the proof:
    /// it declines to play and loses on the clock.
    function testDefenderSilent() public {
        bytes32 id = keccak256("silent");
        vm.prank(challenger);
        d.open{value: 0.01 ether}(id, defender, 1048576, bytes32(uint256(1)), bytes32(uint256(2)));
        vm.warp(block.timestamp + 7 days + 1);
        uint256 g = gasleft();
        d.timeout(id);
        console.log("challenger wins on timeout, gas", g - gasleft());
        (, , , , , , , , Dispute.Status s) = d.games(id);
        assertEq(uint256(s), uint256(Dispute.Status.ChallengerWon));
    }

    function testChallengerSilent() public {
        bytes32 id = keccak256("cs");
        vm.prank(challenger);
        d.open{value: 0.01 ether}(id, defender, 1024, bytes32(uint256(1)), bytes32(uint256(2)));
        vm.prank(defender);
        d.respond(id, keccak256("mid"));
        vm.warp(block.timestamp + 7 days + 1);
        d.timeout(id);
        (, , , , , , , , Dispute.Status s) = d.games(id);
        assertEq(uint256(s), uint256(Dispute.Status.DefenderWon));
        console.log("defender wins when the challenger goes quiet");
    }
}
