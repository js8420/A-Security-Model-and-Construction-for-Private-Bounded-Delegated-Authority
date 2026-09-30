// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test, console} from "forge-std/Test.sol";
import {Reserve} from "../src/Reserve.sol";
import {PreventiveReserve} from "../src/PreventiveReserve.sol";

/// What accountability costs on chain, against the scheme it replaces.
///
/// Both contracts perform the same three public refusals. The preventive one
/// also refuses on the budget and keeps no transcript; the accountable one
/// refuses on nothing hidden and publishes the shares that make overdraft
/// self-revealing. The difference is the price of Corollary 2.
contract BaselineGas is Test {
    Reserve acc;
    PreventiveReserve prev;

    address principal = address(0xA11CE);
    address agent = address(0xB0B);

    uint64 constant CAP = 1_000_000;
    uint64 constant BUDGET = 100_000_000;
    uint64 constant VELOCITY = 1_000;
    uint64 constant WINDOW = 86_400;

    function setUp() public {
        acc = new Reserve();
        prev = new PreventiveReserve();
        vm.deal(principal, 100 ether);
        vm.deal(agent, 1 ether);
    }

    function _elems(uint256 cover) internal pure returns (uint64[] memory e) {
        e = new uint64[](cover * 3);
        for (uint256 i = 0; i < e.length; ++i) {
            e[i] = uint64(0x9E3779B97F4A7C15 ^ (i * 0x100000001B3));
        }
    }

    function testSteadyStateComparison() public {
        vm.prank(principal);
        uint256 a = acc.register{value: 1 ether}(
            agent, CAP, VELOCITY, WINDOW, keccak256(abi.encodePacked(uint64(7), uint64(11)))
        );
        vm.prank(principal);
        uint256 p = prev.register(agent, CAP, BUDGET, VELOCITY, WINDOW);

        // Warm both records first, so neither is charged for the delegation's
        // own cold slots.
        vm.startPrank(agent);
        acc.settle(a, 1000, 1, _elems(64));
        prev.settle(p, 1000, 1);

        uint64[] memory e = _elems(64);
        uint256 g0 = gasleft();
        acc.settle(a, 1000, 2, e);
        uint256 accountable = g0 - gasleft();

        uint256 g1 = gasleft();
        prev.settle(p, 1000, 2);
        uint256 preventive = g1 - gasleft();
        vm.stopPrank();

        console.log("accountable settle, cover 64", accountable);
        console.log("preventive settle", preventive);
        console.log("ratio x100", (accountable * 100) / preventive);
    }
}
