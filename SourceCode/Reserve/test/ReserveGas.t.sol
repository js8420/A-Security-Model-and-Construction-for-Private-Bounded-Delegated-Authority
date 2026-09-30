// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test, console} from "forge-std/Test.sol";
import {Reserve} from "../src/Reserve.sol";

/// Gas for every reserve operation the construction needs, at the slot cover
/// the evaluation uses. Numbers are measured, not estimated: each is the
/// difference in gasleft() across one call on a fresh state.
contract ReserveGas is Test {
    Reserve reserve;
    address principal = address(0xA11CE);
    address agent = address(0xB0B);

    uint64 constant CAP = 1_000_000;
    uint64 constant VELOCITY = 1_000;
    uint64 constant WINDOW = 86_400;

    function setUp() public {
        reserve = new Reserve();
        vm.deal(principal, 100 ether);
        vm.deal(agent, 1 ether);
    }

    function _elems(uint256 cover) internal pure returns (uint64[] memory e) {
        // Two share elements and one nullifier per slot, every slot.
        e = new uint64[](cover * 3);
        for (uint256 i = 0; i < e.length; ++i) {
            e[i] = uint64(0x9E3779B97F4A7C15 ^ (i * 0x100000001B3));
        }
    }

    function _register() internal returns (uint256 id) {
        vm.prank(principal);
        id = reserve.register{value: 1 ether}(
            agent, CAP, VELOCITY, WINDOW, keccak256(abi.encodePacked(uint64(7), uint64(11)))
        );
    }

    function testGasRegister() public {
        vm.prank(principal);
        uint256 g0 = gasleft();
        reserve.register{value: 1 ether}(
            agent, CAP, VELOCITY, WINDOW, keccak256(abi.encodePacked(uint64(7), uint64(11)))
        );
        console.log("register", g0 - gasleft());
    }

    function testGasSettleByCover() public {
        uint16[4] memory covers = [uint16(14), 30, 64, 128];
        for (uint256 k = 0; k < covers.length; ++k) {
            uint256 id = _register();
            uint64[] memory e = _elems(covers[k]);
            vm.prank(agent);
            uint256 g0 = gasleft();
            reserve.settle(id, 1000, uint64(k + 1), e);
            uint256 used = g0 - gasleft();
            console.log("settle cover", covers[k], used);
        }
    }

    function testGasSettleWarm() public {
        // A second settlement under the same delegation, where the delegation
        // record and the window are already warm. This is the steady-state
        // figure; the first settlement pays cold-slot prices for both.
        uint256 id = _register();
        vm.startPrank(agent);
        reserve.settle(id, 1000, 1, _elems(64));
        uint64[] memory e = _elems(64);
        uint256 g0 = gasleft();
        reserve.settle(id, 1000, 2, e);
        console.log("settle cover 64, warm record", g0 - gasleft());
        vm.stopPrank();
    }

    function testGasClaim() public {
        uint256 id = _register();
        uint64[2] memory secret = [uint64(7), uint64(11)];
        uint256 g0 = gasleft();
        reserve.claim(id, secret);
        console.log("claim (keccak commitment, lower bound)", g0 - gasleft());
    }

    function testGasRevoke() public {
        uint256 id = _register();
        uint256 g0 = gasleft();
        reserve.revoke(id, 0, 64);
        console.log("revoke, first range", g0 - gasleft());
        uint256 g1 = gasleft();
        reserve.revoke(id, 128, 64);
        console.log("revoke, subsequent range", g1 - gasleft());
    }

    /// What a challenge would have to carry. Not a call: the proof is over nine
    /// megabytes and no block admits it. The figure is call data cost alone, at
    /// 16 gas a non-zero byte, before any verification work.
    function testChallengeCallDataBudget() public pure {
        uint256 proofBytes = 9_134_533;
        uint256 callDataGas = proofBytes * 16;
        console.log("challenge call data alone, gas", callDataGas);
        console.log("mainnet block gas limit", uint256(30_000_000));
        console.log("blocks of call data required", callDataGas / 30_000_000);
    }
}
