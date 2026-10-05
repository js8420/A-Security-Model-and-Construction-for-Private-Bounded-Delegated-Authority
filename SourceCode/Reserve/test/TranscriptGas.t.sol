// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test, console} from "forge-std/Test.sol";
import {Reserve} from "../src/Reserve.sol";
import {PreventiveReserve} from "../src/PreventiveReserve.sol";

/// Does accountability cost what the transcript costs, or what storing the
/// transcript costs? Extraction reads the shares and nothing in the contract
/// compares against them, so a log would serve. This measures both.
contract TranscriptGas is Test {
    Reserve acc;
    PreventiveReserve prev;
    address principal = address(0xA11CE);
    uint256 constant AGENT_PK = 0xA6E47;
    address agent;

    uint64 constant CAP = 1_000_000;
    uint64 constant BUDGET = 100_000_000;
    uint64 constant VELOCITY = 1_000;
    uint64 constant WINDOW = 86_400;

    function setUp() public {
        agent = vm.addr(AGENT_PK);
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

    /// The agent's signature over everything it is answerable for.
    function _sig(uint256 id, uint64 amount, uint64 index, uint64[] memory elems)
        internal
        view
        returns (bytes32 commitment, bytes memory signature)
    {
        commitment = keccak256(abi.encodePacked("proof", id, index));
        bytes32 digest = keccak256(
            abi.encode(block.chainid, address(acc), id, amount, index,
                       keccak256(abi.encodePacked(elems)), commitment)
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(AGENT_PK, digest);
        signature = abi.encodePacked(r, s, v);
    }

    function _settle(uint256 id, uint64 amount, uint64 index, uint64[] memory e) internal {
        (bytes32 c, bytes memory sg) = _sig(id, amount, index, e);
        acc.settle(id, amount, index, e, c, sg);
    }

    function _settleLogged(uint256 id, uint64 amount, uint64 index, uint64[] memory e) internal {
        (bytes32 c, bytes memory sg) = _sig(id, amount, index, e);
        acc.settleLogged(id, amount, index, e, c, sg);
    }

    function _reg() internal returns (uint256 id) {
        vm.prank(principal);
        id = acc.register{value: 1 ether}(
            agent, CAP, VELOCITY, WINDOW, keccak256(abi.encodePacked(uint64(7), uint64(11)))
        );
    }

    function testStoredAgainstLogged() public {
        uint16[4] memory covers = [uint16(14), 30, 64, 128];
        for (uint256 k = 0; k < covers.length; ++k) {
            uint256 a = _reg();
            uint256 b = _reg();
            uint64[] memory e = _elems(covers[k]);

            vm.startPrank(agent);
            _settle(a, 1000, 1, e);          // warm the record
            uint64[] memory e2 = _elems(covers[k]);
            uint256 g0 = gasleft();
            _settle(a, 1000, 2, e2);
            uint256 stored = g0 - gasleft();

            _settleLogged(b, 1000, 1, e);    // warm the record
            uint64[] memory e3 = _elems(covers[k]);
            uint256 g1 = gasleft();
            _settleLogged(b, 1000, 2, e3);
            uint256 logged = g1 - gasleft();
            vm.stopPrank();

            console.log("cover", covers[k]);
            console.log("  stored", stored);
            console.log("  logged", logged);
            console.log("  ratio x100", (stored * 100) / logged);
        }
    }

    /// Every operation the paper tabulates, measured in one place and warmed
    /// the same way, so no row of the table comes from a different experiment.
    function testAllOperationsOneWarming() public {
        uint256 g0 = gasleft();
        vm.prank(principal);
        uint256 id = acc.register{value: 1 ether}(
            agent, CAP, VELOCITY, WINDOW, keccak256(abi.encodePacked(uint64(7), uint64(11)))
        );
        console.log("Open", g0 - gasleft());

        vm.startPrank(agent);
        _settleLogged(id, 1000, 1, _elems(64));
        uint64[] memory e = _elems(64);
        uint256 g1 = gasleft();
        _settleLogged(id, 1000, 2, e);
        console.log("Settle logged, cover 64", g1 - gasleft());
        vm.stopPrank();

        uint256 g2 = gasleft();
        acc.revoke(id, 0, 64);
        console.log("Revoke, first range", g2 - gasleft());
        uint256 g3 = gasleft();
        acc.revoke(id, 128, 64);
        console.log("Revoke, later range", g3 - gasleft());

        uint64[2] memory secret = [uint64(7), uint64(11)];
        uint256 g4 = gasleft();
        acc.claim(id, secret);
        console.log("Claim", g4 - gasleft());
    }

    /// What a challenge would have to carry. Not a call: the proof is over five
    /// megabytes and no block admits it. Call data cost alone, at 16 gas a
    /// non-zero byte, before any verification work. The proof size is the one
    /// the circuit harness measures for the composed circuit at a 32-row trace.
    function testChallengeCallDataBudget() public pure {
        uint256 proofBytes = 5_112_421;
        uint256 callDataGas = proofBytes * 16;
        console.log("challenge call data alone, gas", callDataGas);
        console.log("proof bytes", proofBytes);
    }

    function testLoggedAgainstPreventive() public {
        uint256 a = _reg();
        vm.prank(principal);
        uint256 p = prev.register(agent, CAP, BUDGET, VELOCITY, WINDOW);

        vm.startPrank(agent);
        _settleLogged(a, 1000, 1, _elems(64));
        prev.settle(p, 1000, 1);

        uint64[] memory e = _elems(64);
        uint256 g0 = gasleft();
        _settleLogged(a, 1000, 2, e);
        uint256 logged = g0 - gasleft();

        uint256 g1 = gasleft();
        prev.settle(p, 1000, 2);
        uint256 preventive = g1 - gasleft();
        vm.stopPrank();

        console.log("accountable, logged transcript, cover 64", logged);
        console.log("preventive", preventive);
        console.log("ratio x100", (logged * 100) / preventive);
    }
}
