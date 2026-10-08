// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {console} from "forge-std/Test.sol";
import {Reserve} from "../src/Reserve.sol";
import {Availability} from "../src/Availability.sol";
import {Fixture} from "./Fixture.sol";

/// Forcing a withheld proof into the open, and what happens when it is not.
///
/// A blob holds 4,096 field elements of BLS12-381. The proof travels as
/// Goldilocks elements, three to a blob element, so that the dispute can load
/// any one of them with a single point evaluation: 12,288 elements a blob.
/// The harness's proof is 5,137,181 bytes of eight-byte elements, so it needs
/// 53 blobs. A transaction carries at most six, so resolution takes nine
/// calls.
contract AvailabilityGas is Fixture {
    Availability av;
    address challenger = address(0xC14);
    uint256 constant BOND = 0.05 ether;
    uint64 constant WINDOW_S = 4 days;
    uint256 constant PROOF_BYTES = 5_137_181;
    uint256 constant WORDS_PER_BLOB = 4096 * 3;
    uint256 constant PER_TX = 6;

    bytes32[] hashes;

    function setUp() public {
        _base();
        av = new Availability(address(acc), WINDOW_S, BOND);
        acc.setArbiters(address(0xD15), address(av));
        vm.deal(challenger, 10 ether);
        uint256 words = (PROOF_BYTES + 7) / 8;
        uint256 n = (words + WORDS_PER_BLOB - 1) / WORDS_PER_BLOB;
        for (uint256 i = 0; i < n; ++i) {
            hashes.push(bytes32((uint256(1) << 248) | uint256(keccak256(abi.encode(i))) >> 8));
        }
    }

    function _settled() internal returns (uint256 id) {
        id = _reg(Reserve.Funding.Deposit);
        _settleWith(id, 1, keccak256(abi.encodePacked(hashes)));
    }

    function testResolveByBlobs() public {
        uint256 id = _settled();
        uint256 n = hashes.length;
        console.log("blobs for the proof", n);

        vm.prank(challenger);
        uint256 g = gasleft();
        av.challenge{value: BOND}(id, 1);
        console.log("challenge, gas", g - gasleft());

        uint256 total;
        uint256 calls;
        for (uint256 off = 0; off < n; off += PER_TX) {
            uint256 k = n - off < PER_TX ? n - off : PER_TX;
            bytes32[] memory here = new bytes32[](k);
            for (uint256 j = 0; j < k; ++j) here[j] = hashes[off + j];
            vm.blobhashes(here);
            g = gasleft();
            av.resolve(id, 1, 0, hashes, off);
            total += g - gasleft();
            ++calls;
        }
        (, , Availability.Status s, , ) = av.challenges(av.key(id, 1));
        assertEq(uint256(s), uint256(Availability.Status.Resolved));
        console.log("resolve calls", calls);
        console.log("resolve, execution gas over all calls", total);
        console.log("blob gas, 131072 a blob", n * 131072);
    }

    function testWithheldForfeits() public {
        uint256 id = _settled();
        vm.prank(challenger);
        av.challenge{value: BOND}(id, 1);
        vm.warp(block.timestamp + WINDOW_S + 1);
        uint256 before = principal.balance;
        uint256 cb = challenger.balance;
        uint256 g = gasleft();
        av.expire(id, 1);
        console.log("withheld: expire, gas", g - gasleft());
        assertEq(principal.balance - before, 1 ether);
        assertEq(challenger.balance - cb, BOND);
    }

    function testWrongBlobRejected() public {
        uint256 id = _settled();
        vm.prank(challenger);
        av.challenge{value: BOND}(id, 1);
        bytes32[] memory here = new bytes32[](1);
        here[0] = bytes32(uint256(0x01) << 248 | 12345);
        vm.blobhashes(here);
        vm.expectRevert(Availability.WrongBlob.selector);
        av.resolve(id, 1, 0, hashes, 0);
    }

    function testLateResolutionRejected() public {
        uint256 id = _settled();
        vm.prank(challenger);
        av.challenge{value: BOND}(id, 1);
        vm.warp(block.timestamp + WINDOW_S + 1);
        bytes32[] memory here = new bytes32[](1);
        here[0] = hashes[0];
        vm.blobhashes(here);
        vm.expectRevert(Availability.TooLate.selector);
        av.resolve(id, 1, 0, hashes, 0);
    }
}
