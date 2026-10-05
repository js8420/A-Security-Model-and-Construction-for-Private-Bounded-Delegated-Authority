// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test, console} from "forge-std/Test.sol";
import {StepVerifier} from "../src/StepVerifier.sol";

/// The adjudicator has to be right before its cost means anything, so the
/// field arithmetic is checked against identities that hold only if it is.
contract StepGas is Test {
    StepVerifier v;
    uint256 constant P = 0xFFFFFFFF00000001;

    function setUp() public {
        v = new StepVerifier();
    }

    function testInverseIsAnInverse() public view {
        uint256[5] memory xs = [uint256(1), 2, 7, 0xDEADBEEF, P - 1];
        for (uint256 i = 0; i < xs.length; ++i) {
            assertEq(mulmod(xs[i], v.inv(xs[i]), P), 1);
        }
    }

    /// A fold of a polynomial whose odd part is zero returns its even part
    /// whatever the challenge: f(x) = f(-x) means odd = 0.
    function testFoldIgnoresBetaWhenOdd() public view {
        uint256 val = 123456789;
        assertEq(v.fold(val, val, 3, 11), val);
        assertEq(v.fold(val, val, 3, 999999), val);
    }

    /// And a fold is linear in beta: moving beta by one moves the result by
    /// exactly the odd part.
    function testFoldLinearInBeta() public view {
        uint256 fx = 1000;
        uint256 fnx = 400;
        uint256 x = 5;
        uint256 a = v.fold(fx, fnx, x, 7);
        uint256 b = v.fold(fx, fnx, x, 8);
        uint256 odd = mulmod(addmod(fx, P - fnx, P), v.inv(mulmod(2, x, P)), P);
        assertEq(addmod(a, odd, P), b);
    }

    function _root(uint256[] memory operands) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(operands));
    }

    function testAdjudicateFold() public view {
        uint256[] memory ops = new uint256[](4);
        ops[0] = 1000; ops[1] = 400; ops[2] = 5; ops[3] = 7;
        uint256 expected = v.fold(ops[0], ops[1], ops[2], ops[3]);
        bytes32[] memory path = new bytes32[](0);

        uint256 g = gasleft();
        bool ok = v.adjudicate(StepVerifier.Step.Fold, ops, expected, _root(ops), path, 0);
        uint256 used = g - gasleft();
        assertTrue(ok);
        console.log("fold step, no path, gas", used);

        bool bad = v.adjudicate(StepVerifier.Step.Fold, ops, expected + 1, _root(ops), path, 0);
        assertFalse(bad);
    }

    function testAdjudicateFoldWithPath() public view {
        uint256[] memory ops = new uint256[](4);
        ops[0] = 1000; ops[1] = 400; ops[2] = 5; ops[3] = 7;
        uint256 expected = v.fold(ops[0], ops[1], ops[2], ops[3]);

        uint8[4] memory depths = [8, 16, 24, 32];
        for (uint256 d = 0; d < depths.length; ++d) {
            bytes32[] memory path = new bytes32[](depths[d]);
            bytes32 node = _root(ops);
            for (uint256 i = 0; i < path.length; ++i) {
                path[i] = keccak256(abi.encodePacked("sib", i));
                node = keccak256(abi.encodePacked(node, path[i]));
            }
            uint256 g = gasleft();
            bool ok = v.adjudicate(StepVerifier.Step.Fold, ops, expected, node, path, 0);
            uint256 used = g - gasleft();
            assertTrue(ok);
            console.log("fold step, path depth", depths[d]);
            console.log("  gas", used);
        }
    }

    function testAdjudicateLinear() public view {
        uint256[] memory ops = new uint256[](9);
        for (uint256 i = 0; i < 8; ++i) ops[i] = (i + 1) * 1000;
        ops[8] = 31; // alpha
        uint256 acc;
        for (uint256 i = 8; i > 0; --i) acc = addmod(mulmod(acc, 31, P), ops[i - 1], P);
        bytes32[] memory path = new bytes32[](0);
        uint256 g = gasleft();
        bool ok = v.adjudicate(StepVerifier.Step.Linear, ops, acc, _root(ops), path, 0);
        console.log("linear step, 8 terms, gas", g - gasleft());
        assertTrue(ok);
    }

    function testWrongOperandsRejected() public view {
        uint256[] memory ops = new uint256[](4);
        ops[0] = 1000; ops[1] = 400; ops[2] = 5; ops[3] = 7;
        uint256 expected = v.fold(ops[0], ops[1], ops[2], ops[3]);
        bytes32[] memory path = new bytes32[](0);
        assertFalse(
            v.adjudicate(StepVerifier.Step.Fold, ops, expected, keccak256("not the root"), path, 0)
        );
    }
}
