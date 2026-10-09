// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test, console} from "forge-std/Test.sol";
import {ConstraintProgram} from "../src/ConstraintProgram.sol";
import {ConstraintVectors as V} from "./ConstraintVectors.sol";

/// The identity's leaf on chain: one constraint's program run at the opened
/// values of a real proof, against the value the verifier's folder gave it.
contract ConstraintGas is Test {
    function measure(string memory name, bytes memory prog, uint256[] memory inputs, uint256 out, uint256 expected)
        internal
        view
    {
        uint256 g = gasleft();
        uint256 r = ConstraintProgram.run(prog, inputs, out);
        uint256 used = g - gasleft();
        assertEq(r, expected, name);
        console.log(name);
        console.log("  operations", prog.length / 5);
        console.log("  slots read and constants", inputs.length);
        console.log("  evaluation gas", used);
    }

    function testWorstByOperations() public view {
        measure("worst by operations", V.WORST_PROGRAM, V.worstInputs(), V.WORST_OUT, V.WORST_EXPECTED);
    }

    function testWorstByReads() public view {
        measure("worst by values read", V.READS_PROGRAM, V.readsInputs(), V.READS_OUT, V.READS_EXPECTED);
    }

    function testMedian() public view {
        measure("median", V.MEDIAN_PROGRAM, V.medianInputs(), V.MEDIAN_OUT, V.MEDIAN_EXPECTED);
    }

    function testOperationReadingAheadReverts() public {
        // Operation 0 naming slot `base`, its own output, is refused.
        uint256[] memory inputs = new uint256[](1);
        inputs[0] = 1;
        bytes memory prog = hex"0000010000";
        vm.expectRevert(ConstraintProgram.BadProgram.selector);
        this.callRun(prog, inputs, 1);
    }

    function testNonCanonicalValueReverts() public {
        uint256[] memory inputs = new uint256[](1);
        inputs[0] = ConstraintProgram.P;
        vm.expectRevert(ConstraintProgram.BadValue.selector);
        this.callRun(hex"0000000000", inputs, 1);
    }

    function callRun(bytes memory prog, uint256[] memory inputs, uint256 out) external pure returns (uint256) {
        return ConstraintProgram.run(prog, inputs, out);
    }
}
