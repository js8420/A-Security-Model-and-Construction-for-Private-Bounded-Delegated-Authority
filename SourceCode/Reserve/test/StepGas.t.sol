// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test, console} from "forge-std/Test.sol";
import {StepVerifier} from "../src/StepVerifier.sol";
import {Poseidon2Goldilocks} from "../src/Poseidon2Goldilocks.sol";
import {Sparse} from "./Sparse.sol";

/// The adjudicator has to be right before its cost means anything, so the
/// field arithmetic is checked against identities that hold only if it is.
/// The costs are of a whole step: the instruction proved against the program,
/// every operand proved against memory, the result written back.
contract StepGas is Test {
    StepVerifier v;
    uint256 constant P = 0xFFFFFFFF00000001;
    uint256 constant MEM_DEPTH = 22;
    uint256 constant PROG_DEPTH = 20;

    function setUp() public {
        v = new StepVerifier(address(new Poseidon2Goldilocks()));
    }

    function testInverseIsAnInverse() public view {
        uint256[5] memory xs = [uint256(1), 2, 7, 0xDEADBEEF, P - 1];
        for (uint256 i = 0; i < xs.length; ++i) {
            assertEq(mulmod(xs[i], v.inv(xs[i]), P), 1);
        }
    }

    function testFoldIgnoresBetaWhenOdd() public view {
        uint256 val = 123456789;
        assertEq(v.fold(val, val, 3, 11), val);
        assertEq(v.fold(val, val, 3, 999999), val);
    }

    function testFoldLinearInBeta() public view {
        uint256 fx = 1000;
        uint256 fnx = 400;
        uint256 x = 5;
        uint256 a = v.fold(fx, fnx, x, 7);
        uint256 b = v.fold(fx, fnx, x, 8);
        uint256 odd = mulmod(addmod(fx, P - fnx, P), v.inv(mulmod(2, x, P)), P);
        assertEq(addmod(a, odd, P), b);
    }

    function testPackRoundTrip() public view {
        uint256[4] memory d = [uint256(1), P - 1, 0, 0xABCDEF];
        uint256[4] memory e = v.unpack(v.pack(d));
        for (uint256 i = 0; i < 4; ++i) assertEq(d[i], e[i]);
    }

    struct Built {
        bytes32 programRoot;
        bytes32 memRoot;
        bytes32 expectedNext;
        StepVerifier.StepInput s;
    }

    /// One step at program index `at`, reading `values` from slots 1..n and
    /// writing slot n + 1, in otherwise empty trees of the deployed depths.
    function _build(StepVerifier.Step kind, uint256[] memory values, uint256 at)
        internal
        view
        returns (Built memory b)
    {
        uint256 n = values.length;
        uint256[] memory reads = new uint256[](n);
        bytes32[] memory leaves = new bytes32[](n);
        for (uint256 i = 0; i < n; ++i) {
            reads[i] = i + 1;
            leaves[i] = bytes32(values[i]);
        }
        b.s.kind = kind;
        b.s.reads = reads;
        b.s.write = n + 1;
        b.s.values = values;
        b.memRoot = Sparse.root(MEM_DEPTH, reads, leaves);
        b.programRoot = _programRoot(kind, reads, n + 1, at);
        b.s.paths = _paths(kind, reads, leaves, at);
        b.expectedNext = _after(kind, reads, leaves, values);
    }

    function _programRoot(StepVerifier.Step kind, uint256[] memory reads, uint256 write, uint256 at)
        internal
        view
        returns (bytes32)
    {
        uint256[] memory pidx = new uint256[](1);
        bytes32[] memory pleaf = new bytes32[](1);
        pidx[0] = at;
        pleaf[0] = v.instructionLeaf(kind, reads, write);
        return Sparse.root(PROG_DEPTH, pidx, pleaf);
    }

    function _paths(StepVerifier.Step kind, uint256[] memory reads, bytes32[] memory leaves, uint256 at)
        internal
        view
        returns (bytes32[] memory paths)
    {
        uint256 n = reads.length;
        uint256[] memory pidx = new uint256[](1);
        bytes32[] memory pleaf = new bytes32[](1);
        pidx[0] = at;
        pleaf[0] = v.instructionLeaf(kind, reads, n + 1);
        paths = new bytes32[](PROG_DEPTH + (n + 1) * MEM_DEPTH);
        bytes32[] memory pp = Sparse.path(PROG_DEPTH, at, pidx, pleaf);
        for (uint256 i = 0; i < PROG_DEPTH; ++i) paths[i] = pp[i];
        for (uint256 r = 0; r <= n; ++r) {
            bytes32[] memory mp = Sparse.path(MEM_DEPTH, r < n ? reads[r] : n + 1, reads, leaves);
            for (uint256 i = 0; i < MEM_DEPTH; ++i) paths[PROG_DEPTH + r * MEM_DEPTH + i] = mp[i];
        }
    }

    function _after(StepVerifier.Step kind, uint256[] memory reads, bytes32[] memory leaves, uint256[] memory values)
        internal
        view
        returns (bytes32)
    {
        uint256 n = reads.length;
        uint256[] memory idx = new uint256[](n + 1);
        bytes32[] memory lv = new bytes32[](n + 1);
        for (uint256 i = 0; i < n; ++i) {
            idx[i] = reads[i];
            lv[i] = leaves[i];
        }
        idx[n] = n + 1;
        lv[n] = bytes32(v.execute(kind, values));
        return Sparse.root(MEM_DEPTH, idx, lv);
    }

    function _measure(string memory label, StepVerifier.Step kind, uint256[] memory values)
        internal
        view
    {
        Built memory b = _build(kind, values, 12345);
        uint256 g = gasleft();
        bytes32 next = v.transition(b.programRoot, PROG_DEPTH, 12345, b.memRoot, MEM_DEPTH, b.s);
        uint256 used = g - gasleft();
        assertEq(next, b.expectedNext);
        console.log(label, used);
    }

    function testStepCosts() public view {
        console.log("memory depth", MEM_DEPTH);
        console.log("program depth", PROG_DEPTH);

        uint256[] memory f = new uint256[](4);
        f[0] = 1000; f[1] = 400; f[2] = 5; f[3] = 7;
        _measure("fold step, gas", StepVerifier.Step.Fold, f);

        uint256[] memory a = new uint256[](2);
        a[0] = v.pack([uint256(1), 2, 3, 4]);
        a[1] = v.pack([uint256(5), 6, 7, 8]);
        _measure("Poseidon2 Merkle level step, gas", StepVerifier.Step.Algebraic, a);

        uint256[] memory l = new uint256[](9);
        for (uint256 i = 0; i < 8; ++i) l[i] = (i + 1) * 1000;
        l[8] = 31;
        _measure("linear step, 8 terms, gas", StepVerifier.Step.Linear, l);

        uint256[] memory e = new uint256[](2);
        e[0] = 77; e[1] = 77;
        _measure("equality step, gas", StepVerifier.Step.Eq, e);
    }

    function testAlgebraicMatchesThePermutation() public view {
        uint256[4] memory l = [uint256(1), 2, 3, 4];
        uint256[4] memory r = [uint256(5), 6, 7, 8];
        uint256[] memory a = new uint256[](2);
        a[0] = v.pack(l);
        a[1] = v.pack(r);
        uint256[4] memory want = Poseidon2Goldilocks(address(v.algebraic())).merkleLevel(l, r);
        assertEq(v.execute(StepVerifier.Step.Algebraic, a), v.pack(want));
    }

    /// A false operand, a different instruction, or a wrong program index
    /// does not change the outcome; it reverts.
    function testFalseInputsRevert() public {
        uint256[] memory f = new uint256[](4);
        f[0] = 1000; f[1] = 400; f[2] = 5; f[3] = 7;
        Built memory b = _build(StepVerifier.Step.Fold, f, 9);

        StepVerifier.StepInput memory s = b.s;
        s.values[0] = 1001;
        vm.expectRevert(StepVerifier.BadPath.selector);
        v.transition(b.programRoot, PROG_DEPTH, 9, b.memRoot, MEM_DEPTH, s);

        b = _build(StepVerifier.Step.Fold, f, 9);
        s = b.s;
        s.kind = StepVerifier.Step.Linear;
        vm.expectRevert(StepVerifier.BadInstruction.selector);
        v.transition(b.programRoot, PROG_DEPTH, 9, b.memRoot, MEM_DEPTH, s);

        b = _build(StepVerifier.Step.Fold, f, 9);
        vm.expectRevert(StepVerifier.BadInstruction.selector);
        v.transition(b.programRoot, PROG_DEPTH, 10, b.memRoot, MEM_DEPTH, b.s);
    }
}
