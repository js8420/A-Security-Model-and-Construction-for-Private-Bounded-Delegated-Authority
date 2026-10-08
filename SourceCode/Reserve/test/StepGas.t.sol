// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test, console} from "forge-std/Test.sol";
import {StepVerifier} from "../src/StepVerifier.sol";
import {Poseidon2Goldilocks} from "../src/Poseidon2Goldilocks.sol";
import {Sparse} from "./Sparse.sol";
import {KzgVectors} from "./KzgVectors.sol";

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

    function _frame(Built memory b, uint256 at) internal pure returns (StepVerifier.Frame memory) {
        return StepVerifier.Frame({
            programRoot: b.programRoot, programDepth: PROG_DEPTH, index: at,
            memRoot: b.memRoot, depth: MEM_DEPTH
        });
    }

    function _none() internal pure returns (StepVerifier.Context memory c) {}

    function _measure(string memory label, StepVerifier.Step kind, uint256[] memory values)
        internal
        view
    {
        Built memory b = _build(kind, values, 12345);
        StepVerifier.Frame memory f = _frame(b, 12345);
        StepVerifier.Context memory c = _none();
        uint256 g = gasleft();
        bytes32 next = v.transition(f, b.s, c);
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
        uint256[] memory fv = new uint256[](4);
        fv[0] = 1000; fv[1] = 400; fv[2] = 5; fv[3] = 7;
        Built memory b = _build(StepVerifier.Step.Fold, fv, 9);

        StepVerifier.StepInput memory s = b.s;
        s.values[0] = 1001;
        StepVerifier.Frame memory f = _frame(b, 9);
        StepVerifier.Context memory c = _none();
        vm.expectRevert(StepVerifier.BadPath.selector);
        v.transition(f, s, c);

        b = _build(StepVerifier.Step.Fold, fv, 9);
        s = b.s;
        s.kind = StepVerifier.Step.Linear;
        f = _frame(b, 9);
        vm.expectRevert(StepVerifier.BadInstruction.selector);
        v.transition(f, s, c);

        b = _build(StepVerifier.Step.Fold, fv, 9);
        f = _frame(b, 10);
        vm.expectRevert(StepVerifier.BadInstruction.selector);
        v.transition(f, b.s, c);
    }

    // ---------------------------------------------------------------------
    // Loads. The proof enters the run only through these.
    // ---------------------------------------------------------------------

    /// A load names its immediates in the instruction and reads no memory,
    /// so its paths are the program path and the write path.
    function _load(StepVerifier.Step kind, uint256[] memory imm, uint256 write, uint256 expected)
        internal
        view
        returns (Built memory b)
    {
        uint256[] memory pidx = new uint256[](1);
        bytes32[] memory pleaf = new bytes32[](1);
        pidx[0] = 12345;
        pleaf[0] = v.instructionLeaf(kind, imm, write);
        b.programRoot = Sparse.root(PROG_DEPTH, pidx, pleaf);
        uint256[] memory none = new uint256[](0);
        bytes32[] memory nol = new bytes32[](0);
        b.memRoot = Sparse.root(MEM_DEPTH, none, nol);
        bytes32[] memory paths = new bytes32[](PROG_DEPTH + MEM_DEPTH);
        bytes32[] memory pp = Sparse.path(PROG_DEPTH, 12345, pidx, pleaf);
        for (uint256 i = 0; i < PROG_DEPTH; ++i) paths[i] = pp[i];
        bytes32[] memory wp = Sparse.path(MEM_DEPTH, write, none, nol);
        for (uint256 i = 0; i < MEM_DEPTH; ++i) paths[PROG_DEPTH + i] = wp[i];
        uint256[] memory widx = new uint256[](1);
        bytes32[] memory wl = new bytes32[](1);
        widx[0] = write;
        wl[0] = bytes32(expected);
        b.expectedNext = Sparse.root(MEM_DEPTH, widx, wl);
        b.s = StepVerifier.StepInput({
            kind: kind, reads: imm, write: write, values: new uint256[](0), oldValue: 0, paths: paths
        });
    }

    function _blobs(uint256 n) internal pure returns (bytes32[] memory bl) {
        bl = new bytes32[](n);
        bl[0] = KzgVectors.VERSIONED_HASH;
        for (uint256 i = 1; i < n; ++i) bl[i] = keccak256(abi.encode("blob", i));
    }

    function testLoadBlobReadsTheProof() public view {
        for (uint256 lane = 0; lane < 3; ++lane) {
            uint256 want = (KzgVectors.Y_777 >> (64 * lane)) & 0xFFFFFFFFFFFFFFFF;
            uint256[] memory imm = new uint256[](3);
            imm[0] = 0; imm[1] = 777; imm[2] = lane;
            Built memory b = _load(StepVerifier.Step.LoadBlob, imm, 3, want);
            StepVerifier.Context memory c;
            c.blobs = _blobs(53);
            c.kzg = KzgVectors.kzg(KzgVectors.Y_777, KzgVectors.PROOF_777);
            StepVerifier.Frame memory f = _frame(b, 12345);
            uint256 g = gasleft();
            bytes32 next = v.transition(f, b.s, c);
            uint256 used = g - gasleft();
            assertEq(next, b.expectedNext);
            if (lane == 0) console.log("load step, one proof word from a blob, gas", used);
        }
    }

    function testLoadBlobRejectsAFalseOpening() public {
        uint256[] memory imm = new uint256[](3);
        imm[0] = 0; imm[1] = 777; imm[2] = 0;
        Built memory b = _load(StepVerifier.Step.LoadBlob, imm, 3, 0);
        StepVerifier.Context memory c;
        c.blobs = _blobs(53);
        StepVerifier.Frame memory f = _frame(b, 12345);
        // a value the blob does not hold at that element
        c.kzg = KzgVectors.kzg(KzgVectors.Y_777 + 1, KzgVectors.PROOF_777);
        vm.expectRevert(StepVerifier.BadOpening.selector);
        v.transition(f, b.s, c);
        // the right value, opened at the wrong element
        imm[1] = 776;
        b = _load(StepVerifier.Step.LoadBlob, imm, 3, 0);
        f = _frame(b, 12345);
        c.kzg = KzgVectors.kzg(KzgVectors.Y_777, KzgVectors.PROOF_777);
        vm.expectRevert(StepVerifier.BadOpening.selector);
        v.transition(f, b.s, c);
    }

    function testEvaluationPointsMatchTheBlobLayout() public view {
        assertEq(v.evaluationPoint(0), 1);
        assertEq(v.evaluationPoint(1), 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000);
    }

    function testLoadPublic() public view {
        uint256[] memory imm = new uint256[](1);
        imm[0] = 9;
        Built memory b = _load(StepVerifier.Step.LoadPublic, imm, 4, 8453);
        StepVerifier.Context memory c;
        c.pub = new uint256[](10);
        c.pub[9] = 8453;
        StepVerifier.Frame memory f = _frame(b, 12345);
        uint256 g = gasleft();
        bytes32 next = v.transition(f, b.s, c);
        console.log("load step, one public value, gas", g - gasleft());
        assertEq(next, b.expectedNext);
    }
}
