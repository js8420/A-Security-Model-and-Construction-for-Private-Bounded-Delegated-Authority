// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {console} from "forge-std/Test.sol";
import {Reserve} from "../src/Reserve.sol";
import {Dispute} from "../src/Dispute.sol";
import {StepVerifier} from "../src/StepVerifier.sol";
import {Poseidon2Goldilocks} from "../src/Poseidon2Goldilocks.sol";
import {Fixture} from "./Fixture.sol";
import {Sparse} from "./Sparse.sol";

/// A dispute from opening to the bond moving, decided by the adjudicator and
/// not by a supplied verdict.
contract DisputeGas is Fixture {
    StepVerifier v;
    address challenger = address(0xC14);
    uint256 constant BOND = 0.01 ether;
    uint64 constant WINDOW_S = 1 days;
    bytes32 constant BLOBS = keccak256("blob list");

    function setUp() public {
        _base();
        v = new StepVerifier(address(new Poseidon2Goldilocks()));
        vm.deal(challenger, 10 ether);
    }

    function _status(Dispute d, bytes32 id) internal view returns (Dispute.Status s) {
        (, , , , , , , s, , , ) = d.games(id);
    }

    // ---------------------------------------------------------------------
    // A four-step verifier run, played honestly and dishonestly.
    //   0: fold   reads 1,2,3,4      writes 8
    //   1: level  reads 5,6          writes 9
    //   2: linear reads 8,1,7        writes 10
    //   3: eq     reads 10,11        writes 0   (the verdict)
    // Slot 11 is part of the input: the value the proof says step 2 yields.
    // ---------------------------------------------------------------------

    uint64 constant MD = 4;
    uint64 constant PD = 2;

    struct Prog {
        StepVerifier.Step[4] kind;
        uint256[][4] reads;
        uint256[4] write;
        bytes32[] leaves;
        uint256[] idx;
        bytes32 root;
    }

    function _program() internal view returns (Prog memory p) {
        p.kind = [StepVerifier.Step.Fold, StepVerifier.Step.Algebraic,
                  StepVerifier.Step.Linear, StepVerifier.Step.Eq];
        p.reads[0] = new uint256[](4);
        p.reads[0][0] = 1; p.reads[0][1] = 2; p.reads[0][2] = 3; p.reads[0][3] = 4;
        p.reads[1] = new uint256[](2);
        p.reads[1][0] = 5; p.reads[1][1] = 6;
        p.reads[2] = new uint256[](3);
        p.reads[2][0] = 8; p.reads[2][1] = 1; p.reads[2][2] = 7;
        p.reads[3] = new uint256[](2);
        p.reads[3][0] = 10; p.reads[3][1] = 11;
        p.write = [uint256(8), 9, 10, 0];
        p.leaves = new bytes32[](4);
        p.idx = new uint256[](4);
        for (uint256 k = 0; k < 4; ++k) {
            p.idx[k] = k;
            p.leaves[k] = v.instructionLeaf(p.kind[k], p.reads[k], p.write[k]);
        }
        p.root = Sparse.root(PD, p.idx, p.leaves);
    }

    function _mem(uint256[16] memory m) internal pure returns (bytes32) {
        uint256[] memory idx = new uint256[](16);
        bytes32[] memory lv = new bytes32[](16);
        for (uint256 i = 0; i < 16; ++i) {
            idx[i] = i;
            lv[i] = bytes32(m[i]);
        }
        return Sparse.root(MD, idx, lv);
    }

    function _input(bool good) internal view returns (uint256[16] memory m) {
        m[1] = 1000; m[2] = 400; m[3] = 5; m[4] = 7;
        m[5] = v.pack([uint256(1), 2, 3, 4]);
        m[6] = v.pack([uint256(5), 6, 7, 8]);
        m[7] = 31;
        uint256 f = v.fold(1000, 400, 5, 7);
        uint256 lin = addmod(mulmod(addmod(mulmod(0, 31, 0xFFFFFFFF00000001), 1000, 0xFFFFFFFF00000001), 31, 0xFFFFFFFF00000001), f, 0xFFFFFFFF00000001);
        m[11] = good ? lin : lin + 1;
    }

    function _run(Prog memory p, uint256[16] memory m)
        internal
        view
        returns (uint256[16][5] memory states)
    {
        states[0] = m;
        for (uint256 k = 0; k < 4; ++k) {
            uint256[] memory vals = new uint256[](p.reads[k].length);
            for (uint256 i = 0; i < vals.length; ++i) vals[i] = states[k][p.reads[k][i]];
            states[k + 1] = states[k];
            states[k + 1][p.write[k]] = v.execute(p.kind[k], vals);
        }
    }

    function _leaves(uint256[16] memory m)
        internal
        pure
        returns (uint256[] memory idx, bytes32[] memory lv)
    {
        idx = new uint256[](16);
        lv = new bytes32[](16);
        for (uint256 i = 0; i < 16; ++i) {
            idx[i] = i;
            lv[i] = bytes32(m[i]);
        }
    }

    function _stepPaths(Prog memory p, uint256[16] memory m, uint256 k)
        internal
        pure
        returns (bytes32[] memory paths)
    {
        uint256 n = p.reads[k].length;
        (uint256[] memory idx, bytes32[] memory lv) = _leaves(m);
        paths = new bytes32[](PD + (n + 1) * MD);
        bytes32[] memory pp = Sparse.path(PD, k, p.idx, p.leaves);
        for (uint256 i = 0; i < PD; ++i) paths[i] = pp[i];
        for (uint256 r = 0; r <= n; ++r) {
            bytes32[] memory mp = Sparse.path(MD, r < n ? p.reads[k][r] : p.write[k], idx, lv);
            for (uint256 i = 0; i < MD; ++i) paths[PD + r * MD + i] = mp[i];
        }
    }

    function _stepInput(Prog memory p, uint256[16] memory m, uint256 k)
        internal
        pure
        returns (StepVerifier.StepInput memory s)
    {
        uint256 n = p.reads[k].length;
        uint256[] memory vals = new uint256[](n);
        for (uint256 r = 0; r < n; ++r) vals[r] = m[p.reads[k][r]];
        s.kind = p.kind[k];
        s.reads = p.reads[k];
        s.write = p.write[k];
        s.values = vals;
        s.oldValue = m[p.write[k]];
        s.paths = _stepPaths(p, m, k);
    }

    function _acceptPath(uint256[16] memory m) internal pure returns (bytes32[] memory) {
        uint256[] memory idx = new uint256[](16);
        bytes32[] memory lv = new bytes32[](16);
        for (uint256 i = 0; i < 16; ++i) {
            idx[i] = i;
            lv[i] = bytes32(m[i]);
        }
        return Sparse.path(MD, 0, idx, lv);
    }

    /// The defender always claims acceptance. `good` decides whether the
    /// input really leads there.
    function _game(bool good) internal returns (Dispute.Status outcome, uint256 principalGain) {
        Prog memory p = _program();
        uint256[16] memory input = _input(good);
        uint256[16][5] memory truth = _run(p, input);
        uint256[16] memory claimedEnd = truth[4];
        claimedEnd[0] = 1;

        Dispute d = new Dispute(address(acc), address(v), p.root, PD, 4, MD, WINDOW_S, BOND);
        acc.setArbiters(address(d), address(0xDEAD));
        uint256 id = _reg(Reserve.Funding.Deposit);
        bytes32 inputRoot = _mem(input);
        _settleWith(id, 1, keccak256(abi.encode(inputRoot, BLOBS)));

        bytes32 gid = d.gameId(id, 1);
        vm.prank(challenger);
        d.open{value: BOND}(id, 1, inputRoot, BLOBS);
        vm.prank(agent);
        d.postFinal(gid, _mem(claimedEnd), _acceptPath(claimedEnd));

        // The defender reports true intermediate states; only its final claim
        // can be false. The challenger, holding the proof, checks each.
        uint64 lo = 0;
        uint64 hi = 4;
        while (hi - lo > 1) {
            uint64 mid = lo + (hi - lo) / 2;
            bytes32 midState = d.state(_mem(truth[mid]), mid);
            vm.prank(agent);
            d.respond(gid, midState);
            vm.prank(challenger);
            d.choose(gid, true);
            lo = mid;
        }
        uint256 before = principal.balance;
        d.settleOneStep(gid, _mem(truth[lo]), _stepInput(p, truth[lo], lo));
        outcome = _status(d, gid);
        principalGain = principal.balance - before;
    }

    function testFalseClaimLoses() public {
        (Dispute.Status s, uint256 gain) = _game(false);
        assertEq(uint256(s), uint256(Dispute.Status.ChallengerWon));
        assertEq(gain, 1 ether);
        console.log("false claim: challenger wins, agent's bond to the principal");
    }

    function testTrueClaimStands() public {
        uint256 before = agent.balance;
        (Dispute.Status s, uint256 gain) = _game(true);
        assertEq(uint256(s), uint256(Dispute.Status.DefenderWon));
        assertEq(gain, 0);
        assertEq(agent.balance - before, BOND);
        console.log("true claim: defender wins and keeps the challenger's bond");
    }

    function testCannotReopen() public {
        Prog memory p = _program();
        uint256[16] memory input = _input(true);
        Dispute d = new Dispute(address(acc), address(v), p.root, PD, 4, MD, WINDOW_S, BOND);
        uint256 id = _reg(Reserve.Funding.Deposit);
        bytes32 inputRoot = _mem(input);
        _settleWith(id, 1, keccak256(abi.encode(inputRoot, BLOBS)));
        vm.prank(challenger);
        d.open{value: BOND}(id, 1, inputRoot, BLOBS);
        vm.prank(challenger);
        vm.expectRevert(Dispute.GameExists.selector);
        d.open{value: BOND}(id, 1, inputRoot, BLOBS);
    }

    // ---------------------------------------------------------------------
    // Cost by length. The step decided at the end is a fold at index 0; the
    // trees have the deployed memory depth and a program as long as the run.
    // ---------------------------------------------------------------------

    uint64 constant BIG_MD = 22;

    struct Big {
        Dispute d;
        uint256 id;
        bytes32 gid;
        bytes32 inputRoot;
        uint256[] reads;
        bytes32[] leaves;
        uint256[] pidx;
        bytes32[] pleaf;
        uint64 pdepth;
        StepVerifier.Step kind;
        uint256[] values;
    }

    function _bigSetup(uint64 steps, uint64 pdepth, bool algebraic) internal returns (Big memory B) {
        Reserve r = new Reserve(DOMAIN, address(token), permit2);
        acc = r;
        vm.prank(principal);
        token.approve(address(r), type(uint256).max);
        B.pdepth = pdepth;
        if (algebraic) {
            B.kind = StepVerifier.Step.Algebraic;
            B.values = new uint256[](2);
            B.values[0] = v.pack([uint256(1), 2, 3, 4]);
            B.values[1] = v.pack([uint256(5), 6, 7, 8]);
        } else {
            B.kind = StepVerifier.Step.Fold;
            B.values = new uint256[](4);
            B.values[0] = 1000; B.values[1] = 400; B.values[2] = 5; B.values[3] = 7;
        }
        uint256 n = B.values.length;
        B.reads = new uint256[](n);
        B.leaves = new bytes32[](n);
        for (uint256 i = 0; i < n; ++i) {
            B.reads[i] = i + 1;
            B.leaves[i] = bytes32(B.values[i]);
        }
        B.pidx = new uint256[](1);
        B.pleaf = new bytes32[](1);
        B.pleaf[0] = v.instructionLeaf(B.kind, B.reads, 5);
        B.inputRoot = Sparse.root(BIG_MD, B.reads, B.leaves);
        B.d = new Dispute(address(r), address(v), Sparse.root(pdepth, B.pidx, B.pleaf), pdepth, steps,
                          BIG_MD, WINDOW_S, BOND);
        r.setArbiters(address(B.d), address(0xDEAD));
        B.id = _reg(Reserve.Funding.Deposit);
        _settleWith(B.id, 1, keccak256(abi.encode(B.inputRoot, BLOBS)));
        B.gid = B.d.gameId(B.id, 1);
    }

    function _bigOpen(Big memory B) internal returns (uint256 used) {
        uint256[] memory a = new uint256[](1);
        bytes32[] memory al = new bytes32[](1);
        al[0] = bytes32(uint256(1));
        bytes32 finalRoot = Sparse.root(BIG_MD, a, al);
        bytes32[] memory acceptPath = Sparse.path(BIG_MD, 0, a, al);
        vm.prank(challenger);
        uint256 g = gasleft();
        B.d.open{value: BOND}(B.id, 1, B.inputRoot, BLOBS);
        used = g - gasleft();
        vm.prank(agent);
        g = gasleft();
        B.d.postFinal(B.gid, finalRoot, acceptPath);
        used += g - gasleft();
    }

    function _bigBisect(Big memory B, uint64 steps) internal returns (uint256 used, uint64 n) {
        uint64 lo = 0;
        uint64 hi = steps;
        while (hi - lo > 1) {
            uint64 mid = lo + (hi - lo) / 2;
            vm.prank(agent);
            uint256 g = gasleft();
            B.d.respond(B.gid, keccak256(abi.encode(mid)));
            used += g - gasleft();
            vm.prank(challenger);
            g = gasleft();
            B.d.choose(B.gid, false);
            used += g - gasleft();
            hi = mid;
            ++n;
        }
    }

    function _bigStep(Big memory B) internal returns (uint256 used) {
        StepVerifier.StepInput memory s;
        uint256 n = B.values.length;
        s.kind = B.kind;
        s.reads = B.reads;
        s.write = 5;
        s.values = B.values;
        s.paths = new bytes32[](B.pdepth + (n + 1) * BIG_MD);
        bytes32[] memory pp = Sparse.path(B.pdepth, 0, B.pidx, B.pleaf);
        for (uint256 i = 0; i < B.pdepth; ++i) s.paths[i] = pp[i];
        for (uint256 rr = 0; rr <= n; ++rr) {
            bytes32[] memory mp = Sparse.path(BIG_MD, rr < n ? B.reads[rr] : 5, B.reads, B.leaves);
            for (uint256 i = 0; i < BIG_MD; ++i) s.paths[B.pdepth + rr * BIG_MD + i] = mp[i];
        }
        uint256 g = gasleft();
        B.d.settleOneStep(B.gid, B.inputRoot, s);
        used = g - gasleft();
        assertEq(uint256(_status(B.d, B.gid)), uint256(Dispute.Status.ChallengerWon));
    }

    function _length(uint64 steps, uint64 pdepth, bool algebraic)
        internal
        returns (uint256 openGas, uint256 roundsGas, uint256 stepGas, uint64 n)
    {
        Big memory B = _bigSetup(steps, pdepth, algebraic);
        openGas = _bigOpen(B);
        (roundsGas, n) = _bigBisect(B, steps);
        stepGas = _bigStep(B);
    }

    function testCostByVerificationLength() public {
        uint64[5] memory logs = [uint64(10), 14, 18, 20, 24];
        for (uint256 i = 0; i < logs.length; ++i) {
            (uint256 o, uint256 r, uint256 s, uint64 n) = _length(uint64(1) << logs[i], logs[i], false);
            console.log("steps 2^", logs[i]);
            console.log("  rounds", n);
            console.log("  open and final claim", o);
            console.log("  bisection", r);
            console.log("  last step, fold, with bonds moving", s);
            console.log("  total", o + r + s);
        }
    }

    /// The dearest place a defender can steer the game: a level of the
    /// proof's own Poseidon2 trees.
    function testDearestStep() public {
        uint64[3] memory logs = [uint64(18), 20, 24];
        for (uint256 i = 0; i < logs.length; ++i) {
            (uint256 o, uint256 r, uint256 s, uint64 n) = _length(uint64(1) << logs[i], logs[i], true);
            console.log("steps 2^", logs[i]);
            console.log("  rounds", n);
            console.log("  last step, Poseidon2 level, with bonds moving", s);
            console.log("  total", o + r + s);
        }
    }

    function testDefenderSilent() public {
        Dispute d = new Dispute(address(acc), address(v), bytes32(0), 2, 4, MD, WINDOW_S, BOND);
        acc.setArbiters(address(d), address(0xDEAD));
        uint256 id = _reg(Reserve.Funding.Deposit);
        bytes32 inputRoot = keccak256("in");
        _settleWith(id, 1, keccak256(abi.encode(inputRoot, BLOBS)));
        vm.prank(challenger);
        d.open{value: BOND}(id, 1, inputRoot, BLOBS);
        vm.warp(block.timestamp + WINDOW_S + 1);
        uint256 before = principal.balance;
        uint256 g = gasleft();
        d.timeout(d.gameId(id, 1));
        console.log("defender silent: challenger wins on timeout, gas", g - gasleft());
        assertEq(principal.balance - before, 1 ether);
    }

    function testChallengerSilent() public {
        Prog memory p = _program();
        uint256[16] memory input = _input(true);
        uint256[16][5] memory truth = _run(p, input);
        Dispute d = new Dispute(address(acc), address(v), p.root, PD, 4, MD, WINDOW_S, BOND);
        uint256 id = _reg(Reserve.Funding.Deposit);
        bytes32 inputRoot = _mem(input);
        _settleWith(id, 1, keccak256(abi.encode(inputRoot, BLOBS)));
        bytes32 gid = d.gameId(id, 1);
        vm.prank(challenger);
        d.open{value: BOND}(id, 1, inputRoot, BLOBS);
        vm.prank(agent);
        d.postFinal(gid, _mem(truth[4]), _acceptPath(truth[4]));
        bytes32 midState = d.state(_mem(truth[2]), 2);
        vm.prank(agent);
        d.respond(gid, midState);
        vm.warp(block.timestamp + WINDOW_S + 1);
        uint256 before = agent.balance;
        d.timeout(gid);
        assertEq(uint256(_status(d, gid)), uint256(Dispute.Status.DefenderWon));
        assertEq(agent.balance - before, BOND);
    }
}
