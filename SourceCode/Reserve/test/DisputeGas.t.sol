// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {console} from "forge-std/Test.sol";
import {Reserve} from "../src/Reserve.sol";
import {Dispute} from "../src/Dispute.sol";
import {StepVerifier} from "../src/StepVerifier.sol";
import {Poseidon2Goldilocks} from "../src/Poseidon2Goldilocks.sol";
import {Fixture} from "./Fixture.sol";
import {Sparse} from "./Sparse.sol";
import {KzgVectors} from "./KzgVectors.sol";

/// A dispute from opening to the bond moving, decided by the adjudicator and
/// not by a supplied verdict, starting from the empty memory with the proof
/// loaded from a real blob.
contract DisputeGas is Fixture {
    StepVerifier v;
    address challenger = address(0xC14);
    uint256 constant BOND = 0.01 ether;
    uint64 constant WINDOW_S = 1 days;
    uint64 constant DIGEST = 7;
    uint256 constant P = 0xFFFFFFFF00000001;

    function setUp() public {
        _base();
        v = new StepVerifier(address(new Poseidon2Goldilocks()));
        vm.deal(challenger, 10 ether);
    }

    function _oneBlob() internal pure returns (bytes32[] memory bl) {
        bl = new bytes32[](1);
        bl[0] = KzgVectors.VERSIONED_HASH;
    }

    function _lane(uint256 l) internal pure returns (uint256) {
        return (KzgVectors.Y_777 >> (64 * l)) & 0xFFFFFFFFFFFFFFFF;
    }

    // ---------------------------------------------------------------------
    // A seven-step verifier run.
    //   0-2: load lanes 0, 1, 2 of blob 0, element 777, into slots 1, 2, 3
    //   3:   load public value 0, the payload digest, into slot 4
    //   4:   fold   reads 1, 2, 3, 4        writes 8
    //   5:   linear reads 8, 1, 4           writes 10
    //   6:   eq     reads 10, `against`     writes 0, the verdict
    // With against = 10 the run accepts; with against = 1 it rejects.
    // ---------------------------------------------------------------------

    uint64 constant MD = 4;
    uint64 constant PD = 3;
    uint64 constant STEPS = 7;

    struct Prog {
        StepVerifier.Step[7] kind;
        uint256[][7] reads;
        uint256[7] write;
        bytes32[] leaves;
        uint256[] idx;
        bytes32 root;
    }

    function _program(uint256 against) internal view returns (Prog memory p) {
        p.kind = [StepVerifier.Step.LoadBlob, StepVerifier.Step.LoadBlob, StepVerifier.Step.LoadBlob,
                  StepVerifier.Step.LoadPublic, StepVerifier.Step.Fold, StepVerifier.Step.Linear,
                  StepVerifier.Step.Eq];
        for (uint256 l = 0; l < 3; ++l) {
            p.reads[l] = new uint256[](3);
            p.reads[l][1] = 777;
            p.reads[l][2] = l;
        }
        p.reads[3] = new uint256[](1);
        p.reads[4] = new uint256[](4);
        p.reads[4][0] = 1; p.reads[4][1] = 2; p.reads[4][2] = 3; p.reads[4][3] = 4;
        p.reads[5] = new uint256[](3);
        p.reads[5][0] = 8; p.reads[5][1] = 1; p.reads[5][2] = 4;
        p.reads[6] = new uint256[](2);
        p.reads[6][0] = 10; p.reads[6][1] = against;
        p.write = [uint256(1), 2, 3, 4, 8, 10, 0];
        p.leaves = new bytes32[](STEPS);
        p.idx = new uint256[](STEPS);
        for (uint256 k = 0; k < STEPS; ++k) {
            p.idx[k] = k;
            p.leaves[k] = v.instructionLeaf(p.kind[k], p.reads[k], p.write[k]);
        }
        p.root = Sparse.root(PD, p.idx, p.leaves);
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

    function _mem(uint256[16] memory m) internal pure returns (bytes32) {
        (uint256[] memory idx, bytes32[] memory lv) = _leaves(m);
        return Sparse.root(MD, idx, lv);
    }

    function _isLoad(StepVerifier.Step k) internal pure returns (bool) {
        return k == StepVerifier.Step.LoadBlob || k == StepVerifier.Step.LoadPublic;
    }

    /// The run as an honest party computes it. `firstLane` lets a dishonest
    /// defender pretend the blob holds something else at step 0.
    function _run(Prog memory p, uint256 firstLane)
        internal
        view
        returns (uint256[16][8] memory states)
    {
        for (uint256 k = 0; k < STEPS; ++k) {
            // Element by element: assigning one memory array to another
            // aliases it, and every state would then be the last.
            for (uint256 i = 0; i < 16; ++i) states[k + 1][i] = states[k][i];
            uint256 r;
            if (p.kind[k] == StepVerifier.Step.LoadBlob) {
                r = k == 0 ? firstLane : _lane(p.reads[k][2]);
            } else if (p.kind[k] == StepVerifier.Step.LoadPublic) {
                r = DIGEST;
            } else {
                uint256[] memory vals = new uint256[](p.reads[k].length);
                for (uint256 i = 0; i < vals.length; ++i) vals[i] = states[k][p.reads[k][i]];
                r = v.execute(p.kind[k], vals);
            }
            states[k + 1][p.write[k]] = r;
        }
    }

    function _stepInput(Prog memory p, uint256[16] memory m, uint256 k)
        internal
        pure
        returns (StepVerifier.StepInput memory s)
    {
        uint256 n = _isLoad(p.kind[k]) ? 0 : p.reads[k].length;
        (uint256[] memory idx, bytes32[] memory lv) = _leaves(m);
        s.kind = p.kind[k];
        s.reads = p.reads[k];
        s.write = p.write[k];
        s.values = new uint256[](n);
        s.oldValue = m[p.write[k]];
        s.paths = new bytes32[](PD + (n + 1) * MD);
        bytes32[] memory pp = Sparse.path(PD, k, p.idx, p.leaves);
        for (uint256 i = 0; i < PD; ++i) s.paths[i] = pp[i];
        for (uint256 r = 0; r <= n; ++r) {
            uint256 slot = r < n ? p.reads[k][r] : p.write[k];
            if (r < n) s.values[r] = m[slot];
            bytes32[] memory mp = Sparse.path(MD, slot, idx, lv);
            for (uint256 i = 0; i < MD; ++i) s.paths[PD + r * MD + i] = mp[i];
        }
    }

    function _acceptPath(uint256[16] memory m) internal pure returns (bytes32[] memory) {
        (uint256[] memory idx, bytes32[] memory lv) = _leaves(m);
        return Sparse.path(MD, 0, idx, lv);
    }

    struct Game {
        Dispute d;
        uint256 id;
        bytes32 gid;
    }

    function _openGame(Prog memory p, uint256[16] memory claimedEnd) internal returns (Game memory G) {
        G.d = new Dispute(address(acc), address(v), p.root, PD, STEPS, MD, WINDOW_S, BOND);
        acc.setArbiters(address(G.d), address(0xDEAD));
        G.id = _reg(Reserve.Funding.Deposit);
        bytes32 blobsHash = keccak256(abi.encodePacked(_oneBlob()));
        _settleWith(G.id, DIGEST, blobsHash);
        G.gid = G.d.gameId(G.id, DIGEST);
        vm.prank(challenger);
        G.d.open{value: BOND}(G.id, DIGEST, blobsHash, 0);
        bytes32 fr = _mem(claimedEnd);
        bytes32[] memory ap = _acceptPath(claimedEnd);
        vm.prank(agent);
        G.d.postFinal(G.gid, fr, ap);
    }

    function _settle(Game memory G, Prog memory p, uint256[16] memory m, uint256 k) internal {
        bytes memory kzg = KzgVectors.kzg(KzgVectors.Y_777, KzgVectors.PROOF_777);
        G.d.settleOneStep(G.gid, _mem(m), _stepInput(p, m, k), _oneBlob(), kzg);
    }

    /// The defender reports its own run; the challenger, holding the proof,
    /// computes the true one and agrees exactly where the two match.
    function _play(Game memory G, uint256[16][8] memory truth, uint256[16][8] memory claim)
        internal
        returns (uint64 lo)
    {
        lo = 0;
        uint64 hi = STEPS;
        while (hi - lo > 1) {
            uint64 mid = lo + (hi - lo) / 2;
            bytes32 ms = G.d.state(_mem(claim[mid]), mid);
            vm.prank(agent);
            G.d.respond(G.gid, ms);
            bool agree = _mem(claim[mid]) == _mem(truth[mid]);
            vm.prank(challenger);
            G.d.choose(G.gid, agree);
            if (agree) lo = mid;
            else hi = mid;
        }
    }

    function testFalseVerdictLoses() public {
        Prog memory p = _program(1);
        uint256[16][8] memory truth = _run(p, _lane(0));
        uint256[16][8] memory claim = _run(p, _lane(0));
        claim[STEPS][0] = 1;
        Game memory G = _openGame(p, claim[STEPS]);
        uint64 lo = _play(G, truth, claim);
        uint256 before = principal.balance;
        _settle(G, p, truth[lo], lo);
        assertEq(uint256(G.d.statusOf(G.gid)), uint256(Dispute.Status.ChallengerWon));
        assertEq(principal.balance - before, 1 ether);
        console.log("false verdict: decided at step", lo, "agent's bond to the principal");
    }

    function testTrueRunStands() public {
        Prog memory p = _program(10);
        uint256[16][8] memory truth = _run(p, _lane(0));
        Game memory G = _openGame(p, truth[STEPS]);
        uint256 before = agent.balance;
        uint64 lo = _play(G, truth, truth);
        _settle(G, p, truth[lo], lo);
        assertEq(uint256(G.d.statusOf(G.gid)), uint256(Dispute.Status.DefenderWon));
        assertEq(agent.balance - before, BOND);
        console.log("true run: defender wins and keeps the challenger's bond");
    }

    /// The gap the load step closes: the agent claims a run over a proof
    /// other than the one in its blob. The game descends to the first load
    /// and the precompile decides it.
    function testRunOverAnotherProofLoses() public {
        Prog memory p = _program(10);
        uint256[16][8] memory truth = _run(p, _lane(0));
        uint256[16][8] memory claim = _run(p, _lane(0) + 1);
        claim[STEPS][0] = 1;
        Game memory G = _openGame(p, claim[STEPS]);
        uint64 lo = _play(G, truth, claim);
        assertEq(lo, 0);
        _settle(G, p, truth[lo], lo);
        assertEq(uint256(G.d.statusOf(G.gid)), uint256(Dispute.Status.ChallengerWon));
        console.log("run over another proof: decided at the first load");
    }

    function testCannotReopen() public {
        Prog memory p = _program(10);
        Dispute d = new Dispute(address(acc), address(v), p.root, PD, STEPS, MD, WINDOW_S, BOND);
        uint256 id = _reg(Reserve.Funding.Deposit);
        bytes32 bh = keccak256(abi.encodePacked(_oneBlob()));
        _settleWith(id, DIGEST, bh);
        vm.prank(challenger);
        d.open{value: BOND}(id, DIGEST, bh, 0);
        vm.prank(challenger);
        vm.expectRevert(Dispute.GameExists.selector);
        d.open{value: BOND}(id, DIGEST, bh, 0);
    }

    /// A settlement made after a revocation is bound to the new root; a game
    /// cannot be opened against the old one.
    function testEpochIsTheReserves() public {
        Prog memory p = _program(10);
        Dispute d = new Dispute(address(acc), address(v), p.root, PD, STEPS, MD, WINDOW_S, BOND);
        uint256 id = _reg(Reserve.Funding.Deposit);
        vm.prank(principal);
        acc.revoke(id, 0, 64, keccak256("root1"));
        bytes32 bh = keccak256(abi.encodePacked(_oneBlob()));
        _settleWith(id, DIGEST, bh);
        vm.prank(challenger);
        vm.expectRevert(Dispute.WrongCommitment.selector);
        d.open{value: BOND}(id, DIGEST, bh, 0);
        vm.prank(challenger);
        d.open{value: BOND}(id, DIGEST, bh, 1);
    }

    // ---------------------------------------------------------------------
    // Cost by length. The last step is at the end of the program; the trees
    // have the deployed memory depth and a program as long as the run.
    // ---------------------------------------------------------------------

    uint64 constant BIG_MD = 22;
    uint256 constant BLOBS = 53;

    struct Big {
        Dispute d;
        uint256 id;
        bytes32 gid;
        bytes32 x;
        uint256[] reads;
        bytes32[] leaves;
        uint256[] pidx;
        bytes32[] pleaf;
        uint64 pdepth;
        StepVerifier.Step kind;
        uint256[] values;
        bytes32[] blobs;
    }

    function _bigBlobs() internal pure returns (bytes32[] memory bl) {
        bl = new bytes32[](BLOBS);
        bl[0] = KzgVectors.VERSIONED_HASH;
        for (uint256 i = 1; i < BLOBS; ++i) bl[i] = keccak256(abi.encode("blob", i));
    }

    function _bigSetup(uint64 steps, uint64 pdepth, StepVerifier.Step kind) internal returns (Big memory B) {
        Reserve r = new Reserve(DOMAIN, address(token), permit2);
        acc = r;
        vm.prank(principal);
        token.approve(address(r), type(uint256).max);
        B.pdepth = pdepth;
        B.kind = kind;
        B.blobs = _bigBlobs();
        uint256 n;
        if (kind == StepVerifier.Step.Algebraic) {
            B.values = new uint256[](2);
            B.values[0] = v.pack([uint256(1), 2, 3, 4]);
            B.values[1] = v.pack([uint256(5), 6, 7, 8]);
            n = 2;
        } else if (kind == StepVerifier.Step.Fold) {
            B.values = new uint256[](4);
            B.values[0] = 1000; B.values[1] = 400; B.values[2] = 5; B.values[3] = 7;
            n = 4;
        }
        B.reads = new uint256[](kind == StepVerifier.Step.LoadBlob ? 3 : n);
        B.leaves = new bytes32[](n);
        for (uint256 i = 0; i < n; ++i) {
            B.reads[i] = i + 1;
            B.leaves[i] = bytes32(B.values[i]);
        }
        if (kind == StepVerifier.Step.LoadBlob) {
            B.reads[0] = 0; B.reads[1] = 777; B.reads[2] = 1;
            B.values = new uint256[](0);
        }
        uint256[] memory memIdx = new uint256[](n);
        for (uint256 i = 0; i < n; ++i) memIdx[i] = i + 1;
        B.x = Sparse.root(BIG_MD, memIdx, B.leaves);
        B.pidx = new uint256[](1);
        B.pidx[0] = steps - 1;
        B.pleaf = new bytes32[](1);
        B.pleaf[0] = v.instructionLeaf(kind, B.reads, 5);
        B.d = new Dispute(address(r), address(v), Sparse.root(pdepth, B.pidx, B.pleaf), pdepth, steps,
                          BIG_MD, WINDOW_S, BOND);
        r.setArbiters(address(B.d), address(0xDEAD));
        B.id = _reg(Reserve.Funding.Deposit);
        _settleWith(B.id, DIGEST, keccak256(abi.encodePacked(B.blobs)));
        B.gid = B.d.gameId(B.id, DIGEST);
    }

    function _bigOpen(Big memory B) internal returns (uint256 used) {
        uint256[] memory a = new uint256[](1);
        bytes32[] memory al = new bytes32[](1);
        al[0] = bytes32(uint256(1));
        bytes32 finalRoot = Sparse.root(BIG_MD, a, al);
        bytes32[] memory acceptPath = Sparse.path(BIG_MD, 0, a, al);
        bytes32 bh = keccak256(abi.encodePacked(B.blobs));
        vm.prank(challenger);
        uint256 g = gasleft();
        B.d.open{value: BOND}(B.id, DIGEST, bh, 0);
        used = g - gasleft();
        vm.prank(agent);
        g = gasleft();
        B.d.postFinal(B.gid, finalRoot, acceptPath);
        used += g - gasleft();
    }

    /// The challenger agrees every time, which drives the game to the last
    /// step of the program and exercises the branch that moves the lower end.
    function _bigBisect(Big memory B, uint64 steps) internal returns (uint256 used, uint64 n) {
        uint64 lo = 0;
        uint64 hi = steps;
        while (hi - lo > 1) {
            uint64 mid = lo + (hi - lo) / 2;
            bytes32 ms = B.d.state(B.x, mid);
            vm.prank(agent);
            uint256 g = gasleft();
            B.d.respond(B.gid, ms);
            used += g - gasleft();
            vm.prank(challenger);
            g = gasleft();
            B.d.choose(B.gid, true);
            used += g - gasleft();
            lo = mid;
            ++n;
        }
    }

    function _bigStep(Big memory B) internal returns (uint256 used) {
        StepVerifier.StepInput memory s;
        bool load = B.kind == StepVerifier.Step.LoadBlob;
        uint256 n = load ? 0 : B.values.length;
        s.kind = B.kind;
        s.reads = B.reads;
        s.write = 5;
        s.values = B.values;
        s.paths = new bytes32[](B.pdepth + (n + 1) * BIG_MD);
        bytes32[] memory pp = Sparse.path(B.pdepth, B.pidx[0], B.pidx, B.pleaf);
        for (uint256 i = 0; i < B.pdepth; ++i) s.paths[i] = pp[i];
        uint256[] memory memIdx = new uint256[](B.leaves.length);
        for (uint256 i = 0; i < memIdx.length; ++i) memIdx[i] = i + 1;
        for (uint256 rr = 0; rr <= n; ++rr) {
            bytes32[] memory mp = Sparse.path(BIG_MD, rr < n ? B.reads[rr] : 5, memIdx, B.leaves);
            for (uint256 i = 0; i < BIG_MD; ++i) s.paths[B.pdepth + rr * BIG_MD + i] = mp[i];
        }
        bytes memory kzg = KzgVectors.kzg(KzgVectors.Y_777, KzgVectors.PROOF_777);
        bytes32[] memory bl = load ? B.blobs : new bytes32[](0);
        uint256 g = gasleft();
        B.d.settleOneStep(B.gid, B.x, s, bl, kzg);
        used = g - gasleft();
        assertEq(uint256(B.d.statusOf(B.gid)), uint256(Dispute.Status.ChallengerWon));
    }

    function _length(uint64 steps, uint64 pdepth, StepVerifier.Step kind)
        internal
        returns (uint256 openGas, uint256 roundsGas, uint256 stepGas, uint64 n)
    {
        Big memory B = _bigSetup(steps, pdepth, kind);
        openGas = _bigOpen(B);
        (roundsGas, n) = _bigBisect(B, steps);
        stepGas = _bigStep(B);
    }

    function testCostByVerificationLength() public {
        uint64[6] memory logs = [uint64(10), 14, 18, 20, 21, 24];
        for (uint256 i = 0; i < logs.length; ++i) {
            (uint256 o, uint256 r, uint256 s, uint64 n) =
                _length(uint64(1) << logs[i], logs[i], StepVerifier.Step.Fold);
            console.log("steps 2^", logs[i]);
            console.log("  rounds", n);
            console.log("  open and final claim", o);
            console.log("  bisection", r);
            console.log("  last step, fold, with bonds moving", s);
            console.log("  total", o + r + s);
        }
    }

    /// The dearer places a defender can steer the game: a level of the
    /// proof's own Poseidon2 trees, and a load from a blob.
    function testDearerSteps() public {
        uint64[3] memory logs = [uint64(20), 21, 24];
        for (uint256 i = 0; i < logs.length; ++i) {
            (uint256 o, uint256 r, uint256 s, ) =
                _length(uint64(1) << logs[i], logs[i], StepVerifier.Step.Algebraic);
            console.log("steps 2^", logs[i]);
            console.log("  last step, Poseidon2 level, with bonds moving", s);
            console.log("  total", o + r + s);
            (o, r, s, ) = _length(uint64(1) << logs[i], logs[i], StepVerifier.Step.LoadBlob);
            console.log("  last step, load from a blob, with bonds moving", s);
            console.log("  total", o + r + s);
        }
    }

    function testDefenderSilent() public {
        Dispute d = new Dispute(address(acc), address(v), bytes32(0), 2, 4, MD, WINDOW_S, BOND);
        acc.setArbiters(address(d), address(0xDEAD));
        uint256 id = _reg(Reserve.Funding.Deposit);
        bytes32 bh = keccak256(abi.encodePacked(_oneBlob()));
        _settleWith(id, DIGEST, bh);
        vm.prank(challenger);
        d.open{value: BOND}(id, DIGEST, bh, 0);
        vm.warp(block.timestamp + WINDOW_S + 1);
        uint256 before = principal.balance;
        uint256 g = gasleft();
        d.timeout(d.gameId(id, DIGEST));
        console.log("defender silent: challenger wins on timeout, gas", g - gasleft());
        assertEq(principal.balance - before, 1 ether);
    }

    function testChallengerSilent() public {
        Prog memory p = _program(10);
        uint256[16][8] memory truth = _run(p, _lane(0));
        Game memory G = _openGame(p, truth[STEPS]);
        bytes32 ms = G.d.state(_mem(truth[3]), 3);
        vm.prank(agent);
        G.d.respond(G.gid, ms);
        vm.warp(block.timestamp + WINDOW_S + 1);
        uint256 before = agent.balance;
        G.d.timeout(G.gid);
        assertEq(uint256(G.d.statusOf(G.gid)), uint256(Dispute.Status.DefenderWon));
        assertEq(agent.balance - before, BOND);
    }
}
