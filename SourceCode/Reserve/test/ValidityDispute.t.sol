// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Reserve} from "../src/Reserve.sol";
import {Poseidon2Goldilocks} from "../src/Poseidon2Goldilocks.sol";
import {TermsOf} from "./TermsOf.sol";
import {ValidityDispute} from "../src/ValidityDispute.sol";
import {Settlement} from "../src/Settlement.sol";
import {SP1Verifier} from "../src/sp1/v6.1.0/SP1VerifierGroth16.sol";
import {Verifier} from "../src/sp1/v6.1.0/Groth16Verifier.sol";
import {MockToken} from "./MockToken.sol";
import {Groth16Result} from "./Groth16Result.sol";
import {Statement} from "./Statement.sol";

/// Challenges against real settlements, answered with the real Groth16 proof.
/// The delegation is registered with the commitment and revocation root the
/// batch proof carries, and its settlements are exactly the batch's
/// payments: their amounts, payee, times and shares. Gas is measured as
/// transaction receipts by script/ValidityDisputeOnChain.s.sol.
contract ValidityDisputeTest is Groth16Result {
    /// Stands for the agent's commitment to a payment's hidden fields, which
    /// the reserve signs over and emits but never reads.
    bytes32 constant OPENING = keccak256("hidden fields");
    uint64 constant DOMAIN = 8453;
    uint64 constant CAP = 1_000_000;
    uint64 constant BUDGET = 100_000_000;
    uint256 constant AGENT_PK = 0xA6E47;
    uint256 constant AGENT_BOND = 1 ether;
    uint256 constant CHALLENGER_BOND = 0.01 ether;
    uint64 constant ACCEPT = 1 days;
    uint64 constant WINDOW = 1 days;
    uint64 constant SLOT = 2 hours;

    MockToken token;
    Reserve acc;
    SP1Verifier sp1;
    ValidityDispute vd;
    address principal = address(0xA11CE);
    address challenger = address(0xC14);
    address agent;
    uint256 id;
    Settlement[] recs;

    function setUp() public {
        _load();
        _cache();
        _checkStatement();
        require(_leaf(0)[9] == DOMAIN, "proof is for another domain");
        vm.warp(_time(Statement.PAYMENTS - 1));
        agent = vm.addr(AGENT_PK);
        token = new MockToken();
        acc = new Reserve(DOMAIN, address(token), address(0), address(new Poseidon2Goldilocks()), 1 hours, 2 days);
        sp1 = new SP1Verifier();
        vd = new ValidityDispute(address(acc), address(sp1), vkey, ACCEPT, WINDOW, SLOT, CHALLENGER_BOND, 8 hours, 0.25 ether, 0);
        acc.setDispute(address(vd));
        vm.deal(principal, 10 ether);
        vm.deal(challenger, 10 ether);
        token.mint(principal, 1e15);
        token.mint(_payee(0), 1);
        vm.prank(principal);
        token.approve(address(acc), type(uint256).max);

        id = _register(_com());
        for (uint256 i = 0; i < Statement.PAYMENTS; ++i) {
            recs.push(_settle(id, i, _elems(i), _amount(i)));
        }
    }

    function _register(bytes32 com) internal returns (uint256 r) {
        vm.prank(principal);
        r = acc.register{value: AGENT_BOND}(TermsOf.make(agent, CAP, 1_000, 86_400, Reserve.Funding.Deposit, BUDGET, com, _root0(), uint64(block.timestamp) + 30 days));
    }

    function _settle(uint256 r, uint256 i, uint64[] memory e, uint64 amount) internal returns (Settlement memory s) {
        s = Settlement({
            elems: keccak256(abi.encodePacked(e)), amount: amount, payee: _payee(i), time: _time(i),
            epoch: 0
        });
        acc.settleLogged(r, s.payee, amount, _digest(i), s.time, e, OPENING, _sign(r, i, s));
    }

    function _sign(uint256 r, uint256 i, Settlement memory s) internal view returns (bytes memory) {
        bytes32 h = acc.signedDigest(r, s.payee, s.amount, _digest(i), s.time, s.elems, OPENING);
        (uint8 v, bytes32 rr, bytes32 ss) = vm.sign(AGENT_PK, h);
        return abi.encodePacked(rr, ss, v);
    }

    function _open(uint256 r, uint256 i, Settlement memory s) internal {
        vm.prank(challenger);
        vd.open{value: CHALLENGER_BOND}(r, _digest(i), s);
    }

    function _answer(uint256 r, uint256 i, Settlement memory s, uint256 at) internal {
        vd.answer(r, _digest(i), s, at, _path(at), proof);
    }

    function testLeavesAreTheReserveRecords() public view {
        for (uint256 i = 0; i < Statement.PAYMENTS; ++i) {
            uint256[26] memory got = vd.leaf(id, _digest(i), recs[i]);
            uint64[] memory want = _leaf(i);
            for (uint256 j = 0; j < 26; ++j) assertEq(got[j], want[j]);
            assertEq(vd.rootOf(id, _digest(i), recs[i], i, _path(i)), Statement.ROOT);
        }
    }

    function testAnswerPaysTheAgent() public {
        _open(id, 77, recs[77]);
        uint256 agentBefore = agent.balance;
        _answer(id, 77, recs[77], 77);
        assertEq(vd.credit(agent), CHALLENGER_BOND);
        assertEq(uint256(vd.challengeOf(id, _digest(77)).status), uint256(ValidityDispute.Status.Answered));
        vm.prank(agent);
        vd.withdraw();
        assertEq(agent.balance, agentBefore + CHALLENGER_BOND);
        assertEq(vd.credit(agent), 0);
    }

    /// One proof of the batch answers a challenge against every payment in it.
    function testOneProofAnswersEveryPaymentOfTheBatch() public {
        uint256 n = Statement.PAYMENTS;
        uint256[] memory ids = new uint256[](n);
        uint64[] memory ds = new uint64[](n);
        Settlement[] memory ss = new Settlement[](n);
        uint256[] memory at = new uint256[](n);
        bytes32[][] memory paths = new bytes32[][](n);
        for (uint256 i = 0; i < n; ++i) {
            _open(id, i, recs[i]);
            (ids[i], ds[i], ss[i], at[i], paths[i]) = (id, _digest(i), recs[i], i, _path(i));
        }
        vd.answerBatch(_items(ids, ds, ss, at, paths), proof);
        for (uint256 i = 0; i < n; ++i) {
            assertEq(uint256(vd.challengeOf(id, ds[i]).status), uint256(ValidityDispute.Status.Answered));
        }
        assertEq(vd.credit(agent), n * CHALLENGER_BOND);
        assertEq(vd.openCount(id), 0);
    }

    function testNoAnswerForfeitsTheAgentBond() public {
        _open(id, 0, recs[0]);
        vm.warp(vd.challengeOf(id, _digest(0)).deadline + 1);
        uint256 principalBefore = principal.balance;
        uint256 challengerBefore = challenger.balance;
        vd.expire(id, _digest(0));
        assertEq(acc.credit(principal), AGENT_BOND);
        vm.prank(principal);
        acc.withdraw();
        assertEq(principal.balance, principalBefore + AGENT_BOND);
        vm.prank(challenger);
        vd.withdraw();
        assertEq(challenger.balance, challengerBefore + CHALLENGER_BOND);
        assertEq(uint256(vd.challengeOf(id, _digest(0)).status), uint256(ValidityDispute.Status.Expired));
    }

    /// A valid proof of the payment cannot answer for a settlement that
    /// published one share the proof did not compute. The agent signed the
    /// substituted shares, so the reserve settled them; the dispute holds the
    /// agent to them, and no proof of them exists.
    function testSubstitutedShareCannotBeAnswered() public {
        uint256 other = _register(_com());
        uint64[] memory e = _elems(5);
        e[0] ^= 1;
        Settlement memory s = _settle(other, 5, e, _amount(5));
        _open(other, 5, s);
        vm.expectRevert(Verifier.ProofInvalid.selector);
        _answer(other, 5, s, 5);
        vm.warp(vd.challengeOf(other, _digest(5)).deadline + 1);
        vd.expire(other, _digest(5));
        assertEq(acc.credit(principal), AGENT_BOND);
    }

    /// The same proof cannot answer for a settlement that paid more for the
    /// same units.
    function testRaisedAmountCannotBeAnswered() public {
        uint256 other = _register(_com());
        uint64 a = _amount(0);
        require((a + 1 + Statement.UNIT - 1) / Statement.UNIT == (a + Statement.UNIT - 1) / Statement.UNIT, "same units");
        Settlement memory s = _settle(other, 0, _elems(0), a + 1);
        _open(other, 0, s);
        vm.expectRevert(Verifier.ProofInvalid.selector);
        _answer(other, 0, s, 0);
    }

    function testProofOfAnotherRecordFails() public {
        uint256 other = _register(bytes32(uint256(_com()) ^ 1));
        Settlement memory s = _settle(other, 3, _elems(3), _amount(3));
        _open(other, 3, s);
        vm.expectRevert(Verifier.ProofInvalid.selector);
        _answer(other, 3, s, 3);
    }

    /// A leaf placed at another payment's position reaches another root.
    function testLeafAtAnotherPositionFails() public {
        _open(id, 2, recs[2]);
        vm.expectRevert(Verifier.ProofInvalid.selector);
        _answer(id, 2, recs[2], 3);
    }

    function testOverlongOrMisplacedPathRefused() public {
        _open(id, 2, recs[2]);
        bytes32[] memory p = new bytes32[](vd.MAX_DEPTH() + 1);
        vm.expectRevert(ValidityDispute.BadPath.selector);
        vd.answer(id, _digest(2), recs[2], 2, p, proof);
        vm.expectRevert(ValidityDispute.BadPath.selector);
        vd.answer(id, _digest(2), recs[2], uint256(1) << _path(2).length, _path(2), proof);
    }

    /// Every settlement in one answer must lie under the same root.
    function testBatchAcrossTwoRootsRefused() public {
        uint256 other = _register(bytes32(uint256(_com()) ^ 1));
        Settlement memory s = _settle(other, 9, _elems(9), _amount(9));
        _open(other, 9, s);
        _open(id, 8, recs[8]);
        uint256[] memory ids = new uint256[](2);
        uint64[] memory ds = new uint64[](2);
        Settlement[] memory ss = new Settlement[](2);
        uint256[] memory at = new uint256[](2);
        bytes32[][] memory paths = new bytes32[][](2);
        (ids[0], ds[0], ss[0], at[0], paths[0]) = (id, _digest(8), recs[8], 8, _path(8));
        (ids[1], ds[1], ss[1], at[1], paths[1]) = (other, _digest(9), s, 9, _path(9));
        vm.expectRevert(ValidityDispute.RootMismatch.selector);
        vd.answerBatch(_items(ids, ds, ss, at, paths), proof);
    }

    function testProofAfterRevocationStillAnswersItsEpoch() public {
        uint64[] memory st = new uint64[](1);
        uint64[] memory ln = new uint64[](1);
        st[0] = Statement.RANGE_BASE;
        ln[0] = 1;
        vm.prank(principal);
        acc.revoke(id, st, ln, bytes32(uint256(0xDEAD)));
        _open(id, 0, recs[0]);
        _answer(id, 0, recs[0], 0);
        assertEq(uint256(vd.challengeOf(id, _digest(0)).status), uint256(ValidityDispute.Status.Answered));
    }

    function testWrongEpochCannotOpen() public {
        Settlement memory s = recs[0];
        s.epoch = 1;
        vm.prank(challenger);
        vm.expectRevert(ValidityDispute.WrongRecord.selector);
        vd.open{value: CHALLENGER_BOND}(id, _digest(0), s);
    }

    function testUnsettledDigestCannotOpen() public {
        vm.prank(challenger);
        vm.expectRevert(ValidityDispute.WrongRecord.selector);
        vd.open{value: CHALLENGER_BOND}(id, _digest(0) ^ 1, recs[0]);
    }

    function testWrongBondCannotOpen() public {
        vm.prank(challenger);
        vm.expectRevert(ValidityDispute.BondTooSmall.selector);
        vd.open{value: CHALLENGER_BOND - 1}(id, _digest(0), recs[0]);
    }

    function testSecondChallengeRefused() public {
        _open(id, 0, recs[0]);
        vm.prank(challenger);
        vm.expectRevert(ValidityDispute.AlreadyChallenged.selector);
        vd.open{value: CHALLENGER_BOND}(id, _digest(0), recs[0]);
    }

    function testLateAnswerRefused() public {
        _open(id, 0, recs[0]);
        vm.warp(vd.challengeOf(id, _digest(0)).deadline + 1);
        vm.expectRevert(ValidityDispute.TooLate.selector);
        _answer(id, 0, recs[0], 0);
    }

    function testEarlyExpireRefused() public {
        _open(id, 0, recs[0]);
        vm.expectRevert(ValidityDispute.TooEarly.selector);
        vd.expire(id, _digest(0));
    }

    function testNoExpireAfterAnswer() public {
        _open(id, 0, recs[0]);
        _answer(id, 0, recs[0], 0);
        vm.warp(vd.challengeOf(id, _digest(0)).deadline + 1);
        vm.expectRevert(ValidityDispute.NotOpen.selector);
        vd.expire(id, _digest(0));
    }

    function _items(
        uint256[] memory ids,
        uint64[] memory ds,
        Settlement[] memory ss,
        uint256[] memory at,
        bytes32[][] memory paths
    ) internal pure returns (ValidityDispute.Item[] memory items) {
        items = new ValidityDispute.Item[](ids.length);
        for (uint256 i = 0; i < ids.length; ++i) {
            items[i] = ValidityDispute.Item({id: ids[i], digest: ds[i], s: ss[i], index: at[i], path: paths[i]});
        }
    }
}
