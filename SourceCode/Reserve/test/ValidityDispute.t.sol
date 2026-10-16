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

/// A challenge against a real settlement, answered with the real Groth16
/// proof. The delegation is registered with the commitment and revocation root
/// Pete's proof carries, and the settlement is exactly the exported payment:
/// its amount, payee, time and shares. Gas is measured as transaction receipts
/// by script/ValidityDisputeOnChain.s.sol.
contract ValidityDisputeTest is Groth16Result {
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
    uint64 digest;
    Settlement rec;

    function setUp() public {
        _load();
        _checkStatement();
        require(_pv(9) == DOMAIN, "proof is for another domain");
        vm.warp(Statement.TIME);
        agent = vm.addr(AGENT_PK);
        token = new MockToken();
        acc = new Reserve(DOMAIN, address(token), address(0), address(new Poseidon2Goldilocks()), 1 hours, 2 days);
        sp1 = new SP1Verifier();
        vd = new ValidityDispute(address(acc), address(sp1), vkey, bytes32(0), ACCEPT, WINDOW, SLOT, CHALLENGER_BOND);
        acc.setDispute(address(vd));
        vm.deal(principal, 10 ether);
        vm.deal(challenger, 1 ether);
        token.mint(principal, 1e15);
        token.mint(Statement.PAYEE, 1);
        vm.prank(principal);
        token.approve(address(acc), type(uint256).max);

        digest = _pv(0);
        id = _register(_lanes(5));
        rec = _settle(id, Statement.elems(), Statement.AMOUNT);
    }

    function _register(bytes32 com) internal returns (uint256 r) {
        vm.prank(principal);
        r = acc.register{value: AGENT_BOND}(TermsOf.make(agent, CAP, 1_000, 86_400, Reserve.Funding.Deposit, BUDGET, com, _lanes(1), uint64(block.timestamp) + 30 days));
    }

    function _settle(uint256 r, uint64[] memory e, uint64 amount) internal returns (Settlement memory s) {
        bytes32 eh = keccak256(abi.encodePacked(e));
        bytes32 h = acc.signedDigest(r, Statement.PAYEE, amount, digest, Statement.TIME, eh);
        (uint8 v, bytes32 rr, bytes32 ss) = vm.sign(AGENT_PK, h);
        acc.settleLogged(r, Statement.PAYEE, amount, digest, Statement.TIME, e, abi.encodePacked(rr, ss, v));
        s = Settlement({
            elems: eh, amount: amount, payee: Statement.PAYEE, time: Statement.TIME, epoch: 0
        });
    }

    function _open(uint256 r, Settlement memory s) internal {
        vm.prank(challenger);
        vd.open{value: CHALLENGER_BOND}(r, digest, s);
    }

    function testPublicValuesAreTheReserveRecord() public view {
        assertEq(vd.publicValues(id, digest, rec), publicValues);
    }

    function testAnswerPaysTheAgent() public {
        _open(id, rec);
        uint256 agentBefore = agent.balance;
        vd.answer(id, digest, rec, proof);
        assertEq(vd.credit(agent), CHALLENGER_BOND);
        assertEq(uint256(vd.challengeOf(id, digest).status), uint256(ValidityDispute.Status.Answered));
        vm.prank(agent);
        vd.withdraw();
        assertEq(agent.balance, agentBefore + CHALLENGER_BOND);
        assertEq(vd.credit(agent), 0);
    }

    function testNoAnswerForfeitsTheAgentBond() public {
        _open(id, rec);
        vm.warp(vd.challengeOf(id, digest).deadline + 1);
        uint256 principalBefore = principal.balance;
        uint256 challengerBefore = challenger.balance;
        vd.expire(id, digest);
        assertEq(principal.balance, principalBefore + AGENT_BOND);
        vm.prank(challenger);
        vd.withdraw();
        assertEq(challenger.balance, challengerBefore + CHALLENGER_BOND);
        assertEq(uint256(vd.challengeOf(id, digest).status), uint256(ValidityDispute.Status.Expired));
    }

    /// R1: a valid proof of the payment cannot answer for a settlement that
    /// published one share the proof did not compute. The agent signed the
    /// substituted shares, so the reserve settled them; the dispute holds the
    /// agent to them, and no proof of them exists.
    function testSubstitutedShareCannotBeAnswered() public {
        uint256 other = _register(_lanes(5));
        uint64[] memory e = Statement.elems();
        e[0] ^= 1;
        Settlement memory s = _settle(other, e, Statement.AMOUNT);
        _open(other, s);
        vm.expectRevert(Verifier.ProofInvalid.selector);
        vd.answer(other, digest, s, proof);
        vm.warp(vd.challengeOf(other, digest).deadline + 1);
        uint256 before = principal.balance;
        vd.expire(other, digest);
        assertEq(principal.balance, before + AGENT_BOND);
    }

    /// R1b: the same proof cannot answer for a settlement that paid more.
    function testRaisedAmountCannotBeAnswered() public {
        uint256 other = _register(_lanes(5));
        Settlement memory s = _settle(other, Statement.elems(), Statement.AMOUNT + 1);
        _open(other, s);
        vm.expectRevert(Verifier.ProofInvalid.selector);
        vd.answer(other, digest, s, proof);
    }

    function testProofOfAnotherRecordFails() public {
        uint256 other = _register(bytes32(uint256(_lanes(5)) ^ 1));
        Settlement memory s = _settle(other, Statement.elems(), Statement.AMOUNT);
        _open(other, s);
        vm.expectRevert(Verifier.ProofInvalid.selector);
        vd.answer(other, digest, s, proof);
    }

    function testProofAfterRevocationStillAnswersItsEpoch() public {
        uint64[] memory st = new uint64[](1);
        uint64[] memory ln = new uint64[](1);
        st[0] = Statement.RANGE_BASE;
        ln[0] = 1;
        vm.prank(principal);
        acc.revoke(id, st, ln, bytes32(uint256(0xDEAD)));
        _open(id, rec);
        vd.answer(id, digest, rec, proof);
        assertEq(uint256(vd.challengeOf(id, digest).status), uint256(ValidityDispute.Status.Answered));
    }

    function testWrongEpochCannotOpen() public {
        Settlement memory s = rec;
        s.epoch = 1;
        vm.prank(challenger);
        vm.expectRevert(ValidityDispute.WrongRecord.selector);
        vd.open{value: CHALLENGER_BOND}(id, digest, s);
    }

    function testUnsettledDigestCannotOpen() public {
        vm.prank(challenger);
        vm.expectRevert(ValidityDispute.WrongRecord.selector);
        vd.open{value: CHALLENGER_BOND}(id, digest ^ 1, rec);
    }

    function testWrongBondCannotOpen() public {
        vm.prank(challenger);
        vm.expectRevert(ValidityDispute.BondTooSmall.selector);
        vd.open{value: CHALLENGER_BOND - 1}(id, digest, rec);
    }

    function testSecondChallengeRefused() public {
        _open(id, rec);
        vm.prank(challenger);
        vm.expectRevert(ValidityDispute.AlreadyChallenged.selector);
        vd.open{value: CHALLENGER_BOND}(id, digest, rec);
    }

    function testLateAnswerRefused() public {
        _open(id, rec);
        vm.warp(vd.challengeOf(id, digest).deadline + 1);
        vm.expectRevert(ValidityDispute.TooLate.selector);
        vd.answer(id, digest, rec, proof);
    }

    function testEarlyExpireRefused() public {
        _open(id, rec);
        vm.expectRevert(ValidityDispute.TooEarly.selector);
        vd.expire(id, digest);
    }

    function testNoExpireAfterAnswer() public {
        _open(id, rec);
        vd.answer(id, digest, rec, proof);
        vm.warp(vd.challengeOf(id, digest).deadline + 1);
        vm.expectRevert(ValidityDispute.NotOpen.selector);
        vd.expire(id, digest);
    }
}
