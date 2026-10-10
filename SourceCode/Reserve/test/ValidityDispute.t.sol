// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Reserve} from "../src/Reserve.sol";
import {ValidityDispute} from "../src/ValidityDispute.sol";
import {SP1Verifier} from "../src/sp1/v6.1.0/SP1VerifierGroth16.sol";
import {Verifier} from "../src/sp1/v6.1.0/Groth16Verifier.sol";
import {MockToken} from "./MockToken.sol";
import {Groth16Result} from "./Groth16Result.sol";

/// A challenge against a real settlement, answered with the real Groth16
/// proof. The reserve's record is set to the statement Pete proved: the
/// digest, revocation root, commitment and domain of the proof file. Gas is
/// measured as transaction receipts by script/ValidityDisputeOnChain.s.sol.
contract ValidityDisputeTest is Groth16Result {
    uint64 constant DOMAIN = 8453;
    uint64 constant CAP = 1_000_000;
    uint64 constant BUDGET = 100_000_000;
    uint256 constant AGENT_PK = 0xA6E47;
    uint256 constant AGENT_BOND = 1 ether;
    uint256 constant CHALLENGER_BOND = 0.01 ether;
    uint64 constant WINDOW = 1 days;

    MockToken token;
    Reserve acc;
    SP1Verifier sp1;
    ValidityDispute vd;
    address principal = address(0xA11CE);
    address payee = address(0xBEEF);
    address challenger = address(0xC14);
    address agent;
    uint256 id;
    uint64 digest;
    bytes32 commitment;

    function setUp() public {
        _load();
        agent = vm.addr(AGENT_PK);
        token = new MockToken();
        acc = new Reserve(DOMAIN, address(token), address(0));
        sp1 = new SP1Verifier();
        vd = new ValidityDispute(address(acc), address(sp1), vkey, WINDOW, CHALLENGER_BOND);
        acc.setArbiters(address(vd), address(0));
        vm.deal(principal, 10 ether);
        vm.deal(challenger, 1 ether);
        token.mint(principal, 1e15);
        token.mint(payee, 1);
        vm.prank(principal);
        token.approve(address(acc), type(uint256).max);

        require(_pv(9) == DOMAIN, "proof is for another domain");
        digest = _pv(0);
        id = _register(_lanes(5));
        commitment = keccak256(abi.encodePacked("settlement", id, digest));
        _settle(id, digest, commitment);
    }

    function _register(bytes32 com) internal returns (uint256 r) {
        vm.prank(principal);
        r = acc.register{value: AGENT_BOND}(
            agent, CAP, 1_000, 86_400, keccak256(abi.encodePacked(uint64(7), uint64(11))),
            Reserve.Funding.Deposit, BUDGET, com, _lanes(1)
        );
    }

    function _settle(uint256 r, uint64 d, bytes32 c) internal {
        uint64[] memory e = new uint64[](3);
        e[0] = 1; e[1] = 2; e[2] = 3;
        bytes32 h = acc.signedDigest(r, payee, 1000, d, keccak256(abi.encodePacked(e)), c);
        (uint8 v, bytes32 rr, bytes32 s) = vm.sign(AGENT_PK, h);
        acc.settleLogged(r, payee, 1000, d, e, c, abi.encodePacked(rr, s, v));
    }

    function _open() internal {
        vm.prank(challenger);
        vd.open{value: CHALLENGER_BOND}(id, digest, commitment, 0);
    }

    function testPublicValuesAreTheReserveRecord() public view {
        assertEq(vd.publicValues(id, digest, 0), publicValues);
    }

    function testAnswerPaysTheAgent() public {
        _open();
        uint256 agentBefore = agent.balance;
        vd.answer(id, digest, proof);
        assertEq(agent.balance, agentBefore + CHALLENGER_BOND);
        assertEq(uint256(vd.challengeOf(id, digest).status), uint256(ValidityDispute.Status.Answered));
    }

    function testNoAnswerForfeitsTheAgentBond() public {
        _open();
        vm.warp(block.timestamp + WINDOW + 1);
        uint256 principalBefore = principal.balance;
        uint256 challengerBefore = challenger.balance;
        vd.expire(id, digest);
        assertEq(principal.balance, principalBefore + AGENT_BOND);
        assertEq(challenger.balance, challengerBefore + CHALLENGER_BOND);
        assertEq(uint256(vd.challengeOf(id, digest).status), uint256(ValidityDispute.Status.Expired));
    }

    function testProofOfAnotherRecordFails() public {
        uint256 other = _register(bytes32(uint256(_lanes(5)) ^ 1));
        bytes32 c = keccak256(abi.encodePacked("settlement", other, digest));
        _settle(other, digest, c);
        vm.prank(challenger);
        vd.open{value: CHALLENGER_BOND}(other, digest, c, 0);
        vm.expectRevert(Verifier.ProofInvalid.selector);
        vd.answer(other, digest, proof);
    }

    function testProofAfterRevocationStillAnswersItsEpoch() public {
        vm.prank(principal);
        acc.revoke(id, 0, 1, bytes32(uint256(0xDEAD)));
        _open();
        vd.answer(id, digest, proof);
        assertEq(uint256(vd.challengeOf(id, digest).status), uint256(ValidityDispute.Status.Answered));
    }

    function testWrongEpochCannotOpen() public {
        vm.prank(challenger);
        vm.expectRevert(ValidityDispute.WrongCommitment.selector);
        vd.open{value: CHALLENGER_BOND}(id, digest, commitment, 1);
    }

    function testUnsettledDigestCannotOpen() public {
        vm.prank(challenger);
        vm.expectRevert(ValidityDispute.WrongCommitment.selector);
        vd.open{value: CHALLENGER_BOND}(id, digest ^ 1, commitment, 0);
    }

    function testWrongBondCannotOpen() public {
        vm.prank(challenger);
        vm.expectRevert(ValidityDispute.BondTooSmall.selector);
        vd.open{value: CHALLENGER_BOND - 1}(id, digest, commitment, 0);
    }

    function testSecondChallengeRefused() public {
        _open();
        vm.prank(challenger);
        vm.expectRevert(ValidityDispute.AlreadyChallenged.selector);
        vd.open{value: CHALLENGER_BOND}(id, digest, commitment, 0);
    }

    function testLateAnswerRefused() public {
        _open();
        vm.warp(block.timestamp + WINDOW + 1);
        vm.expectRevert(ValidityDispute.TooLate.selector);
        vd.answer(id, digest, proof);
    }

    function testEarlyExpireRefused() public {
        _open();
        vm.expectRevert(ValidityDispute.TooEarly.selector);
        vd.expire(id, digest);
    }

    function testNoExpireAfterAnswer() public {
        _open();
        vd.answer(id, digest, proof);
        vm.warp(block.timestamp + WINDOW + 1);
        vm.expectRevert(ValidityDispute.NotOpen.selector);
        vd.expire(id, digest);
    }
}
