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

/// Batch answers checked with the real Groth16 proofs Pete made of the batch
/// program over one, two and four payment proofs. Each payment proof is of the
/// same statement, so k delegations are registered with that statement's
/// commitment and root and each settles the exported payment once.
contract ValidityDisputeBatchTest is Groth16Result {
    uint64 constant DOMAIN = 8453;
    uint256 constant AGENT_PK = 0xA6E47;
    uint256 constant AGENT_BOND = 1 ether;
    uint256 constant BOND = 0.01 ether;
    uint64 constant ACCEPT = 1 days;
    uint64 constant WINDOW = 1 days;
    uint64 constant SLOT = 2 hours;

    MockToken token;
    Reserve acc;
    ValidityDispute vd;
    address principal = address(0xA11CE);
    address challenger = address(0xC14);
    address agent;
    uint64 digest;

    function _proof(uint256 k) internal view returns (bytes memory) {
        return vm.parseBytes(_field(_batchFile(k), "proof"));
    }

    function setUp() public {
        publicValues = vm.parseBytes(_field(_batchFile(4), "public_values"));
        require(publicValues.length == 8 + 8 * 4 * VALUES, "four proofs' values");
        _checkStatement();
        require(_pv(9) == DOMAIN, "proof is for another domain");
        digest = _pv(0);
        bytes32 single = vm.parseBytes32(_field(SINGLE, "vkey"));
        bytes32 batch = vm.parseBytes32(_field(_batchFile(4), "vkey"));
        vm.warp(Statement.TIME);
        agent = vm.addr(AGENT_PK);
        token = new MockToken();
        acc = new Reserve(DOMAIN, address(token), address(0), address(new Poseidon2Goldilocks()), 1 hours, 2 days);
        vd = new ValidityDispute(address(acc), address(new SP1Verifier()), single, batch, ACCEPT, WINDOW, SLOT, BOND);
        acc.setDispute(address(vd));
        vm.deal(principal, 100 ether);
        vm.deal(challenger, 10 ether);
        token.mint(principal, 1e15);
        token.mint(Statement.PAYEE, 1);
        vm.prank(principal);
        token.approve(address(acc), type(uint256).max);
    }

    function _challenged(bytes32 com) internal returns (uint256 r, Settlement memory s) {
        vm.prank(principal);
        r = acc.register{value: AGENT_BOND}(TermsOf.make(agent, 1_000_000, 1_000, 86_400, Reserve.Funding.Deposit, 100_000_000, com, _lanes(1), uint64(block.timestamp) + 30 days));
        uint64[] memory e = Statement.elems();
        bytes32 eh = keccak256(abi.encodePacked(e));
        bytes32 h = acc.signedDigest(r, Statement.PAYEE, Statement.AMOUNT, digest, Statement.TIME, eh);
        (uint8 v, bytes32 rr, bytes32 ss) = vm.sign(AGENT_PK, h);
        acc.settleLogged(r, Statement.PAYEE, Statement.AMOUNT, digest, Statement.TIME, e, abi.encodePacked(rr, ss, v));
        s = Settlement({
            elems: eh, amount: Statement.AMOUNT, payee: Statement.PAYEE, time: Statement.TIME, epoch: 0
        });
        vm.prank(challenger);
        vd.open{value: BOND}(r, digest, s);
    }

    function _batch(uint256 k)
        internal
        returns (uint256[] memory ids, uint64[] memory ds, Settlement[] memory ss)
    {
        ids = new uint256[](k);
        ds = new uint64[](k);
        ss = new Settlement[](k);
        for (uint256 i = 0; i < k; ++i) {
            (ids[i], ss[i]) = _challenged(_lanes(5));
            ds[i] = digest;
        }
    }

    function testBatchProofsCarryEveryPaymentsValues() public view {
        for (uint256 k = 1; k <= 4; k *= 2) {
            bytes memory got = vm.parseBytes(_field(_batchFile(k), "public_values"));
            assertEq(got.length, 8 + 8 * VALUES * k);
            for (uint256 i = 0; i < k; ++i) {
                for (uint256 b = 0; b < 8 * VALUES; ++b) assertEq(got[8 + 8 * VALUES * i + b], publicValues[8 + b]);
            }
        }
    }

    function testBatchOfOneCommitsWhatTheSingleProgramCommits() public view {
        assertEq(vm.parseBytes(_field(_batchFile(1), "public_values")), vm.parseBytes(_field(SINGLE, "public_values")));
    }

    function testOneProofAnswersFourChallenges() public {
        (uint256[] memory ids, uint64[] memory ds, Settlement[] memory ss) = _batch(4);
        vd.answerBatch(ids, ds, ss, _proof(4));
        for (uint256 i = 0; i < 4; ++i) {
            assertEq(uint256(vd.challengeOf(ids[i], ds[i]).status), uint256(ValidityDispute.Status.Answered));
        }
        assertEq(vd.credit(agent), 4 * BOND);
    }

    function testOneProofAnswersTwoChallenges() public {
        (uint256[] memory ids, uint64[] memory ds, Settlement[] memory ss) = _batch(2);
        vd.answerBatch(ids, ds, ss, _proof(2));
        assertEq(vd.credit(agent), 2 * BOND);
    }

    function testBatchOfOneAnswersOneChallenge() public {
        (uint256[] memory ids, uint64[] memory ds, Settlement[] memory ss) = _batch(1);
        vd.answerBatch(ids, ds, ss, _proof(1));
        assertEq(vd.credit(agent), BOND);
    }

    function testProofOfFourCannotAnswerThree() public {
        (uint256[] memory ids, uint64[] memory ds, Settlement[] memory ss) = _batch(3);
        vm.expectRevert(Verifier.ProofInvalid.selector);
        vd.answerBatch(ids, ds, ss, _proof(4));
    }

    function testProofCannotAnswerASettlementOfAnotherStatement() public {
        (uint256[] memory ids, uint64[] memory ds, Settlement[] memory ss) = _batch(4);
        (ids[3], ss[3]) = _challenged(bytes32(uint256(_lanes(5)) ^ 1));
        vm.expectRevert(Verifier.ProofInvalid.selector);
        vd.answerBatch(ids, ds, ss, _proof(4));
    }

    function testSingleProofIsNotABatchProof() public {
        (uint256[] memory ids, uint64[] memory ds, Settlement[] memory ss) = _batch(1);
        vm.expectRevert(Verifier.ProofInvalid.selector);
        vd.answerBatch(ids, ds, ss, vm.parseBytes(_field(SINGLE, "proof")));
    }
}
