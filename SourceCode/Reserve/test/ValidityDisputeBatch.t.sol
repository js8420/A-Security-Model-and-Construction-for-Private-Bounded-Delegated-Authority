// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {Reserve} from "../src/Reserve.sol";
import {ValidityDispute} from "../src/ValidityDispute.sol";
import {SP1Verifier} from "../src/sp1/v6.1.0/SP1VerifierGroth16.sol";
import {Verifier} from "../src/sp1/v6.1.0/Groth16Verifier.sol";
import {MockToken} from "./MockToken.sol";

/// Batch answers checked with the real Groth16 proofs Pete made of the batch
/// program over one, two and four payment proofs. Each payment proof is of the
/// same statement, so k delegations are registered with that statement's
/// commitment and root and each settles its digest once.
contract ValidityDisputeBatchTest is Test {
    string constant DIR = "../../WorkingHistory/groth16_batch_20261012/";
    string constant SINGLE = "../../WorkingHistory/groth16_keccak_20261011/out_8272496/onchain.txt";
    uint64 constant DOMAIN = 8453;
    uint256 constant AGENT_PK = 0xA6E47;
    uint256 constant AGENT_BOND = 1 ether;
    uint256 constant BOND = 0.01 ether;
    uint64 constant WINDOW = 1 days;
    uint64 constant SLOT = 2 hours;

    MockToken token;
    Reserve acc;
    ValidityDispute vd;
    address principal = address(0xA11CE);
    address payee = address(0xBEEF);
    address challenger = address(0xC14);
    address agent;
    bytes pv;
    uint64 digest;

    function _field(string memory file, string memory key) internal view returns (string memory) {
        string[] memory lines = vm.split(vm.readFile(file), "\n");
        for (uint256 i; i < lines.length; ++i) {
            string[] memory kv = vm.split(vm.replace(lines[i], "\r", ""), " ");
            if (kv.length == 2 && keccak256(bytes(kv[0])) == keccak256(bytes(key))) return kv[1];
        }
        revert(string.concat("no ", key, " in ", file));
    }

    function _file(uint256 k) internal pure returns (string memory) {
        if (k == 1) return string.concat(DIR, "out_8272597/onchain.txt");
        if (k == 2) return string.concat(DIR, "out_8272599/onchain.txt");
        return string.concat(DIR, "out_8272601/onchain.txt");
    }

    function _proof(uint256 k) internal view returns (bytes memory) {
        return vm.parseBytes(_field(_file(k), "proof"));
    }

    function _pv(uint256 i) internal view returns (uint64 x) {
        for (uint64 b = 0; b < 8; ++b) x |= uint64(uint8(pv[8 * (i + 1) + b])) << (8 * b);
    }

    function _lanes(uint256 first) internal view returns (bytes32) {
        uint256 w;
        for (uint256 j = 0; j < 4; ++j) w |= uint256(_pv(first + j)) << (64 * j);
        return bytes32(w);
    }

    function setUp() public {
        pv = vm.parseBytes(_field(_file(4), "public_values"));
        require(pv.length == 8 + 8 * 40, "four proofs' values");
        require(_pv(9) == DOMAIN, "proof is for another domain");
        digest = _pv(0);
        bytes32 single = vm.parseBytes32(_field(SINGLE, "vkey"));
        bytes32 batch = vm.parseBytes32(_field(_file(4), "vkey"));
        agent = vm.addr(AGENT_PK);
        token = new MockToken();
        acc = new Reserve(DOMAIN, address(token), address(0));
        vd = new ValidityDispute(address(acc), address(new SP1Verifier()), single, batch, WINDOW, SLOT, BOND);
        acc.setArbiters(address(vd), address(0));
        vm.deal(principal, 100 ether);
        vm.deal(challenger, 10 ether);
        token.mint(principal, 1e15);
        token.mint(payee, 1);
        vm.prank(principal);
        token.approve(address(acc), type(uint256).max);
    }

    function _challenged(bytes32 com) internal returns (uint256 r) {
        vm.prank(principal);
        r = acc.register{value: AGENT_BOND}(
            agent, 1_000_000, 1_000, 86_400, keccak256(abi.encodePacked(uint64(7), uint64(11))),
            Reserve.Funding.Deposit, 100_000_000, com, _lanes(1)
        );
        bytes32 c = keccak256(abi.encodePacked("settlement", r, digest));
        uint64[] memory e = new uint64[](3);
        e[0] = 1; e[1] = 2; e[2] = 3;
        bytes32 h = acc.signedDigest(r, payee, 1000, digest, keccak256(abi.encodePacked(e)), c);
        (uint8 v, bytes32 rr, bytes32 s) = vm.sign(AGENT_PK, h);
        acc.settleLogged(r, payee, 1000, digest, e, c, abi.encodePacked(rr, s, v));
        vm.prank(challenger);
        vd.open{value: BOND}(r, digest, c, 0);
    }

    function _batch(uint256 k) internal returns (uint256[] memory ids, uint64[] memory ds) {
        ids = new uint256[](k);
        ds = new uint64[](k);
        for (uint256 i = 0; i < k; ++i) {
            ids[i] = _challenged(_lanes(5));
            ds[i] = digest;
        }
    }

    function testBatchProofsCarryEveryPaymentsValues() public view {
        for (uint256 k = 1; k <= 4; k *= 2) {
            bytes memory got = vm.parseBytes(_field(_file(k), "public_values"));
            assertEq(got.length, 8 + 80 * k);
            for (uint256 i = 0; i < k; ++i) {
                for (uint256 b = 0; b < 80; ++b) assertEq(got[8 + 80 * i + b], pv[8 + b]);
            }
        }
    }

    function testBatchOfOneCommitsWhatTheSingleProgramCommits() public view {
        assertEq(vm.parseBytes(_field(_file(1), "public_values")), vm.parseBytes(_field(SINGLE, "public_values")));
    }

    function testOneProofAnswersFourChallenges() public {
        (uint256[] memory ids, uint64[] memory ds) = _batch(4);
        vd.answerBatch(ids, ds, _proof(4));
        for (uint256 i = 0; i < 4; ++i) {
            assertEq(uint256(vd.challengeOf(ids[i], ds[i]).status), uint256(ValidityDispute.Status.Answered));
        }
        assertEq(vd.credit(agent), 4 * BOND);
    }

    function testOneProofAnswersTwoChallenges() public {
        (uint256[] memory ids, uint64[] memory ds) = _batch(2);
        vd.answerBatch(ids, ds, _proof(2));
        assertEq(vd.credit(agent), 2 * BOND);
    }

    function testBatchOfOneAnswersOneChallenge() public {
        (uint256[] memory ids, uint64[] memory ds) = _batch(1);
        vd.answerBatch(ids, ds, _proof(1));
        assertEq(vd.credit(agent), BOND);
    }

    function testProofOfFourCannotAnswerThree() public {
        (uint256[] memory ids, uint64[] memory ds) = _batch(3);
        vm.expectRevert(Verifier.ProofInvalid.selector);
        vd.answerBatch(ids, ds, _proof(4));
    }

    function testProofCannotAnswerASettlementOfAnotherStatement() public {
        (uint256[] memory ids, uint64[] memory ds) = _batch(4);
        ids[3] = _challenged(bytes32(uint256(_lanes(5)) ^ 1));
        vm.expectRevert(Verifier.ProofInvalid.selector);
        vd.answerBatch(ids, ds, _proof(4));
    }

    function testSingleProofIsNotABatchProof() public {
        (uint256[] memory ids, uint64[] memory ds) = _batch(1);
        vm.expectRevert(Verifier.ProofInvalid.selector);
        vd.answerBatch(ids, ds, vm.parseBytes(_field(SINGLE, "proof")));
    }
}
