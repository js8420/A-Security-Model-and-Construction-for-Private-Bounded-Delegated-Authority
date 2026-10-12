// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {Reserve} from "../src/Reserve.sol";
import {ValidityDispute} from "../src/ValidityDispute.sol";
import {ISP1Verifier} from "../src/sp1/ISP1Verifier.sol";
import {MockToken} from "./MockToken.sol";

/// Accepts a "proof" that is exactly the public values the contract built,
/// under the expected key, so these tests check what the contract asks the
/// verifier, not the pairing. The pairing is tested on Pete's real proofs.
contract EchoVerifier is ISP1Verifier {
    bytes32 public immutable single;
    bytes32 public immutable batch;

    constructor(bytes32 single_, bytes32 batch_) {
        single = single_;
        batch = batch_;
    }

    function verifyProof(bytes32 vk, bytes calldata pv, bytes calldata proof) external view {
        require(vk == single || vk == batch, "key");
        require(keccak256(pv) == keccak256(proof), "values");
    }
}

contract RefusesEther {
    function openOn(ValidityDispute vd, uint256 id, uint64 digest, bytes32 c) external payable {
        vd.open{value: msg.value}(id, digest, c, 0);
    }
}

contract ValidityDisputeScaleTest is Test {
    uint64 constant DOMAIN = 8453;
    uint256 constant AGENT_PK = 0xA6E47;
    uint256 constant OTHER_PK = 0xB0B;
    uint256 constant AGENT_BOND = 1 ether;
    uint256 constant BOND = 0.01 ether;
    uint64 constant WINDOW = 1 days;
    uint64 constant SLOT = 2 hours;
    bytes32 constant SINGLE = bytes32(uint256(1));
    bytes32 constant BATCH = bytes32(uint256(2));

    MockToken token;
    Reserve acc;
    ValidityDispute vd;
    address principal = address(0xA11CE);
    address payee = address(0xBEEF);
    address challenger = address(0xC14);

    function setUp() public {
        token = new MockToken();
        acc = new Reserve(DOMAIN, address(token), address(0));
        vd = new ValidityDispute(address(acc), address(new EchoVerifier(SINGLE, BATCH)), SINGLE, BATCH, WINDOW, SLOT, BOND);
        acc.setArbiters(address(vd), address(0));
        vm.deal(principal, 100 ether);
        vm.deal(challenger, 100 ether);
        token.mint(principal, 1e15);
        token.mint(payee, 1);
        vm.prank(principal);
        token.approve(address(acc), type(uint256).max);
    }

    function _register(uint256 pk, uint256 tag) internal returns (uint256 r) {
        vm.prank(principal);
        r = acc.register{value: AGENT_BOND}(
            vm.addr(pk), 1_000_000, 1_000, 86_400, keccak256(abi.encodePacked(uint64(7), uint64(11))),
            Reserve.Funding.Deposit, 100_000_000, bytes32(tag), bytes32(tag + 1)
        );
    }

    function _settle(uint256 pk, uint256 r, uint64 d) internal returns (bytes32 c) {
        c = keccak256(abi.encodePacked("settlement", r, d));
        uint64[] memory e = new uint64[](1);
        e[0] = d;
        bytes32 h = acc.signedDigest(r, payee, 1, d, keccak256(abi.encodePacked(e)), c);
        (uint8 v, bytes32 rr, bytes32 s) = vm.sign(pk, h);
        acc.settleLogged(r, payee, 1, d, e, c, abi.encodePacked(rr, s, v));
    }

    /// k settlements of one delegation, each challenged.
    function _openMany(uint256 pk, uint256 r, uint256 k) internal returns (uint256[] memory ids, uint64[] memory ds) {
        ids = new uint256[](k);
        ds = new uint64[](k);
        for (uint64 i = 0; i < k; ++i) {
            ids[i] = r;
            ds[i] = 1000 + i;
            bytes32 c = _settle(pk, r, ds[i]);
            vm.prank(challenger);
            vd.open{value: BOND}(r, ds[i], c, 0);
        }
    }

    function _epochs(uint256 k) internal pure returns (uint64[] memory e) {
        e = new uint64[](k);
    }

    function testDeadlinesOfOneAgentAreSpacedBySlot() public {
        uint256 r = _register(AGENT_PK, 10);
        (uint256[] memory ids, uint64[] memory ds) = _openMany(AGENT_PK, r, 5);
        uint64 first = uint64(block.timestamp) + WINDOW;
        for (uint64 i = 0; i < 5; ++i) {
            assertEq(vd.challengeOf(ids[i], ds[i]).deadline, first + i * SLOT);
        }
    }

    function testOtherAgentsAreNotQueued() public {
        uint256 a = _register(AGENT_PK, 10);
        uint256 b = _register(OTHER_PK, 20);
        _openMany(AGENT_PK, a, 3);
        (uint256[] memory ids, uint64[] memory ds) = _openMany(OTHER_PK, b, 1);
        assertEq(vd.challengeOf(ids[0], ds[0]).deadline, uint64(block.timestamp) + WINDOW);
    }

    function testQueueDrainsOverTime() public {
        uint256 r = _register(AGENT_PK, 10);
        _openMany(AGENT_PK, r, 3);
        vm.warp(block.timestamp + 10 days);
        bytes32 c = _settle(AGENT_PK, r, 77);
        vm.prank(challenger);
        vd.open{value: BOND}(r, 77, c, 0);
        assertEq(vd.challengeOf(r, 77).deadline, uint64(block.timestamp) + WINDOW);
    }

    function testBatchValuesAreTheSingleValuesInOrder() public {
        uint256 a = _register(AGENT_PK, 10);
        uint256 b = _register(OTHER_PK, 20);
        uint256[] memory ids = new uint256[](2);
        uint64[] memory ds = new uint64[](2);
        ids[0] = a; ds[0] = 5;
        ids[1] = b; ds[1] = 6;
        bytes memory pv = vd.batchPublicValues(ids, ds, _epochs(2));
        bytes memory one = vd.publicValues(a, 5, 0);
        bytes memory two = vd.publicValues(b, 6, 0);
        assertEq(pv.length, 8 + 160);
        assertEq(uint8(pv[0]), 20);
        for (uint256 i = 0; i < 80; ++i) {
            assertEq(pv[8 + i], one[8 + i]);
            assertEq(pv[88 + i], two[8 + i]);
        }
    }

    function testBatchAnswersEveryChallengeAndCreditsEachAgent() public {
        uint256 a = _register(AGENT_PK, 10);
        uint256 b = _register(OTHER_PK, 20);
        (uint256[] memory ia, uint64[] memory da) = _openMany(AGENT_PK, a, 3);
        (uint256[] memory ib, uint64[] memory db) = _openMany(OTHER_PK, b, 2);
        uint256[] memory ids = new uint256[](5);
        uint64[] memory ds = new uint64[](5);
        for (uint256 i = 0; i < 3; ++i) (ids[i], ds[i]) = (ia[i], da[i]);
        for (uint256 i = 0; i < 2; ++i) (ids[3 + i], ds[3 + i]) = (ib[i], db[i]);
        vd.answerBatch(ids, ds, vd.batchPublicValues(ids, ds, _epochs(5)));
        for (uint256 i = 0; i < 5; ++i) {
            assertEq(uint256(vd.challengeOf(ids[i], ds[i]).status), uint256(ValidityDispute.Status.Answered));
        }
        assertEq(vd.credit(vm.addr(AGENT_PK)), 3 * BOND);
        assertEq(vd.credit(vm.addr(OTHER_PK)), 2 * BOND);
    }

    function testBatchWithWrongValuesFails() public {
        uint256 r = _register(AGENT_PK, 10);
        (uint256[] memory ids, uint64[] memory ds) = _openMany(AGENT_PK, r, 2);
        bytes memory pv = vd.batchPublicValues(ids, ds, _epochs(2));
        pv[pv.length - 1] ^= 0x01;
        vm.expectRevert(bytes("values"));
        vd.answerBatch(ids, ds, pv);
    }

    function testBatchNamingASettlementTwiceFails() public {
        uint256 r = _register(AGENT_PK, 10);
        (uint256[] memory one, uint64[] memory d1) = _openMany(AGENT_PK, r, 1);
        uint256[] memory ids = new uint256[](2);
        uint64[] memory ds = new uint64[](2);
        (ids[0], ds[0]) = (one[0], d1[0]);
        (ids[1], ds[1]) = (one[0], d1[0]);
        bytes memory pv = vd.batchPublicValues(ids, ds, _epochs(2));
        vm.expectRevert(ValidityDispute.NotOpen.selector);
        vd.answerBatch(ids, ds, pv);
    }

    function testBatchWithAnUnchallengedSettlementFails() public {
        uint256 r = _register(AGENT_PK, 10);
        (uint256[] memory one, uint64[] memory d1) = _openMany(AGENT_PK, r, 1);
        _settle(AGENT_PK, r, 999);
        uint256[] memory ids = new uint256[](2);
        uint64[] memory ds = new uint64[](2);
        (ids[0], ds[0]) = (one[0], d1[0]);
        (ids[1], ds[1]) = (r, 999);
        vm.expectRevert(ValidityDispute.NotOpen.selector);
        vd.answerBatch(ids, ds, "");
    }

    function testBatchAfterAnyDeadlineFails() public {
        uint256 r = _register(AGENT_PK, 10);
        (uint256[] memory ids, uint64[] memory ds) = _openMany(AGENT_PK, r, 2);
        vm.warp(vd.challengeOf(ids[0], ds[0]).deadline + 1);
        bytes memory pv = vd.batchPublicValues(ids, ds, _epochs(2));
        vm.expectRevert(ValidityDispute.TooLate.selector);
        vd.answerBatch(ids, ds, pv);
    }

    function testEmptyAndUnevenBatchesFail() public {
        uint256[] memory none = new uint256[](0);
        uint64[] memory noneD = new uint64[](0);
        vm.expectRevert(ValidityDispute.EmptyBatch.selector);
        vd.answerBatch(none, noneD, "");
        uint256 r = _register(AGENT_PK, 10);
        (uint256[] memory ids, ) = _openMany(AGENT_PK, r, 1);
        vm.expectRevert(ValidityDispute.LengthMismatch.selector);
        vd.answerBatch(ids, noneD, "");
    }

    function testSingleAnswerUsesTheSingleKey() public {
        uint256 r = _register(AGENT_PK, 10);
        (uint256[] memory ids, uint64[] memory ds) = _openMany(AGENT_PK, r, 1);
        vd.answer(ids[0], ds[0], vd.publicValues(ids[0], ds[0], 0));
        assertEq(uint256(vd.challengeOf(ids[0], ds[0]).status), uint256(ValidityDispute.Status.Answered));
    }

    function testAnsweredSettlementCannotBeChallengedAgain() public {
        uint256 r = _register(AGENT_PK, 10);
        (uint256[] memory ids, uint64[] memory ds) = _openMany(AGENT_PK, r, 1);
        vd.answer(ids[0], ds[0], vd.publicValues(ids[0], ds[0], 0));
        bytes32 c = keccak256(abi.encodePacked("settlement", r, ds[0]));
        vm.prank(challenger);
        vm.expectRevert(ValidityDispute.AlreadyChallenged.selector);
        vd.open{value: BOND}(r, ds[0], c, 0);
    }

    function testChallengerThatRefusesEtherCannotBlockForfeit() public {
        uint256 r = _register(AGENT_PK, 10);
        bytes32 c = _settle(AGENT_PK, r, 42);
        RefusesEther bad = new RefusesEther();
        bad.openOn{value: BOND}(vd, r, 42, c);
        vm.warp(block.timestamp + WINDOW + 1);
        uint256 before = principal.balance;
        vd.expire(r, 42);
        assertEq(principal.balance, before + AGENT_BOND);
        assertEq(vd.credit(address(bad)), BOND);
    }

    function testWithdrawWithNoCreditFails() public {
        vm.expectRevert(ValidityDispute.NothingToWithdraw.selector);
        vd.withdraw();
    }
}
