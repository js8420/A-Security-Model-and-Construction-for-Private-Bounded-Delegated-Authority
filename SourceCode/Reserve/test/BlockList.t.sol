// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {Reserve} from "../src/Reserve.sol";
import {Poseidon2Goldilocks} from "../src/Poseidon2Goldilocks.sol";
import {TermsOf} from "./TermsOf.sol";
import {Statement} from "./Statement.sol";
import {BlockListToken} from "./MockToken.sol";

interface IPermit2Approve {
    function approve(address token, address spender, uint160 amount, uint48 expiration) external;
}

/// A token whose issuer can block an address, against the real Permit2: once
/// the reserve is blocked, a Permit2 payment, which moves from the principal
/// to the payee and not through the reserve, is refused by the reserve.
contract BlockListTest is Test {
    bytes32 constant OPENING = keccak256("hidden fields");
    bytes32 constant COM = bytes32(uint256(11));
    bytes32 constant ROOT0 = bytes32(uint256(21));
    uint256 constant AGENT_PK = 0xA6E47;

    BlockListToken token;
    address permit2;
    Reserve acc;
    address principal = address(0xA11CE);
    address payee = address(0xBEEF);
    address agent;
    uint256 id;

    function setUp() public {
        agent = vm.addr(AGENT_PK);
        token = new BlockListToken();
        bytes memory code = vm.getCode("lib/permit2/out/Permit2.sol/Permit2.json");
        address a;
        assembly {
            a := create(0, add(code, 32), mload(code))
        }
        permit2 = a;
        acc = new Reserve(8453, address(token), permit2, address(new Poseidon2Goldilocks()), 1 hours, 2 days);
        token.mint(principal, 1e15);
        token.mint(payee, 1);
        vm.startPrank(principal);
        token.approve(permit2, type(uint256).max);
        IPermit2Approve(permit2).approve(address(token), address(acc), type(uint160).max, type(uint48).max);
        id = acc.register(TermsOf.make(agent, 1_000_000, 1_000, 86_400, Reserve.Funding.Permit2, 0, COM, ROOT0, uint64(block.timestamp) + 30 days));
        vm.stopPrank();
        token.mint(agent, TermsOf.BOND);
        vm.startPrank(agent);
        token.approve(address(acc), type(uint256).max);
        acc.accept(id);
        vm.stopPrank();
    }

    function _settle(uint64 digest) internal {
        uint64[] memory e = new uint64[](3);
        e[0] = digest;
        e[1] = digest + 1;
        e[2] = digest + 2;
        uint64 t = uint64(block.timestamp);
        bytes32 h = acc.signedDigest(id, payee, Statement.UNIT, digest, t, keccak256(abi.encodePacked(e)), OPENING);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(AGENT_PK, h);
        acc.settleLogged(id, payee, Statement.UNIT, digest, t, e, OPENING, abi.encodePacked(r, s, v));
    }

    function testBlockedReserveRefusesPermit2Payments() public {
        _settle(1);
        assertEq(token.balanceOf(payee), 1 + Statement.UNIT);
        token.blacklist(address(acc));
        vm.expectRevert(Reserve.ReserveBlocked.selector);
        this.settleAgain(2);
        assertEq(token.balanceOf(payee), 1 + Statement.UNIT);
    }

    /// A principal the issuer blocks cannot keep the agent's bond in the
    /// reserve: the close credits the deposit left rather than sending it, so
    /// it does not revert, and the agent withdraws its bond.
    function testBlockedPrincipalCannotHoldTheAgentsBond() public {
        vm.startPrank(principal);
        token.approve(address(acc), type(uint256).max);
        uint256 d = acc.register(TermsOf.make(agent, 1_000_000, 1_000, 86_400, Reserve.Funding.Deposit, 100_000_000, COM, ROOT0, uint64(block.timestamp) + 1 days));
        vm.stopPrank();
        token.mint(agent, TermsOf.BOND);
        vm.prank(agent);
        acc.accept(d);
        token.blacklist(principal);
        vm.warp(block.timestamp + 1 days + 2 days + 1);
        acc.close(d);
        assertEq(acc.tokenCredit(principal), 100_000_000);
        uint256 before = token.balanceOf(agent);
        vm.prank(agent);
        acc.withdrawToken();
        assertEq(token.balanceOf(agent), before + TermsOf.BOND);
        vm.prank(principal);
        vm.expectRevert();
        acc.withdrawToken();
    }

    function settleAgain(uint64 digest) external {
        _settle(digest);
    }
}
