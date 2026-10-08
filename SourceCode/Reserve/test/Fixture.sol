// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {Reserve} from "../src/Reserve.sol";
import {PreventiveReserve} from "../src/PreventiveReserve.sol";
import {MockToken} from "./MockToken.sol";

interface IPermit2Approve {
    function approve(address token, address spender, uint160 amount, uint48 expiration) external;
}

/// Everything a settlement test needs, deployed the same way every time.
/// Permit2 is the real contract, built by its own pinned toolchain in
/// lib/permit2 and deployed here from that artifact.
contract Fixture is Test {
    uint64 constant DOMAIN = 8453;
    uint64 constant CAP = 1_000_000;
    uint64 constant BUDGET = 100_000_000;
    uint64 constant VELOCITY = 1_000;
    uint64 constant WINDOW = 86_400;
    uint256 constant AGENT_PK = 0xA6E47;
    /// D.com and the first revocation root, four Goldilocks lanes each.
    bytes32 constant COM = bytes32(uint256(11) | uint256(12) << 64 | uint256(13) << 128 | uint256(14) << 192);
    bytes32 constant ROOT0 = bytes32(uint256(21) | uint256(22) << 64 | uint256(23) << 128 | uint256(24) << 192);

    MockToken token;
    address permit2;
    Reserve acc;
    PreventiveReserve prev;
    address principal = address(0xA11CE);
    address payee = address(0xBEEF);
    address agent;

    function _deployPermit2() internal returns (address a) {
        bytes memory code = vm.getCode("lib/permit2/out/Permit2.sol/Permit2.json");
        assembly {
            a := create(0, add(code, 32), mload(code))
        }
        require(a != address(0), "permit2");
    }

    function _base() internal {
        agent = vm.addr(AGENT_PK);
        token = new MockToken();
        permit2 = _deployPermit2();
        acc = new Reserve(DOMAIN, address(token), permit2);
        prev = new PreventiveReserve(address(token));
        vm.deal(principal, 100 ether);
        vm.deal(agent, 1 ether);
        token.mint(principal, 1e15);
        // payee already holds a balance, as a merchant does, so a payment
        // writes a non-zero slot rather than creating one
        token.mint(payee, 1);
        vm.startPrank(principal);
        token.approve(address(acc), type(uint256).max);
        token.approve(address(prev), type(uint256).max);
        token.approve(permit2, type(uint256).max);
        IPermit2Approve(permit2).approve(address(token), address(acc), type(uint160).max, type(uint48).max);
        vm.stopPrank();
    }

    function _reg(Reserve.Funding f) internal returns (uint256 id) {
        vm.prank(principal);
        id = acc.register{value: 1 ether}(
            agent, CAP, VELOCITY, WINDOW, keccak256(abi.encodePacked(uint64(7), uint64(11))),
            f, f == Reserve.Funding.Deposit ? BUDGET : 0, COM, ROOT0
        );
    }

    function _elems(uint256 cover, uint256 salt) internal pure returns (uint64[] memory e) {
        e = new uint64[](cover * 3);
        for (uint256 i = 0; i < e.length; ++i) {
            e[i] = uint64(0x9E3779B97F4A7C15 ^ ((i + salt * 7919) * 0x100000001B3));
        }
    }

    function _sign(uint256 id, uint64 amount, uint64 digest, uint64[] memory elems, bytes32 c)
        internal
        view
        returns (bytes memory)
    {
        bytes32 h = acc.signedDigest(id, payee, amount, digest, keccak256(abi.encodePacked(elems)), c);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(AGENT_PK, h);
        return abi.encodePacked(r, s, v);
    }

    /// Stands for the hash of a proof's blob list.
    function _commit(uint256 id, uint64 digest) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("blobs", id, digest));
    }

    function _settleWith(uint256 id, uint64 digest, bytes32 c) internal {
        uint64[] memory e = _elems(64, digest);
        bytes memory sg = _sign(id, 1000, digest, e, c);
        acc.settleLogged(id, payee, 1000, digest, e, c, sg);
    }

    /// Gas of one settlement call and nothing else: the signature is made
    /// before the meter starts.
    function _settle(uint256 id, uint64 digest, uint64[] memory e, bool logged)
        internal
        returns (uint256 used)
    {
        bytes32 c = _commit(id, digest);
        bytes memory sg = _sign(id, 1000, digest, e, c);
        uint256 g = gasleft();
        if (logged) acc.settleLogged(id, payee, 1000, digest, e, c, sg);
        else acc.settle(id, payee, 1000, digest, e, c, sg);
        used = g - gasleft();
    }
}
