// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test, console} from "forge-std/Test.sol";
import {Reserve} from "../src/Reserve.sol";
import {Poseidon2Goldilocks} from "../src/Poseidon2Goldilocks.sol";
import {Statement} from "./Statement.sol";
import {TermsOf} from "./TermsOf.sol";
import {MockToken} from "./MockToken.sol";

interface IUsdc {
    function masterMinter() external view returns (address);
    function blacklister() external view returns (address);
    function configureMinter(address minter, uint256 allowance) external returns (bool);
    function mint(address to, uint256 amount) external returns (bool);
    function blacklist(address account) external;
    function approve(address spender, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

interface IPermit2Approve {
    function approve(address token, address spender, uint160 amount, uint48 expiration) external;
}

/// The reserve against USDC's own code on a fork of Base, beside the plain
/// token the other measurements use: the same calls, side by side, and what
/// the issuer's blacklist does to a reserve and to a payee. Runs when
/// L2_FORK names a Base endpoint, and is skipped otherwise.
contract UsdcForkGas is Test {
    address constant USDC = 0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913;
    address constant PERMIT2 = 0x000000000022D473030F116dDEE9F6B43aC78BA3;
    bytes32 constant OPENING = keccak256("hidden fields");
    bytes32 constant COM = bytes32(uint256(11) | uint256(12) << 64 | uint256(13) << 128 | uint256(14) << 192);
    bytes32 constant ROOT0 = bytes32(uint256(21) | uint256(22) << 64 | uint256(23) << 128 | uint256(24) << 192);
    uint256 constant AGENT_PK = 0xA6E47;
    uint64 constant BUDGET = 100_000_000;
    address principal = address(0xA11CE);
    address payee = address(0xBEEF);
    address agent;
    Poseidon2Goldilocks poseidon;

    function setUp() public {
        string memory rpc = vm.envOr("L2_FORK", string(""));
        if (bytes(rpc).length == 0) vm.skip(true);
        vm.createSelectFork(rpc);
        agent = vm.addr(AGENT_PK);
        poseidon = new Poseidon2Goldilocks();
        vm.deal(principal, 100 ether);
        vm.deal(agent, 100 ether);
        IUsdc u = IUsdc(USDC);
        vm.prank(u.masterMinter());
        u.configureMinter(address(this), type(uint256).max);
        u.mint(principal, 1e15);
        u.mint(payee, 1);
    }

    function _reserve(address token) internal returns (Reserve r) {
        r = new Reserve(8453, token, PERMIT2, address(poseidon), 1 hours, 2 days);
        vm.startPrank(principal);
        IUsdc(token).approve(address(r), type(uint256).max);
        IUsdc(token).approve(PERMIT2, type(uint256).max);
        IPermit2Approve(PERMIT2).approve(token, address(r), type(uint160).max, type(uint48).max);
        vm.stopPrank();
    }

    function _open(Reserve r, Reserve.Funding f) internal returns (uint256 id, uint256 used) {
        Reserve.Terms memory t = TermsOf.make(agent, 1_000_000, 1_000, 86_400, f, f == Reserve.Funding.Deposit ? BUDGET : 0, COM, ROOT0, uint64(block.timestamp) + 365 days);
        vm.prank(principal);
        uint256 g = gasleft();
        id = r.register(t);
        used = g - gasleft();
        address tk = address(r.token());
        if (tk == USDC) IUsdc(USDC).mint(agent, TermsOf.BOND);
        else MockToken(tk).mint(agent, TermsOf.BOND);
        vm.startPrank(agent);
        IUsdc(tk).approve(address(r), type(uint256).max);
        r.accept(id);
        vm.stopPrank();
    }

    function _elems(uint256 cover, uint256 salt) internal pure returns (uint64[] memory e) {
        e = new uint64[](cover * 3);
        for (uint256 i = 0; i < e.length; ++i) e[i] = uint64(0x9E3779B97F4A7C15 ^ ((i + salt * 7919) * 0x100000001B3));
    }

    function _settle(Reserve r, uint256 id, uint64 digest, uint64 cover) internal returns (uint256 used) {
        uint64[] memory e = _elems(cover, digest);
        uint64 a = cover * Statement.UNIT;
        uint64 t = uint64(block.timestamp);
        bytes32 h = r.signedDigest(id, payee, a, digest, t, keccak256(abi.encodePacked(e)), OPENING);
        (uint8 v, bytes32 rr, bytes32 s) = vm.sign(AGENT_PK, h);
        uint256 g = gasleft();
        r.settleLogged(id, payee, a, digest, t, e, OPENING, abi.encodePacked(rr, s, v));
        used = g - gasleft();
    }

    function _measure(address token) internal returns (uint256[4] memory g) {
        Reserve r = _reserve(token);
        uint256 a;
        uint256 b;
        (a, g[0]) = _open(r, Reserve.Funding.Deposit);
        (b, g[1]) = _open(r, Reserve.Funding.Permit2);
        _settle(r, a, 1, 64);
        g[2] = _settle(r, a, 2, 64);
        _settle(r, b, 1, 64);
        g[3] = _settle(r, b, 2, 64);
    }

    function testAgainstThePlainToken() public {
        MockToken m = new MockToken();
        m.mint(principal, 1e15);
        m.mint(payee, 1);
        uint256[4] memory plain = _measure(address(m));
        uint256[4] memory usdc = _measure(USDC);
        string[4] memory what = ["Open, deposit", "Open, permit2", "Settle logged, 64 units, deposit", "Settle logged, 64 units, permit2"];
        console.log("fork block", block.number);
        for (uint256 i = 0; i < 4; ++i) {
            console.log(what[i]);
            console.log("  plain token", plain[i]);
            console.log("  USDC", usdc[i]);
            console.log("  USDC minus plain", usdc[i] - plain[i]);
        }
    }

    /// The issuer blacklists the reserve: nothing it holds can move, so no
    /// settlement goes through, whatever its terms.
    function testBlacklistedReserveCannotPay() public {
        Reserve r = _reserve(USDC);
        (uint256 id,) = _open(r, Reserve.Funding.Deposit);
        IUsdc u = IUsdc(USDC);
        vm.prank(u.blacklister());
        u.blacklist(address(r));
        uint64[] memory e = _elems(1, 9);
        uint64 t = uint64(block.timestamp);
        bytes32 h = r.signedDigest(id, payee, Statement.UNIT, 9, t, keccak256(abi.encodePacked(e)), OPENING);
        (uint8 v, bytes32 rr, bytes32 s) = vm.sign(AGENT_PK, h);
        vm.expectRevert();
        r.settleLogged(id, payee, Statement.UNIT, 9, t, e, OPENING, abi.encodePacked(rr, s, v));
        console.log("a settlement through a blacklisted reserve reverts");
    }

    /// The bond is a credit in the token: a claim after the issuer has
    /// blacklisted the reserve still credits it to the principal, and only
    /// the withdrawal waits on the issuer, as the deposit's does.
    function testForfeitCreditsUnderABlacklistedReserve() public {
        Reserve r = _reserve(USDC);
        (uint256 id,) = _open(r, Reserve.Funding.Deposit);
        IUsdc u = IUsdc(USDC);
        vm.prank(u.blacklister());
        u.blacklist(address(r));
        r.claim(id, [Statement.SECRET0, Statement.SECRET1]);
        assertEq(r.tokenCredit(principal), TermsOf.BOND);
        vm.prank(principal);
        vm.expectRevert();
        r.withdrawToken();
        console.log("a claim against a blacklisted reserve credits the bond; its withdrawal reverts");
    }

    /// The issuer blacklists a payee: a settlement to it reverts, and the
    /// agent's other payments go through.
    function testBlacklistedPayeeIsRefused() public {
        Reserve r = _reserve(USDC);
        (uint256 id,) = _open(r, Reserve.Funding.Deposit);
        IUsdc u = IUsdc(USDC);
        vm.prank(u.blacklister());
        u.blacklist(payee);
        uint64[] memory e = _elems(1, 9);
        uint64 t = uint64(block.timestamp);
        bytes32 h = r.signedDigest(id, payee, Statement.UNIT, 9, t, keccak256(abi.encodePacked(e)), OPENING);
        (uint8 v, bytes32 rr, bytes32 s) = vm.sign(AGENT_PK, h);
        vm.expectRevert();
        r.settleLogged(id, payee, Statement.UNIT, 9, t, e, OPENING, abi.encodePacked(rr, s, v));
        console.log("a settlement to a blacklisted payee reverts");
    }
}
