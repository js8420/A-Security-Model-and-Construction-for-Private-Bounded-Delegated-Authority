// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Script, console} from "forge-std/Script.sol";
import {Reserve} from "../src/Reserve.sol";
import {ValidityDispute} from "../src/ValidityDispute.sol";
import {SP1Verifier} from "../src/sp1/v6.1.0/SP1VerifierGroth16.sol";
import {MockToken} from "../test/MockToken.sol";

/// The validity dispute as real transactions on a local node, so every gas
/// figure is a receipt's gasUsed: intrinsic cost, calldata (with the EIP-7623
/// floor) and execution with cold accounts and storage, as on chain.
contract ValidityDisputeOnChain is Script {
    string constant RESULT = "../../WorkingHistory/groth16_20261009/onchain.txt";
    uint64 constant DOMAIN = 8453;
    uint256 constant AGENT_PK = 0xA6E47;

    bytes32 vkey;
    bytes publicValues;
    bytes proof;
    MockToken token;
    Reserve acc;
    SP1Verifier sp1;
    ValidityDispute vd;
    uint256 id;
    uint64 digest;
    bytes32 commitment;

    function run() external {
        vkey = vm.parseBytes32(_field("vkey"));
        publicValues = vm.parseBytes(_field("public_values"));
        proof = vm.parseBytes(_field("proof"));
        digest = _pv(0);
        uint256 pk = vm.envUint("LOCAL_PK");

        vm.startBroadcast(pk);
        _deploy(vm.addr(pk), 1 days);
        _settle();
        (bool ok, ) = address(sp1).call(abi.encodeCall(SP1Verifier.verifyProof, (vkey, publicValues, proof)));
        require(ok, "verifyProof");
        vd.open{value: 0.01 ether}(id, digest, commitment, 0);
        vd.answer(id, digest, proof);
        console.log("dispute answered", uint256(vd.challengeOf(id, digest).status) == 2);

        // The unanswered case, on a second reserve whose answer window is
        // zero, so the next block is already past the deadline.
        _deploy(vm.addr(pk), 0);
        _settle();
        vd.open{value: 0.01 ether}(id, digest, commitment, 0);
        vm.warp(block.timestamp + 1);
        // Gas is given because estimating at the latest block, the open's own,
        // would see the deadline not yet passed.
        vd.expire{gas: 200_000}(id, digest);
        vm.stopBroadcast();
        console.log("dispute expired", uint256(vd.challengeOf(id, digest).status) == 3);
    }

    function _deploy(address me, uint64 window) internal {
        token = new MockToken();
        acc = new Reserve(DOMAIN, address(token), address(0));
        if (address(sp1) == address(0)) sp1 = new SP1Verifier();
        vd = new ValidityDispute(address(acc), address(sp1), vkey, window, 0.01 ether);
        acc.setArbiters(address(vd), address(0));
        token.mint(me, 1e15);
        token.mint(address(0xBEEF), 1);
        token.approve(address(acc), type(uint256).max);
        id = acc.register{value: 1 ether}(
            vm.addr(AGENT_PK), 1_000_000, 1_000, 86_400, keccak256(abi.encodePacked(uint64(7), uint64(11))),
            Reserve.Funding.Deposit, 100_000_000, _lanes(5), _lanes(1)
        );
        commitment = keccak256(abi.encodePacked("settlement", id, digest));
    }

    function _settle() internal {
        uint64[] memory e = new uint64[](3);
        e[0] = 1; e[1] = 2; e[2] = 3;
        bytes32 h = acc.signedDigest(id, address(0xBEEF), 1000, digest, keccak256(abi.encodePacked(e)), commitment);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(AGENT_PK, h);
        acc.settleLogged(id, address(0xBEEF), 1000, digest, e, commitment, abi.encodePacked(r, s, v));
    }

    /// Reads the whole file at once: a line cursor is shared by every test
    /// running in parallel and gave one of them another's line.
    function _field(string memory key) internal view returns (string memory) {
        string[] memory lines = vm.split(vm.readFile(RESULT), "\n");
        for (uint256 i; i < lines.length; ++i) {
            string[] memory kv = vm.split(vm.replace(lines[i], "\r", ""), " ");
            if (kv.length == 2 && keccak256(bytes(kv[0])) == keccak256(bytes(key))) return kv[1];
        }
        revert(string.concat("no ", key, " in onchain.txt"));
    }

    function _pv(uint256 i) internal view returns (uint64 x) {
        for (uint64 b = 0; b < 8; ++b) x |= uint64(uint8(publicValues[8 * (i + 1) + b])) << (8 * b);
    }

    function _lanes(uint256 first) internal view returns (bytes32) {
        uint256 w;
        for (uint256 j = 0; j < 4; ++j) w |= uint256(_pv(first + j)) << (64 * j);
        return bytes32(w);
    }
}
