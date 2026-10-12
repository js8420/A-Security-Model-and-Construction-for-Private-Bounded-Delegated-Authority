// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Script} from "forge-std/Script.sol";
import {Reserve} from "../src/Reserve.sol";
import {ValidityDispute} from "../src/ValidityDispute.sol";
import {SP1Verifier} from "../src/sp1/v6.1.0/SP1VerifierGroth16.sol";
import {MockToken} from "../test/MockToken.sol";

/// Batch answers as real transactions on a local node: one answerBatch for
/// one, two and four open challenges, each with Pete's Groth16 proof of the
/// batch program, so every gas figure is a receipt's gasUsed.
contract ValidityDisputeBatchOnChain is Script {
    string constant DIR = "../../WorkingHistory/groth16_batch_20261012/";
    uint64 constant DOMAIN = 8453;
    uint256 constant AGENT_PK = 0xA6E47;

    bytes pv;
    uint64 digest;
    MockToken token;
    Reserve acc;
    SP1Verifier sp1;
    ValidityDispute vd;

    function run() external {
        uint256 pk = vm.envUint("LOCAL_PK");
        address me = vm.addr(pk);
        pv = vm.parseBytes(_field(_file(4), "public_values"));
        digest = _pv(0);
        bytes32 batchKey = vm.parseBytes32(_field(_file(4), "vkey"));

        vm.startBroadcast(pk);
        sp1 = new SP1Verifier();
        token = new MockToken();
        acc = new Reserve(DOMAIN, address(token), address(0));
        vd = new ValidityDispute(address(acc), address(sp1), bytes32(0), batchKey, 1 days, 2 hours, 0.01 ether);
        acc.setArbiters(address(vd), address(0));
        token.mint(me, 1e15);
        token.mint(address(0xBEEF), 1);
        token.approve(address(acc), type(uint256).max);
        for (uint256 k = 1; k <= 4; k *= 2) {
            uint256[] memory ids = new uint256[](k);
            uint64[] memory ds = new uint64[](k);
            for (uint256 i = 0; i < k; ++i) {
                ids[i] = _challenged();
                ds[i] = digest;
            }
            vd.answerBatch(ids, ds, vm.parseBytes(_field(_file(k), "proof")));
        }
        vm.stopBroadcast();
    }

    function _challenged() internal returns (uint256 id) {
        id = acc.register{value: 0.1 ether}(
            vm.addr(AGENT_PK), 1_000_000, 1_000, 86_400, keccak256(abi.encodePacked(uint64(7), uint64(11))),
            Reserve.Funding.Deposit, 100_000_000, _lanes(5), _lanes(1)
        );
        bytes32 c = keccak256(abi.encodePacked("settlement", id, digest));
        uint64[] memory e = new uint64[](3);
        e[0] = 1; e[1] = 2; e[2] = 3;
        bytes32 h = acc.signedDigest(id, address(0xBEEF), 1000, digest, keccak256(abi.encodePacked(e)), c);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(AGENT_PK, h);
        acc.settleLogged(id, address(0xBEEF), 1000, digest, e, c, abi.encodePacked(r, s, v));
        vd.open{value: 0.01 ether}(id, digest, c, 0);
    }

    function _file(uint256 k) internal pure returns (string memory) {
        if (k == 1) return string.concat(DIR, "out_8272597/onchain.txt");
        if (k == 2) return string.concat(DIR, "out_8272599/onchain.txt");
        return string.concat(DIR, "out_8272601/onchain.txt");
    }

    function _field(string memory file, string memory key) internal view returns (string memory) {
        string[] memory lines = vm.split(vm.readFile(file), "\n");
        for (uint256 i; i < lines.length; ++i) {
            string[] memory kv = vm.split(vm.replace(lines[i], "\r", ""), " ");
            if (kv.length == 2 && keccak256(bytes(kv[0])) == keccak256(bytes(key))) return kv[1];
        }
        revert(string.concat("no ", key, " in ", file));
    }

    function _pv(uint256 i) internal view returns (uint64 x) {
        for (uint64 b = 0; b < 8; ++b) x |= uint64(uint8(pv[8 * (i + 1) + b])) << (8 * b);
    }

    function _lanes(uint256 first) internal view returns (bytes32) {
        uint256 w;
        for (uint256 j = 0; j < 4; ++j) w |= uint256(_pv(first + j)) << (64 * j);
        return bytes32(w);
    }
}
