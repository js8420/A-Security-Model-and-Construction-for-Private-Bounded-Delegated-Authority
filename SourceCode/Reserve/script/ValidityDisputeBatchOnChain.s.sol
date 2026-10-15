// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Script} from "forge-std/Script.sol";
import {Reserve} from "../src/Reserve.sol";
import {Poseidon2Goldilocks} from "../src/Poseidon2Goldilocks.sol";
import {TermsOf} from "../test/TermsOf.sol";
import {ValidityDispute} from "../src/ValidityDispute.sol";
import {Settlement} from "../src/Settlement.sol";
import {SP1Verifier} from "../src/sp1/v6.1.0/SP1VerifierGroth16.sol";
import {MockToken} from "../test/MockToken.sol";
import {Statement} from "../test/Statement.sol";

/// Batch answers as real transactions on a local node: one answerBatch for
/// one, two and four open challenges, each with Pete's Groth16 proof of the
/// batch program, so every gas figure is a receipt's gasUsed. The node is
/// started at the exported payment's time: anvil --timestamp 5000.
contract ValidityDisputeBatchOnChain is Script {
    string constant DIR = "../../WorkingHistory/groth16_s5b/";
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
        require(digest == Statement.DIGEST, "proof is not of the exported payment");
        bytes32 batchKey = vm.parseBytes32(_field(_file(4), "vkey"));

        vm.startBroadcast(pk);
        sp1 = new SP1Verifier();
        token = new MockToken();
        acc = new Reserve(DOMAIN, address(token), address(0), address(new Poseidon2Goldilocks()), 1 hours, 2 days);
        vd = new ValidityDispute(address(acc), address(sp1), bytes32(0), batchKey, 1 days, 1 days, 2 hours, 0.01 ether);
        acc.setDispute(address(vd));
        token.mint(me, 1e15);
        token.mint(Statement.PAYEE, 1);
        token.approve(address(acc), type(uint256).max);
        for (uint256 k = 1; k <= 4; k *= 2) {
            uint256[] memory ids = new uint256[](k);
            uint64[] memory ds = new uint64[](k);
            Settlement[] memory ss = new Settlement[](k);
            for (uint256 i = 0; i < k; ++i) {
                (ids[i], ss[i]) = _challenged();
                ds[i] = digest;
            }
            vd.answerBatch(ids, ds, ss, vm.parseBytes(_field(_file(k), "proof")));
        }
        vm.stopBroadcast();
    }

    function _challenged() internal returns (uint256 id, Settlement memory s) {
        id = acc.register{value: 0.1 ether}(TermsOf.make(vm.addr(AGENT_PK), 1_000_000, 1_000, 86_400, Reserve.Funding.Deposit, 100_000_000, _lanes(5), _lanes(1), type(uint64).max >> 1));
        uint64[] memory e = Statement.elems();
        bytes32 eh = keccak256(abi.encodePacked(e));
        bytes32 h = acc.signedDigest(id, Statement.PAYEE, Statement.AMOUNT, digest, Statement.TIME, eh);
        (uint8 v, bytes32 r, bytes32 sg) = vm.sign(AGENT_PK, h);
        acc.settleLogged(id, Statement.PAYEE, Statement.AMOUNT, digest, Statement.TIME, e, abi.encodePacked(r, sg, v));
        s = Settlement({elems: eh, amount: Statement.AMOUNT, payee: Statement.PAYEE, time: Statement.TIME, epoch: 0});
        vd.open{value: 0.01 ether}(id, digest, s);
    }

    function _file(uint256 k) internal pure returns (string memory) {
        if (k == 1) return string.concat(DIR, "out_s5b_batch1_a/onchain.txt");
        if (k == 2) return string.concat(DIR, "out_s5b_batch2_a/onchain.txt");
        return string.concat(DIR, "out_s5b_batch4_a/onchain.txt");
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
