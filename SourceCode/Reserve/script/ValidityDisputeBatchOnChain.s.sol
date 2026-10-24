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

/// Answers as real transactions on a local node: one answerBatch for 1, 2, 4,
/// 8, 16, 32, 64 and 128 open challenges by the principal against payments of
/// the exported batch, each with Pete's one Groth16 proof, so every gas figure
/// is a receipt's gasUsed. Each size settles on its own delegation, so no answer
/// meets a settlement an earlier one closed. The node is started at the
/// exported payments' time: anvil --timestamp 5000.
contract ValidityDisputeBatchOnChain is Script {
    /// Stands for the agent's commitment to a payment's hidden fields, which
    /// the reserve signs over and emits but never reads.
    bytes32 constant OPENING = keccak256("hidden fields");
    string constant RESULT = "../../WorkingHistory/groth16_s8/out_s8_batch_a/onchain.txt";
    uint64 constant DOMAIN = 8453;
    uint256 constant AGENT_PK = 0xA6E47;

    MockToken token;
    Reserve acc;
    ValidityDispute vd;

    function run() external {
        uint256 pk = vm.envUint("LOCAL_PK");
        address me = vm.addr(pk);
        require(bytes32(vm.parseBytes(_field("public_values"))) == Statement.ROOT, "proof is not of the exported batch");
        bytes memory proof = vm.parseBytes(_field("proof"));
        Statement.Data memory d = Statement.load();

        vm.startBroadcast(pk);
        token = new MockToken();
        acc = new Reserve(DOMAIN, address(token), address(0), address(new Poseidon2Goldilocks()), 1 hours, 2 days);
        vd = new ValidityDispute(address(acc), address(new SP1Verifier()), vm.parseBytes32(_field("vkey")), 1 days, 1 days, 2 hours, 0.01 ether, 30 hours, 0.25 ether, 0);
        acc.setDispute(address(vd));
        token.mint(me, 1e15);
        token.mint(Statement.payee(d, 0), 1);
        token.approve(address(acc), type(uint256).max);
        for (uint256 k = 1; k <= Statement.PAYMENTS; k *= 2) {
            uint256 id = acc.register{value: 0.1 ether}(TermsOf.make(vm.addr(AGENT_PK), 1_000_000, 1_000, 86_400, Reserve.Funding.Deposit, 100_000_000, _lanes(d, 5), _lanes(d, 1), type(uint64).max >> 1));
            uint256[] memory ids = new uint256[](k);
            uint64[] memory ds = new uint64[](k);
            Settlement[] memory ss = new Settlement[](k);
            uint256[] memory at = new uint256[](k);
            bytes32[][] memory paths = new bytes32[][](k);
            // Every payment settles before any challenge: the principal's
            // challenge holds the delegation's settlement until answered.
            for (uint256 i = 0; i < k; ++i) {
                ss[i] = _settled(d, id, i);
                (ids[i], ds[i], at[i], paths[i]) = (id, Statement.digest(d, i), i, Statement.path(d, i));
            }
            for (uint256 i = 0; i < k; ++i) vd.open{value: 0.26 ether}(id, ds[i], ss[i]);
            vd.answerBatch(_items(ids, ds, ss, at, paths), proof);
        }
        vm.stopBroadcast();
    }

    function _settled(Statement.Data memory d, uint256 id, uint256 i) internal returns (Settlement memory s) {
        uint64[] memory e = Statement.elems(d, i);
        s = Settlement({
            elems: keccak256(abi.encodePacked(e)), amount: Statement.amount(d, i), payee: Statement.payee(d, i),
            time: Statement.time(d, i), epoch: 0
        });
        acc.settleLogged(id, s.payee, s.amount, Statement.digest(d, i), s.time, e, OPENING, _sign(d, id, i, s));
    }

    function _sign(Statement.Data memory d, uint256 id, uint256 i, Settlement memory s) internal view returns (bytes memory) {
        bytes32 h = acc.signedDigest(id, s.payee, s.amount, Statement.digest(d, i), s.time, s.elems, OPENING);
        (uint8 v, bytes32 r, bytes32 sg) = vm.sign(AGENT_PK, h);
        return abi.encodePacked(r, sg, v);
    }

    function _field(string memory key) internal view returns (string memory) {
        string[] memory lines = vm.split(vm.readFile(RESULT), "\n");
        for (uint256 i; i < lines.length; ++i) {
            string[] memory kv = vm.split(vm.replace(lines[i], "\r", ""), " ");
            if (kv.length == 2 && keccak256(bytes(kv[0])) == keccak256(bytes(key))) return kv[1];
        }
        revert(string.concat("no ", key, " in ", RESULT));
    }

    function _lanes(Statement.Data memory d, uint256 first) internal pure returns (bytes32) {
        uint64[] memory l = Statement.leaf(d, 0);
        uint256 w;
        for (uint256 j = 0; j < 4; ++j) w |= uint256(l[first + j]) << (64 * j);
        return bytes32(w);
    }

    function _items(
        uint256[] memory ids,
        uint64[] memory ds,
        Settlement[] memory ss,
        uint256[] memory at,
        bytes32[][] memory paths
    ) internal pure returns (ValidityDispute.Item[] memory items) {
        items = new ValidityDispute.Item[](ids.length);
        for (uint256 i = 0; i < ids.length; ++i) {
            items[i] = ValidityDispute.Item({id: ids[i], digest: ds[i], s: ss[i], index: at[i], path: paths[i]});
        }
    }
}
