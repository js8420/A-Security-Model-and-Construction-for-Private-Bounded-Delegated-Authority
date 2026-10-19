// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Script, console} from "forge-std/Script.sol";
import {RevealDispute} from "../src/RevealDispute.sol";
import {KeccakTree} from "../test/KeccakTree.sol";

/// The reveal-on-dispute baseline as real transactions on a local node, so
/// every gas figure is a receipt's gasUsed, as for the validity dispute. The
/// lists hold 128 merchants, 128 categories and 128 revoked-range leaves.
contract RevealDisputeOnChain is Script {
    uint64 constant DOMAIN = 8453;
    uint256 constant DEPTH = 7;

    function run() external {
        bytes32[] memory merchants = KeccakTree.merchants(DEPTH);
        bytes32[] memory categories = KeccakTree.categories(DEPTH);
        (bytes32[] memory revoked, uint64[] memory starts, uint64[] memory lengths) = KeccakTree.revoked(DEPTH, 3);
        RevealDispute.Policy memory p = RevealDispute.Policy({
            budget: 100_000, cap: 50_000, tStart: 0, tExpiry: type(uint64).max,
            merchants: KeccakTree.root(merchants), categories: KeccakTree.root(categories), salt: keccak256("policy salt")
        });
        RevealDispute.Opening memory o = RevealDispute.Opening({
            salt: keccak256("payment salt"), amount: 20_000, merchant: 5, category: 3, time: uint64(block.timestamp),
            payee: KeccakTree.payeeOf(5), domain: DOMAIN, nonce: 1, runStart: 0
        });
        bytes32 opening = keccak256(abi.encode(o));
        RevealDispute.Answer memory a = RevealDispute.Answer(
            o, o.amount, p, 5, KeccakTree.path(merchants, 5), 3, KeccakTree.path(categories, 3), KeccakTree.gap(revoked, starts, lengths, 0)
        );

        vm.startBroadcast(vm.envUint("LOCAL_PK"));
        RevealDispute rd = new RevealDispute(DOMAIN, 1 days, 2 hours, 0.01 ether);
        uint256 id = rd.register(keccak256(abi.encode(p)), KeccakTree.root(revoked), 10_000, 0, 4096);
        rd.settle(id, 1, o.amount, o.payee, o.time, opening);
        rd.open{value: 0.01 ether}(id, 1, o.amount, o.payee, o.time, opening, o.amount);
        rd.answer(id, 1, a);
        rd.withdraw();
        vm.stopBroadcast();
        (, , RevealDispute.Status st) = rd.challenges(rd.key(id, 1));
        console.log("reveal dispute answered", uint256(st) == 2);
    }
}
