// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test, console} from "forge-std/Test.sol";
import {StateRead} from "./StateRead.sol";

/// The cross-domain read of StateRead on real proofs that
/// fetch_state_proofs.sh took from Ethereum and Base mainnet. Skipped when
/// they have not been fetched.
contract StateReadTest is Test {
    string constant DIR = "../../WorkingHistory/state_proofs/";

    function _slot(string memory json) internal pure returns (StateRead.Slot memory s) {
        s.account = vm.parseJsonAddress(json, ".address");
        s.accountProof = vm.parseJsonBytesArray(json, ".accountProof");
        s.key = vm.parseJsonBytes32(json, ".slot");
        s.storageProof = vm.parseJsonBytesArray(json, ".storageProof");
    }

    function _input(string memory a, string memory b) internal pure returns (StateRead.Input memory x) {
        x.header = vm.parseJsonBytes(a, ".header");
        x.l1BlockHash = vm.parseJsonBytes32(a, ".blockHash");
        x.l1 = _slot(a);
        x.l2StateRoot = vm.parseJsonBytes32(b, ".stateRoot");
        x.messagePasserRoot = vm.parseJsonBytes32(b, ".messagePasserRoot");
        x.l2BlockHash = vm.parseJsonBytes32(b, ".blockHash");
        x.l2 = _slot(b);
    }

    function testReadAcrossDomains() public {
        if (!vm.exists(string.concat(DIR, "l1.json"))) {
            vm.skip(true);
            return;
        }
        string memory a = vm.readFile(string.concat(DIR, "l1.json"));
        string memory b = vm.readFile(string.concat(DIR, "l2.json"));
        StateRead r = new StateRead();
        StateRead.Input memory x = _input(a, b);
        uint256 g0 = gasleft();
        (bytes32 v1, , bytes32 v2) = r.read(x);
        uint256 used = g0 - gasleft();
        assertEq(v1, vm.parseJsonBytes32(a, ".value"));
        assertEq(v2, vm.parseJsonBytes32(b, ".value"));
        bytes memory call = abi.encodeCall(StateRead.read, (x));
        uint256 zeros;
        for (uint256 i = 0; i < call.length; ++i) if (call[i] == 0) ++zeros;
        console.log("cross-domain read, execution gas", used);
        console.log("calldata bytes", call.length, "of them zero", zeros);
        StateRead.Slot memory l1 = x.l1;
        StateRead.Slot memory l2 = x.l2;
        console.log("Ethereum proof nodes, account and storage", l1.accountProof.length, l1.storageProof.length);
        console.log("Base proof nodes, account and storage", l2.accountProof.length, l2.storageProof.length);
    }
}
