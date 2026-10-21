// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Script, console} from "forge-std/Script.sol";
import {StateRead} from "../test/StateRead.sol";

/// The cross-domain read as a real transaction on a local node, so its gas is
/// a receipt's gasUsed, calldata included. The read is sent as a call that
/// the reader's own state does not need: a deployment would make it inside
/// the answer of a dispute.
contract StateReadOnChain is Script {
    string constant DIR = "../../WorkingHistory/state_proofs/";

    function _slot(string memory json) internal pure returns (StateRead.Slot memory s) {
        s.account = vm.parseJsonAddress(json, ".address");
        s.accountProof = vm.parseJsonBytesArray(json, ".accountProof");
        s.key = vm.parseJsonBytes32(json, ".slot");
        s.storageProof = vm.parseJsonBytesArray(json, ".storageProof");
    }

    function run() external {
        string memory a = vm.readFile(string.concat(DIR, "l1.json"));
        string memory b = vm.readFile(string.concat(DIR, "l2.json"));
        vm.startBroadcast(vm.envUint("LOCAL_PK"));
        StateRead r = new StateRead();
        Reader w = new Reader(r);
        StateRead.Input memory x;
        x.header = vm.parseJsonBytes(a, ".header");
        x.l1BlockHash = vm.parseJsonBytes32(a, ".blockHash");
        x.l1 = _slot(a);
        x.l2StateRoot = vm.parseJsonBytes32(b, ".stateRoot");
        x.messagePasserRoot = vm.parseJsonBytes32(b, ".messagePasserRoot");
        x.l2BlockHash = vm.parseJsonBytes32(b, ".blockHash");
        x.l2 = _slot(b);
        w.read(x);
        vm.stopBroadcast();
        console.log("cross-domain read recorded", w.last() != bytes32(0));
    }
}

/// Sends the read in a transaction and keeps the value, as a dispute would.
contract Reader {
    StateRead immutable r;
    bytes32 public last;

    constructor(StateRead r_) {
        r = r_;
    }

    function read(StateRead.Input calldata x) external {
        (, , bytes32 v) = r.read(x);
        last = v;
    }
}
