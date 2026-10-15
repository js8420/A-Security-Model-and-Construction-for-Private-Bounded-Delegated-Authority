// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Script, console} from "forge-std/Script.sol";
import {Reserve} from "../src/Reserve.sol";
import {Poseidon2Goldilocks} from "../src/Poseidon2Goldilocks.sol";
import {TermsOf} from "../test/TermsOf.sol";
import {ValidityDispute} from "../src/ValidityDispute.sol";
import {Settlement} from "../src/Settlement.sol";
import {SP1Verifier} from "../src/sp1/v6.1.0/SP1VerifierGroth16.sol";
import {MockToken} from "../test/MockToken.sol";
import {Statement} from "../test/Statement.sol";

/// The validity dispute as real transactions on a local node, so every gas
/// figure is a receipt's gasUsed: intrinsic cost, calldata (with the EIP-7623
/// floor) and execution with cold accounts and storage, as on chain. The
/// settlement is the exported payment, shares included.
///
/// The exported payment was signed at time 5000, so the node is started with
/// its clock there: anvil --timestamp 5000.
contract ValidityDisputeOnChain is Script {
    string constant RESULT = "../../WorkingHistory/groth16_s5b/out_s5b_keccak_a/onchain.txt";
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
    Settlement rec;

    function run() external {
        vkey = vm.parseBytes32(_field("vkey"));
        publicValues = vm.parseBytes(_field("public_values"));
        proof = vm.parseBytes(_field("proof"));
        digest = _pv(0);
        require(digest == Statement.DIGEST, "proof is not of the exported payment");
        uint256 pk = vm.envUint("LOCAL_PK");

        vm.startBroadcast(pk);
        _deploy(vm.addr(pk), 1 days, 2 hours);
        _settle();
        (bool ok, ) = address(sp1).call(abi.encodeCall(SP1Verifier.verifyProof, (vkey, publicValues, proof)));
        require(ok, "verifyProof");
        vd.open{value: 0.01 ether}(id, digest, rec);
        vd.answer(id, digest, rec, proof);
        console.log("dispute answered", uint256(vd.challengeOf(id, digest).status) == 2);

        // The unanswered case, on a second reserve whose answer window is zero
        // and whose slot is one second, so the deadline falls within two
        // seconds; three blocks later it has passed.
        _deploy(vm.addr(pk), 0, 1);
        _settle();
        vd.open{value: 0.01 ether}(id, digest, rec);
        for (uint256 i = 0; i < 3; ++i) token.mint(vm.addr(pk), 1);
        // The script runs every call locally first, in one block; the warp
        // moves only that local clock past the deadline. On the node the three
        // mints above take three blocks. Gas is given because estimating at an
        // earlier block would see the deadline not yet passed.
        vm.warp(block.timestamp + 3);
        vd.expire{gas: 200_000}(id, digest);
        vd.withdraw{gas: 100_000}();
        vm.stopBroadcast();
        console.log("dispute expired", uint256(vd.challengeOf(id, digest).status) == 3);
    }

    function _deploy(address me, uint64 window, uint64 slot) internal {
        token = new MockToken();
        acc = new Reserve(DOMAIN, address(token), address(0), address(new Poseidon2Goldilocks()), 1 hours, 2 days);
        if (address(sp1) == address(0)) sp1 = new SP1Verifier();
        vd = new ValidityDispute(address(acc), address(sp1), vkey, bytes32(0), 1 days, window, slot, 0.01 ether);
        acc.setDispute(address(vd));
        token.mint(me, 1e15);
        token.mint(Statement.PAYEE, 1);
        token.approve(address(acc), type(uint256).max);
        id = acc.register{value: 1 ether}(TermsOf.make(vm.addr(AGENT_PK), 1_000_000, 1_000, 86_400, Reserve.Funding.Deposit, 100_000_000, _lanes(5), _lanes(1), type(uint64).max >> 1));
    }

    function _settle() internal {
        uint64[] memory e = Statement.elems();
        bytes32 eh = keccak256(abi.encodePacked(e));
        bytes32 h = acc.signedDigest(id, Statement.PAYEE, Statement.AMOUNT, digest, Statement.TIME, eh);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(AGENT_PK, h);
        acc.settleLogged(id, Statement.PAYEE, Statement.AMOUNT, digest, Statement.TIME, e, abi.encodePacked(r, s, v));
        rec = Settlement({
            elems: eh, amount: Statement.AMOUNT, payee: Statement.PAYEE, time: Statement.TIME,
            epoch: 0
        });
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
