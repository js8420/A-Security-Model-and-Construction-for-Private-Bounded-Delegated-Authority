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
import {KeccakTree} from "../test/KeccakTree.sol";

/// The validity dispute as real transactions on a local node, so every gas
/// figure is a receipt's gasUsed: intrinsic cost, calldata (with the EIP-7623
/// floor) and execution with cold accounts and storage, as on chain. The
/// settlement is payment 0 of the exported batch, shares included; the answer
/// carries its leaf's path to the root the proof commits. The answer to the
/// principal's challenge asks for what backs the settlement: its sealed
/// opening, posted at its position in a tree of one 349-byte opening per
/// payment of the batch, and the batch's STARK proof, posted in chunks under
/// the hash the answerer's receipt names.
///
/// The exported payments were signed from time 5000, so the node is started
/// with its clock there: anvil --timestamp 5000.
contract ValidityDisputeOnChain is Script {
    /// Stands for the agent's commitment to a payment's hidden fields, which
    /// the reserve signs over and emits but never reads.
    bytes32 constant OPENING = keccak256("hidden fields");
    string constant RESULT = "../../WorkingHistory/groth16_s6/out_s6_batch_a/onchain.txt";
    /// The exported batch's STARK proof with its public values, as the agent hands it on.
    string constant STARK = "../../Circuits/target/proof_128_keccak.bin";
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
        require(keccak256(publicValues) == keccak256(abi.encodePacked(Statement.ROOT)), "proof is not of the exported batch");
        Statement.Data memory d = Statement.load();
        digest = Statement.digest(d, 0);
        uint256 pk = vm.envUint("LOCAL_PK");

        vm.startBroadcast(pk);
        _deploy(d, vm.addr(pk), 1 days, 2 hours);
        _settle(d);
        (bool ok, ) = address(sp1).call(abi.encodeCall(SP1Verifier.verifyProof, (vkey, publicValues, proof)));
        require(ok, "verifyProof");
        vd.open{value: 0.01 ether}(id, digest, rec);
        vd.answer(id, digest, rec, 0, Statement.path(d, 0), proof);
        console.log("dispute answered", uint256(vd.challengeOf(id, digest).status) == 2);
        bytes memory stark = vm.readFileBinary(STARK);
        bytes32 ph = _proofHash(stark);
        _deliver(d, pk, ph);
        console.log("sealed opening delivered", uint256(vd.challengeOf(id, digest).status) == 4);
        _postProof(stark);
        console.log("proof posted, bytes", stark.length, vd.postedAt(id, ph) != 0);

        // The unanswered case, on a second reserve whose answer window is zero
        // and whose slot is one second, so the deadline falls within two
        // seconds; three blocks later it has passed.
        _deploy(d, vm.addr(pk), 0, 1);
        _settle(d);
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

    function _deploy(Statement.Data memory d, address me, uint64 window, uint64 slot) internal {
        token = new MockToken();
        acc = new Reserve(DOMAIN, address(token), address(0), address(new Poseidon2Goldilocks()), 1 hours, 2 days);
        if (address(sp1) == address(0)) sp1 = new SP1Verifier();
        vd = new ValidityDispute(address(acc), address(sp1), vkey, 1 days, window, slot, 0.01 ether, 8 hours);
        acc.setDispute(address(vd));
        token.mint(me, 1e15);
        token.mint(Statement.payee(d, 0), 1);
        token.approve(address(acc), type(uint256).max);
        Reserve.Terms memory t = TermsOf.make(vm.addr(AGENT_PK), 1_000_000, 1_000, 86_400, Reserve.Funding.Deposit, 100_000_000, _lanes(d, 5), _lanes(d, 1), type(uint64).max >> 1);
        t.answerer = me;
        id = acc.register{value: 1 ether}(t);
        acc.stakeAnswerer{value: 1 ether}(id);
    }

    /// The answerer's receipt for the batch and its sealed openings, and the
    /// delivery of payment 0's.
    function _deliver(Statement.Data memory d, uint256 pk, bytes32 proofHash) internal {
        bytes32[] memory leaves = new bytes32[](Statement.PAYMENTS);
        for (uint256 i = 0; i < leaves.length; ++i) leaves[i] = keccak256(_opening(i));
        ValidityDispute.Receipt memory rc = _receipt(pk, KeccakTree.root(leaves), proofHash);
        bytes32[] memory sealedPath = KeccakTree.path(leaves, 0);
        vd.deliver(id, digest, rec, 0, Statement.path(d, 0), rc, _opening(0), sealedPath);
    }

    function _receipt(uint256 pk, bytes32 sealedRoot, bytes32 proofHash) internal view returns (ValidityDispute.Receipt memory) {
        uint64 at = uint64(block.timestamp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, vd.receiptDigest(id, Statement.ROOT, sealedRoot, proofHash, at));
        return ValidityDispute.Receipt({sealedRoot: sealedRoot, proofHash: proofHash, receivedAt: at, signature: abi.encodePacked(r, s, v)});
    }

    /// The chained hash postProof checks, computed in place: the word before
    /// each chunk briefly holds the hash so far.
    function _proofHash(bytes memory b) internal view returns (bytes32 h) {
        uint256 size = vd.CHUNK();
        uint256 n = b.length;
        assembly {
            let base := add(b, 32)
            for { let at := 0 } lt(at, n) { at := add(at, size) } {
                let len := sub(n, at)
                if gt(len, size) { len := size }
                let p := add(base, at)
                let keep := mload(sub(p, 32))
                mstore(sub(p, 32), h)
                h := keccak256(sub(p, 32), add(len, 32))
                mstore(sub(p, 32), keep)
            }
            let f := mload(0x40)
            mstore(f, h)
            mstore(add(f, 32), n)
            h := keccak256(f, 64)
        }
    }

    /// One transaction a chunk, as an answerer posts it. One buffer is
    /// reused, and the memory each call's encoding takes is given back.
    function _postProof(bytes memory b) internal {
        bytes32 h = _proofHash(b);
        uint256 size = vd.CHUNK();
        bytes memory buf = new bytes(size);
        uint256 i;
        for (uint256 at = 0; at < b.length; at += size) {
            uint256 len = b.length - at < size ? b.length - at : size;
            uint256 fmp;
            assembly {
                let src := add(add(b, 32), at)
                let dst := add(buf, 32)
                for { let j := 0 } lt(j, len) { j := add(j, 32) } { mstore(add(dst, j), mload(add(src, j))) }
                mstore(buf, len)
                fmp := mload(0x40)
            }
            vd.postProof(id, h, i++, buf, at + len == b.length);
            assembly {
                mstore(0x40, fmp)
            }
        }
    }

    /// A stand-in for payment i's sealed opening: 349 bytes, as every one is.
    function _opening(uint256 i) internal pure returns (bytes memory b) {
        b = new bytes(349);
        for (uint256 j = 0; j < 349; j += 32) {
            bytes32 w = keccak256(abi.encode(i, j));
            for (uint256 k = 0; k < 32 && j + k < 349; ++k) b[j + k] = w[k];
        }
    }

    function _settle(Statement.Data memory d) internal {
        uint64[] memory e = Statement.elems(d, 0);
        bytes32 eh = keccak256(abi.encodePacked(e));
        address to = Statement.payee(d, 0);
        uint64 t = Statement.time(d, 0);
        uint64 a = Statement.amount(d, 0);
        bytes32 h = acc.signedDigest(id, to, a, digest, t, eh, OPENING);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(AGENT_PK, h);
        acc.settleLogged(id, to, a, digest, t, e, OPENING, abi.encodePacked(r, s, v));
        rec = Settlement({elems: eh, amount: a, payee: to, time: t, epoch: 0});
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

    /// Four values of payment 0's leaf from `first`, packed low lane first.
    function _lanes(Statement.Data memory d, uint256 first) internal pure returns (bytes32) {
        uint64[] memory l = Statement.leaf(d, 0);
        uint256 w;
        for (uint256 j = 0; j < 4; ++j) w |= uint256(l[first + j]) << (64 * j);
        return bytes32(w);
    }
}
