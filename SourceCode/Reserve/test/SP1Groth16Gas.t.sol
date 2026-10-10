// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test, console} from "forge-std/Test.sol";
import {SP1Verifier} from "../src/sp1/v6.1.0/SP1VerifierGroth16.sol";
import {Verifier} from "../src/sp1/v6.1.0/Groth16Verifier.sol";

/// The dispute's validity proof on chain: Succinct's v6.1.0 Groth16 verifier
/// checking the proof Pete made of the deployed STARK verifier.
contract SP1Groth16Gas is Test {
    string constant RESULT = "../../WorkingHistory/groth16_20261009/onchain.txt";

    SP1Verifier verifier;
    bytes32 vkey;
    bytes publicValues;
    bytes proof;

    function setUp() public {
        verifier = new SP1Verifier();
        vkey = vm.parseBytes32(field("vkey"));
        publicValues = vm.parseBytes(field("public_values"));
        proof = vm.parseBytes(field("proof"));
    }

    function field(string memory key) internal returns (string memory) {
        vm.closeFile(RESULT);
        for (uint256 i; i < 16; ++i) {
            string memory line = vm.replace(vm.readLine(RESULT), "\r", "");
            string[] memory kv = vm.split(line, " ");
            if (kv.length == 2 && keccak256(bytes(kv[0])) == keccak256(bytes(key))) return kv[1];
        }
        revert(string.concat("no ", key, " in onchain.txt"));
    }

    function calldataGas(bytes memory data) internal pure returns (uint256 standard, uint256 floor) {
        uint256 zeros;
        for (uint256 i; i < data.length; ++i) {
            if (data[i] == 0) ++zeros;
        }
        uint256 tokens = zeros + 4 * (data.length - zeros);
        standard = 4 * tokens;
        floor = 10 * tokens;
    }

    function testVerifyGas() public view {
        uint256 g = gasleft();
        verifier.verifyProof(vkey, publicValues, proof);
        uint256 used = g - gasleft();

        bytes memory data = abi.encodeCall(SP1Verifier.verifyProof, (vkey, publicValues, proof));
        (uint256 standard, uint256 floor) = calldataGas(data);
        uint256 execution = 21000 + standard + used;
        uint256 total = execution > 21000 + floor ? execution : 21000 + floor;

        console.log("SP1 v6.1.0 Groth16 verifier, the dispute's validity proof");
        console.log("  circuit version", verifier.VERSION());
        console.log("  public value bytes", publicValues.length);
        console.log("  proof bytes", proof.length);
        console.log("  calldata bytes", data.length);
        console.log("  verifyProof call gas", used);
        console.log("  calldata gas, standard", standard);
        console.log("  calldata gas, EIP-7623 floor", floor);
        console.log("  transaction gas, verifyProof alone", total);
    }

    function testTamperedPublicValuesRevert() public {
        bytes memory pv = publicValues;
        pv[pv.length - 1] ^= 0x01;
        vm.expectRevert(Verifier.ProofInvalid.selector);
        verifier.verifyProof(vkey, pv, proof);
    }

    function testWrongProgramRevert() public {
        bytes32 other = bytes32(uint256(vkey) ^ 1);
        vm.expectRevert(Verifier.ProofInvalid.selector);
        verifier.verifyProof(other, publicValues, proof);
    }

    function testTamperedProofRevert() public {
        bytes memory p = proof;
        p[p.length - 1] ^= 0x01;
        vm.expectRevert();
        verifier.verifyProof(vkey, publicValues, p);
    }

    function testWrongVerifierSelectorRevert() public {
        bytes memory p = proof;
        p[0] ^= 0x01;
        bytes4 expected = bytes4(verifier.VERIFIER_HASH());
        vm.expectRevert(
            abi.encodeWithSelector(SP1Verifier.WrongVerifierSelector.selector, expected ^ 0x01000000, expected)
        );
        verifier.verifyProof(vkey, publicValues, p);
    }
}
