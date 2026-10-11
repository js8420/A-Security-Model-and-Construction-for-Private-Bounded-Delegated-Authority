// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {SP1Verifier} from "../src/sp1/v6.1.0/SP1VerifierGroth16.sol";
import {Verifier} from "../src/sp1/v6.1.0/Groth16Verifier.sol";
import {Groth16Result} from "./Groth16Result.sol";

/// The dispute's validity proof on chain: Succinct's v6.1.0 Groth16 verifier
/// checking the proof Pete made of the deployed STARK verifier.
contract SP1Groth16Gas is Groth16Result {
    SP1Verifier verifier;

    function setUp() public {
        verifier = new SP1Verifier();
        _load();
    }

    /// Gas is taken from transaction receipts by script/ValidityDisputeOnChain.s.sol.
    function testVerifies() public view {
        assertEq(verifier.VERSION(), "v6.1.0");
        assertEq(publicValues.length, 88);
        assertEq(proof.length, 356);
        verifier.verifyProof(vkey, publicValues, proof);
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
