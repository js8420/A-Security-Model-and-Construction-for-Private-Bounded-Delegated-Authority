// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test, console} from "forge-std/Test.sol";
import {Poseidon2Goldilocks} from "../src/Poseidon2Goldilocks.sol";

/// The contract has to agree with the crate the prover uses, not with itself.
///
/// These vectors are the output of `cargo run --release -- permute`, which
/// calls `default_goldilocks_poseidon2_8` directly. If the Solidity round
/// structure is wrong in any way --- the order of the external layer, the form
/// of the internal one, a transcribed constant --- these fail.
contract Poseidon2Gas is Test {
    Poseidon2Goldilocks p;

    function setUp() public {
        p = new Poseidon2Goldilocks();
    }

    function _check(uint256[8] memory input, uint256[8] memory expected, string memory label)
        internal
        view
    {
        uint256[8] memory got = p.permute(input);
        for (uint256 i = 0; i < 8; ++i) {
            assertEq(got[i], expected[i], label);
        }
    }

    function testAgainstTheCrateZeros() public view {
        _check(
            [uint256(0), 0, 0, 0, 0, 0, 0, 0],
            [
                uint256(4904961330882102773),
                6914533505831728251,
                16060085509051262978,
                161169382960502813,
                8610401995229161121,
                6947968519022847962,
                9668808541865791489,
                7055543217974479047
            ],
            "zeros"
        );
    }

    function testAgainstTheCrateCounting() public view {
        _check(
            [uint256(1), 2, 3, 4, 5, 6, 7, 8],
            [
                uint256(15506260347376358782),
                2994144798473533345,
                1833939590059144543,
                15204941819943812974,
                14698243433528585034,
                119683474010473000,
                5368738736850845934,
                12216367676790481710
            ],
            "counting"
        );
    }

    function testAgainstTheCrateLargeFirst() public view {
        _check(
            [uint256(4294967293), 0, 1, 2, 3, 4, 5, 6],
            [
                uint256(10214557320059612825),
                8356369697423656944,
                1768380156506946077,
                6979154712236571247,
                7123206276911537751,
                9942320711526508910,
                48793503114292196,
                15252172175273084701
            ],
            "large first"
        );
    }

    function testPermutationGas() public view {
        uint256[8] memory s = [uint256(1), 2, 3, 4, 5, 6, 7, 8];
        uint256 g = gasleft();
        p.permute(s);
        console.log("one permutation, gas", g - gasleft());
    }

    function testMerkleLevelGas() public view {
        uint256[4] memory l = [uint256(1), 2, 3, 4];
        uint256[4] memory r = [uint256(5), 6, 7, 8];
        uint256 g = gasleft();
        p.merkleLevel(l, r);
        console.log("one Merkle level over the proof's trees, gas", g - gasleft());
    }
}
