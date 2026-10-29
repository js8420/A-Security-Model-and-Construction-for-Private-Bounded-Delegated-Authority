// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ValidityDispute} from "../src/ValidityDispute.sol";

/// The prices the dispute contract is deployed with on Base, as the paper
/// derives them. The proving bond is twice the price of one answer, $6.03
/// (6,000.0 s of a 64-vCPU node at $3.616 an hour, the Groth16 run s9_batch_a),
/// at the last measured ether price, $2,339.10, rounded up to the microether.
/// bond_and_contention.py reads this value and reports the margin it gives at
/// the price on the day it runs. The forced answer's L1 gas was measured on a fork of
/// Ethereum mainnet. The posting gas and bytes are one batch's postings:
/// 106 proof chunks, 256 sealed openings and the binding.
library Deployment {
    uint256 internal constant PROVING_BOND = 0.005153 ether;
    uint256 internal constant FORCE_GAS = 572_345;
    uint256 internal constant FEE_FACTOR = 2;
    uint256 internal constant POSTING_GAS = 470_000_000;
    uint256 internal constant POSTING_BYTES = 10_800_000;

    function params(uint64 w, uint64 wa, uint64 eta, uint64 wp) internal pure returns (ValidityDispute.Params memory) {
        return ValidityDispute.Params({
            acceptWindow: w,
            answerWindow: wa,
            slot: eta,
            deliveryWait: wp,
            provingBond: PROVING_BOND,
            forceGas: FORCE_GAS,
            feeFactor: FEE_FACTOR,
            postingGas: POSTING_GAS,
            postingBytes: POSTING_BYTES
        });
    }
}
