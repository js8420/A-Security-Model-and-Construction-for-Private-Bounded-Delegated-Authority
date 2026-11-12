// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ValidityDispute} from "../src/ValidityDispute.sol";
import {Postings} from "../src/Postings.sol";

/// The prices the dispute contract is deployed with on Base, as the paper
/// derives them. The price of one answer is $6.03 (6,000.0 s of a 64-vCPU
/// node at $3.616 an hour, the Groth16 run s9_batch_a). The proving cost,
/// what an answer to the principal's challenges is paid for each batch, is
/// that price in the reserve's token, USDC with six decimals, so the price of
/// ether does not move it. The proving bond, the fixed part of a third
/// party's bond, is twice that price in ether at the last measured ether
/// price, $2,339.10, rounded up to the microether; bond_and_contention.py
/// reads it and reports the margin it gives at the price on the day it runs.
/// The forced answer's L1 gas was measured on a fork of
/// Ethereum mainnet. The fee factors and floors come from the base fees of
/// Ethereum and Base since Dencun (fee_ratio.py floors): with each fee read no
/// lower than its floor, no window since Dencun needed more than the factor.
/// The posting gas and bytes are one batch's postings on Base as measured:
/// 106 proof chunks, 414,854,690 gas and 10,386,344 bytes, and 256 deliveries
/// of 239,788 gas and 1,636 bytes, the first binding the batch. The posting
/// deposit is sized to that domain way alone: a posting as blobs is refunded
/// no more than the domain way costs when its report arrives.
library Deployment {
    uint256 internal constant PROVING_BOND = 0.005153 ether;
    uint256 internal constant PROVING_COST = 6_030_000;
    uint64 internal constant DELIVERY_TIME = 8 hours;
    uint256 internal constant FORCE_GAS = 572_345;
    uint256 internal constant L1_FACTOR = 10;
    uint256 internal constant L2_FACTOR = 4;
    uint256 internal constant L1_FEE_FLOOR = 2 gwei;
    uint256 internal constant L2_FEE_FLOOR = 0.01 gwei;
    uint256 internal constant POSTING_GAS = 476_240_418;
    uint256 internal constant POSTING_BYTES = 10_805_160;
    /// One batch's postings as blobs, as blobPayload lays them out: the
    /// 10,365,547-byte proof file and 256 sealed openings of 349 bytes, each
    /// after its 8-byte digest, two 4-byte lengths and an end byte, 10,456,948
    /// bytes at 31 to each of a blob's 4,096 field elements; and the Ethereum
    /// gas of the 14 transactions that carry them, measured on a fork. No
    /// contract reads them: fee_ratio.py compares the blob way's cost with
    /// the domain way's over the fee history.
    uint256 internal constant BLOBS = 83;
    uint256 internal constant BLOB_GAS = 1_032_754;
    address internal constant MESSENGER = 0x4200000000000000000000000000000000000007;
    /// Base's sequencing window, 3,600 Ethereum blocks of 12 seconds.
    uint64 internal constant INCLUSION_WAIT = 12 hours;

    function params(uint64 w, uint64 wa, uint64 eta, uint64 wp) internal pure returns (ValidityDispute.Params memory) {
        return ValidityDispute.Params({
            acceptWindow: w,
            answerWindow: wa,
            slot: eta,
            deliveryWait: wp,
            deliveryTime: DELIVERY_TIME,
            provingBond: PROVING_BOND,
            provingCost: PROVING_COST,
            forceGas: FORCE_GAS,
            l1Factor: L1_FACTOR,
            l2Factor: L2_FACTOR,
            l1FeeFloor: L1_FEE_FLOOR,
            l2FeeFloor: L2_FEE_FLOOR
        });
    }

    function postingParams() internal pure returns (Postings.Params memory) {
        return Postings.Params({
            postingGas: POSTING_GAS,
            postingBytes: POSTING_BYTES,
            l2Factor: L2_FACTOR,
            l2FeeFloor: L2_FEE_FLOOR,
            messenger: MESSENGER,
            inclusionWait: INCLUSION_WAIT
        });
    }
}
