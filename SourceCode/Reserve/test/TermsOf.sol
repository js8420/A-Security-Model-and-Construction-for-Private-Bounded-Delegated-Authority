// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Reserve} from "../src/Reserve.sol";
import {Statement} from "./Statement.sol";

/// Registration terms for the tests: the delegation's unit size, range and
/// H(s) are the exported payment's, so a delegation registered here is one
/// the exported proof can speak for.
library TermsOf {
    /// The bond every test delegation asks its agent for.
    uint256 internal constant BOND = 1 ether;

    function make(
        address agent,
        uint64 cap,
        uint64 velocityN,
        uint64 windowW,
        Reserve.Funding funding,
        uint256 deposit,
        bytes32 commitment,
        bytes32 revocationRoot,
        uint64 expiry
    ) internal pure returns (Reserve.Terms memory t) {
        t.agent = agent;
        t.cap = cap;
        t.velocityN = velocityN;
        t.windowW = windowW;
        t.secretHash = Statement.SECRET_HASH;
        t.funding = funding;
        t.deposit = deposit;
        t.commitment = commitment;
        t.revocationRoot = revocationRoot;
        t.expiry = expiry;
        t.unitSize = Statement.UNIT;
        t.rangeBase = Statement.RANGE_BASE;
        t.rangeLen = Statement.RANGE_LEN;
        t.bond = BOND;
    }
}
