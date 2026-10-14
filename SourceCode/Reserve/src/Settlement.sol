// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// What the reserve records of one settlement, and what a challenge opens.
/// Everything the reserve paid or published is here, so the statement a
/// dispute rebuilds from it covers the whole settlement and not part of it.
struct Settlement {
    /// keccak256(abi.encodePacked(elems)) of the shares and nullifiers published.
    bytes32 elems;
    uint64 amount;
    address payee;
    /// The time the agent signed, which the reserve checked against its clock,
    /// so it is also within maxAge of when the reserve settled. Challenges are
    /// open for a window from it.
    uint64 time;
    /// The revocation epoch in force at settlement, the reserve's and not the agent's.
    uint64 epoch;
}

library SettlementHash {
    function hash(Settlement memory s) internal pure returns (bytes32) {
        return keccak256(abi.encode(s));
    }
}
