// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Reserve} from "../src/Reserve.sol";

/// A contract that answers every call a facilitator makes of a reserve as
/// Reserve.sol does, deployed with the same arguments, and adds one: its
/// deployer can take the deposits. Only its code tells it apart, which is
/// what the facilitator's check reads.
contract LookAlikeReserve is Reserve {
    address private immutable owner;

    constructor(uint64 domainId, address token_, address permit2_, address poseidon_, uint64 maxAge_, uint64 closeDelay_)
        Reserve(domainId, token_, permit2_, poseidon_, maxAge_, closeDelay_)
    {
        owner = msg.sender;
    }

    function sweep(address to, uint256 amount) external {
        require(msg.sender == owner, "owner");
        require(token.transfer(to, amount), "transfer");
    }
}
