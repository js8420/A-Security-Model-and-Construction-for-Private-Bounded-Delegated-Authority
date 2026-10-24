// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test, console} from "forge-std/Test.sol";

interface IOptimismPortal {
    function depositTransaction(address to, uint256 value, uint64 gasLimit, bool isCreation, bytes memory data) external payable;
}

/// What forcing one proof chunk in through Ethereum costs the answerer on L1
/// beyond its call data: the portal's work, including the gas it burns to buy
/// the deposit's L2 gas. Runs against a fork of Ethereum mainnet when L1_FORK
/// names an endpoint, and is skipped otherwise.
contract ForcedPostingGas is Test {
    /// Base's portal on Ethereum.
    address constant PORTAL = 0x49048044D57e1C92A77f79988d21Fa8fAF74E97e;
    /// L2 gas a full chunk's postProof needs, above the largest measured.
    uint64 constant L2_GAS = 4_000_000;
    uint256 constant CHUNK = 98304;

    function testPortalGasForOneChunk() public {
        string memory rpc = vm.envOr("L1_FORK", string(""));
        if (bytes(rpc).length == 0) vm.skip(true);
        vm.createSelectFork(rpc);
        bytes memory data = new bytes(CHUNK + 228);
        for (uint256 i = 0; i < data.length; ++i) data[i] = bytes1(uint8(1 + (i % 255)));
        address sender = address(0xF0CED);
        vm.deal(sender, 1 ether);
        vm.prank(sender, sender);
        uint256 g0 = gasleft();
        IOptimismPortal(PORTAL).depositTransaction(address(0xD15), 0, L2_GAS, false, data);
        uint256 used = g0 - gasleft();
        console.log("fork block", block.number);
        console.log("L1 base fee, wei", block.basefee);
        console.log("portal execution gas for one chunk", used);
    }
}
