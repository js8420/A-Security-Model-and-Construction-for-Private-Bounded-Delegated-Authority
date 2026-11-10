// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test, console} from "forge-std/Test.sol";
import {BlobPosting} from "../src/BlobPosting.sol";

/// What posting one batch as blobs costs in Ethereum gas besides the blob
/// gas: every call of BlobPosting, the last sending its report through
/// Base's own messenger on Ethereum, each with its intrinsic gas and its call
/// data at the price EIP-7623 sets. The batch is the deployed one: the proof
/// file and 256 sealed openings as blobPayload lays them out, 83 blobs, six
/// to a transaction as Fusaka allows. Runs against a fork of Ethereum mainnet
/// when L1_FORK names an endpoint, and is skipped otherwise.
contract BlobPostingGas is Test {
    /// Base's L1CrossDomainMessenger on Ethereum.
    address constant MESSENGER = 0x866E82a600A1414e583f7F13623F1aC5d58b0Afa;
    uint256 constant PROOF_FILE_BYTES = 10_365_547;
    uint256 constant BATCH = 256;
    uint256 constant PER_TX = 6;

    function testGasOfOneBatchAsBlobs() public {
        string memory rpc = vm.envOr("L1_FORK", string(""));
        if (bytes(rpc).length == 0) vm.skip(true);
        vm.createSelectFork(rpc);
        uint256 payload = 4 + PROOF_FILE_BYTES + 4 + BATCH * (8 + 349) + 1;
        uint256 blobs = (payload + 31 * 4096 - 1) / (31 * 4096);
        BlobPosting bp = new BlobPosting(MESSENGER, address(0x9057));
        address answerer = address(0xA45E);
        uint256 total;
        uint256 txs;
        for (uint256 at = 0; at < blobs; at += PER_TX) {
            uint256 count = blobs - at < PER_TX ? blobs - at : PER_TX;
            bool last = at + count == blobs;
            bytes32[] memory h = new bytes32[](count);
            for (uint256 i = 0; i < count; ++i) h[i] = bytes32((uint256(1) << 248) | (uint256(keccak256(abi.encode(at + i))) >> 8));
            vm.blobhashes(h);
            bytes memory call = abi.encodeCall(BlobPosting.post, (7, keccak256("batch root"), count, last));
            vm.prank(answerer, answerer);
            uint256 g0 = gasleft();
            (bool ok,) = address(bp).call(call);
            uint256 exec = g0 - gasleft();
            require(ok, "post");
            total += _txGas(call, exec);
            txs += 1;
            if (last) console.log("closing call, execution gas", exec);
        }
        console.log("fork block", block.number);
        console.log("blobs", blobs);
        console.log("transactions", txs);
        console.log("Ethereum gas of one batch's blob postings", total);
    }

    /// A transaction's gas from its call data and execution: the intrinsic
    /// 21,000, the call data's tokens at 4 gas each, or at the EIP-7623 floor
    /// of 10 if that is more.
    function _txGas(bytes memory data, uint256 exec) internal pure returns (uint256) {
        uint256 tokens;
        for (uint256 i = 0; i < data.length; ++i) tokens += data[i] == 0 ? 1 : 4;
        uint256 standard = 21_000 + 4 * tokens + exec;
        uint256 floor = 21_000 + 10 * tokens;
        return standard > floor ? standard : floor;
    }
}
