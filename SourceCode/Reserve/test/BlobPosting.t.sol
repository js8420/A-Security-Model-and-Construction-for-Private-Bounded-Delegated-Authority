// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test, console} from "forge-std/Test.sol";
import {BlobPosting} from "../src/BlobPosting.sol";

/// Ethereum's messenger to the domain as BlobPosting sees it: it keeps the
/// last message sent.
contract MockL1Messenger {
    address public target;
    bytes public message;
    uint32 public gasLimit;

    function sendMessage(address target_, bytes calldata message_, uint32 gasLimit_) external payable {
        target = target_;
        message = message_;
        gasLimit = gasLimit_;
    }
}

contract BlobPostingTest is Test {
    MockL1Messenger messenger;
    BlobPosting bp;
    address constant POSTINGS = address(0x9057);
    address constant ANSWERER = address(0xA45E);
    bytes32 constant ROOT = keccak256("batch root");

    function setUp() public {
        messenger = new MockL1Messenger();
        bp = new BlobPosting(address(messenger), POSTINGS);
        vm.fee(10 gwei);
        vm.blobBaseFee(3);
    }

    function _hashes(uint256 from, uint256 n) internal pure returns (bytes32[] memory h) {
        h = new bytes32[](n);
        for (uint256 i = 0; i < n; ++i) h[i] = bytes32((uint256(0x01) << 248) | uint256(keccak256(abi.encode("blob", from + i))) >> 8);
    }

    /// Two transactions of blobs: the hashes chain in order across them, the
    /// count closes the chain, and the last sends the posting contract the
    /// poster, the batch, the hash, the measured cost and the block's time.
    function testPostingChainsTheHashesAndTellsTheDomain() public {
        bytes32[] memory a = _hashes(0, 6);
        bytes32[] memory b = _hashes(6, 3);
        vm.blobhashes(a);
        vm.prank(ANSWERER);
        uint256 g0 = gasleft();
        bp.post(7, ROOT, 6, false);
        console.log("blob post, 6 blobs, not last", g0 - gasleft());
        assertEq(messenger.target(), address(0));
        vm.blobhashes(b);
        vm.prank(ANSWERER);
        g0 = gasleft();
        bp.post(7, ROOT, 3, true);
        console.log("blob post, 3 blobs, last", g0 - gasleft());

        bytes32 acc;
        for (uint256 i = 0; i < 6; ++i) acc = keccak256(abi.encodePacked(acc, a[i]));
        for (uint256 i = 0; i < 3; ++i) acc = keccak256(abi.encodePacked(acc, b[i]));
        bytes32 blobsHash = keccak256(abi.encodePacked(acc, uint256(9)));
        assertEq(messenger.target(), POSTINGS);
        assertEq(messenger.gasLimit(), bp.MESSAGE_GAS());
        (address poster, uint256 id, bytes32 root, bytes32 h, uint256 cost, uint64 at) =
            abi.decode(_args(messenger.message()), (address, uint256, bytes32, bytes32, uint256, uint64));
        assertEq(poster, ANSWERER);
        assertEq(id, 7);
        assertEq(root, ROOT);
        assertEq(h, blobsHash);
        assertEq(at, uint64(block.timestamp));
        // The blob gas at the blob base fee, and at least each call's
        // intrinsic gas at the base fee.
        assertGe(cost, 9 * 131_072 * 3 + 2 * 21_000 * 10 gwei);
        assertLt(cost, 9 * 131_072 * 3 + 2 * 21_000 * 10 gwei + 2 * 400_000 * 10 gwei);
        (bytes32 left,,) = bp.runs(ANSWERER, 7, ROOT);
        assertEq(left, bytes32(0));
    }

    /// The count must be the blobs the transaction carries, no more and no fewer.
    function testWrongCountRefused() public {
        vm.blobhashes(_hashes(0, 4));
        vm.expectRevert(BlobPosting.WrongCount.selector);
        bp.post(7, ROOT, 3, true);
        vm.expectRevert(BlobPosting.WrongCount.selector);
        bp.post(7, ROOT, 5, true);
        vm.expectRevert(BlobPosting.NoBlobs.selector);
        bp.post(7, ROOT, 0, true);
        bp.post(7, ROOT, 4, true);
    }

    /// Posters do not share a chain: another sender's blobs for the same
    /// batch neither join nor spoil the answerer's.
    function testPostersKeepTheirOwnChains() public {
        bytes32[] memory a = _hashes(0, 2);
        vm.blobhashes(a);
        vm.prank(address(0xBAD));
        bp.post(7, ROOT, 2, false);
        vm.prank(ANSWERER);
        bp.post(7, ROOT, 2, true);
        (,, , bytes32 h,,) = abi.decode(_args(messenger.message()), (address, uint256, bytes32, bytes32, uint256, uint64));
        bytes32 acc = keccak256(abi.encodePacked(keccak256(abi.encodePacked(bytes32(0), a[0])), a[1]));
        assertEq(h, keccak256(abi.encodePacked(acc, uint256(2))));
    }

    /// The call's arguments without its selector.
    function _args(bytes memory call) internal pure returns (bytes memory a) {
        a = new bytes(call.length - 4);
        for (uint256 i = 0; i < a.length; ++i) a[i] = call[i + 4];
    }
}
