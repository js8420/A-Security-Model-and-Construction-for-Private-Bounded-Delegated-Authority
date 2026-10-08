// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// One real blob and KZG openings of four of its elements, produced by c-kzg
/// 2.x against the mainnet trusted setup (SourceCode/gen_kzg_vectors.py).
/// Element j holds three Goldilocks lanes, lane l being (3j + l) * 0x9E3779B97F4A7C15 mod p.
library KzgVectors {
    bytes32 internal constant VERSIONED_HASH = 0x0150aabc51a83a46d8114976ea642632dbc776ad9d8d82ccba4bab9e16b22490;
    bytes internal constant COMMITMENT = hex"b7f9e9d0348c176ca4d089e571e0a0f3be68007140a8a6fd3e0a3ffe55a009f79b1de91e9eaa10ef45cbe0b0b8d25fdb";
    uint256 internal constant Y_0 = 0x00000000000000003c6ef373fe94f8299e3779b97f4a7c150000000000000000;
    bytes internal constant PROOF_0 = hex"8983b14601b0a85f22c13c658ffd0db35c26f26938f0de1e2a1d60085561a0a3e6beecd8c581912a194f4cafaf8de1d6";
    uint256 internal constant Y_1 = 0x0000000000000000171560a27c746c6678dde6e7fd29f052daa66d2d7ddf743e;
    bytes internal constant PROOF_1 = hex"8f4a99730590abc17833f1cb505917336cd29b829afcd57e62135c5b67e0c449a7b53ef22bf5ccc251dd27797ff39e31";
    uint256 internal constant Y_777 = 0x0000000000000000df90551e09ccc5c04158db648a8249aba32161aa0b37cd97;
    bytes internal constant PROOF_777 = hex"99a91cf768bb3cf40694ac2c14c3d7e3a98edd8571eca4c52353a89f3df6be682266b127c1104b59703cacdce50cef93";
    uint256 internal constant Y_4095 = 0x0000000000000000c89b6bcd77f956422a63f213f8aeda2d8c2c785979645e19;
    bytes internal constant PROOF_4095 = hex"a93b14626f7ec190394e93e2d1acc51de6893011b9d86d9b8a9f131da87637f02bc3f191d49c7d94e416850cc35d93ab";

    function kzg(uint256 y, bytes memory proof) internal pure returns (bytes memory) {
        return abi.encodePacked(bytes32(y), COMMITMENT, proof);
    }
}
