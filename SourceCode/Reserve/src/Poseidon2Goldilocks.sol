// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// The permutation the proof's Merkle trees hash with, on chain.
///
/// Most of the steps a dispute can land on are Merkle levels, and a Merkle
/// level over this proof is one call to this permutation. Without it the
/// adjudicator decides folding steps and nothing else, which is a dispute an
/// agent can steer away from.
///
/// Width 8 over Goldilocks, p = 2^64 - 2^32 + 1: four full rounds, twenty-two
/// partial rounds, four full rounds, with an x^7 S-box. Field elements fit in
/// 64 bits, so products fit in 128 and `mulmod` on 256-bit words is exact.
///
/// Every constant here is emitted by the crate the prover uses rather than
/// transcribed from a paper, because a contract that hashes differently from
/// the circuit it judges would pass any test that only compares it with
/// itself.
contract Poseidon2Goldilocks {
    uint256 internal constant P = 0xFFFFFFFF00000001;

    function _rcExternalInitial(uint256 r, uint256 i) internal pure returns (uint256) {
        uint64[8][4] memory c = [
            [uint64(15949291268843349465), 14644164809401934923, 18420360874837380316, 4756469047455716334, 8685499049481102115, 3799221349720045367, 13676397835037157930, 6566439050423619635],
            [uint64(17428268347612331188), 2833135872454503769, 4767009016213040191, 2797635963551733652, 5312339450141126694, 5356668452102813289, 1234059326449530173, 7724302552453704877],
            [uint64(14868588146468890290), 12825281145595371185, 13097885453579304196, 7905326782341128063, 14167525334039893569, 2082169701994688927, 12190787523818595537, 12602917751946636],
            [uint64(14890907856876319003), 16552240149997473409, 5634093690795187558, 4883714163685656967, 12440776365164557866, 3923800234666204307, 9858064884105950259, 16040043470428402038]
        ];
        return c[r][i];
    }

    function _rcExternalFinal(uint256 r, uint256 i) internal pure returns (uint256) {
        uint64[8][4] memory c = [
            [uint64(94277733998400326), 10891359798487446420, 18280773820738154043, 13714589910668449566, 10639034072771185213, 14148790895768484219, 18341268649720100165, 3096672942770686236],
            [uint64(12277596046563557393), 400461754528604020, 12955488253560265444, 11773677676764285572, 4833837465239476573, 17645852643693996619, 6605134696140007471, 588040525114200273],
            [uint64(11001741536026769411), 17917086578469406776, 14893530806420712543, 727997185253761138, 3443873847340254325, 13095911531247069692, 8330737046680948619, 6014364575875986011],
            [uint64(16851679856681761121), 17817965496543149594, 12823640325246269760, 13685256787930775147, 4682652317564502291, 4233879762155685988, 11097258179564187322, 10804761421745472094]
        ];
        return c[r][i];
    }

    function _rcInternal(uint256 r) internal pure returns (uint256) {
        uint64[22] memory c = [
            uint64(5226594323142090582), 1243120476974621208, 12100812801659301173, 11228203327983058121,
            13891617888374767564, 5742893160230537107, 3763472116988983643, 2466655769425769160,
            6254574254498162968, 14183251225809189357, 11565357354521717084, 17300657704266685688,
            310485250821938281, 16853586468012618118, 1978800426240373849, 6948188224235462572,
            1486402152218690509, 5669161690283398991, 17943970877073781734, 17926851897715769433,
            13052837496695000666, 18138113741095562305
        ];
        return c[r];
    }

    function _diag(uint256 i) internal pure returns (uint256) {
        uint64[8] memory d = [
            uint64(18446744069414584319), 1, 2, 9223372034707292161,
            3, 9223372034707292160, 18446744069414584318, 18446744069414584317
        ];
        return d[i];
    }

    /// x^7, four multiplications.
    function _sbox(uint256 x) internal pure returns (uint256) {
        uint256 x2 = mulmod(x, x, P);
        uint256 x4 = mulmod(x2, x2, P);
        uint256 x6 = mulmod(x4, x2, P);
        return mulmod(x6, x, P);
    }

    /// The M4 block of the external layer, as Poseidon2 defines it.
    function _mat4(uint256[8] memory s, uint256 o) internal pure {
        uint256 t01 = addmod(s[o], s[o + 1], P);
        uint256 t23 = addmod(s[o + 2], s[o + 3], P);
        uint256 t0123 = addmod(t01, t23, P);
        uint256 t01123 = addmod(t0123, s[o + 1], P);
        uint256 t01233 = addmod(t0123, s[o + 3], P);
        uint256 x0 = s[o];
        uint256 x2 = s[o + 2];
        s[o + 3] = addmod(t01233, addmod(x0, x0, P), P);
        s[o + 1] = addmod(t01123, addmod(x2, x2, P), P);
        s[o] = addmod(t01123, t01, P);
        s[o + 2] = addmod(t01233, t23, P);
    }

    /// M4 on each half, then the circulant sum across halves.
    function _external(uint256[8] memory s) internal pure {
        _mat4(s, 0);
        _mat4(s, 4);
        for (uint256 i = 0; i < 4; ++i) {
            uint256 sum = addmod(s[i], s[i + 4], P);
            s[i] = addmod(s[i], sum, P);
            s[i + 4] = addmod(s[i + 4], sum, P);
        }
    }

    /// The internal layer: a diagonal matrix plus the all-ones matrix.
    function _internal(uint256[8] memory s) internal pure {
        uint256 sum;
        for (uint256 i = 0; i < 8; ++i) sum = addmod(sum, s[i], P);
        for (uint256 i = 0; i < 8; ++i) {
            s[i] = addmod(mulmod(s[i], _diag(i), P), sum, P);
        }
    }

    /// One permutation of the state, in place.
    function permute(uint256[8] memory s) public pure returns (uint256[8] memory) {
        _external(s);

        for (uint256 r = 0; r < 4; ++r) {
            for (uint256 i = 0; i < 8; ++i) {
                s[i] = _sbox(addmod(s[i], _rcExternalInitial(r, i), P));
            }
            _external(s);
        }

        for (uint256 r = 0; r < 22; ++r) {
            s[0] = _sbox(addmod(s[0], _rcInternal(r), P));
            _internal(s);
        }

        for (uint256 r = 0; r < 4; ++r) {
            for (uint256 i = 0; i < 8; ++i) {
                s[i] = _sbox(addmod(s[i], _rcExternalFinal(r, i), P));
            }
            _external(s);
        }
        return s;
    }

    /// One Merkle level over the proof's own trees: two four-element digests
    /// absorbed into the permutation, the first four elements taken out.
    function merkleLevel(uint256[4] memory left, uint256[4] memory right)
        public
        pure
        returns (uint256[4] memory out)
    {
        uint256[8] memory s;
        for (uint256 i = 0; i < 4; ++i) {
            s[i] = left[i];
            s[i + 4] = right[i];
        }
        s = permute(s);
        for (uint256 i = 0; i < 4; ++i) out[i] = s[i];
    }
}
