// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// The step the dispute game comes down to.
///
/// Bisection narrows a disagreement about verification to a single step, and
/// something must then decide it. That decision is the verifier's transition
/// function applied once: read the operands the step consumes, re-execute it,
/// and compare the result against the state the defender claimed. Nothing else
/// about the proof matters, which is why one step can be afforded where the
/// whole proof cannot.
///
/// A step here is typed rather than an instruction of a general machine. A FRI
/// verifier does a handful of distinct things, each small, and naming them
/// directly costs far less on chain than emulating a processor executing them.
/// Operands and results live in a commitment the two parties already agree on,
/// so a step carries its own inputs and a path proving they belong.
///
/// Arithmetic is over the Goldilocks field, p = 2^64 - 2^32 + 1. Field
/// elements fit in 64 bits, so their products fit in 128 and `mulmod` on
/// 256-bit words is exact.
interface IPoseidon2 {
    function merkleLevel(uint256[4] memory left, uint256[4] memory right)
        external pure returns (uint256[4] memory);
}

contract StepVerifier {
    uint256 internal constant P = 0xFFFFFFFF00000001;

    /// The permutation the proof's own Merkle trees hash with. Most steps a
    /// dispute can land on are levels of those trees, so without this the
    /// adjudicator decides folds and nothing else.
    IPoseidon2 public immutable algebraic;

    constructor(address poseidon2) {
        algebraic = IPoseidon2(poseidon2);
    }

    enum Step {
        Fold,      // one FRI folding step
        Merkle,    // one level of a keccak-committed path
        Algebraic, // one level of the proof's own Poseidon2 trees
        Linear,    // a linear combination, as constraint batching uses
        Squeeze    // derive a challenge from transcript state
    }

    error BadOperand();
    error PathTooLong();

    /// Modular inverse by Fermat, through the modexp precompile. The exponent
    /// is p-2 and the modulus is p, both constant.
    function inv(uint256 a) public view returns (uint256 r) {
        if (a == 0 || a >= P) revert BadOperand();
        bytes memory input = abi.encode(uint256(32), uint256(32), uint256(32), a, P - 2, P);
        bool ok;
        bytes memory out = new bytes(32);
        assembly {
            ok := staticcall(gas(), 0x05, add(input, 32), 192, add(out, 32), 32)
        }
        require(ok, "modexp");
        r = abi.decode(out, (uint256));
    }

    /// One FRI fold. Given a polynomial's values at x and -x and a challenge
    /// beta, the folded value is the even part plus beta times the odd part:
    ///   even = (f(x) + f(-x)) / 2
    ///   odd  = (f(x) - f(-x)) / 2x
    ///   out  = even + beta * odd
    /// This is the step a FRI verifier repeats down the whole commitment, and
    /// it is the one a dispute most often lands on.
    function fold(uint256 fx, uint256 fnx, uint256 x, uint256 beta)
        public
        view
        returns (uint256)
    {
        if (fx >= P || fnx >= P || x >= P || beta >= P) revert BadOperand();
        uint256 sum = addmod(fx, fnx, P);
        uint256 diff = addmod(fx, P - fnx, P);
        uint256 even = mulmod(sum, inv(2), P);
        uint256 odd = mulmod(diff, inv(mulmod(2, x, P)), P);
        return addmod(even, mulmod(beta, odd, P), P);
    }

    /// One level of a Merkle path over a keccak-committed tree. The reserve
    /// commits with keccak256, so this is exact for the structures it holds; a
    /// trace committed with an algebraic hash needs that hash here instead, and
    /// its permutation is the dominant cost of such a step.
    function merkleStep(bytes32 node, bytes32 sibling, bool rightward)
        public
        pure
        returns (bytes32)
    {
        return rightward
            ? keccak256(abi.encodePacked(node, sibling))
            : keccak256(abi.encodePacked(sibling, node));
    }

    /// A linear combination over the field, as batching several constraints
    /// into one uses. Bounded so a step cannot be made arbitrarily expensive.
    function linear(uint256[] calldata terms, uint256 alpha)
        public
        pure
        returns (uint256 acc)
    {
        if (terms.length > 64) revert PathTooLong();
        for (uint256 i = terms.length; i > 0; --i) {
            uint256 t = terms[i - 1];
            if (t >= P) revert BadOperand();
            acc = addmod(mulmod(acc, alpha, P), t, P);
        }
    }

    /// Walk a Merkle path from a leaf to its root.
    function _pathRoot(bytes32 leaf, bytes32[] calldata path, uint256 idx)
        internal
        pure
        returns (bytes32 node)
    {
        if (path.length > 64) revert PathTooLong();
        node = leaf;
        for (uint256 i = 0; i < path.length; ++i) {
            node = (idx & 1 == 0)
                ? keccak256(abi.encodePacked(node, path[i]))
                : keccak256(abi.encodePacked(path[i], node));
            idx >>= 1;
        }
    }

    /// Re-execute one step from its operands.
    function _execute(Step kind, uint256[] calldata operands)
        internal
        view
        returns (uint256)
    {
        if (kind == Step.Fold) {
            return fold(operands[0], operands[1], operands[2], operands[3]);
        }
        if (kind == Step.Merkle) {
            return uint256(
                merkleStep(bytes32(operands[0]), bytes32(operands[1]), operands[2] != 0)
            );
        }
        if (kind == Step.Linear) {
            uint256 n = operands.length;
            uint256 alpha = operands[n - 1];
            uint256 acc;
            for (uint256 i = n - 1; i > 0; --i) {
                acc = addmod(mulmod(acc, alpha, P), operands[i - 1], P);
            }
            return acc;
        }
        if (kind == Step.Algebraic) {
            uint256[4] memory l;
            uint256[4] memory r;
            for (uint256 i = 0; i < 4; ++i) {
                l[i] = operands[i];
                r[i] = operands[i + 4];
            }
            return algebraic.merkleLevel(l, r)[0];
        }
        return uint256(keccak256(abi.encodePacked(operands))) % P;
    }

    /// Adjudicate one step. The operands and the claimed result are bound to
    /// the state both parties committed to during bisection, so a defender
    /// cannot answer with operands it prefers.
    function adjudicate(
        Step kind,
        uint256[] calldata operands,
        uint256 claimed,
        bytes32 operandRoot,
        bytes32[] calldata path,
        uint256 leafIndex
    ) external view returns (bool) {
        if (_pathRoot(keccak256(abi.encodePacked(operands)), path, leafIndex) != operandRoot) {
            return false;
        }
        return _execute(kind, operands) == claimed;
    }
}
