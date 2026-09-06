use p3_air::BaseAir;
use p3_goldilocks::{
    GenericPoseidon2LinearLayersGoldilocks, Goldilocks,
    GOLDILOCKS_POSEIDON2_RC_8_EXTERNAL_FINAL, GOLDILOCKS_POSEIDON2_RC_8_EXTERNAL_INITIAL,
    GOLDILOCKS_POSEIDON2_RC_8_INTERNAL,
};
use p3_poseidon2_air::{num_cols, Poseidon2Air, RoundConstants};
use p3_uni_stark::{get_max_constraint_degree, get_symbolic_constraints, AirLayout};

pub const WIDTH: usize = 8;
pub const SBOX_DEGREE: u64 = 7;
pub const HALF_FULL_ROUNDS: usize = 4;
pub const PARTIAL_ROUNDS: usize = 22;

/// Domain separators absorbed by each in-circuit use of this permutation, so
/// that a collision found in one cannot be transported to another.
///
/// The circuit uses the permutation three ways. The opening sponge starts its
/// capacity at DOMAIN_OPENING rather than at zero, which also constrains an
/// initial state that was previously left to the prover. Key derivation carries
/// DOMAIN_KEY in the lane after the direction bit. Merkle compression carries no
/// tag and needs none: it is the only use whose input occupies the full width,
/// while the others pad with zeros, so its input domain is disjoint from theirs
/// by shape.
pub const DOMAIN_OPENING: u64 = 1;
pub const DOMAIN_KEY: u64 = 2;

/// Padding slots derive their key from the root key, the payload digest and the
/// slot position rather than from a parent, so the key is fresh for every
/// payment and every slot and no two padding shares ever stand under one key.
/// It carries its own separator so a padding derivation cannot be confused with
/// a real one.
pub const DOMAIN_PAD: u64 = 3;

/// The payload sponge, which computes H(m) from the payment's own columns. C7
/// requires the proof to be bound to the payment; absorbing a supplied digest
/// into the opening sponge bound it to a number the verifier chose and the
/// circuit never related to any field of m.
pub const DOMAIN_PAYLOAD: u64 = 4;

/// The nullifier, when it is derived by a second invocation rather than read
/// from a spare lane of the key's permutation. Under that variant the nullifier
/// is a pseudorandom function of the key and nothing about the key is published
/// beside it, so the joint-lane assumption of the tag construction is not
/// needed and an ordinary PRF assumption suffices.
pub const DOMAIN_NULL: u64 = 5;

type F = Goldilocks;

pub type HashAir<const R: usize> = Poseidon2Air<
    F,
    GenericPoseidon2LinearLayersGoldilocks,
    WIDTH,
    SBOX_DEGREE,
    R,
    HALF_FULL_ROUNDS,
    PARTIAL_ROUNDS,
>;

/// Poseidon2Cols lays out inputs, then the beginning full rounds, the partial
/// rounds, and the ending full rounds. The permutation output is the `post`
/// state of the final full round, so it occupies the last WIDTH columns.
pub fn output_offset<const R: usize>() -> usize {
    num_cols::<WIDTH, SBOX_DEGREE, R, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>() - WIDTH
}

pub fn new_hash_air<const R: usize>() -> HashAir<R> {
    Poseidon2Air::new(constants())
}

fn constants() -> RoundConstants<F, WIDTH, HALF_FULL_ROUNDS, PARTIAL_ROUNDS> {
    // The published Goldilocks constants, not random ones. Their shapes line up
    // with WIDTH 8, four half-full rounds and 22 partial rounds.
    RoundConstants::new(
        GOLDILOCKS_POSEIDON2_RC_8_EXTERNAL_INITIAL,
        GOLDILOCKS_POSEIDON2_RC_8_INTERNAL,
        GOLDILOCKS_POSEIDON2_RC_8_EXTERNAL_FINAL,
    )
}

/// (columns, constraints, max degree) for one permutation at the given
/// number of S-box registers.
pub fn measure<const R: usize>() -> (usize, usize, usize) {
    let air: HashAir<R> = new_hash_air::<R>();
    let constraints = get_symbolic_constraints::<F, _>(&air, AirLayout::from_air::<F>(&air));
    let degree = get_max_constraint_degree::<F, _>(&air, AirLayout::from_air::<F>(&air));
    let cols = num_cols::<WIDTH, SBOX_DEGREE, R, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>();
    debug_assert_eq!(cols, BaseAir::<F>::width(&air));
    (cols, constraints.len(), degree)
}
