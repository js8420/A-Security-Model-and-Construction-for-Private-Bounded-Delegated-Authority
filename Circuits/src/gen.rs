use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::{
    GenericPoseidon2LinearLayersGoldilocks, Goldilocks,
    GOLDILOCKS_POSEIDON2_RC_8_EXTERNAL_FINAL, GOLDILOCKS_POSEIDON2_RC_8_EXTERNAL_INITIAL,
    GOLDILOCKS_POSEIDON2_RC_8_INTERNAL,
};
use p3_matrix::dense::RowMajorMatrix;
use p3_poseidon2_air::{generate_trace_rows, num_cols, RoundConstants};

use crate::hash::{HALF_FULL_ROUNDS, PARTIAL_ROUNDS, SBOX_DEGREE, WIDTH};

type F = Goldilocks;

pub fn constants() -> RoundConstants<F, WIDTH, HALF_FULL_ROUNDS, PARTIAL_ROUNDS> {
    RoundConstants::new(
        GOLDILOCKS_POSEIDON2_RC_8_EXTERNAL_INITIAL,
        GOLDILOCKS_POSEIDON2_RC_8_INTERNAL,
        GOLDILOCKS_POSEIDON2_RC_8_EXTERNAL_FINAL,
    )
}

/// One permutation's worth of columns for a given input state.
///
/// generate_trace_rows lays out one permutation per ROW; the composed circuit
/// places permutations side by side within a row, so the row produced here is
/// what gets copied into a column range. It also insists on a power-of-two row
/// count, hence generating two and keeping the first.
pub fn perm_row<const R: usize>(input: [F; WIDTH]) -> Vec<F> {
    let cols = num_cols::<WIDTH, SBOX_DEGREE, R, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>();
    let m: RowMajorMatrix<F> = generate_trace_rows::<
        F,
        GenericPoseidon2LinearLayersGoldilocks,
        WIDTH,
        SBOX_DEGREE,
        R,
        HALF_FULL_ROUNDS,
        PARTIAL_ROUNDS,
    >(vec![input, input], &constants(), 0);
    m.values[..cols].to_vec()
}

/// The permutation output, which repr(C) places in the final WIDTH columns.
pub fn perm_output<const R: usize>(row: &[F]) -> [F; WIDTH] {
    let cols = num_cols::<WIDTH, SBOX_DEGREE, R, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>();
    let mut out = [F::ZERO; WIDTH];
    out.copy_from_slice(&row[cols - WIDTH..cols]);
    out
}

/// Absorb `elements` in rate-sized chunks, overwriting the rate lanes and
/// carrying the capacity, and return one row per permutation. The first
/// capacity lane starts at the domain separator rather than at zero, so two
/// sponges over the same elements in different roles diverge from the outset.
pub fn sponge<const R: usize>(elements: &[F], rate: usize, domain: u64) -> Vec<Vec<F>> {
    let mut state = [F::ZERO; WIDTH];
    state[rate] = F::from_u64(domain);
    let mut rows = Vec::new();
    for chunk in elements.chunks(rate) {
        for (i, e) in chunk.iter().enumerate() {
            state[i] = *e;
        }
        let row = perm_row::<R>(state);
        state = perm_output::<R>(&row);
        rows.push(row);
    }
    rows
}
