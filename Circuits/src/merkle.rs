use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_goldilocks::Goldilocks;
use p3_poseidon2_air::num_cols;
use p3_uni_stark::{get_max_constraint_degree, get_symbolic_constraints, AirLayout, SubAirBuilder};

use crate::hash::{new_hash_air, output_offset, HashAir, HALF_FULL_ROUNDS, PARTIAL_ROUNDS, SBOX_DEGREE, WIDTH};

type F = Goldilocks;

/// A digest is half the permutation width, so one permutation compresses a
/// pair of digests into one.
pub const DIGEST: usize = WIDTH / 2;

/// Merkle inclusion of a leaf under a committed root: one permutation per
/// level, with a direction bit selecting which side the sibling sits on.
///
/// Per level the layout is digest-in, sibling, direction bit, permutation block.
pub struct MerkleAir<const R: usize, const DEPTH: usize> {
    hash: HashAir<R>,
}

impl<const R: usize, const DEPTH: usize> MerkleAir<R, DEPTH> {
    pub fn new() -> Self {
        Self { hash: new_hash_air::<R>() }
    }

    pub(crate) fn block_width(&self) -> usize {
        num_cols::<WIDTH, SBOX_DEGREE, R, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>()
    }

    pub(crate) fn level_width(&self) -> usize {
        DIGEST + DIGEST + 1 + self.block_width()
    }
}

impl<const R: usize, const DEPTH: usize> MerkleAir<R, DEPTH> {
    /// The root digest sits after the per-level blocks.
    pub(crate) fn root_offset(&self) -> usize {
        DEPTH * self.level_width()
    }
}

impl<const R: usize, const DEPTH: usize> BaseAir<F> for MerkleAir<R, DEPTH> {
    fn width(&self) -> usize {
        DEPTH * self.level_width() + DIGEST
    }
}

impl<AB, const R: usize, const DEPTH: usize> Air<AB> for MerkleAir<R, DEPTH>
where
    AB: AirBuilder<F = F>,
{
    fn eval(&self, builder: &mut AB) {
        let lw = self.level_width();
        let bw = self.block_width();

        for level in 0..DEPTH {
            let base = level * lw;
            let perm_start = base + DIGEST + DIGEST + 1;

            let mut sub =
                SubAirBuilder::<AB, HashAir<R>, F>::new(builder, perm_start..perm_start + bw);
            self.hash.eval(&mut sub);

            let row = builder.main().current_slice().to_vec();
            let bit = row[base + 2 * DIGEST].clone();
            builder.assert_bool(bit.clone());

            for j in 0..DIGEST {
                let cur = row[base + j].clone();
                let sib = row[base + DIGEST + j].clone();

                // left = cur + bit*(sib - cur), right = sib + bit*(cur - sib).
                // Written this way so no field constant one is needed.
                let left = cur.clone().into()
                    + bit.clone().into() * (sib.clone().into() - cur.clone().into());
                let right = sib.clone().into()
                    + bit.clone().into() * (cur.clone().into() - sib.clone().into());

                builder.assert_eq(left, row[perm_start + j].clone());
                builder.assert_eq(right, row[perm_start + DIGEST + j].clone());

                // The compressed output feeds the next level's digest-in. It is
                // the final round's post state, not the input.
                let out = row[perm_start + output_offset::<R>() + j].clone();
                let next = if level + 1 < DEPTH {
                    row[(level + 1) * lw + j].clone()
                } else {
                    row[DEPTH * lw + j].clone()
                };
                builder.assert_eq(out, next);
            }
        }
    }
}

pub fn measure<const R: usize, const DEPTH: usize>() -> (usize, usize, usize) {
    let a = MerkleAir::<R, DEPTH>::new();
    let constraints = get_symbolic_constraints::<F, _>(&a, AirLayout::from_air::<F>(&a));
    let degree = get_max_constraint_degree::<F, _>(&a, AirLayout::from_air::<F>(&a));
    (BaseAir::<F>::width(&a), constraints.len(), degree)
}
