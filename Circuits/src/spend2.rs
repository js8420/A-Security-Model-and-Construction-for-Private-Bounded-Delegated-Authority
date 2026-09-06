use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::Goldilocks;
use p3_uni_stark::{get_max_constraint_degree, get_symbolic_constraints, AirLayout, SubAirBuilder};

use crate::hash::{new_hash_air, output_offset, HashAir, DOMAIN_NULL, WIDTH};
use crate::spend::{SpendAir, NODE_KEY, NODE_NULL, PER_NODE, SECRET_ELEMS};

type F = Goldilocks;

/// The accountability half with the nullifier derived by a second invocation of
/// the permutation rather than read from a spare lane of the first.
///
/// As built, a slot runs one permutation and publishes three lanes of its
/// output: two as the share's key and one as the nullifier. Exculpability and
/// bound privacy therefore need those lanes to be jointly pseudorandom --- the
/// assumption of the tag construction, which does not follow from $F$ being a
/// pseudorandom function and which both propositions consume.
///
/// Here the key comes from the first permutation and the nullifier is
/// $F(K_v, \\mathsf{null})$ from a second, so nothing about the key is published
/// beside it and an ordinary PRF assumption suffices. The cost is one further
/// permutation per slot, which is what this AIR exists to measure.
pub struct SpendTwoAir<const R: usize, const DEPTH: usize, const COVER: usize> {
    inner: SpendAir<R, DEPTH, COVER>,
    hash: HashAir<R>,
}

impl<const R: usize, const DEPTH: usize, const COVER: usize> SpendTwoAir<R, DEPTH, COVER> {
    pub fn new() -> Self {
        Self {
            inner: SpendAir::<R, DEPTH, COVER>::new(),
            hash: new_hash_air::<R>(),
        }
    }

    /// Where the second round of permutations begins: after everything the
    /// single-invocation AIR uses.
    pub fn null_base(&self) -> usize {
        BaseAir::<F>::width(&self.inner)
    }
}

impl<const R: usize, const DEPTH: usize, const COVER: usize> BaseAir<F>
    for SpendTwoAir<R, DEPTH, COVER>
{
    fn width(&self) -> usize {
        self.null_base() + COVER * self.inner.block_width()
    }

    fn num_public_values(&self) -> usize {
        1
    }
}

impl<AB, const R: usize, const DEPTH: usize, const COVER: usize> Air<AB>
    for SpendTwoAir<R, DEPTH, COVER>
where
    AB: AirBuilder<F = F>,
{
    fn eval(&self, builder: &mut AB) {
        // Everything the single-invocation AIR constrains, except the tie
        // between a slot's nullifier and a lane of its key's permutation.
        self.inner.constrain_with(builder, 0, true);

        let bw = self.inner.block_width();
        let nb = self.null_base();
        for c in 0..COVER {
            let s = nb + c * bw;
            let mut sub = SubAirBuilder::<AB, HashAir<R>, F>::new(builder, s..s + bw);
            self.hash.eval(&mut sub);
        }

        let row = builder.main().current_slice().to_vec();
        let node = self.inner.node_base_pub();

        for c in 0..COVER {
            let blk = nb + c * bw;
            let n = node + c * PER_NODE;

            // The second invocation takes the key and its own separator, so its
            // input domain is disjoint from every other use of the permutation.
            for j in 0..SECRET_ELEMS {
                builder.assert_eq(
                    row[blk + j].clone().into(),
                    row[n + NODE_KEY + j].clone().into(),
                );
            }
            builder.assert_eq(
                row[blk + SECRET_ELEMS].clone().into(),
                AB::Expr::from_u64(DOMAIN_NULL),
            );
            for lane in (SECRET_ELEMS + 1)..WIDTH {
                builder.assert_zero(row[blk + lane].clone());
            }

            builder.assert_eq(
                row[n + NODE_NULL].clone().into(),
                row[blk + output_offset::<R>()].clone().into(),
            );
        }
    }
}

pub fn measure<const R: usize, const DEPTH: usize, const COVER: usize>(
) -> (usize, usize, usize) {
    let a = SpendTwoAir::<R, DEPTH, COVER>::new();
    let constraints = get_symbolic_constraints::<F, _>(&a, AirLayout::from_air::<F>(&a));
    let degree = get_max_constraint_degree::<F, _>(&a, AirLayout::from_air::<F>(&a));
    (BaseAir::<F>::width(&a), constraints.len(), degree)
}
