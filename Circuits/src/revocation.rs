use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::Goldilocks;
use p3_uni_stark::{get_max_constraint_degree, get_symbolic_constraints, AirLayout, SubAirBuilder};

use crate::air::{recompose, RANGE_BITS};
use crate::merkle::{MerkleAir, DIGEST};

type F = Goldilocks;

/// C8, non-revocation, over an accumulator of revoked unit ranges.
///
/// One exhibit suffices because a payment's run is contiguous: reserving from a
/// single counter leaves nothing to wrap around, so the run lies in one gap
/// between consecutive revoked ranges. An earlier revision divided the budget,
/// which made a run wrap and become two segments at opposite ends of a
/// division; that forced either two exhibits on every payment or revocation at
/// the granularity of a division, and we took the second. Neither is needed
/// now.
///
/// A leaf is one revoked range of unit indices together with the start of
/// the next: (start, end, next_start, 0). The comparisons are the argument. An
/// earlier form of this file carried three gap columns and decomposed them into
/// bits, which established that three witnessed values were small and related
/// them to nothing at all: the path held, the decompositions held, the negative
/// control fired, and no revoked range was ever compared against anything.
pub struct NonMembershipAir<const R: usize, const DEPTH: usize> {
    path: MerkleAir<R, DEPTH>,
}

/// Lanes of the exhibited leaf, which is the digest the path starts from.
pub const LEAF_START: usize = 0;
pub const LEAF_END: usize = 1;
pub const LEAF_NEXT: usize = 2;
pub const LEAF_PAD: usize = 3;

/// The run of units the payment consumes, immediately after the path.
pub const RUN_LO: usize = 0;
pub const RUN_HI: usize = 1;
pub const RUN_COLS: usize = 2;

/// lo - start, lo - end - 1, next - hi - 1, and hi - lo.
pub const RANGE_BLOCKS: usize = 4;

impl<const R: usize, const DEPTH: usize> NonMembershipAir<R, DEPTH> {
    pub fn new() -> Self {
        Self { path: MerkleAir::<R, DEPTH>::new() }
    }

    pub(crate) fn path_width(&self) -> usize {
        BaseAir::<F>::width(&self.path)
    }

    /// Where the run columns sit, so the composed circuit can bind them to the
    /// units a payment actually consumes.
    pub(crate) fn run_offset(&self) -> usize {
        self.path_width()
    }

    fn range_base(&self) -> usize {
        self.path_width() + RUN_COLS
    }
}

impl<const R: usize, const DEPTH: usize> NonMembershipAir<R, DEPTH> {
    pub(crate) fn root_offset(&self) -> usize {
        self.path.root_offset()
    }
}

impl<const R: usize, const DEPTH: usize> BaseAir<F> for NonMembershipAir<R, DEPTH> {
    fn width(&self) -> usize {
        self.range_base() + RANGE_BLOCKS * RANGE_BITS
    }
}

impl<AB, const R: usize, const DEPTH: usize> Air<AB> for NonMembershipAir<R, DEPTH>
where
    AB: AirBuilder<F = F>,
{
    fn eval(&self, builder: &mut AB) {
        let pw = self.path_width();

        {
            let mut sub =
                SubAirBuilder::<AB, MerkleAir<R, DEPTH>, F>::new(builder, 0..pw);
            self.path.eval(&mut sub);
        }

        let row = builder.main().current_slice().to_vec();

        let start: AB::Expr = row[LEAF_START].clone().into();
        let end: AB::Expr = row[LEAF_END].clone().into();
        let next: AB::Expr = row[LEAF_NEXT].clone().into();
        let lo: AB::Expr = row[pw + RUN_LO].clone().into();
        let hi: AB::Expr = row[pw + RUN_HI].clone().into();

        // A leaf is a digest and the record occupies three of its four lanes.
        // The fourth is fixed so the path cannot prove inclusion of any leaf
        // agreeing with the record in three elements.
        builder.assert_zero(row[LEAF_PAD].clone());

        let one = AB::Expr::ONE;
        let gaps = [
            lo.clone() - start,
            lo.clone() - end - one.clone(),
            next - hi.clone() - one,
            hi - lo,
        ];

        let rb = self.range_base();
        for (g, gap) in gaps.into_iter().enumerate() {
            let start = rb + g * RANGE_BITS;
            let bits: Vec<AB::Var> =
                row[start..start + RANGE_BITS].iter().cloned().collect();
            for i in 0..bits.len() {
                builder.assert_bool(bits[i].clone());
            }
            builder.assert_eq(gap, recompose::<AB>(&bits));
        }
    }
}

pub fn measure<const R: usize, const DEPTH: usize>() -> (usize, usize, usize) {
    let a = NonMembershipAir::<R, DEPTH>::new();
    let constraints = get_symbolic_constraints::<F, _>(&a, AirLayout::from_air::<F>(&a));
    let degree = get_max_constraint_degree::<F, _>(&a, AirLayout::from_air::<F>(&a));
    (BaseAir::<F>::width(&a), constraints.len(), degree)
}

const _: () = assert!(LEAF_PAD < DIGEST);
