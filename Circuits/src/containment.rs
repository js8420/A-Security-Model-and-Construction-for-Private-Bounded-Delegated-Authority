use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::Goldilocks;
use p3_uni_stark::{get_max_constraint_degree, get_symbolic_constraints, AirLayout, SubAirBuilder};

use crate::air::{recompose, RANGE_BITS};
use crate::merkle::MerkleAir;

type F = Goldilocks;

/// A sub-delegation may not grant more than its parent holds.
///
/// Allowlist containment is one Merkle inclusion of the child's root under the
/// parent's, since the child's root is required to be a NODE of the parent's
/// tree rather than an arbitrary root. Proving instead that every leaf of the
/// child's set lies under the parent root would be linear in that set.
///
/// The rest is six comparisons and one equality. The velocity windows are
/// required equal, which reduces comparing two rates to comparing two counts.
pub struct ContainmentAir<const R: usize, const DEPTH: usize> {
    merchant: MerkleAir<R, DEPTH>,
    category: MerkleAir<R, DEPTH>,
}

const C_TSTART: usize = 0;
const C_TSTART_SUB: usize = 1;
const C_TEXP: usize = 2;
const C_TEXP_SUB: usize = 3;
const C_CAP: usize = 4;
const C_CAP_SUB: usize = 5;
const C_N: usize = 6;
const C_N_SUB: usize = 7;
const C_W: usize = 8;
const C_W_SUB: usize = 9;
const C_START: usize = 10;
const C_START_SUB: usize = 11;
const C_END: usize = 12;
const C_END_SUB: usize = 13;
const VALUE_COLS: usize = 14;

/// Windows, caps, counts and the two ends of the unit range.
pub const GAPS: usize = 6;

impl<const R: usize, const DEPTH: usize> ContainmentAir<R, DEPTH> {
    pub fn new() -> Self {
        Self {
            merchant: MerkleAir::<R, DEPTH>::new(),
            category: MerkleAir::<R, DEPTH>::new(),
        }
    }

    fn path_width(&self) -> usize {
        BaseAir::<F>::width(&self.merchant)
    }
}

impl<const R: usize, const DEPTH: usize> BaseAir<F> for ContainmentAir<R, DEPTH> {
    fn width(&self) -> usize {
        VALUE_COLS + 2 * self.path_width() + GAPS * RANGE_BITS
    }
}

impl<AB, const R: usize, const DEPTH: usize> Air<AB> for ContainmentAir<R, DEPTH>
where
    AB: AirBuilder<F = F>,
{
    fn eval(&self, builder: &mut AB) {
        let pw = self.path_width();
        let m0 = VALUE_COLS;
        let c0 = m0 + pw;
        let g0 = c0 + pw;

        {
            let mut sub = SubAirBuilder::<AB, MerkleAir<R, DEPTH>, F>::new(builder, m0..m0 + pw);
            self.merchant.eval(&mut sub);
        }
        {
            let mut sub = SubAirBuilder::<AB, MerkleAir<R, DEPTH>, F>::new(builder, c0..c0 + pw);
            self.category.eval(&mut sub);
        }

        let row = builder.main().current_slice().to_vec();

        // Equal windows, so N' <= N compares rates rather than counts.
        builder.assert_eq(row[C_W].clone(), row[C_W_SUB].clone());


        let gaps = [
            row[C_TSTART_SUB].clone().into() - row[C_TSTART].clone().into(),
            row[C_TEXP].clone().into() - row[C_TEXP_SUB].clone().into(),
            row[C_CAP].clone().into() - row[C_CAP_SUB].clone().into(),
            row[C_N].clone().into() - row[C_N_SUB].clone().into(),
            row[C_START_SUB].clone().into() - row[C_START].clone().into(),
            row[C_END].clone().into() - row[C_END_SUB].clone().into(),
        ];
        for (g, gap) in gaps.into_iter().enumerate() {
            let start = g0 + g * RANGE_BITS;
            let bits: Vec<AB::Var> = row[start..start + RANGE_BITS].iter().cloned().collect();
            for i in 0..bits.len() {
                builder.assert_bool(bits[i].clone());
            }
            builder.assert_eq(gap, recompose::<AB>(&bits));
        }
        let _ = AB::Expr::ONE;
    }
}

pub fn measure<const R: usize, const DEPTH: usize>() -> (usize, usize, usize) {
    let a = ContainmentAir::<R, DEPTH>::new();
    let constraints = get_symbolic_constraints::<F, _>(&a, AirLayout::from_air::<F>(&a));
    let degree = get_max_constraint_degree::<F, _>(&a, AirLayout::from_air::<F>(&a));
    (BaseAir::<F>::width(&a), constraints.len(), degree)
}
