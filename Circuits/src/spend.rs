use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::Goldilocks;
use p3_poseidon2_air::num_cols;
use p3_uni_stark::{get_max_constraint_degree, get_symbolic_constraints, AirLayout, SubAirBuilder};

use crate::air::{recompose, RANGE_BITS};
use crate::hash::{
    new_hash_air, output_offset, HashAir, DOMAIN_KEY, DOMAIN_PAD, HALF_FULL_ROUNDS, PARTIAL_ROUNDS,
    SBOX_DEGREE, WIDTH,
};

type F = Goldilocks;

/// One payment's spend against the budget: which units it consumes, that their
/// keys belong to the positions claimed, and the shares published under them.
///
/// Consumption is at the level of single units and nowhere else. An earlier form
/// let a payment consume an aligned block of many units as one node, which is
/// cheaper and unsound: two payments can then overlap without consuming a common
/// node, one taking the block and the other the units inside it, and their
/// shares stand under keys related by a derivation no reader can invert.
/// Overspending was undetectable by spending coarsely once and finely
/// afterwards. Restricting consumption to single units removes the case, because
/// two overlapping payments share a unit and a shared unit is a shared key.
///
/// With the block structure gone there is no reason to derive keys through a
/// tree: the tree existed to relate an ancestor's key to a descendant's, which
/// is exactly the relation that failed. A unit's key is one application of the
/// permutation to the root key and the unit's index.
///
/// The constraints live in `constrain` rather than in `eval` so the composed
/// circuit can place them at an offset. Copying them into a second AIR is what
/// the layout comment in spend_trace.rs is about, and it went wrong three times.
pub struct SpendAir<const R: usize, const DEPTH: usize, const COVER: usize> {
    hash: HashAir<R>,
}

/// Field elements in the secret and in a key. One Goldilocks element is about
/// 64 bits and H(s) is public, so a scalar secret would fall to a search cheaper
/// than every other assumption the scheme makes.
pub const SECRET_ELEMS: usize = 2;

/// r is non-negative; the run ends within the units the delegation kept for
/// itself; the delegation's padded range lies inside the deployment's index
/// space; and what it kept does not exceed what it holds.
///
/// The second is the only refusal this circuit performs. Its threshold is the
/// self-region g, which equals m = B/u for a delegation that grants nothing and
/// is committed alongside B in either case, so the bound-privacy game excludes
/// it as a trivial win on the same terms. An earlier revision divided the budget
/// and needed six checks, three of which refused at thresholds below the budget
/// and were open refusal channels.
pub const RANGE_BLOCKS: usize = 4;

pub const COL_SECRET: usize = 0;
pub const COL_INDEX: usize = COL_SECRET + SECRET_ELEMS;
pub const COL_INDEX_INV: usize = COL_INDEX + 1;
pub const COL_ROOT_KEY: usize = COL_INDEX_INV + 1;
/// The spendable unit count, m = B/u, committed with the policy. It is the one
/// threshold at which this circuit refuses, and it is the budget --- which the
/// bound-privacy game excludes as a trivial win, so the refusal channel it
/// opens is closed in the sense of the model's Definition 15.
pub const COL_M: usize = COL_ROOT_KEY + SECRET_ELEMS;
/// The units the delegation may consume itself. The rest of what it holds is
/// what it may grant away, and a run is checked against this rather than
/// against the whole holding.
pub const COL_SELF: usize = COL_M + 1;
/// Where the payment's run starts, and how many units it charges. The run is
/// [r, r + units) and it is contiguous: reserving from a single counter leaves
/// nothing to wrap around.
pub const COL_R: usize = COL_SELF + 1;
pub const COL_UNITS: usize = COL_R + 1;
/// The first index of the delegation's padded range.
pub const COL_BASE: usize = COL_UNITS + 1;
pub const FIXED_COLS: usize = COL_BASE + 1;

/// Per slot. The consumed unit's index is the running position and is not
/// stored a second time.
pub const NODE_ACTIVE: usize = 0;
pub const NODE_KEY: usize = 1;
pub const NODE_SHARE: usize = NODE_KEY + SECRET_ELEMS;
pub const NODE_NULL: usize = NODE_SHARE + SECRET_ELEMS;
pub const PER_NODE: usize = NODE_NULL + 1;

impl<const R: usize, const DEPTH: usize, const COVER: usize> SpendAir<R, DEPTH, COVER> {
    pub fn new() -> Self {
        Self { hash: new_hash_air::<R>() }
    }

    pub(crate) fn block_width(&self) -> usize {
        num_cols::<WIDTH, SBOX_DEGREE, R, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>()
    }

    pub(crate) fn node_base_pub(&self) -> usize {
        self.node_base()
    }

    /// One derivation per slot and nothing else. The tree's boundary walk cost
    /// 2*DEPTH permutations on every payment whatever it spent.
    pub const fn permutations() -> usize {
        COVER
    }

    /// The running offset of the consumed units within the delegation's range.
    /// The consumed unit is the range's base plus this. Runs are contiguous and
    /// an offset that would leave the range has no satisfying witness.
    pub(crate) fn pos_base(&self) -> usize {
        FIXED_COLS
    }

    fn range_base(&self) -> usize {
        self.pos_base() + COVER + 1
    }

    fn node_base(&self) -> usize {
        self.range_base() + RANGE_BLOCKS * RANGE_BITS
    }

    pub(crate) fn value_cols(&self) -> usize {
        self.node_base() + PER_NODE * COVER
    }

    pub(crate) fn constrain<AB>(&self, builder: &mut AB, base: usize)
    where
        AB: AirBuilder<F = F>,
    {
        self.constrain_with(builder, base, false);
    }

    /// The same constraints, with the nullifier optionally left to the caller.
    /// `external_nullifier = true` omits only the equality tying a slot's
    /// nullifier to a spare lane of the permutation that produced its key, so
    /// the variant of \cref{sec:eval:secondinv} can derive it from a second
    /// invocation instead and be measured against this one.
    pub(crate) fn constrain_with<AB>(&self, builder: &mut AB, base: usize, external_nullifier: bool)
    where
        AB: AirBuilder<F = F>,
    {
        let bw = self.block_width();
        let vals = base + self.value_cols();

        for i in 0..Self::permutations() {
            let s = vals + i * bw;
            let mut sub = SubAirBuilder::<AB, HashAir<R>, F>::new(builder, s..s + bw);
            self.hash.eval(&mut sub);
        }

        let pv: Vec<AB::Expr> = builder.public_values().iter().map(|v| (*v).into()).collect();
        let row = builder.main().current_slice().to_vec();

        let secret: Vec<AB::Var> =
            (0..SECRET_ELEMS).map(|j| row[base + COL_SECRET + j].clone()).collect();
        let index = row[base + COL_INDEX].clone();
        let m = row[base + COL_M].clone();
        let self_units = row[base + COL_SELF].clone();
        let r = row[base + COL_R].clone();
        let units = row[base + COL_UNITS].clone();
        let pbase = row[base + COL_BASE].clone();

        builder.assert_eq(index.clone().into(), pv[0].clone());
        builder.assert_one(index.clone().into() * row[base + COL_INDEX_INV].clone().into());

        let mut two_pow: Vec<AB::Expr> = Vec::with_capacity(DEPTH + 1);
        let mut p: AB::Expr = AB::Expr::ONE;
        for _ in 0..=DEPTH {
            two_pow.push(p.clone());
            p = p.clone() + p.clone();
        }

        let posb = base + self.pos_base();
        let rb = base + self.range_base();
        let gaps = [
            r.clone().into(),
            self_units.clone().into() - r.clone().into() - units.clone().into(),
            two_pow[DEPTH].clone() - pbase.clone().into() - m.clone().into(),
            m.clone().into() - self_units.clone().into(),
        ];
        for (g, gap) in gaps.into_iter().enumerate() {
            let start = rb + g * RANGE_BITS;
            let bits: Vec<AB::Var> = row[start..start + RANGE_BITS].iter().cloned().collect();
            for b in &bits {
                builder.assert_bool(b.clone());
            }
            builder.assert_eq(gap, recompose::<AB>(&bits));
        }

        // The consumed units are the contiguous run [r, r + units) inside the
        // delegation's range. There is nothing to wrap around: a payment
        // reserves at the counter value it finds, and the second gap above is
        // the only threshold at which this circuit refuses --- the units the
        // delegation kept for itself, which is the budget for a delegation that
        // grants nothing and is committed either way, so the bound-privacy game
        // excludes it.
        let nb = base + self.node_base();
        builder.assert_eq(row[posb].clone().into(), r.clone().into());

        let mut charged: AB::Expr = AB::Expr::ZERO;
        for c in 0..COVER {
            let n = nb + c * PER_NODE;
            let active = row[n + NODE_ACTIVE].clone();
            builder.assert_bool(active.clone());
            charged = charged + active.clone().into();
            builder.assert_eq(
                row[posb + c + 1].clone().into(),
                row[posb + c].clone().into() + active.clone().into(),
            );

            // A real slot derives from the root key and the unit index; a padded
            // slot from the root key, the payload digest and its own position.
            // The separator lane differs, so the two occupy disjoint input
            // domains and a padding key can never coincide with a real one.
            let blk = vals + c * bw;
            let inactive: AB::Expr = AB::Expr::ONE - active.clone().into();
            for j in 0..SECRET_ELEMS {
                builder.assert_eq(
                    row[blk + j].clone().into(),
                    row[base + COL_ROOT_KEY + j].clone().into(),
                );
            }
            builder.assert_eq(
                row[blk + SECRET_ELEMS].clone().into(),
                active.clone().into()
                    * (pbase.clone().into() + row[posb + c].clone().into())
                    + inactive.clone() * index.clone().into(),
            );
            builder.assert_eq(
                row[blk + SECRET_ELEMS + 1].clone().into(),
                active.clone().into() * AB::Expr::from_u64(DOMAIN_KEY)
                    + inactive.clone() * AB::Expr::from_u64(DOMAIN_PAD),
            );
            builder.assert_eq(
                row[blk + SECRET_ELEMS + 2].clone().into(),
                inactive.clone() * AB::Expr::from_u64(c as u64 + 1),
            );
            for lane in (SECRET_ELEMS + 3)..WIDTH {
                builder.assert_zero(row[blk + lane].clone());
            }

            // Key, nullifier and share come from one permutation output and hold
            // on every slot, so a padded share is indistinguishable from a real
            // one and contributes nothing an extractor can use.
            for j in 0..SECRET_ELEMS {
                builder.assert_eq(
                    row[n + NODE_KEY + j].clone().into(),
                    row[blk + output_offset::<R>() + j].clone().into(),
                );
                builder.assert_eq(
                    row[n + NODE_SHARE + j].clone().into(),
                    secret[j].clone().into()
                        + row[n + NODE_KEY + j].clone().into() * index.clone().into(),
                );
            }
            if !external_nullifier {
                builder.assert_eq(
                    row[n + NODE_NULL].clone().into(),
                    row[blk + output_offset::<R>() + SECRET_ELEMS].clone().into(),
                );
            }
        }

        builder.assert_eq(charged, units.clone().into());
    }
}

impl<const R: usize, const DEPTH: usize, const COVER: usize> BaseAir<F>
    for SpendAir<R, DEPTH, COVER>
{
    fn width(&self) -> usize {
        self.value_cols() + Self::permutations() * self.block_width()
    }

    /// The payload digest, which is the share index.
    fn num_public_values(&self) -> usize {
        1
    }
}

impl<AB, const R: usize, const DEPTH: usize, const COVER: usize> Air<AB>
    for SpendAir<R, DEPTH, COVER>
where
    AB: AirBuilder<F = F>,
{
    fn eval(&self, builder: &mut AB) {
        self.constrain(builder, 0);
    }
}

pub fn measure<const R: usize, const DEPTH: usize, const COVER: usize>(
) -> (usize, usize, usize) {
    let a = SpendAir::<R, DEPTH, COVER>::new();
    let constraints = get_symbolic_constraints::<F, _>(&a, AirLayout::from_air::<F>(&a));
    let degree = get_max_constraint_degree::<F, _>(&a, AirLayout::from_air::<F>(&a));
    (BaseAir::<F>::width(&a), constraints.len(), degree)
}
