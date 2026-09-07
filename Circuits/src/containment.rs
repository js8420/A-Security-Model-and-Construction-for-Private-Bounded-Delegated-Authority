use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::Goldilocks;
use p3_poseidon2_air::num_cols;
use p3_uni_stark::{get_max_constraint_degree, get_symbolic_constraints, AirLayout, SubAirBuilder};

use crate::air::{recompose, DIGEST, POLICY_ELEMS, RANGE_BITS};
use crate::full::{C9_PERMUTATIONS, RATE};
use crate::hash::{
    new_hash_air, output_offset, HashAir, DOMAIN_OPENING, HALF_FULL_ROUNDS, PARTIAL_ROUNDS,
    SBOX_DEGREE, WIDTH,
};
use crate::merkle::MerkleAir;

type F = Goldilocks;

/// A sub-delegation may not grant more than its parent holds, and the units it
/// is granted must leave the parent's own reach.
///
/// The second half is what nesting alone does not give. Two delegations hold
/// different secrets, so a unit consumed once by a parent and once by a child
/// publishes two shares under one key at two indices with two unknown secrets:
/// three unknowns, two equations, and the hash test fails. A cross-delegation
/// collision is settled value with nothing extractable behind it. Nesting the
/// ranges does not prevent one, and neither does forbidding siblings to
/// overlap, since the parent goes on spending its whole range after granting.
///
/// So each delegation commits g <= m, spends only [base, base + g), and
/// publishes a block [base + p, base + p + 2^j) with g <= p and p + 2^j <= m
/// from which its grants are cut. The reserve refuses a registration whose
/// range leaves the issuer's published block or overlaps one already recorded. Every delegation's spendable set
/// is then disjoint from every other's, the chain's total is bounded by the
/// root's m, and an overspend has to be one delegation colliding with itself,
/// which is the case the tag scheme detects.
///
/// Both policies are opened here rather than assumed. Each party's block is
/// absorbed by its own sponge and the two outputs are public, so the values
/// compared below are the values the two records commit to. Without that the
/// comparisons relate columns the prover chooses.
///
/// What is NOT here is any comparison against the parent's own boundaries. A
/// grant is checked against the parent's published grant block, which is public,
/// so the reserve decides it synchronously without reading a committed value --
/// a reserve refusing at a boundary derived from a hidden budget would be a
/// refusal at a hidden threshold, and the paper's own criterion says such a
/// threshold is recoverable by probing. What this circuit establishes instead is
/// that the CHILD's own block is well formed against the child's committed
/// policy: it begins at or after the child's self-region and ends within what
/// the child holds. Applied at every registration, that is what makes the
/// published blocks down a chain describe disjoint spendable regions.
///
/// Allowlist containment is one Merkle inclusion of the child's root under the
/// parent's, with the path's root bound to the parent's committed root and its
/// leaf to the child's, so the inclusion is about the two committed trees and
/// not about two digests standing beside them.
///
/// That the granted range is a power of two is not checked here: the range is
/// public, so the reserve checks it at registration for nothing.
pub struct ContainmentAir<const R: usize, const DEPTH: usize> {
    merchant: MerkleAir<R, DEPTH>,
    category: MerkleAir<R, DEPTH>,
    hash: HashAir<R>,
}

// A policy block, laid out in the order the opening sponge absorbs it, so the
// column of absorbed element e is e.
const P_B: usize = 0;
const P_C: usize = 1;
const P_TSTART: usize = 2;
const P_TEXP: usize = 3;
const P_N: usize = 4;
const P_W: usize = 5;
const P_G: usize = 6;
const P_MROOT: usize = 7;
const P_CROOT: usize = P_MROOT + DIGEST;
const P_R: usize = P_CROOT + DIGEST;
const POLICY_COLS: usize = P_R + 1;

// The block order is the absorption order, so a divergence between this layout
// and the one the payment circuit commits would be a different commitment over
// the same fields.
const _: () = assert!(POLICY_COLS == POLICY_ELEMS);

const PARENT: usize = 0;
const CHILD: usize = POLICY_COLS;
/// The canonical unit, which turns the two committed values into unit counts.
const C_UNIT: usize = 2 * POLICY_COLS;
const C_CM: usize = C_UNIT + 1;
const C_CG: usize = C_CM + 1;
/// Public, from the child's record: the length of the range it was granted, and
/// the offset and length of the block it publishes for its own sub-delegations.
const C_LEN: usize = C_CG + 1;
const C_P: usize = C_LEN + 1;
const C_BLK: usize = C_P + 1;
const VALUE_COLS: usize = C_BLK + 1;

/// Windows, caps, counts, the units the child may commit, and the two ends of
/// the block it publishes.
pub const GAPS: usize = 7;

/// Both commitments, then the granted length and the child's published block.
pub const PUBLIC_VALUES: usize = 2 * DIGEST + 3;

impl<const R: usize, const DEPTH: usize> ContainmentAir<R, DEPTH> {
    pub fn new() -> Self {
        Self {
            merchant: MerkleAir::<R, DEPTH>::new(),
            category: MerkleAir::<R, DEPTH>::new(),
            hash: new_hash_air::<R>(),
        }
    }

    fn path_width(&self) -> usize {
        BaseAir::<F>::width(&self.merchant)
    }

    fn block_width(&self) -> usize {
        num_cols::<WIDTH, SBOX_DEGREE, R, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>()
    }
}

impl<const R: usize, const DEPTH: usize> BaseAir<F> for ContainmentAir<R, DEPTH> {
    fn width(&self) -> usize {
        VALUE_COLS
            + 2 * self.path_width()
            + 2 * C9_PERMUTATIONS * self.block_width()
            + GAPS * RANGE_BITS
    }

    fn num_public_values(&self) -> usize {
        PUBLIC_VALUES
    }
}

impl<AB, const R: usize, const DEPTH: usize> Air<AB> for ContainmentAir<R, DEPTH>
where
    AB: AirBuilder<F = F>,
{
    fn eval(&self, builder: &mut AB) {
        let pw = self.path_width();
        let bw = self.block_width();
        let m0 = VALUE_COLS;
        let c0 = m0 + pw;
        let s0 = c0 + pw;
        let s1 = s0 + C9_PERMUTATIONS * bw;
        let g0 = s1 + C9_PERMUTATIONS * bw;

        {
            let mut sub = SubAirBuilder::<AB, MerkleAir<R, DEPTH>, F>::new(builder, m0..m0 + pw);
            self.merchant.eval(&mut sub);
        }
        {
            let mut sub = SubAirBuilder::<AB, MerkleAir<R, DEPTH>, F>::new(builder, c0..c0 + pw);
            self.category.eval(&mut sub);
        }
        for i in 0..(2 * C9_PERMUTATIONS) {
            let start = s0 + i * bw;
            let mut sub = SubAirBuilder::<AB, HashAir<R>, F>::new(builder, start..start + bw);
            self.hash.eval(&mut sub);
        }

        // Copied out before any assertion, because public_values() borrows the
        // builder and the assertions need it mutably.
        let pv: Vec<AB::Expr> = builder.public_values().iter().map(|v| (*v).into()).collect();
        let row = builder.main().current_slice().to_vec();

        for (party, block, sbase) in [(0usize, PARENT, s0), (1usize, CHILD, s1)] {
            for e in 0..POLICY_COLS {
                let lane = sbase + (e / RATE) * bw + (e % RATE);
                builder.assert_eq(row[block + e].clone(), row[lane].clone());
            }

            builder.assert_eq(
                row[sbase + RATE].clone().into(),
                AB::Expr::from_u64(DOMAIN_OPENING),
            );
            for lane in (RATE + 1)..WIDTH {
                builder.assert_zero(row[sbase + lane].clone());
            }

            for i in 1..C9_PERMUTATIONS {
                let taken = core::cmp::min(RATE, POLICY_COLS - i * RATE);
                let prev_out = sbase + (i - 1) * bw + output_offset::<R>();
                let next_in = sbase + i * bw;
                for lane in taken..WIDTH {
                    builder.assert_eq(row[prev_out + lane].clone(), row[next_in + lane].clone());
                }
            }

            let last = sbase + (C9_PERMUTATIONS - 1) * bw + output_offset::<R>();
            for j in 0..DIGEST {
                builder.assert_eq(row[last + j].clone().into(), pv[party * DIGEST + j].clone());
            }
        }

        // The path runs from the child's committed root up to the parent's, so
        // the child's permitted set is the leaves beneath a node of the
        // parent's tree and not a tree of its own.
        let mroot = m0 + self.merchant.root_offset();
        let croot = c0 + self.category.root_offset();
        for j in 0..DIGEST {
            builder.assert_eq(row[PARENT + P_MROOT + j].clone(), row[mroot + j].clone());
            builder.assert_eq(row[CHILD + P_MROOT + j].clone(), row[m0 + j].clone());
            builder.assert_eq(row[PARENT + P_CROOT + j].clone(), row[croot + j].clone());
            builder.assert_eq(row[CHILD + P_CROOT + j].clone(), row[c0 + j].clone());
        }

        // The counts the comparisons run over are the committed values divided
        // by the unit, which is the binding the composed circuit makes for one
        // delegation and this one makes for both.
        let u = row[C_UNIT].clone();
        for (count, value) in [(C_CM, CHILD + P_B), (C_CG, CHILD + P_G)] {
            builder.assert_eq(
                u.clone().into() * row[count].clone().into(),
                row[value].clone().into(),
            );
        }

        // Equal windows, so N' <= N compares rates rather than counts.
        builder.assert_eq(row[PARENT + P_W].clone(), row[CHILD + P_W].clone());

        // The granted length and the published block are the ones the record
        // carries and the reserve checked.
        for (k, col) in [C_LEN, C_P, C_BLK].into_iter().enumerate() {
            builder.assert_eq(row[col].clone().into(), pv[2 * DIGEST + k].clone());
        }

        let gaps = [
            row[CHILD + P_TSTART].clone().into() - row[PARENT + P_TSTART].clone().into(),
            row[PARENT + P_TEXP].clone().into() - row[CHILD + P_TEXP].clone().into(),
            row[PARENT + P_C].clone().into() - row[CHILD + P_C].clone().into(),
            row[PARENT + P_N].clone().into() - row[CHILD + P_N].clone().into(),
            // The child cannot commit more units than it was granted.
            row[C_LEN].clone().into() - row[C_CM].clone().into(),
            // Its published block begins at or after its own units end,
            row[C_P].clone().into() - row[C_CG].clone().into(),
            // and ends inside what it holds.
            row[C_CM].clone().into() - row[C_P].clone().into() - row[C_BLK].clone().into(),
        ];
        for (g, gap) in gaps.into_iter().enumerate() {
            let start = g0 + g * RANGE_BITS;
            let bits: Vec<AB::Var> = row[start..start + RANGE_BITS].iter().cloned().collect();
            for i in 0..bits.len() {
                builder.assert_bool(bits[i].clone());
            }
            builder.assert_eq(gap, recompose::<AB>(&bits));
        }
    }
}

pub fn measure<const R: usize, const DEPTH: usize>() -> (usize, usize, usize) {
    let a = ContainmentAir::<R, DEPTH>::new();
    let constraints = get_symbolic_constraints::<F, _>(&a, AirLayout::from_air::<F>(&a));
    let degree = get_max_constraint_degree::<F, _>(&a, AirLayout::from_air::<F>(&a));
    (BaseAir::<F>::width(&a), constraints.len(), degree)
}
