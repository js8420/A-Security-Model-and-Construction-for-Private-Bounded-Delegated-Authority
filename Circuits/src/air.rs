use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};

use crate::hash::WIDTH;

/// Bits used for each range check. Budgets run to ~10^9 canonical units, so 40
/// leaves headroom without paying for a full 64-bit decomposition.
pub const RANGE_BITS: usize = 40;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Clause {
    C1Cap,
    C2Cumulative,
    C3Merchant,
    C4Category,
    C5Temporal,
    C6Velocity,
}

impl Clause {
    pub fn name(&self) -> &'static str {
        match self {
            Clause::C1Cap => "C1 per-payment cap",
            Clause::C2Cumulative => "C2 cumulative budget",
            Clause::C3Merchant => "C3 merchant allowlist",
            Clause::C4Category => "C4 category allowlist",
            Clause::C5Temporal => "C5 validity window",
            Clause::C6Velocity => "C6 velocity",
        }
    }

    /// Range checks this clause needs. C5 needs two, one per endpoint.
    fn range_checks(&self) -> usize {
        match self {
            Clause::C1Cap | Clause::C2Cumulative | Clause::C6Velocity => 1,
            Clause::C5Temporal => 2,
            Clause::C3Merchant | Clause::C4Category => 0,
        }
    }
}

/// The clauses a proof can establish on its own: functions of the policy and
/// the payload, with no spend state in them.
///
/// C2 and C6 are deliberately absent. A cumulative total supplied by the prover
/// is a value the prover chooses, so a constraint over it binds nothing; the
/// budget is enforced by the tree, where exceeding it consumes a node twice.
/// The rate limit is a public policy field and is counted by the reserve, which
/// is the only party that sees every settlement. Both clauses remain in the
/// policy and in the commitment; neither belongs in the circuit.
pub const ALL_CLAUSES: [Clause; 4] = [
    Clause::C1Cap,
    Clause::C3Merchant,
    Clause::C4Category,
    Clause::C5Temporal,
];

/// Every clause, including the two the circuit does not carry, so their cost
/// can still be reported against the clauses that replaced them.
pub const EVERY_CLAUSE: [Clause; 6] = [
    Clause::C1Cap,
    Clause::C2Cumulative,
    Clause::C3Merchant,
    Clause::C4Category,
    Clause::C5Temporal,
    Clause::C6Velocity,
];

/// A digest is half the permutation width. A Merkle root is that many field
/// elements, and the policy carries all of them: a single column would let a
/// prover exhibit any tree agreeing with the committed root in one element.
pub const DIGEST: usize = WIDTH / 2;

// One row per payment, grouped by what each column belongs to, because C9
// commits to the policy group and nothing else.
//
// payment: what this payment is
pub const COL_AMOUNT: usize = 0;
pub const COL_MID: usize = 1;
pub const COL_CID: usize = 2;
pub const COL_T: usize = 3;
/// The party the payment pays. C3 proves that a merchant identifier lies in the
/// committed allowlist; without this column nothing relates that identifier to
/// the recipient, and the allowlist constrains a value no settlement layer ever
/// sees.
pub const COL_PAYEE: usize = 4;
// policy scalars, in commitment order
pub const COL_B: usize = 5;
pub const COL_C: usize = COL_B + 1;
pub const COL_TSTART: usize = COL_C + 1;
pub const COL_TEXP: usize = COL_TSTART + 1;
pub const COL_N: usize = COL_TEXP + 1;
pub const COL_W: usize = COL_N + 1;
/// The part of the budget the delegation keeps for itself, in value. Grants to
/// sub-delegations are cut from what is left, so no two delegations on a chain
/// can spend the same unit --- which matters because they hold different
/// secrets, and a unit consumed by two of them yields two shares under one key
/// with two unknowns behind them and nothing extractable.
pub const COL_G: usize = COL_W + 1;
// policy roots, DIGEST elements each, base index of the first lane
pub const COL_MROOT: usize = COL_G + 1;
pub const COL_CROOT: usize = COL_MROOT + DIGEST;
// blinding value, absorbed last of the policy
pub const COL_R: usize = COL_CROOT + DIGEST;
/// The payload's freshness value. Definition 3 has carried a nonce since the
/// model was written and the circuit had no column for it, so the payload
/// digest could not have been computed from m even in principle.
pub const COL_NONCE: usize = COL_R + 1;
// membership verdicts, bound to the Merkle components in the composed circuit
const COL_MERCHANT_OK: usize = COL_NONCE + 1;
const COL_CATEGORY_OK: usize = COL_MERCHANT_OK + 1;
pub const VALUE_COLS: usize = COL_CATEGORY_OK + 1;

/// The scalar policy fields C9 absorbs, in the order it absorbs them. The two
/// roots follow, DIGEST elements each, then the blinding value.
pub const POLICY_SCALARS: [usize; 7] =
    [COL_B, COL_C, COL_TSTART, COL_TEXP, COL_N, COL_W, COL_G];

/// Elements C9 absorbs from the policy: the scalars, both roots in full, and
/// the blinding value.
pub const POLICY_ELEMS: usize = POLICY_SCALARS.len() + 2 * DIGEST + 1;

/// The payment payload, in the order the C7 sponge absorbs it. These are the
/// six fields of Definition 3 and nothing else: a digest over a subset of them
/// would leave the rest detachable from the proof.
pub const PAYLOAD_SRC: [usize; 6] =
    [COL_AMOUNT, COL_MID, COL_CID, COL_T, COL_PAYEE, COL_NONCE];

pub const PAYLOAD_ELEMS: usize = PAYLOAD_SRC.len();

/// The column an absorbed policy element is drawn from.
pub const fn policy_src(e: usize) -> usize {
    if e < POLICY_SCALARS.len() {
        POLICY_SCALARS[e]
    } else if e < POLICY_SCALARS.len() + DIGEST {
        COL_MROOT + (e - POLICY_SCALARS.len())
    } else if e < POLICY_SCALARS.len() + 2 * DIGEST {
        COL_CROOT + (e - POLICY_SCALARS.len() - DIGEST)
    } else {
        COL_R
    }
}

pub struct PolicyAir {
    pub clauses: Vec<Clause>,
}

impl PolicyAir {
    pub fn new(clauses: &[Clause]) -> Self {
        Self { clauses: clauses.to_vec() }
    }

    fn total_range_checks(&self) -> usize {
        self.clauses.iter().map(|c| c.range_checks()).sum()
    }
}

impl<F: Sync> BaseAir<F> for PolicyAir {
    fn width(&self) -> usize {
        VALUE_COLS + self.total_range_checks() * RANGE_BITS
    }
}

/// Little-endian recomposition, built by doubling so no field constant is needed.
pub(crate) fn recompose<AB: AirBuilder>(bits: &[AB::Var]) -> AB::Expr {
    let mut acc: AB::Expr = bits[bits.len() - 1].clone().into();
    for i in (0..bits.len() - 1).rev() {
        acc = acc.clone() + acc.clone() + bits[i].clone().into();
    }
    acc
}

impl PolicyAir {
    /// The clause constraints, placed at an offset so the composed circuit can
    /// hold them without a second copy of this body.
    pub(crate) fn constrain<AB: AirBuilder>(&self, builder: &mut AB, base: usize) {
        let main = builder.main();
        let row = main.current_slice().to_vec();

        // Range-check blocks are laid out after the value columns in clause order.
        let mut block = 0usize;
        let mut take = |n: usize| {
            let start = base + VALUE_COLS + block * RANGE_BITS;
            block += n;
            start
        };

        let mut checks: Vec<(AB::Expr, usize)> = Vec::new();

        for clause in &self.clauses {
            match clause {
                Clause::C1Cap => {
                    let d = row[base + COL_C].clone().into() - row[base + COL_AMOUNT].clone().into();
                    checks.push((d, take(1)));
                }
                Clause::C5Temporal => {
                    let lo = row[base + COL_T].clone().into() - row[base + COL_TSTART].clone().into();
                    let hi = row[base + COL_TEXP].clone().into() - row[base + COL_T].clone().into();
                    let start = take(2);
                    checks.push((lo, start));
                    checks.push((hi, start + RANGE_BITS));
                }
                Clause::C2Cumulative | Clause::C6Velocity => {
                    unreachable!("state-dependent clauses are not circuit clauses")
                }
                Clause::C3Merchant => {
                    // The identifier the allowlist is checked against is the
                    // party being paid. Proving membership for anything else
                    // constrains a value no settlement layer observes.
                    builder.assert_eq(row[base + COL_MID].clone(), row[base + COL_PAYEE].clone());
                    builder.assert_one(row[base + COL_MERCHANT_OK].clone());
                }
                Clause::C4Category => {
                    builder.assert_one(row[base + COL_CATEGORY_OK].clone());
                }
            }
        }

        for (diff, start) in checks {
            let bits: Vec<AB::Var> =
                row[start..start + RANGE_BITS].iter().cloned().collect();
            for i in 0..bits.len() {
                builder.assert_bool(bits[i].clone());
            }
            builder.assert_eq(diff, recompose::<AB>(&bits));
        }
    }
}

impl<AB: AirBuilder> Air<AB> for PolicyAir {
    fn eval(&self, builder: &mut AB) {
        self.constrain(builder, 0);
    }
}
