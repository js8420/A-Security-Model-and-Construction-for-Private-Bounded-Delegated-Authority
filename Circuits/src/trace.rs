use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::Goldilocks;
use p3_matrix::dense::RowMajorMatrix;

use crate::gen::{perm_output, sponge};
use crate::hash::{DOMAIN_OPENING, DOMAIN_PAYLOAD};
use crate::hash::WIDTH;
use p3_poseidon2_air::num_cols;
use crate::hash::{HALF_FULL_ROUNDS, PARTIAL_ROUNDS, SBOX_DEGREE};
use crate::air::{
    RANGE_BITS, COL_AMOUNT, COL_B, COL_C, COL_CID, COL_CROOT, COL_MID, COL_MROOT,
    COL_G, COL_N, COL_NONCE, COL_PAYEE, COL_R, COL_T, COL_TEXP, COL_TSTART, COL_W, DIGEST,
    PAYLOAD_SRC, VALUE_COLS,
};
use crate::full::C9_PERMUTATIONS;
use crate::whole::PAYLOAD_PERMUTATIONS;

type F = Goldilocks;

/// The payload digest is no longer a constant. It is the output of the C7
/// sponge over the payment's own columns, so a verifier supplies a value the
/// circuit recomputes rather than one it absorbs on trust.

const COL_MERCHANT_OK: usize = VALUE_COLS - 2;
const COL_CATEGORY_OK: usize = VALUE_COLS - 1;

/// Range-check blocks the policy AIR allocates: C1, then C5's two endpoints.
const GAP_BLOCKS: usize = 3;

/// A payment that satisfies every clause, with room to spare in each gap so a
/// single off-by-one in the circuit shows up as a failed decomposition rather
/// than as a borderline pass.
struct Row {
    amount: u64,
    cap: u64,
    budget: u64,
    t: u64,
    t_start: u64,
    t_exp: u64,
    velocity_n: u64,
}

/// The budget is the unit size times the spendable count: 4 * 1536 = 6144.
/// The composed circuit constrains that relation, so a budget that did not
/// factor this way would make the binding unsatisfiable for reasons that have
/// nothing to do with the circuit.
/// The delegation holds SPENDABLE units from BASE_INDEX, inside a range padded
/// to a power of two. With a unit size of 4 the budget is 6144. The composed
/// circuit constrains B = u * SPENDABLE, and the padding is what keeps
/// revocation from publishing the budget rather than its bracket.
const SPENDABLE: u64 = 1536;
const BASE_INDEX: u64 = 0;

const GOOD: Row = Row {
    amount: 10,
    cap: 200,
    budget: 6144,
    t: 5000,
    t_start: 1000,
    t_exp: 9000,
    velocity_n: 5,
};

fn bits_of(v: u64) -> Vec<F> {
    (0..RANGE_BITS)
        .map(|i| F::from_u64((v >> i) & 1))
        .collect()
}

/// The gaps, in the order the AIR allocates their bit blocks: C1, then C5's
/// two endpoints. C2 and C6 are not circuit clauses.
fn gaps(r: &Row) -> [u64; GAP_BLOCKS] {
    [
        r.cap - r.amount,
        r.t - r.t_start,
        r.t_exp - r.t,
    ]
}

pub fn policy_trace(rows: usize) -> RowMajorMatrix<F> {
    policy_trace_amount(rows, GOOD.amount)
}

/// The same row at a chosen amount, with C1's decomposition recomputed. A
/// control that moves the amount to break the units binding must leave every
/// other constraint satisfied, or it tests two things at once.
pub fn policy_trace_amount(rows: usize, amount: u64) -> RowMajorMatrix<F> {
    policy_trace_full(rows, amount, GOOD.cap)
}

/// The policy row at a chosen amount and a chosen cap, with C1's decomposition
/// recomputed for both. The cap is a parameter so the vacuity demonstration can
/// put one cap in the columns and another in the commitment.
pub fn policy_trace_full(rows: usize, amount: u64, cap: u64) -> RowMajorMatrix<F> {
    let width = VALUE_COLS + GAP_BLOCKS * RANGE_BITS;
    let mut values = Vec::with_capacity(rows * width);
    let r = Row { amount, cap, ..GOOD };

    for _ in 0..rows {
        let mut row = vec![F::ZERO; width];
        row[COL_AMOUNT] = F::from_u64(r.amount);
        row[COL_MID] = F::from_u64(7);
        row[COL_PAYEE] = F::from_u64(7);
        row[COL_CID] = F::from_u64(3);
        row[COL_T] = F::from_u64(GOOD.t);
        row[COL_B] = F::from_u64(GOOD.budget);
        row[COL_C] = F::from_u64(r.cap);
        for j in 0..DIGEST {
            row[COL_MROOT + j] = F::from_u64(11 + j as u64);
            row[COL_CROOT + j] = F::from_u64(13 + j as u64);
        }
        row[COL_TSTART] = F::from_u64(GOOD.t_start);
        row[COL_TEXP] = F::from_u64(GOOD.t_exp);
        row[COL_N] = F::from_u64(GOOD.velocity_n);
        row[COL_W] = F::from_u64(100);
        row[COL_G] = F::from_u64(GOOD.budget);
        row[COL_R] = F::from_u64(4242);
        row[COL_NONCE] = F::from_u64(777);
        row[COL_MERCHANT_OK] = F::ONE;
        row[COL_CATEGORY_OK] = F::ONE;

        for (b, gap) in gaps(&r).into_iter().enumerate() {
            let start = VALUE_COLS + b * RANGE_BITS;
            for (i, bit) in bits_of(gap).into_iter().enumerate() {
                row[start + i] = bit;
            }
        }
        values.extend(row);
    }
    RowMajorMatrix::new(values, width)
}

/// A trace with one gap decomposition corrupted, used to confirm the check is
/// actually checking. A generator that only ever produces valid traces proves
/// nothing about the circuit.
pub fn broken_trace(rows: usize) -> RowMajorMatrix<F> {
    let mut m = policy_trace(rows);
    let w = m.width;
    m.values[w * (rows / 2) + VALUE_COLS] += F::ONE;
    m
}

/// The nine elements C9 absorbs, in commitment order, matching the values the
/// policy columns carry.
/// The C9 sponge's input, in the order POLICY_SCALARS names the columns. This
/// is the third place the absorbed list is built, after whole_trace_amount and
/// whole_public_values_amount, and extending two of the three is how the sponge
/// came to want five permutations from a generator that produced four.
fn absorbed() -> Vec<F> {
    [
        GOOD.budget, GOOD.cap,
        GOOD.t_start, GOOD.t_exp, GOOD.velocity_n, 100, GOOD.budget,
    ]
    .into_iter()
    .chain((0..DIGEST).map(|j| 11 + j as u64))
    .chain((0..DIGEST).map(|j| 13 + j as u64))
    .chain(std::iter::once(4242))
    .map(F::from_u64)
    .collect()
}

/// Policy columns followed by the three C9 permutation blocks. The bindings
/// hold by construction: the sponge absorbs exactly the values the policy
/// columns carry, so each absorbed lane already equals its source column.
/// The commitment the policy-plus-opening circuit computes, which that circuit
/// now has to produce rather than merely contain.
pub fn full_public_values<const R: usize>() -> Vec<F> {
    let perms = sponge::<R>(&absorbed(), 4, DOMAIN_OPENING);
    perm_output::<R>(perms.last().expect("sponge produced no permutation"))[..DIGEST].to_vec()
}

pub fn composed_trace<const R: usize>(rows: usize) -> RowMajorMatrix<F> {
    let bw = num_cols::<WIDTH, SBOX_DEGREE, R, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>();
    let policy = policy_trace(rows);
    let pw = VALUE_COLS + GAP_BLOCKS * RANGE_BITS;
    let width = pw + C9_PERMUTATIONS * bw;

    let perms = sponge::<R>(&absorbed(), 4, DOMAIN_OPENING);
    assert_eq!(perms.len(), C9_PERMUTATIONS);

    let mut values = Vec::with_capacity(rows * width);
    for r in 0..rows {
        values.extend_from_slice(&policy.values[r * pw..(r + 1) * pw]);
        for p in &perms {
            values.extend_from_slice(p);
        }
    }
    RowMajorMatrix::new(values, width)
}

/// How a composed trace can be broken. Each targets a different constraint, so
/// a passing round trip on all three would mean something specific is unchecked
/// rather than that the trace happens to be valid.
#[derive(Clone, Copy)]
pub enum Break {
    /// An absorbed lane no longer equals the policy column it is bound to.
    Binding,
    /// A capacity lane no longer carries from one permutation into the next.
    Chaining,
    /// A permutation's internal round state is altered.
    Permutation,
}

pub fn broken_composed<const R: usize>(rows: usize, how: Break) -> RowMajorMatrix<F> {
    let bw = num_cols::<WIDTH, SBOX_DEGREE, R, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>();
    let pw = VALUE_COLS + GAP_BLOCKS * RANGE_BITS;
    let mut m = composed_trace::<R>(rows);
    let w = m.width;

    // Row zero is enough; the constraints hold at every row.
    let at = match how {
        // First absorbed lane of the first permutation, which C9 binds to the
        // budget column.
        Break::Binding => pw,
        // A capacity lane of the second permutation's input, which the sponge
        // chaining ties to the first permutation's output.
        Break::Chaining => pw + bw + 4,
        // A post state inside the first permutation's rounds.
        Break::Permutation => pw + 20,
    };
    for r in 0..rows {
        m.values[r * w + at] += F::ONE;
    }
    m
}

/// Merkle inclusion: a leaf carried up through DEPTH compressions, each level
/// supplying a sibling and a direction bit and a permutation whose output
/// becomes the next level's digest.
pub fn merkle_trace<const R: usize, const DEPTH: usize>(rows: usize) -> RowMajorMatrix<F> {
    // A leaf carries its identifier in the first lane and zeros in the rest.
    // The composed circuit constrains those lanes to zero, so a path cannot
    // prove inclusion of any leaf that merely agrees in one element.
    merkle_trace_leaf::<R, DEPTH>(rows, [F::from_u64(99), F::ZERO, F::ZERO, F::ZERO])
}

/// The same path over a caller-supplied leaf. The revocation accumulator's
/// leaves are range records rather than identifiers, so they occupy three lanes
/// and cannot be built by the fixed-leaf form above.
pub fn merkle_trace_leaf<const R: usize, const DEPTH: usize>(
    rows: usize,
    leaf: [F; 4],
) -> RowMajorMatrix<F> {
    let bw = num_cols::<WIDTH, SBOX_DEGREE, R, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>();
    let digest = WIDTH / 2;
    let lw = digest + digest + 1 + bw;
    let width = DEPTH * lw + digest;

    let mut cur = leaf;
    let mut levels: Vec<(Vec<F>, [F; 4], u64)> = Vec::with_capacity(DEPTH);
    for level in 0..DEPTH {
        let sib = [F::from_u64(1000 + level as u64); 4];
        let bit = (level % 2) as u64;
        let (mut left, mut right) = (cur, sib);
        if bit == 1 {
            core::mem::swap(&mut left, &mut right);
        }
        let mut input = [F::ZERO; WIDTH];
        input[..4].copy_from_slice(&left);
        input[4..].copy_from_slice(&right);
        let prow = crate::gen::perm_row::<R>(input);
        let out = crate::gen::perm_output::<R>(&prow);
        levels.push((prow, sib, bit));
        cur.copy_from_slice(&out[..4]);
    }
    let root = cur;

    let mut values = Vec::with_capacity(rows * width);
    for _ in 0..rows {
        let mut row = vec![F::ZERO; width];
        let mut digest_in = leaf;
        for (level, (prow, sib, bit)) in levels.iter().enumerate() {
            let base = level * lw;
            row[base..base + 4].copy_from_slice(&digest_in);
            row[base + 4..base + 8].copy_from_slice(sib);
            row[base + 8] = F::from_u64(*bit);
            row[base + 9..base + 9 + bw].copy_from_slice(prow);
            let out = crate::gen::perm_output::<R>(prow);
            digest_in.copy_from_slice(&out[..4]);
        }
        row[DEPTH * lw..DEPTH * lw + 4].copy_from_slice(&root);
        values.extend(row);
    }
    RowMajorMatrix::new(values, width)
}

/// Corrupt one column of a trace at every row, for the negative controls.
pub fn corrupt(mut m: RowMajorMatrix<F>, col: usize) -> RowMajorMatrix<F> {
    let w = m.width;
    let rows = m.values.len() / w;
    for r in 0..rows {
        m.values[r * w + col] += F::ONE;
    }
    m
}

/// The revoked range the accumulator holds, the start of the next revoked
/// range, and the run of units a payment consumes in the gap between them.
/// Chosen with room on both sides so an off-by-one in the comparisons shows up
/// as a failed decomposition rather than as a borderline pass.
/// Units 100 to 200 are revoked and the next revoked range starts at 20000, so
/// the payment's run sits in the gap with room on both sides. The spend
/// component reserves at offset 385 of a delegation based at 0.
const REVOKED_START: u64 = 100;
const REVOKED_END: u64 = 200;
const NEXT_REVOKED_START: u64 = 20000;
const RUN_START: u64 = 385;
const RUN_UNITS: u64 = 3;

/// What a control corrupts. The last three could not exist before the
/// comparisons did: under the previous form of this component there was nothing
/// relating a consumed unit to a revoked range, so no trace could violate the
/// property while satisfying every constraint.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RevokeBreak {
    /// One bit of a gap decomposition, which is the control that existed before.
    GapDecomposition,
    /// The run begins inside the exhibited revoked range.
    RunStartsInsideRange,
    /// The run extends into the next revoked range.
    RunReachesNextRange,
    /// The run ends before it starts, which would let a single unit stand for
    /// an interval whose far end the comparisons never see.
    RunInverted,
}

/// Non-membership over revoked ranges: the inclusion proof for the exhibited
/// range record, then the four comparisons placing the consumed run beyond that
/// range's end and before the next range's start.
pub fn nonmembership_trace<const R: usize, const DEPTH: usize>(rows: usize) -> RowMajorMatrix<F> {
    build_nonmembership::<R, DEPTH>(rows, None)
}

pub fn broken_nonmembership<const R: usize, const DEPTH: usize>(
    rows: usize,
    how: RevokeBreak,
) -> RowMajorMatrix<F> {
    build_nonmembership::<R, DEPTH>(rows, Some(how))
}

fn build_nonmembership<const R: usize, const DEPTH: usize>(
    rows: usize,
    how: Option<RevokeBreak>,
) -> RowMajorMatrix<F> {
    let leaf = [
        F::from_u64(REVOKED_START),
        F::from_u64(REVOKED_END),
        F::from_u64(NEXT_REVOKED_START),
        F::ZERO,
    ];
    let path = merkle_trace_leaf::<R, DEPTH>(rows, leaf);
    let pw = path.width;
    let width = pw + 2 + 4 * RANGE_BITS;

    let (lo, hi) = match how {
        Some(RevokeBreak::RunStartsInsideRange) => (150, 150 + RUN_UNITS - 1),
        Some(RevokeBreak::RunReachesNextRange) => (RUN_START, NEXT_REVOKED_START),
        Some(RevokeBreak::RunInverted) => (RUN_START, RUN_START - 1),
        _ => (RUN_START, RUN_START + RUN_UNITS - 1),
    };

    // Signed, because a control makes one of these negative and the honest
    // decomposition of a negative gap does not exist. The generator writes the
    // low bits of the value reduced modulo the field and the constraint rejects it.
    let gaps: [i128; 4] = [
        lo as i128 - REVOKED_START as i128,
        lo as i128 - REVOKED_END as i128 - 1,
        NEXT_REVOKED_START as i128 - hi as i128 - 1,
        hi as i128 - lo as i128,
    ];

    let mask = (1u64 << RANGE_BITS) - 1;
    let mut values = Vec::with_capacity(rows * width);
    for r in 0..rows {
        let mut row = vec![F::ZERO; width];
        row[..pw].copy_from_slice(&path.values[r * pw..(r + 1) * pw]);
        row[pw] = F::from_u64(lo);
        row[pw + 1] = F::from_u64(hi);
        for (g, gap) in gaps.iter().enumerate() {
            let start = pw + 2 + g * RANGE_BITS;
            for (i, bit) in bits_of((*gap as u64) & mask).into_iter().enumerate() {
                row[start + i] = bit;
            }
        }
        if how == Some(RevokeBreak::GapDecomposition) {
            row[pw + 2] += F::ONE;
        }
        values.extend(row);
    }
    RowMajorMatrix::new(values, width)
}

/// A sub-delegation strictly inside its parent: later start, earlier expiry,
/// smaller cap, fewer payments per window, and a unit range within the
/// parent's. The two Merkle paths carry the child's allowlist roots up to the
/// parent's.
pub fn whole_trace<const R: usize, const MD: usize, const RD: usize>(
    rows: usize,
) -> RowMajorMatrix<F> {
    whole_trace_amount::<R, MD, RD>(rows, GOOD.amount)
}

pub fn whole_trace_amount<const R: usize, const MD: usize, const RD: usize>(
    rows: usize,
    amount: u64,
) -> RowMajorMatrix<F> {
    whole_trace_full::<R, MD, RD>(rows, amount, GOOD.cap, GOOD.cap)
}

/// The whole-circuit trace with the cap in the policy columns chosen
/// separately from the cap the commitment opens to. They agree everywhere
/// except in the vacuity demonstration of \cref{sec:eval:vacuity}, where a
/// payment of $10$ complies with a cap of $1000$ in the columns while the
/// commitment carries $200$ --- a policy the principal never signed.
pub fn whole_trace_full<const R: usize, const MD: usize, const RD: usize>(
    rows: usize,
    amount: u64,
    cap_in_columns: u64,
    cap_committed: u64,
) -> RowMajorMatrix<F> {
    let bw = num_cols::<WIDTH, SBOX_DEGREE, R, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>();
    let pw = VALUE_COLS + GAP_BLOCKS * RANGE_BITS;

    let mk = merkle_trace::<R, MD>(1);
    let mw = mk.width;
    let rv = nonmembership_trace::<R, RD>(1);
    let rw = rv.width;

    let digest = WIDTH / 2;
    let mk_root_off = MD * (digest + digest + 1 + bw);
    let rv_root_off = RD * (digest + digest + 1 + bw);
    let mroot: Vec<F> = mk.values[mk_root_off..mk_root_off + digest].to_vec();
    let rroot: Vec<F> = rv.values[rv_root_off..rv_root_off + digest].to_vec();

    let policy = policy_trace_full(1, amount, cap_in_columns);
    // What the commitment opens to, which is the real policy whatever the
    // columns say.
    let committed = policy_trace_full(1, amount, cap_committed);

    // C9 absorbs the policy scalars, both roots in full and the blinding value,
    // and stops there. The roots are the ones the paths actually compute, so the
    // commitment fixes the trees the inclusion proofs run against.
    let mut absorbed_v: Vec<F> = vec![
        committed.values[COL_B], committed.values[COL_C],
        committed.values[COL_TSTART], committed.values[COL_TEXP],
        committed.values[COL_N], committed.values[COL_W],
        committed.values[COL_G],
    ];
    absorbed_v.extend_from_slice(&mroot);
    absorbed_v.extend_from_slice(&mroot);
    absorbed_v.push(policy.values[COL_R]);
    let perms = sponge::<R>(&absorbed_v, 4, DOMAIN_OPENING);

    // C7 absorbs the payment. The leaf identifier the paths carry is what the
    // merchant, category and payee columns hold, so the digest is over the
    // values the clauses read rather than over a number chosen beside them.
    let leaf = mk.values[0];
    let payload_v: Vec<F> = PAYLOAD_SRC
        .iter()
        .map(|&c| match c {
            COL_MID | COL_CID | COL_PAYEE => leaf,
            _ => policy.values[c],
        })
        .collect();
    let pl_perms = sponge::<R>(&payload_v, 4, DOMAIN_PAYLOAD);
    let payload = perm_output::<R>(pl_perms.last().expect("payload sponge is non-empty"))[0];

    let base_pl = pw + C9_PERMUTATIONS * bw;
    let base_h = pw;
    let base_mc = base_pl + PAYLOAD_PERMUTATIONS * bw;
    let base_mk = base_mc;
    let base_ct = base_mk + mw;
    let base_rv = base_ct + mw;
    let base_glue = base_rv + rw;
    let width = base_glue + digest + 3;
    // Where the non-membership component keeps the consumed run, so the glue
    // carries the two values the comparisons are made against.
    let rv_run_off = rv_root_off + digest;

    let mut values = Vec::with_capacity(rows * width);
    for _ in 0..rows {
        let mut row = vec![F::ZERO; width];
        row[..pw].copy_from_slice(&policy.values[..pw]);
        row[COL_MROOT..COL_MROOT + digest].copy_from_slice(&mroot);
        row[COL_CROOT..COL_CROOT + digest].copy_from_slice(&mroot);
        row[COL_MID] = mk.values[0];
        row[COL_PAYEE] = mk.values[0];
        row[COL_CID] = mk.values[0];

        for (i, p) in perms.iter().enumerate() {
            row[base_h + i * bw..base_h + (i + 1) * bw].copy_from_slice(p);
        }
        for (i, p) in pl_perms.iter().enumerate() {
            row[base_pl + i * bw..base_pl + (i + 1) * bw].copy_from_slice(p);
        }
        row[base_mk..base_mk + mw].copy_from_slice(&mk.values[..mw]);
        row[base_ct..base_ct + mw].copy_from_slice(&mk.values[..mw]);
        row[base_rv..base_rv + rw].copy_from_slice(&rv.values[..rw]);

        row[base_glue..base_glue + digest].copy_from_slice(&rroot);
        row[base_glue + digest] = payload;
        row[base_glue + digest + 1] = rv.values[rv_run_off];
        row[base_glue + digest + 2] = rv.values[rv_run_off + 1];
        values.extend(row);
    }
    RowMajorMatrix::new(values, width)
}

/// The public values a verifier supplies for the whole circuit: the payload
/// digest, the revocation accumulator root, and the delegation commitment.
/// Computed from the same pieces whole_trace uses, so a divergence between the
/// two shows up as a rejected proof rather than as a silent mismatch.
pub fn whole_public_values<const R: usize, const MD: usize, const RD: usize>() -> Vec<F> {
    whole_public_values_amount::<R, MD, RD>(GOOD.amount)
}

/// The same nine values at a chosen amount. The commitment lanes must not move
/// with the amount and the digest must; that is the property the split of the
/// two sponges exists to give, and the harness checks it rather than asserting
/// it in prose.
pub fn whole_public_values_amount<const R: usize, const MD: usize, const RD: usize>(
    amount: u64,
) -> Vec<F> {
    whole_public_values_cap::<R, MD, RD>(amount, GOOD.cap)
}

/// The public values when the committed policy carries a chosen cap, so the
/// control for the cap well-formedness condition can commit to the policy it
/// is testing rather than to a different one.
pub fn whole_public_values_cap<const R: usize, const MD: usize, const RD: usize>(
    amount: u64,
    cap: u64,
) -> Vec<F> {
    let bw = num_cols::<WIDTH, SBOX_DEGREE, R, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>();
    let level = DIGEST + DIGEST + 1 + bw;

    let mk = merkle_trace::<R, MD>(1);
    let mroot: Vec<F> = mk.values[MD * level..MD * level + DIGEST].to_vec();
    let rv = nonmembership_trace::<R, RD>(1);
    let rroot: Vec<F> = rv.values[RD * level..RD * level + DIGEST].to_vec();

    let policy = policy_trace_full(1, amount, cap);

    let mut absorbed_v: Vec<F> = vec![
        policy.values[COL_B], policy.values[COL_C],
        policy.values[COL_TSTART], policy.values[COL_TEXP],
        policy.values[COL_N], policy.values[COL_W],
        policy.values[COL_G],
    ];
    absorbed_v.extend_from_slice(&mroot);
    absorbed_v.extend_from_slice(&mroot);
    absorbed_v.push(policy.values[COL_R]);

    let perms = sponge::<R>(&absorbed_v, 4, DOMAIN_OPENING);
    let com = perm_output::<R>(perms.last().expect("sponge produced no permutation"));

    let leaf = mk.values[0];
    let payload_v: Vec<F> = PAYLOAD_SRC
        .iter()
        .map(|&c| match c {
            COL_MID | COL_CID | COL_PAYEE => leaf,
            _ => policy.values[c],
        })
        .collect();
    let pl_perms = sponge::<R>(&payload_v, 4, DOMAIN_PAYLOAD);
    let payload = perm_output::<R>(pl_perms.last().expect("payload sponge is non-empty"))[0];

    let mut out = Vec::with_capacity(1 + 2 * DIGEST);
    out.push(payload);
    out.extend_from_slice(&rroot);
    out.extend_from_slice(&com[..DIGEST]);
    out
}

/// What a control corrupts in the composed circuit. Each leaves both halves
/// internally satisfied and breaks only the binding between them, which is the
/// point: proved separately, every one of these traces verifies.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ComposedBreak {
    /// A policy whose per-payment cap exceeds the budget. Every other
    /// constraint is satisfied --- the clauses read the cap, the sponge absorbs
    /// it, the commitment opens to it --- and the payment itself is small. What
    /// fails is that the policy admits payments the budget cannot cover.
    CapAboveBudget,
    /// The spend component consumes a run one unit later than the run C8 was
    /// checked against. Both halves are correct about their own run.
    RunStartMismatch,
    /// The amount exceeds what the charged units buy.
    AmountRaised,
    /// The amount is low enough that one fewer unit would have covered it, so
    /// the rounding is not the upward rounding of Section VI-A.
    AmountLowered,
    /// The witnessed unit size does not divide the committed budget.
    UnitSizeWrong,
}

/// A trace for the composed circuit: the compliance row, the spend row for the
/// same payment, the unit size, and the two comparisons relating the units
/// charged to the amount paid.
///
/// The two halves are generated from one set of parameters here, which is the
/// whole point of composing them. Previously nothing could disagree because
/// nothing compared them.
/// The vacuity demonstration: a payment of $10$ against a cap of $1000$ in the
/// policy columns, while the commitment opens to a cap of $200$. Every clause
/// is satisfied, every path recomputes its committed root, the sponge produces
/// the committed value, and the only thing wrong is that the policy the clauses
/// read is not the policy the principal signed.
pub fn vacuous_trace<const R: usize, const MD: usize, const RD: usize>(
    rows: usize,
) -> RowMajorMatrix<F> {
    whole_trace_full::<R, MD, RD>(rows, GOOD.amount, 1000, GOOD.cap)
}

pub fn composed_air_trace<
    const R: usize,
    const MD: usize,
    const RD: usize,
    const DEPTH: usize,
    const COVER: usize,
>(
    rows: usize,
) -> RowMajorMatrix<F> {
    build_composed::<R, MD, RD, DEPTH, COVER>(rows, None)
}

pub fn broken_composed_air<
    const R: usize,
    const MD: usize,
    const RD: usize,
    const DEPTH: usize,
    const COVER: usize,
>(
    rows: usize,
    how: ComposedBreak,
) -> RowMajorMatrix<F> {
    build_composed::<R, MD, RD, DEPTH, COVER>(rows, Some(how))
}

fn build_composed<
    const R: usize,
    const MD: usize,
    const RD: usize,
    const DEPTH: usize,
    const COVER: usize,
>(
    rows: usize,
    how: Option<ComposedBreak>,
) -> RowMajorMatrix<F> {
    // B = u * m, the same relation the composed circuit constrains.
    let u = GOOD.budget / SPENDABLE;
    assert!(
        u > 0 && u * SPENDABLE == GOOD.budget,
        "the budget is not a whole number of units"
    );
    assert!(
        (BASE_INDEX + SPENDABLE).next_power_of_two() <= (1u64 << DEPTH),
        "the padded range does not fit the deployment's index space"
    );

    // The amount the payment settles, the units it charges, and the unit size
    // it is proved against. The three controls that move them are the whole
    // content of binding the two halves: each leaves both halves internally
    // correct and only their relation false.
    let amount = GOOD.amount;
    let units = match how {
        Some(ComposedBreak::AmountLowered) => (amount + u - 1) / u + 1,
        _ => (amount + u - 1) / u,
    };
    let amount = match how {
        Some(ComposedBreak::AmountRaised) => units * u + 1,
        _ => amount,
    };
    let u_written = match how {
        Some(ComposedBreak::UnitSizeWrong) => u + 1,
        _ => u,
    };

    // A cap larger than the budget. It is written into the policy columns and
    // into the commitment alike, so every other constraint is satisfied and
    // only the well-formedness gap goes negative.
    let cap = match how {
        Some(ComposedBreak::CapAboveBudget) => GOOD.budget + 1,
        _ => GOOD.cap,
    };
    let whole = whole_trace_full::<R, MD, RD>(1, amount, cap, cap);
    let w = whole.width;
    let pv = whole_public_values_cap::<R, MD, RD>(amount, cap);

    // The run the spend half reserves. Moving it by one unit leaves that half
    // internally correct and disagreeing with the run C8 was checked against,
    // which is the binding this control exists to test.
    let off_delta = match how {
        Some(ComposedBreak::RunStartMismatch) => 1,
        _ => 0,
    };
    let spend = crate::spend_trace::spend_row::<R, DEPTH, COVER>(
        pv[0],
        Some(units as usize),
        off_delta,
        BASE_INDEX as usize,
        SPENDABLE as usize,
        None,
    );

    let width = w + spend.len() + 1 + 3 * RANGE_BITS;
    let mask = (1u64 << RANGE_BITS) - 1;
    let gaps: [i128; 3] = [
        units as i128 * u_written as i128 - amount as i128,
        amount as i128 - (units as i128 - 1) * u_written as i128 - 1,
        GOOD.budget as i128 - cap as i128,
    ];

    // One row is generated and repeated. whole_trace_amount is called for a
    // single row above, so indexing it by the row counter walks off the end.
    let mut values = Vec::with_capacity(rows * width);
    for _ in 0..rows {
        let mut row = vec![F::ZERO; width];
        row[..w].copy_from_slice(&whole.values[..w]);
        row[w..w + spend.len()].copy_from_slice(&spend);
        row[w + spend.len()] = F::from_u64(u_written);
        let rb = w + spend.len() + 1;
        for (g, gap) in gaps.iter().enumerate() {
            let start = rb + g * RANGE_BITS;
            for (i, bit) in bits_of((*gap as u64) & mask).into_iter().enumerate() {
                row[start + i] = bit;
            }
        }
        values.extend(row);
    }
    RowMajorMatrix::new(values, width)
}
