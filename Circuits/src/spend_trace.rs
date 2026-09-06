use p3_field::{Field, PrimeCharacteristicRing};
use p3_goldilocks::Goldilocks;
use p3_matrix::dense::RowMajorMatrix;
use p3_poseidon2_air::num_cols;

use crate::air::RANGE_BITS;
use crate::gen::{perm_output, perm_row};
use crate::hash::{DOMAIN_KEY, DOMAIN_NULL, DOMAIN_PAD, HALF_FULL_ROUNDS, PARTIAL_ROUNDS, SBOX_DEGREE, WIDTH};
// The layout is declared once, by the AIR, and imported here. It was restated in
// this file until the two copies drifted apart three times.
use crate::spend::{
    COL_BASE, COL_INDEX, COL_INDEX_INV, COL_M, COL_R,
    COL_ROOT_KEY, COL_SECRET, COL_UNITS, FIXED_COLS, NODE_ACTIVE, NODE_KEY, NODE_NULL, NODE_SHARE,
    PER_NODE, RANGE_BLOCKS, SECRET_ELEMS,
};

type F = Goldilocks;

/// The payload digest, supplied to prove and verify as the single public value.
pub const PAYLOAD: u64 = 31337;

const SECRET: [u64; SECRET_ELEMS] = [987654321, 1234567891];
const ROOT_KEY: [u64; SECRET_ELEMS] = [424242, 858585];

struct Layout {
    pos: usize,
    rng: usize,
    node: usize,
    vals: usize,
    width: usize,
}

fn layout(depth: usize, cover: usize, bw: usize) -> Layout {
    let _ = depth;
    let pos = FIXED_COLS;
    let rng = pos + cover + 1;
    let node = rng + RANGE_BLOCKS * RANGE_BITS;
    let vals = node + PER_NODE * cover;
    Layout { pos, rng, node, vals, width: vals + cover * bw }
}

fn bits_of(v: usize) -> Vec<F> {
    (0..RANGE_BITS).map(|i| F::from_u64(((v >> i) & 1) as u64)).collect()
}

/// The delegation's base index, and the run of units this payment charges.
/// The base is non-zero, so the alignment
/// constraints are exercised rather than trivially satisfied at zero.
///
/// `units_want` lets the composed circuit charge the number of units the
/// payment's amount actually buys rather than filling every slot, and
/// `off_delta` moves the run without disturbing anything else, which is how a
/// control makes the run disagree with the one C8 is checked against while
/// leaving this component internally consistent.
fn interval(
    depth: usize,
    cover: usize,
    units_want: Option<usize>,
    off_delta: usize,
    base: usize,
    spendable: usize,
) -> (usize, usize, usize, usize) {
    let _ = depth;
    let part = spendable;
    let off = part / 4 + 1 + off_delta;
    let room = part - off - 1;
    let cap = if cover < room { cover } else { room };
    let units = match units_want {
        Some(u) if u <= cap => u,
        Some(_) => panic!("units_want exceeds the slot count or the spendable range"),
        None => cap,
    };
    (part, base, off, units)
}

/// One row of the spend component, so the composed trace does not restate a
/// layout this file already builds. The layout was written twice once and the
/// two copies drifted apart three times.
pub fn spend_row<const R: usize, const DEPTH: usize, const COVER: usize>(
    payload: F,
    units_want: Option<usize>,
    off_delta: usize,
    pindex: usize,
    part: usize,
    how: Option<SpendBreak>,
) -> Vec<F> {
    row_of::<R, DEPTH, COVER>(payload, units_want, off_delta, pindex, part, how)
}

/// What a control corrupts. Each must make verification fail.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SpendBreak {
    Share,
    Key,
    Nullifier,
    Deactivate,
    RunStart,
    Modulus,
    Units,
    RangeBase,
    /// The attack the block construction admitted: consume a span of units in
    /// one slot rather than one unit per slot, so that a later fine-grained
    /// payment overlaps it without repeating a key. Here it is expressible only
    /// as a run whose positions skip, and it must be rejected.
    CoarseSpan,
    /// The run ends past the delegation's spendable units. This is the only
    /// refusal the circuit performs and its threshold is the budget, so it is
    /// the control for the one range check that remains after the divisions
    /// went.
    RunPastBudget,
}

/// The same payment under the second-invocation variant: the row the
/// single-invocation AIR uses, with each slot's nullifier replaced by
/// F(key, null) and that permutation's columns appended.
pub fn spend_two_trace<const R: usize, const DEPTH: usize, const COVER: usize>(
    rows: usize,
) -> RowMajorMatrix<F> {
    let bw = num_cols::<WIDTH, SBOX_DEGREE, R, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>();
    let l = layout(DEPTH, COVER, bw);
    let mut row = row_of::<R, DEPTH, COVER>(
        F::from_u64(PAYLOAD), None, 0, 0, 1usize << (DEPTH - 1), None);

    let mut tail: Vec<F> = Vec::with_capacity(COVER * bw);
    for c in 0..COVER {
        let n = l.node + c * PER_NODE;
        let mut state = [F::ZERO; WIDTH];
        for j in 0..SECRET_ELEMS {
            state[j] = row[n + NODE_KEY + j];
        }
        state[SECRET_ELEMS] = F::from_u64(DOMAIN_NULL);
        let prow = perm_row::<R>(state);
        row[n + NODE_NULL] = perm_output::<R>(&prow)[0];
        tail.extend_from_slice(&prow);
    }
    row.extend_from_slice(&tail);

    let width = row.len();
    let mut values = Vec::with_capacity(rows * width);
    for _ in 0..rows {
        values.extend_from_slice(&row);
    }
    RowMajorMatrix::new(values, width)
}

pub fn spend_trace<const R: usize, const DEPTH: usize, const COVER: usize>(
    rows: usize,
) -> RowMajorMatrix<F> {
    build::<R, DEPTH, COVER>(rows, None)
}

pub fn broken_spend<const R: usize, const DEPTH: usize, const COVER: usize>(
    rows: usize,
    how: SpendBreak,
) -> RowMajorMatrix<F> {
    build::<R, DEPTH, COVER>(rows, Some(how))
}

fn build<const R: usize, const DEPTH: usize, const COVER: usize>(
    rows: usize,
    how: Option<SpendBreak>,
) -> RowMajorMatrix<F> {
    let bw = num_cols::<WIDTH, SBOX_DEGREE, R, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>();
    let l = layout(DEPTH, COVER, bw);
    let row = row_of::<R, DEPTH, COVER>(
        F::from_u64(PAYLOAD), None, 0, 0, 1usize << (DEPTH - 1), how);
    let mut values = Vec::with_capacity(rows * l.width);
    for _ in 0..rows {
        values.extend_from_slice(&row);
    }
    RowMajorMatrix::new(values, l.width)
}

fn row_of<const R: usize, const DEPTH: usize, const COVER: usize>(
    payload: F,
    units_want: Option<usize>,
    off_delta: usize,
    pindex: usize,
    part_units: usize,
    how: Option<SpendBreak>,
) -> Vec<F> {
    // pindex is the delegation's base index and part_units its spendable count.
    assert!(payload != F::ZERO, "the share index is forced non-zero by a witnessed inverse");
    let bw = num_cols::<WIDTH, SBOX_DEGREE, R, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>();
    let l = layout(DEPTH, COVER, bw);
    let (spendable, base, off, units) =
        interval(DEPTH, COVER, units_want, off_delta, pindex, part_units);
    // Placed so the run ends one unit past the delegation's spendable units.
    // The row stays internally consistent and exactly one gap goes negative.
    let off = if how == Some(SpendBreak::RunPastBudget) {
        spendable - units + 1
    } else {
        off
    };

    let mut row = vec![F::ZERO; l.width];

    for j in 0..SECRET_ELEMS {
        row[COL_SECRET + j] = F::from_u64(SECRET[j]);
        row[COL_ROOT_KEY + j] = F::from_u64(ROOT_KEY[j]);
    }
    row[COL_INDEX] = payload;
    row[COL_INDEX_INV] = payload.inverse();
    row[COL_M] = F::from_u64(spendable as u64);
    row[COL_R] = F::from_u64(off as u64);
    row[COL_UNITS] = F::from_u64(units as u64);
    row[COL_BASE] = F::from_u64(base as u64);

    // Signed, because the control drives one of these negative; the generator
    // writes the low bits of the value reduced modulo the field and the constraint rejects it.
    let mask = (1u64 << RANGE_BITS) - 1;
    for (g, v) in [
        off as i128,
        spendable as i128 - off as i128 - units as i128,
        (1i128 << DEPTH) - base as i128 - spendable as i128,
    ]
    .into_iter()
    .enumerate()
    {
        for (i, b) in bits_of(((v as u64) & mask) as usize).into_iter().enumerate() {
            row[l.rng + g * RANGE_BITS + i] = b;
        }
    }

    let mut pos = off;
    for c in 0..COVER {
        let n = l.node + c * PER_NODE;
        row[l.pos + c] = F::from_u64(pos as u64);
        let active = c < units;

        let mut state = [F::ZERO; WIDTH];
        for j in 0..SECRET_ELEMS {
            state[j] = F::from_u64(ROOT_KEY[j]);
        }
        if active {
            state[SECRET_ELEMS] = F::from_u64((base + pos) as u64);
            state[SECRET_ELEMS + 1] = F::from_u64(DOMAIN_KEY);
        } else {
            state[SECRET_ELEMS] = payload;
            state[SECRET_ELEMS + 1] = F::from_u64(DOMAIN_PAD);
            state[SECRET_ELEMS + 2] = F::from_u64(c as u64 + 1);
        }
        let prow = perm_row::<R>(state);
        let outp = perm_output::<R>(&prow);
        let blk = l.vals + c * bw;
        row[blk..blk + bw].copy_from_slice(&prow);

        row[n + NODE_ACTIVE] = if active { F::ONE } else { F::ZERO };
        for j in 0..SECRET_ELEMS {
            row[n + NODE_KEY + j] = outp[j];
            row[n + NODE_SHARE + j] = F::from_u64(SECRET[j]) + outp[j] * payload;
        }
        row[n + NODE_NULL] = outp[SECRET_ELEMS];

        if active {
            pos += 1;
        }
    }
    row[l.pos + COVER] = F::from_u64(pos as u64);

    if let Some(b) = how {
        let n0 = l.node;
        let n1 = l.node + PER_NODE;
        match b {
            SpendBreak::Share => row[n0 + NODE_SHARE] += F::ONE,
            SpendBreak::Key => row[n0 + NODE_KEY] += F::ONE,
            SpendBreak::Nullifier => row[n0 + NODE_NULL] += F::ONE,
            SpendBreak::Deactivate => row[n1 + NODE_ACTIVE] = F::ZERO,
            SpendBreak::RunStart => row[l.pos] += F::ONE,
            SpendBreak::Modulus => row[COL_M] += F::ONE,
            SpendBreak::Units => row[COL_UNITS] -= F::ONE,
            SpendBreak::RangeBase => row[COL_BASE] += F::ONE,
            SpendBreak::CoarseSpan => {
                // Charge the same units while advancing the run by two per slot,
                // which is what consuming an aligned block of two units in one
                // slot would look like. The run must advance by exactly the
                // active flag, so this is rejected.
                for c in 1..=COVER {
                    let p = row[l.pos + c - 1];
                    row[l.pos + c] = p + F::from_u64(2);
                }
            }
            // These two are applied where the run offset and the reduction
            // quotient are chosen, so the row is already built against them and
            // nothing is corrupted afterwards. Listing them rather than adding a
            // wildcard is deliberate: a wildcard would silently swallow the next
            // variant somebody adds and the control would never fire.
            SpendBreak::RunPastBudget => {}
        }
    }

    row
}
