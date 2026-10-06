//! What a settlement domain would have to carry, and what it would have to give
//! up to make the proof smaller.
//!
//! Two numbers govern a deployment and the paper reports only one of them. The
//! first is proof size, which decides whether a chain can hold the proof at all.
//! The second is soundness, which decides what the proof is worth. They move
//! against each other through the FRI parameters, and quoting one setting hides
//! the trade.
//!
//! Soundness is reported twice on purpose. The conjectured figure assumes a
//! query costs an adversary the full rate, which is what deployed systems
//! assume and what the upstream defaults are chosen for. The Johnson figure is
//! what is provable without that conjecture, and it is roughly half. A reader
//! sizing a secret or a bond should use the second.

use crate::prover::{composed_proof_at, composed_verifies};

/// Bits of soundness if each query costs the full rate. This is the number
/// usually quoted and it rests on a conjecture about list decoding.
fn bits_conjectured(queries: usize, log_blowup: usize, pow: usize) -> usize {
    queries * log_blowup + pow
}

/// Bits provable in the Johnson regime, where a query is worth half the rate.
/// No conjecture is needed for this one.
fn bits_johnson(queries: usize, log_blowup: usize, pow: usize) -> usize {
    (queries * log_blowup) / 2 + pow
}

/// The challenge field is a degree-2 extension of Goldilocks, so no argument
/// over it is worth more than about this, whatever FRI contributes.
const FIELD_BITS: usize = 126;

/// Call data a 30M-gas block admits at 16 gas per non-zero byte.
const CALLDATA_BYTES_PER_BLOCK: usize = 30_000_000 / 16;
/// One EIP-4844 blob.
const BLOB_BYTES: usize = 131_072;

struct Row {
    queries: usize,
    blowup: usize,
    pow: usize,
    conjectured: usize,
    johnson: usize,
    bytes: usize,
    commit: usize,
    opened: usize,
    opening: usize,
    prove_ms: f64,
    verify_ms: f64,
    verifies: bool,
}

/// Is the dispersion of the hiding rows the grinding search?
///
/// The deployment grinds 20 proof-of-work bits, a search over about 2^20
/// hashes whose running time is geometric, so its mean and its spread are the
/// same order. If that is what the hiding rows carry, then proving the same
/// circuit at 0 bits and at 20 bits should differ by that amount in the median
/// AND the 0-bit rows should be the tighter of the two. Measured here rather
/// than argued from the distribution, with the two settings interleaved.
fn grinding() {
    const ITERS: usize = 24;
    let mut off: Vec<f64> = Vec::with_capacity(ITERS);
    let mut on: Vec<f64> = Vec::with_capacity(ITERS);
    let mut ok_all = true;
    for _ in 0..ITERS {
        let (_, _, _, _, us0, _, o0) =
            composed_proof_at::<{ crate::prover::REGISTERS }, 16, 32, 16, 64>(32, 40, 4, 0);
        let (_, _, _, _, us1, _, o1) =
            composed_proof_at::<{ crate::prover::REGISTERS }, 16, 32, 16, 64>(32, 40, 4, 20);
        off.push(us0 as f64 / 1000.0);
        on.push(us1 as f64 / 1000.0);
        ok_all &= o0 && o1;
    }
    let q = |mut v: Vec<f64>| {
        v.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let p = |f: f64| v[((v.len() - 1) as f64 * f).round() as usize];
        (v[0], p(0.25), p(0.5), p(0.75))
    };
    let (a0, b0, c0, d0) = q(off);
    let (a1, b1, c1, d1) = q(on);

    println!();
    println!("WHERE THE DISPERSION COMES FROM: GRINDING, MEASURED");
    println!("{}", "=".repeat(78));
    println!("  Same circuit, same rate, {} interleaved pairs. Only the grinding", ITERS);
    println!("  bits differ. Both settings are below the rate this circuit needs to");
    println!("  verify, so neither proof is accepted ({}); the timing is the point.", ok_all);
    println!();
    println!("  {:<22} {:>9} {:>9} {:>9} {:>9} {:>9}", "grinding bits", "min", "q1", "median", "q3", "q3-q1");
    println!("  {:<22} {:>9} {:>9} {:>9} {:>9} {:>9}",
             "-".repeat(22), "-".repeat(9), "-".repeat(9), "-".repeat(9), "-".repeat(9), "-".repeat(9));
    println!("  {:<22} {:>9.2} {:>9.2} {:>9.2} {:>9.2} {:>9.2}", "0", a0, b0, c0, d0, d0 - b0);
    println!("  {:<22} {:>9.2} {:>9.2} {:>9.2} {:>9.2} {:>9.2}", "20", a1, b1, c1, d1, d1 - b1);
    println!();
    println!("  median difference {:.2} ms, spread difference {:.2} ms.", c1 - c0, (d1 - b1) - (d0 - b0));
    println!("  A geometric search over 2^20 hashes has a mean and a standard");
    println!("  deviation of the same order, so if grinding is the source these two");
    println!("  differences should be comparable and the 0-bit row should be tight.");
}

/// One hiding configuration reused, against a fresh one per proof.
fn config_reuse() {
    const ITERS: usize = 20;
    let shared = crate::prover::composed_times::<{ crate::prover::REGISTERS }, 16, 32, 16, 64>(32, ITERS, true);
    let fresh  = crate::prover::composed_times::<{ crate::prover::REGISTERS }, 16, 32, 16, 64>(32, ITERS, false);
    let q = |v: &Vec<u128>| {
        let mut w: Vec<f64> = v.iter().map(|&x| x as f64 / 1000.0).collect();
        w.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let p = |f: f64| w[((w.len() - 1) as f64 * f).round() as usize];
        (w[0], p(0.25), p(0.5), p(0.75))
    };
    let (a0, b0, c0, d0) = q(&shared);
    let (a1, b1, c1, d1) = q(&fresh);
    println!();
    println!("ONE CONFIGURATION REUSED, AGAINST A FRESH ONE PER PROOF");
    println!("{}", "=".repeat(78));
    println!("  Same circuit, same prebuilt trace, {} proofs each. The only", ITERS);
    println!("  difference is whether the hiding configuration is rebuilt.");
    println!();
    println!("  {:<22} {:>9} {:>9} {:>9} {:>9} {:>9}", "configuration", "min", "q1", "median", "q3", "q3-q1");
    println!("  {:<22} {:>9} {:>9} {:>9} {:>9} {:>9}",
             "-".repeat(22), "-".repeat(9), "-".repeat(9), "-".repeat(9), "-".repeat(9), "-".repeat(9));
    println!("  {:<22} {:>9.2} {:>9.2} {:>9.2} {:>9.2} {:>9.2}", "shared", a0, b0, c0, d0, d0 - b0);
    println!("  {:<22} {:>9.2} {:>9.2} {:>9.2} {:>9.2} {:>9.2}", "rebuilt each proof", a1, b1, c1, d1, d1 - b1);
    println!();
    println!("  If sharing is the cause, the shared row is the wide one.");
}

/// How many adjudicable steps is one verification?
///
/// Counted on a real verification of the composed circuit at the deployed
/// parameters: every Poseidon2 permutation the verifier runs, through a
/// counter placed in front of the permutation, and every distinct operation
/// in evaluating the constraints at the out-of-domain point. Each permutation
/// is one Algebraic step of StepVerifier.sol and each operation one arithmetic
/// step. FRI's own folding and the batched reduction of the opened values are
/// further work on top, so the total is a lower bound on the program's length.
pub fn step_count() {
    let w = crate::prover::verifier_work::<{ crate::prover::REGISTERS }, 16, 32, 16, 64>(32);
    let total = w.permutations as usize + w.constraint_ops + 2 * w.constraints;
    println!();
    println!("ADJUDICABLE STEPS IN ONE VERIFICATION, COUNTED");
    println!("{}", "=".repeat(78));
    println!("  composed circuit, 32 rows, verifies          {:>12}", w.verifies);
    println!("  Poseidon2 permutations during verify         {:>12}", w.permutations);
    println!("  constraints                                  {:>12}", w.constraints);
    println!("  distinct operations evaluating them          {:>12}", w.constraint_ops);
    println!("  folding them into one, two per constraint    {:>12}", 2 * w.constraints);
    println!("  lower bound on steps                         {:>12}  (2^{:.2})",
             total, (total as f64).log2());
    println!("  rounds of bisection                          {:>12}",
             (total as f64).log2().ceil() as usize);
}

pub fn run() {
    step_count();
    config_reuse();
    grinding();

    println!();
    println!("DOES THE COMPOSED CIRCUIT VERIFY AT THE PARAMETERS THE PAPER QUOTES?");
    println!("{}", "=".repeat(78));
    println!("  {:<46} {:>10}", "allowlist / revocation / depth / cover, rows", "verifies");
    println!("  {:<46} {:>10}", "-".repeat(46), "-".repeat(10));
    println!("  {:<46} {:>10}", "8 / 8 / 16 / 14, 64 rows",
             composed_verifies::<{ crate::prover::REGISTERS }, 8, 8, 16, 14>(64));
    println!("  {:<46} {:>10}", "16 / 32 / 16 / 14, 64 rows",
             composed_verifies::<{ crate::prover::REGISTERS }, 16, 32, 16, 14>(64));
    println!("  {:<46} {:>10}", "16 / 32 / 16 / 14, 32 rows",
             composed_verifies::<{ crate::prover::REGISTERS }, 16, 32, 16, 14>(32));
    println!("  {:<46} {:>10}", "16 / 32 / 16 / 64, 64 rows",
             composed_verifies::<{ crate::prover::REGISTERS }, 16, 32, 16, 64>(64));
    println!("  {:<46} {:>10}", "16 / 32 / 16 / 64, 32 rows (what the paper quotes)",
             composed_verifies::<{ crate::prover::REGISTERS }, 16, 32, 16, 64>(32));
    println!();
    println!("FRI PARAMETERS: PROOF SIZE AGAINST SOUNDNESS, COMPOSED CIRCUIT AT 32 ROWS");
    println!("{}", "=".repeat(78));

    // Chosen rather than swept exhaustively: three blowups at a fixed query
    // count to isolate rate, three query counts at the deployed blowup to
    // isolate queries, and the two grinding settings that bracket the default.
    let settings: Vec<(usize, usize, usize)> = vec![
        (40, 2, 8),   // the deployment's setting
        (40, 1, 8),
        (40, 3, 8),
        (20, 2, 8),
        (30, 2, 8),
        (60, 2, 8),
        (80, 2, 8),
        (40, 2, 0),
        (40, 2, 16),
        (84, 3, 16),  // the smallest setting here clearing 128 provable bits
        // Candidates for 100 provable bits. Blowup is nearly free in proof
        // size and grinding is free entirely, so these buy security from the
        // two cheap directions rather than from queries.
        (40, 4, 20),
        (54, 3, 20),
        (80, 2, 20),
    ];

    let mut rows: Vec<Row> = Vec::new();
    for (q, b, p) in settings {
        let (bytes, commit, opened, opening, prove_us, verify_us, ok) =
            composed_proof_at::<{ crate::prover::REGISTERS }, 16, 32, 16, 64>(32, q, b, p);
        rows.push(Row {
            queries: q,
            blowup: b,
            pow: p,
            conjectured: bits_conjectured(q, b, p).min(FIELD_BITS),
            johnson: bits_johnson(q, b, p).min(FIELD_BITS),
            bytes,
            commit,
            opened,
            opening,
            prove_ms: prove_us as f64 / 1000.0,
            verify_ms: verify_us as f64 / 1000.0,
            verifies: ok,
        });
    }

    println!("  {:>7} {:>7} {:>5} {:>7} {:>8} {:>12} {:>10} {:>10} {:>9}",
             "queries", "blowup", "pow", "conj.", "Johnson", "proof bytes", "prove ms", "verify ms", "verifies");
    println!("  {:>7} {:>7} {:>5} {:>7} {:>8} {:>12} {:>10} {:>10}",
             "-".repeat(7), "-".repeat(7), "-".repeat(5), "-".repeat(7),
             "-".repeat(8), "-".repeat(12), "-".repeat(10), "-".repeat(10));
    for r in &rows {
        println!("  {:>7} {:>7} {:>5} {:>7} {:>8} {:>12} {:>10.2} {:>10.3} {:>9}",
                 r.queries, 1usize << r.blowup, r.pow, r.conjectured, r.johnson,
                 r.bytes, r.prove_ms, r.verify_ms, r.verifies);
    }

    println!();
    println!("  Blowup is the reciprocal rate. Conjectured soundness assumes a query");
    println!("  costs the full rate; Johnson is what holds without that conjecture and");
    println!("  is the figure to size a secret or a bond against. Both are capped at");
    println!("  {} bits, the challenge field.", FIELD_BITS);

    println!();
    println!("  WHERE THE BYTES ARE. A wrapper replaces the opening proof and nothing else.");
    println!("  {:>7} {:>7} {:>5} {:>12} {:>12} {:>12} {:>7}",
             "queries", "blowup", "pow", "commitments", "opened", "opening", "opening%");
    println!("  {:>7} {:>7} {:>5} {:>12} {:>12} {:>12} {:>7}",
             "-".repeat(7), "-".repeat(7), "-".repeat(5),
             "-".repeat(12), "-".repeat(12), "-".repeat(12), "-".repeat(7));
    for r in &rows {
        let pct = 100.0 * r.opening as f64 / r.bytes as f64;
        println!("  {:>7} {:>7} {:>5} {:>12} {:>12} {:>12} {:>6.1}%",
                 r.queries, 1usize << r.blowup, r.pow, r.commit, r.opened, r.opening, pct);
    }

    println!();
    println!("WHAT A SETTLEMENT DOMAIN CAN CARRY");
    println!("{}", "=".repeat(78));
    println!("  call data in one 30M-gas block, at 16 gas a byte    {:>12}", CALLDATA_BYTES_PER_BLOCK);
    println!("  one EIP-4844 blob                                   {:>12}", BLOB_BYTES);
    println!();
    println!("  {:>12} {:>10} {:>12} {:>12}", "proof bytes", "Johnson", "blocks", "blobs");
    println!("  {:>12} {:>10} {:>12} {:>12}",
             "-".repeat(12), "-".repeat(10), "-".repeat(12), "-".repeat(12));
    for r in &rows {
        println!("  {:>12} {:>10} {:>12.2} {:>12.1}",
                 r.bytes, r.johnson,
                 r.bytes as f64 / CALLDATA_BYTES_PER_BLOCK as f64,
                 r.bytes as f64 / BLOB_BYTES as f64);
    }

    let best = rows.iter().min_by_key(|r| r.bytes).expect("at least one setting");
    println!();
    println!("  The smallest proof measured here is {} bytes at {} provable bits,",
             best.bytes, best.johnson);
    println!("  which is {:.1} blobs. No setting in this sweep brings a proof of this",
             best.bytes as f64 / BLOB_BYTES as f64);
    println!("  circuit within one block of call data: the opening proof dominates and");
    println!("  it shrinks only with the query count, which is what soundness buys.");
    println!("  A backend meeting a settlement domain's budget has to replace the");
    println!("  opening argument, not tune it.");
}
