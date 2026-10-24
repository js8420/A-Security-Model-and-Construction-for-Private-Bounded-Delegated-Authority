//! What a settlement domain would have to carry, and what it would have to give
//! up to make the proof smaller.
//!
//! Two numbers govern a deployment and the paper reports only one of them. The
//! first is proof size, which decides whether a chain can hold the proof at all.
//! The second is soundness, which decides what the proof is worth. They move
//! against each other through the FRI parameters, and quoting one setting hides
//! the trade.
//!
//! Soundness is reported twice on purpose. The conjectured figure charges a
//! query the full rate, which is what deployed systems assume. The provable
//! figure is the round-by-round bound of `soundness.rs`, which needs no
//! conjecture. Over the cubic extension the deployment uses, the queries bind
//! it; over a degree-2 extension the batching term would cap it near 72 bits
//! whatever the queries. A reader sizing a secret or a bond should use the
//! provable figure.

use crate::prover::{composed_proof_at, composed_verifies, LOG_BLOWUP, NUM_QUERIES, POW_BITS};
use crate::soundness::{conjectured, provable, provable_against, COMPOSED};

/// Gas a byte of call data costs a data-heavy transaction under EIP-7623's
/// floor, which the measured posting of the batch proof pays.
const CALLDATA_GAS_PER_BYTE: usize = 40;
/// Call data one 60M-gas Ethereum block admits at that price.
const CALLDATA_BYTES_PER_BLOCK: usize = 60_000_000 / CALLDATA_GAS_PER_BYTE;
/// The chunk the dispute contract posts a proof in, under the 128 KiB
/// transaction pool limit and the 120,000-byte deposit cap of the OP Stack.
const CHUNK_BYTES: usize = 98_304;
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
/// than argued from the distribution, with the two settings interleaved, at
/// the deployed queries and rate.
fn grinding() {
    const ITERS: usize = 24;
    let mut off: Vec<f64> = Vec::with_capacity(ITERS);
    let mut on: Vec<f64> = Vec::with_capacity(ITERS);
    let mut ok_all = true;
    for _ in 0..ITERS {
        let (_, _, _, _, us0, _, o0) =
            composed_proof_at::<{ crate::prover::REGISTERS }, 16, 32, 16, 64>(crate::prover::ROWS, NUM_QUERIES, LOG_BLOWUP, 0);
        let (_, _, _, _, us1, _, o1) =
            composed_proof_at::<{ crate::prover::REGISTERS }, 16, 32, 16, 64>(crate::prover::ROWS, NUM_QUERIES, LOG_BLOWUP, POW_BITS);
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
    println!("  Same circuit, {} queries at blowup {}, {} interleaved pairs. Only the", NUM_QUERIES, 1usize << LOG_BLOWUP, ITERS);
    println!("  grinding bits differ. Every proof verifies: {}.", ok_all);
    println!();
    println!("  {:<22} {:>9} {:>9} {:>9} {:>9} {:>9}", "grinding bits", "min", "q1", "median", "q3", "q3-q1");
    println!("  {:<22} {:>9} {:>9} {:>9} {:>9} {:>9}",
             "-".repeat(22), "-".repeat(9), "-".repeat(9), "-".repeat(9), "-".repeat(9), "-".repeat(9));
    println!("  {:<22} {:>9.2} {:>9.2} {:>9.2} {:>9.2} {:>9.2}", "0", a0, b0, c0, d0, d0 - b0);
    println!("  {:<22} {:>9.2} {:>9.2} {:>9.2} {:>9.2} {:>9.2}", POW_BITS, a1, b1, c1, d1, d1 - b1);
    println!();
    println!("  median difference {:.2} ms, spread difference {:.2} ms.", c1 - c0, (d1 - b1) - (d0 - b0));
    println!("  A geometric search over 2^20 hashes has a mean and a standard");
    println!("  deviation of the same order, so if grinding is the source these two");
    println!("  differences should be comparable and the 0-bit row should be tight.");
}

/// One hiding configuration reused, against a fresh one per proof.
fn config_reuse() {
    const ITERS: usize = 20;
    let shared = crate::prover::composed_times::<{ crate::prover::REGISTERS }, 16, 32, 16, 64>(crate::prover::ROWS, ITERS, true);
    let fresh  = crate::prover::composed_times::<{ crate::prover::REGISTERS }, 16, 32, 16, 64>(crate::prover::ROWS, ITERS, false);
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
/// step. Every game starts from the empty memory, so the program first loads
/// the proof, one Goldilocks element per step from the blobs it was published
/// in, and the statement's public values from the reserve's record. FRI's
/// own folding and the batched reduction of the opened values are further work
/// on top, so the total is a lower bound on the program's length.
pub fn step_count() {
    let public_values = p3_air::BaseAir::<p3_goldilocks::Goldilocks>::num_public_values(
        &crate::composed::ComposedAir::<{ crate::prover::REGISTERS }, 16, 32, 16, 64>::new(),
    );
    const ELEMENTS_PER_BLOB: usize = 4096 * 3;
    let w = crate::prover::verifier_work::<{ crate::prover::REGISTERS }, 16, 32, 16, 64>(crate::prover::ROWS);
    let words = w.proof_bytes.div_ceil(8);
    let blobs = words.div_ceil(ELEMENTS_PER_BLOB);
    let total = w.permutations as usize + w.constraint_ops + 2 * w.constraints + words + public_values;
    println!();
    println!("ADJUDICABLE STEPS IN ONE VERIFICATION, COUNTED, POSEIDON2 COMMITMENTS (BISECTION STUDY)");
    println!("{}", "=".repeat(78));
    println!("  composed circuit, {} rows, verifies         {:>12}", crate::prover::ROWS, w.verifies);
    println!("  Poseidon2 permutations during verify         {:>12}", w.permutations);
    println!("  constraints                                  {:>12}", w.constraints);
    println!("  distinct operations evaluating them          {:>12}", w.constraint_ops);
    println!("  folding them into one, two per constraint    {:>12}", 2 * w.constraints);
    println!("  proof bytes                                  {:>12}", w.proof_bytes);
    println!("  loading the proof, one element per step      {:>12}", words);
    println!("  loading the public values                    {:>12}", public_values);
    println!("  blobs, three elements to a blob element      {:>12}", blobs);
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
    println!("  {:<46} {:>10}", "8 / 8 / 16 / 14, deployed height",
             composed_verifies::<{ crate::prover::REGISTERS }, 8, 8, 16, 14>(crate::prover::ROWS));
    println!("  {:<46} {:>10}", "16 / 32 / 16 / 14, deployed height",
             composed_verifies::<{ crate::prover::REGISTERS }, 16, 32, 16, 14>(crate::prover::ROWS));
    println!("  {:<46} {:>10}", "16 / 32 / 16 / 64, deployed height (the paper's)",
             composed_verifies::<{ crate::prover::REGISTERS }, 16, 32, 16, 64>(crate::prover::ROWS));
    println!();
    println!("FRI PARAMETERS: PROOF SIZE AGAINST SOUNDNESS, COMPOSED CIRCUIT AT {} ROWS", crate::prover::ROWS);
    println!("{}", "=".repeat(78));

    let settings: Vec<(usize, usize, usize)> = vec![
        // The deployed setting, then the neighbours that reach about 100
        // provable bits over the cubic extension, then settings that do not
        // admit a degree-seven quotient under the hiding commitment.
        (44, 4, 20),
        (40, 4, 20),
        (50, 4, 20),
        (44, 3, 20),
        (54, 3, 20),
        (58, 3, 20),
        (40, 3, 8),
        (44, 2, 20),
        (40, 2, 8),
        (40, 1, 8),
    ];

    let mut rows: Vec<Row> = Vec::new();
    for (q, b, p) in settings {
        let (bytes, commit, opened, opening, prove_us, verify_us, ok) =
            composed_proof_at::<{ crate::prover::REGISTERS }, 16, 32, 16, 64>(crate::prover::ROWS, q, b, p);
        rows.push(Row {
            queries: q,
            blowup: b,
            pow: p,
            conjectured: conjectured(&COMPOSED, q, b, p).floor() as usize,
            johnson: provable(&COMPOSED, q, b, p).floor() as usize,
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
             "queries", "blowup", "pow", "conj.", "provable", "proof bytes", "prove ms", "verify ms", "verifies");
    println!("  {:>7} {:>7} {:>5} {:>7} {:>8} {:>12} {:>10} {:>10}",
             "-".repeat(7), "-".repeat(7), "-".repeat(5), "-".repeat(7),
             "-".repeat(8), "-".repeat(12), "-".repeat(10), "-".repeat(10));
    for r in &rows {
        println!("  {:>7} {:>7} {:>5} {:>7} {:>8} {:>12} {:>10.2} {:>10.3} {:>9}",
                 r.queries, 1usize << r.blowup, r.pow, r.conjectured, r.johnson,
                 r.bytes, r.prove_ms, r.verify_ms, r.verifies);
    }

    println!();
    println!("  Blowup is the reciprocal rate. Conjectured soundness charges a query");
    println!("  the full rate; provable is the round-by-round bound, which needs no");
    println!("  conjecture and is the figure to size a secret or a bond against.");

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
    println!("  call data in one 60M-gas block, at {} gas a byte   {:>12}", CALLDATA_GAS_PER_BYTE, CALLDATA_BYTES_PER_BLOCK);
    println!("  the dispute contract's chunk                        {:>12}", CHUNK_BYTES);
    println!("  one EIP-4844 blob                                   {:>12}", BLOB_BYTES);
    println!();
    println!("  {:>12} {:>10} {:>12} {:>12} {:>12}", "proof bytes", "provable", "blocks", "chunks", "blobs");
    println!("  {:>12} {:>10} {:>12} {:>12} {:>12}",
             "-".repeat(12), "-".repeat(10), "-".repeat(12), "-".repeat(12), "-".repeat(12));
    for r in &rows {
        println!("  {:>12} {:>10} {:>12.2} {:>12} {:>12.1}",
                 r.bytes, r.johnson,
                 r.bytes as f64 / CALLDATA_BYTES_PER_BLOCK as f64,
                 r.bytes.div_ceil(CHUNK_BYTES),
                 r.bytes as f64 / BLOB_BYTES as f64);
    }

    let best = rows.iter().filter(|r| r.verifies).min_by_key(|r| r.bytes).expect("a setting that verifies");
    println!();
    println!("  The smallest proof that verifies here is {} bytes at {} provable bits:",
             best.bytes, best.johnson);
    println!("  {:.2} blocks of call data, {} chunks, {:.1} blobs. The opening proof",
             best.bytes as f64 / CALLDATA_BYTES_PER_BLOCK as f64,
             best.bytes.div_ceil(CHUNK_BYTES), best.bytes as f64 / BLOB_BYTES as f64);
    println!("  dominates and shrinks only with the query count, which is what");
    println!("  soundness buys, so a smaller proof needs another opening argument.");
}


/// For each of blowup 16 with 20 grinding bits, blowup 16 with 30, and
/// blowup 32 with 20, the fewest queries over the degree-5 extension that are
/// provably at least 100 bits against an adversary making 2^64 oracle
/// queries (`se_bound.py`), beside the earlier setting, which is not, all at
/// the deployed height. Each round proves and verifies
/// every setting once, in rotating order, so drift falls on all of them.
pub fn candidates(rounds: usize) {
    let settings: [(usize, usize, usize); 4] = [(44, 4, 20), (74, 4, 20), (68, 4, 30), (58, 5, 20)];
    let mut prove: Vec<Vec<f64>> = vec![Vec::new(); settings.len()];
    let mut check: Vec<Vec<f64>> = vec![Vec::new(); settings.len()];
    let mut bytes = [0usize; 4];
    let mut ok = [true; 4];
    for round in 0..rounds {
        for k in 0..settings.len() {
            let i = (k + round) % settings.len();
            let (q, b, p) = settings[i];
            let (whole, _, _, _, pu, vu, good) =
                composed_proof_at::<{ crate::prover::REGISTERS }, 16, 32, 16, 64>(crate::prover::ROWS, q, b, p);
            bytes[i] = whole;
            ok[i] &= good;
            prove[i].push(pu as f64 / 1000.0);
            check[i].push(vu as f64 / 1000.0);
        }
    }
    let quart = |v: &mut Vec<f64>| {
        v.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let at = |f: f64| v[((v.len() - 1) as f64 * f).round() as usize];
        (at(0.25), at(0.5), at(0.75))
    };
    println!("DEGREE-5 EXTENSION: SETTINGS AGAINST 2^64 ORACLE QUERIES, {} ROWS, {rounds} ROUNDS", crate::prover::ROWS);
    println!("{}", "=".repeat(78));
    println!("  {:>7} {:>6} {:>4} {:>8} {:>7} {:>7} {:>11} {:>23} {:>22} {:>8}",
             "queries", "blowup", "pow", "rbr", "2^48", "2^64", "proof bytes", "prove ms q1/med/q3", "verify ms q1/med/q3", "verifies");
    for (i, (q, b, p)) in settings.iter().enumerate() {
        let (p1, pm, p3) = quart(&mut prove[i]);
        let (v1, vm, v3) = quart(&mut check[i]);
        println!("  {:>7} {:>6} {:>4} {:>8.1} {:>7.1} {:>7.1} {:>11} {:>7.0} {:>7.0} {:>7.0} {:>7.2} {:>6.2} {:>7.2} {:>8}",
                 q, 1usize << b, p,
                 provable(&COMPOSED, *q, *b, *p),
                 provable_against(&COMPOSED, *q, *b, *p, 48),
                 provable_against(&COMPOSED, *q, *b, *p, 64),
                 bytes[i], p1, pm, p3, v1, vm, v3, ok[i]);
    }
}
