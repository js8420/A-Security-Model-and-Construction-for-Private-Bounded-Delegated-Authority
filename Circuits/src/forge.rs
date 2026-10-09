//! Stage one of the structure-aware dispute, fourth part: the forger's best
//! response.
//!
//! Corrupting a finished proof says little about where a dispute lands. A
//! value the transcript absorbs moves the proof-of-work, and a value it does
//! not absorb is caught by the root it opens under. A forger redoes the work
//! instead: it changes what it claims at the out-of-domain point, and then
//! runs the rest of the prover honestly, so the proof-of-work is ground again
//! and every query is opened at the positions the new transcript draws.
//!
//! uni-stark's prove is followed step for step through the public Pcs trait.
//! The one step it hides is the opening, which computes the values at zeta
//! and absorbs them in one call; it is ported here from p3-fri 0.6.3
//! (two_adic_pcs.rs, open, and the hiding wrapper in hiding_pcs.rs) with a
//! single place where the claimed values can be changed before they are
//! absorbed. Opened honestly, the port must give a proof Plonky3 accepts.

use std::marker::PhantomData;

use p3_air::{AirLayout, BaseAir};
use p3_challenger::{CanObserve, FieldChallenger};
use p3_commit::{Mmcs, PolynomialSpace};
use p3_dft::{Radix2DFTSmallBatch, TwoAdicSubgroupDft};
use p3_field::coset::TwoAdicMultiplicativeCoset;
use p3_field::{Field, PrimeCharacteristicRing};
use p3_fri::prover::prove_fri;
use p3_fri::TwoAdicFriFoldingForMmcs;
use p3_goldilocks::default_goldilocks_poseidon2_8;
use p3_matrix::bitrev::BitReversibleMatrix;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::interpolation::Interpolate;
use p3_matrix::Matrix;
use p3_uni_stark::{get_log_num_quotient_chunks, quotient_values, Commitments, OpenedValues, Proof};
use p3_util::{log2_strict_usize, reverse_slice_index_bits};

use crate::naysay::{
    all_positions, first_word, identity, outputs, record, run_queries, sides, Air, Point, RConfig, RProof,
};
use crate::prover::{
    deployed_fri, deployed_pcs, Challenge, Challenger, Compress, Hash, Pcs, SaltRng, Val, ValMmcs,
    LOG_BLOWUP, LOG_FINAL_POLY_LEN, NUM_QUERIES, NUM_RANDOM_CODEWORDS, ROWS,
};

/// Coefficients of the final polynomial. The FRI prover reads them off the
/// first this many values of the last layer, in bit-reversed order.
const FINAL_POLY_LEN: usize = 1 << LOG_FINAL_POLY_LEN;

/// Each lying forgery is made this many times, every time with fresh
/// randomness, because how many queries it fails is a random draw.
pub const REPEATS: usize = 8;
use crate::trace::{composed_case, ComposedBreak};

type Data = <ValMmcs as Mmcs<Val>>::ProverData<RowMajorMatrix<Val>>;

/// Every value claimed at an opening point: round, matrix, point, column,
/// random codewords included.
type Claims = Vec<Vec<Vec<Vec<Challenge>>>>;

/// What the forger changes before the claims are absorbed.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Lie {
    /// Nothing: the port must then agree with Plonky3's own prover.
    None,
    /// One trace value at zeta.
    TraceAtZeta,
    /// One trace value at the next row.
    TraceAtNext,
    /// One quotient chunk value at zeta.
    QuotientChunk,
    /// The quotient chunk value that makes the out-of-domain identity hold,
    /// which is what a forger proving a false statement needs.
    BalanceIdentity,
    /// The same, and then the FRI input replaced by its low-degree part
    /// before it is committed as layer 0, so every later layer and the
    /// final polynomial agree and the lie sits between the opened rows and
    /// layer 0.
    BalanceAndSmooth,
}

/// Values the forger needs to balance the identity.
struct Ood<'a> {
    air: &'a Air,
    pv: &'a [Val],
    alpha: Challenge,
    zeta: Challenge,
    degree_bits: usize,
    width: usize,
}

fn apply(lie: Lie, claims: &mut Claims, ood: &Ood) {
    match lie {
        Lie::None => {}
        Lie::TraceAtZeta => claims[1][0][0][0] += Challenge::ONE,
        Lie::TraceAtNext => claims[1][0][1][0] += Challenge::ONE,
        Lie::QuotientChunk => claims[2][0][0][0] += Challenge::ONE,
        Lie::BalanceIdentity | Lie::BalanceAndSmooth => {
            let w = ood.width;
            let local = &claims[1][0][0][..w];
            let next = &claims[1][0][1][..w];
            let chunks: Vec<Vec<Challenge>> =
                claims[2].iter().map(|m| m[0][..m[0].len() - NUM_RANDOM_CODEWORDS].to_vec()).collect();
            let side = |c: &[Vec<Challenge>]| sides(ood.air, local, next, c, ood.pv, ood.alpha, ood.zeta, ood.degree_bits);
            // The recomposed quotient is linear in each chunk value, so one
            // probe gives the step that balances it.
            let (target, q0, _) = side(&chunks);
            let mut probe = chunks.clone();
            probe[0][0] += Challenge::ONE;
            let (_, q1, _) = side(&probe);
            claims[2][0][0][0] += (target - q0) * (q1 - q0).inverse();
        }
    }
}

/// A bit-reversed codeword cut to its first `keep` coefficients. The coset
/// shift does not matter: interpolating and evaluating both treat the values
/// as those of f(gx) on the subgroup.
fn low_degree_part(mut v: Vec<Challenge>, keep: usize) -> Vec<Challenge> {
    let dft = Radix2DFTSmallBatch::<Val>::default();
    reverse_slice_index_bits(&mut v);
    let mut c = dft.idft_algebra(v);
    c[keep..].iter_mut().for_each(|x| *x = Challenge::ZERO);
    let mut e = dft.dft_algebra(c);
    reverse_slice_index_bits(&mut e);
    e
}

/// p3-fri's TwoAdicFriPcs::open and HidingFriPcs::open, with the forger's
/// change made to the claims before they are absorbed.
fn open(
    rounds: &[(&Data, Vec<Vec<Challenge>>)],
    ch: &mut Challenger,
    lie: Lie,
    ood: &Ood,
) -> (Claims, <Pcs as p3_commit::Pcs<Challenge, Challenger>>::Proof) {
    let perm = default_goldilocks_poseidon2_8();
    let mmcs = ValMmcs::new(Hash::new(perm.clone()), Compress::new(perm), 0, SaltRng::seeded(0));
    let mats: Vec<Vec<&RowMajorMatrix<Val>>> = rounds.iter().map(|(d, _)| mmcs.get_matrices(*d)).collect();

    let log_global = mats.iter().flatten().map(|m| log2_strict_usize(m.height())).max().expect("a matrix");

    // The value at z of each committed column, from the rows that are the
    // polynomial's own evaluations: the first height >> blowup of the
    // bit-reversed LDE are the coset of that size.
    let mut claims: Claims = mats
        .iter()
        .zip(rounds)
        .map(|(ms, (_, pts))| {
            ms.iter()
                .zip(pts)
                .map(|(m, ps)| {
                    let h = m.height() >> LOG_BLOWUP;
                    let low = m.as_view().split_rows(h).0.bit_reverse_rows().to_row_major_matrix();
                    ps.iter().map(|&z| low.interpolate_coset(Val::GENERATOR, z)).collect()
                })
                .collect()
        })
        .collect();

    apply(lie, &mut claims, ood);
    for ys in claims.iter().flatten().flatten() {
        ch.observe_algebra_slice(ys);
    }
    let alpha: Challenge = ch.sample_algebra_element();

    // sum alpha^k (f(z) - f(x)) / (z - x), one vector per height, rows in
    // bit-reversed order, as the library builds them.
    let mut coset: Vec<Val> = TwoAdicMultiplicativeCoset::new(Val::GENERATOR, log_global).expect("coset").iter().collect();
    reverse_slice_index_bits(&mut coset);
    let mut reduced: Vec<Option<Vec<Challenge>>> = vec![None; 33];
    let mut used = [0usize; 33];
    for ((ms, (_, pts)), cr) in mats.iter().zip(rounds).zip(&claims) {
        for ((m, ps), cm) in ms.iter().zip(pts).zip(cr) {
            let lh = log2_strict_usize(m.height());
            let acc = reduced[lh].get_or_insert_with(|| vec![Challenge::ZERO; m.height()]);
            let pows: Vec<Challenge> = alpha.powers().take(m.width()).collect();
            let rows: Vec<Challenge> = (0..m.height())
                .map(|r| m.row_slice(r).expect("row").iter().zip(&pows).map(|(&v, &a)| a * v).sum())
                .collect();
            for (&z, ys) in ps.iter().zip(cm) {
                let offset = alpha.exp_u64(used[lh] as u64);
                let at_z: Challenge = ys.iter().zip(&pows).map(|(&y, &a)| a * y).sum();
                for (r, ro) in acc.iter_mut().enumerate() {
                    *ro += offset * (at_z - rows[r]) * (z - coset[r]).inverse();
                }
                used[lh] += m.width();
            }
        }
    }
    let mut inputs: Vec<Vec<Challenge>> = reduced.into_iter().rev().flatten().collect();
    if lie == Lie::BalanceAndSmooth {
        let keep = inputs[0].len() >> LOG_BLOWUP;
        inputs[0] = low_degree_part(std::mem::take(&mut inputs[0]), keep);
    }

    let folding: TwoAdicFriFoldingForMmcs<Val, ValMmcs> = p3_fri::TwoAdicFriFolding(PhantomData);
    let refs: Vec<(&Data, Vec<Vec<Challenge>>)> = rounds.iter().map(|(d, p)| (*d, p.clone())).collect();
    let fri = prove_fri(&folding, &deployed_fri(), inputs, ch, log_global, &refs, &mmcs);

    // The hiding wrapper keeps the random codewords' values out of the
    // public openings and carries them in the proof.
    let hidden: Claims = claims
        .iter_mut()
        .map(|r| {
            r.iter_mut()
                .map(|m| m.iter_mut().map(|p| p.split_off(p.len() - NUM_RANDOM_CODEWORDS)).collect())
                .collect()
        })
        .collect();
    (claims, (hidden, fri))
}

/// uni-stark's prove, step for step, with the opening replaced by the port.
pub fn forge(air: &Air, trace: RowMajorMatrix<Val>, pv: &[Val], lie: Lie) -> RProof {
    let pcs = deployed_pcs();
    let nd = |d: usize| <Pcs as p3_commit::Pcs<Challenge, Challenger>>::natural_domain_for_degree(&pcs, d);
    let mut ch = Challenger::new(default_goldilocks_poseidon2_8());

    let degree = trace.height();
    let log_degree = log2_strict_usize(degree);
    let log_ext = log_degree + 1;
    let layout = AirLayout {
        preprocessed_width: 0,
        main_width: BaseAir::<Val>::width(air),
        num_public_values: BaseAir::<Val>::num_public_values(air),
        num_periodic_columns: BaseAir::<Val>::num_periodic_columns(air),
        ..Default::default()
    };
    let log_chunks = get_log_num_quotient_chunks::<Val, Air>(air, layout, 1);
    let chunks = 1usize << (log_chunks + 1);
    let trace_domain = nd(degree);
    let ext_domain = nd(degree << 1);

    let (trace_commit, trace_data) = <Pcs as p3_commit::Pcs<Challenge, Challenger>>::commit(&pcs, [(ext_domain, trace)]);
    ch.observe(Val::from_usize(log_ext));
    ch.observe(Val::from_usize(log_degree));
    ch.observe(Val::ZERO);
    ch.observe(trace_commit.clone());
    ch.observe_slice(pv);
    let alpha: Challenge = ch.sample_algebra_element();

    let quotient_domain = ext_domain.create_disjoint_domain(1 << (log_ext + log_chunks));
    let on_quotient = <Pcs as p3_commit::Pcs<Challenge, Challenger>>::get_evaluations_on_domain(&pcs, &trace_data, 0, quotient_domain);
    let q = quotient_values::<RConfig, Air, _>(
        &pcs, air, pv, layout, trace_domain, quotient_domain, &on_quotient, None, alpha,
    );
    let flat = RowMajorMatrix::new_col(q).flatten_to_base();
    let (q_commit, q_data) = <Pcs as p3_commit::Pcs<Challenge, Challenger>>::commit_quotient(&pcs, quotient_domain, flat, chunks);
    ch.observe(q_commit.clone());

    let (r_commit, r_data) = <Pcs as p3_commit::Pcs<Challenge, Challenger>>::get_opt_randomization_poly_commitment(
        &pcs,
        core::iter::once(ext_domain),
    )
    .expect("zero knowledge");
    ch.observe(r_commit.clone());

    let zeta: Challenge = ch.sample_algebra_element();
    let zeta_next = trace_domain.next_point(zeta).expect("next point");

    let rounds = [
        (&r_data, vec![vec![zeta]]),
        (&trace_data, vec![vec![zeta, zeta_next]]),
        (&q_data, vec![vec![zeta]; chunks]),
    ];
    let ood = Ood { air, pv, alpha, zeta, degree_bits: log_ext, width: layout.main_width };
    let (claims, opening_proof) = open(&rounds, &mut ch, lie, &ood);

    Proof {
        commitments: Commitments { trace: trace_commit, quotient_chunks: q_commit, random: Some(r_commit) },
        opened_values: OpenedValues {
            trace_local: claims[1][0][0].clone(),
            trace_next: Some(claims[1][0][1].clone()),
            preprocessed_local: None,
            preprocessed_next: None,
            quotient_chunks: claims[2].iter().map(|m| m[0].clone()).collect(),
            random: Some(claims[0][0][0].clone()),
        },
        opening_proof,
        degree_bits: log_ext,
    }
}

/// One forgery, judged by Plonky3 and by the port.
pub struct Forgery {
    pub plonky3: String,
    /// The out-of-domain identity, judged by the port of part 2.
    pub identity_holds: bool,
    /// Queries in which any comparison fails, and how many queries fail first
    /// at each kind of comparison.
    pub queries_failing: usize,
    pub first_at: Vec<(Point, usize)>,
    /// The port's first failure (query, comparison), or the identity if no
    /// query fails, agrees with Plonky3's error.
    pub agrees: bool,
    pub library_agrees: bool,
    /// A query passes exactly when it lands on one of the last layer's
    /// points the final polynomial was read from.
    pub passes_where_read: bool,
}

fn judge(air: &Air, proof: &RProof, pv: &[Val]) -> Forgery {
    let (ev, verdict) = record(air, proof, pv);
    let plonky3 = verdict.err().map(|e| first_word(&e)).unwrap_or_else(|| "accepted".into());
    let id = identity(air, proof, pv, &ev);
    // Plonky3 stops at the first failing query, so its recording holds the
    // positions only up to there; all forty are drawn again from the state
    // the proof-of-work was checked in.
    let fri = &proof.opening_proof.1;
    let log_global = fri.query_proofs[0].commit_phase_openings.iter().map(|s| s.log_arity as usize).sum::<usize>()
        + LOG_BLOWUP
        + LOG_FINAL_POLY_LEN;
    let mut out = outputs(&ev, fri.commit_phase_commits.len());
    out.positions = all_positions(&ev, log_global, fri.query_proofs.len());
    let (runs, _) = run_queries(proof, &out);
    let mut first_at: Vec<(Point, usize)> = Vec::new();
    for p in runs.iter().filter_map(|r| r.failed.first()) {
        match first_at.iter_mut().find(|(q, _)| q == p) {
            Some((_, n)) => *n += 1,
            None => first_at.push((*p, 1)),
        }
    }
    let first = runs.iter().find_map(|r| r.failed.first());
    let agrees = match first {
        Some(p) => plonky3.contains(p.plonky3()),
        None if !id.holds => plonky3.contains("OodEvaluationMismatch"),
        None => plonky3 == "accepted",
    };
    Forgery {
        plonky3,
        identity_holds: id.holds,
        queries_failing: runs.iter().filter(|r| !r.failed.is_empty()).count(),
        first_at,
        agrees,
        library_agrees: runs.iter().all(|r| r.library_agrees),
        passes_where_read: runs.iter().all(|r| r.failed.is_empty() == (r.final_index < FINAL_POLY_LEN)),
    }
}

/// One kind of forgery over its repeats.
pub struct Row {
    pub label: &'static str,
    pub lie: Lie,
    pub runs: Vec<Forgery>,
}

impl Row {
    /// Queries failing per repeat: min, median, max.
    pub fn failing(&self) -> (usize, usize, usize) {
        let mut v: Vec<usize> = self.runs.iter().map(|f| f.queries_failing).collect();
        v.sort_unstable();
        (v[0], v[v.len() / 2], v[v.len() - 1])
    }

    pub fn passed(&self) -> usize {
        self.runs.iter().map(|f| NUM_QUERIES - f.queries_failing).sum()
    }

    pub fn holds(&self) -> bool {
        // A lie folded honestly leaves the last layer far from low degree,
        // so a query passes only where the final polynomial was read off. A
        // smoothed lie fails every query at layer 0. No lie, every query
        // passes.
        self.runs.iter().all(|f| {
            f.agrees
                && f.library_agrees
                && match self.lie {
                    Lie::None => f.queries_failing == 0,
                    Lie::BalanceAndSmooth => f.first_at == [(Point::LayerRoot(0), NUM_QUERIES)],
                    _ => f.passes_where_read,
                }
        })
    }

    pub fn lying(&self) -> bool {
        !matches!(self.lie, Lie::None | Lie::BalanceAndSmooth)
    }
}

pub struct ForgeReport {
    pub honest_port_accepted: bool,
    pub rows: Vec<Row>,
}

pub fn run() -> ForgeReport {
    let air = Air::new();
    let (t, pv) = composed_case::<{ crate::prover::REGISTERS }, 16, 32, 16, 64>(ROWS, None);

    // The port of the opening, telling no lie, against Plonky3's verifier.
    let honest = forge(&air, t.clone(), &pv, Lie::None);
    let honest_port_accepted = record(&air, &honest, &pv).1.is_ok();

    let mut rows = Vec::new();
    let mut row = |label: &'static str, trace: &RowMajorMatrix<Val>, pv: &[Val], lie: Lie, times: usize| {
        let runs = (0..times).map(|_| judge(&air, &forge(&air, trace.clone(), pv, lie), pv)).collect();
        rows.push(Row { label, lie, runs });
    };

    row("true statement, trace value at zeta", &t, &pv, Lie::TraceAtZeta, REPEATS);
    row("true statement, trace value at next row", &t, &pv, Lie::TraceAtNext, REPEATS);
    row("true statement, quotient chunk at zeta", &t, &pv, Lie::QuotientChunk, REPEATS);

    // A public value changed and the whole proof made again is the forger's
    // answer to the public-value corruption of part 1: an honest proof of a
    // false statement. Its verdict does not depend on the draw.
    let mut pvs = pv.clone();
    pvs[0] += Val::ONE;
    row("public value changed, proved again", &t, &pvs, Lie::None, 1);

    for (honest_label, label, smooth_label, b) in [
        ("run start disagrees with C8, no lie", "run start disagrees with C8, identity balanced",
         "run start disagrees with C8, balanced, layer 0 smoothed", ComposedBreak::RunStartMismatch),
        ("amount exceeds the units, no lie", "amount exceeds the units, identity balanced",
         "amount exceeds the units, balanced, layer 0 smoothed", ComposedBreak::AmountRaised),
        ("shares under another domain, no lie", "shares under another domain, identity balanced",
         "shares under another domain, balanced, layer 0 smoothed", ComposedBreak::ShareDomain),
    ] {
        let (tb, pvb) = composed_case::<{ crate::prover::REGISTERS }, 16, 32, 16, 64>(ROWS, Some(b));
        row(honest_label, &tb, &pvb, Lie::None, 1);
        row(label, &tb, &pvb, Lie::BalanceIdentity, REPEATS);
        row(smooth_label, &tb, &pvb, Lie::BalanceAndSmooth, REPEATS);
    }
    ForgeReport { honest_port_accepted, rows }
}
