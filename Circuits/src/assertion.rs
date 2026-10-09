//! Stage one of the structure-aware dispute, fifth part: what a challenged
//! defender asserts for every target, and the game that decides it.
//!
//! Each long check of the verifier is a chain: a start, a step applied n
//! times, and an end that meets a committed value. The transcript is a chain
//! of duplex permutations; a leaf hash is a chain of sponge permutations; the
//! out-of-domain identity and a query's reduced opening are running sums. The
//! defender asserts states of the chain, the naysayer holds the true chain
//! computed from public data, and bisection over the defender's states ends
//! at one step that either side can recompute: the leaf a contract decides.
//!
//! Every chain is built here from a real proof and checked against what the
//! verifier itself computes. Then a lying defender is played against it at
//! the start, middle and end of each chain, and against the forgeries of
//! part four, where the lie is solved for so the chain ends where the
//! forgery needs it to.

use std::collections::HashMap;

use p3_air::symbolic::SymbolicExpr;
use p3_air::{BaseEntry, BaseLeaf};
use p3_commit::PolynomialSpace;
use p3_field::{BasedVectorSpace, Field, PrimeCharacteristicRing, TwoAdicField};
use p3_goldilocks::default_goldilocks_poseidon2_8;
use p3_symmetric::Permutation;
use p3_uni_stark::prove;
use p3_util::reverse_bits_len;

use crate::forge::{forge_with_layer0, Lie};
use crate::naysay::{
    all_positions, at_root, config, fold, outputs, record_ops, rounds, run_queries, sides, walk, Air, Op,
    Outputs, RProof, Recording,
};
use crate::prover::{
    deployed_pcs, Challenge, Compress, Hash, Pcs, Val, LOG_BLOWUP, LOG_FINAL_POLY_LEN, ROWS,
};
use crate::trace::{composed_case, ComposedBreak};

type State = [Val; 8];
const RATE: usize = 4;

/// A start and n steps. states[k + 1] = step(k, states[k]).
pub struct Chain<S, F: Fn(usize, &S) -> S> {
    pub states: Vec<S>,
    step: F,
}

impl<S: Clone + PartialEq, F: Fn(usize, &S) -> S> Chain<S, F> {
    pub fn build(start: S, n: usize, step: F) -> Self {
        let mut states = Vec::with_capacity(n + 1);
        states.push(start);
        for k in 0..n {
            let next = step(k, &states[k]);
            states.push(next);
        }
        Self { states, step }
    }

    pub fn steps(&self) -> usize {
        self.states.len() - 1
    }

    pub fn end(&self) -> &S {
        &self.states[self.steps()]
    }

    /// A defender who agrees up to state j - 1, asserts a changed state j,
    /// and then steps honestly from it, so its chain is consistent everywhere
    /// except the one step into j.
    pub fn lie_at(&self, j: usize, change: impl Fn(&S) -> S) -> Vec<S> {
        let mut out = self.states[..j].to_vec();
        out.push(change(&self.states[j]));
        for k in j..self.steps() {
            let next = (self.step)(k, &out[k]);
            out.push(next);
        }
        out
    }

    /// The game. The naysayer holds this chain; the defender's claimed chain
    /// starts where it does and ends elsewhere. Each round the defender
    /// asserts the midpoint and the naysayer keeps the half where they first
    /// disagree. The leaf is one step from an agreed state to a disputed one,
    /// recomputed by the adjudicator.
    pub fn bisect(&self, claimed: &[S]) -> Game {
        let n = self.steps();
        assert!(claimed[0] == self.states[0] && claimed[n] != self.states[n], "a dispute needs a disputed end");
        let (mut lo, mut hi, mut rounds) = (0, n, 0);
        while hi - lo > 1 {
            let mid = (lo + hi) / 2;
            rounds += 1;
            if claimed[mid] == self.states[mid] {
                lo = mid;
            } else {
                hi = mid;
            }
        }
        Game { rounds, leaf: lo, rejects: (self.step)(lo, &claimed[lo]) != claimed[hi] }
    }
}

pub struct Game {
    pub rounds: usize,
    pub leaf: usize,
    /// The adjudicator, stepping from the agreed state, does not reach what
    /// the defender asserted.
    pub rejects: bool,
}

fn rounds_for(n: usize) -> usize {
    n.next_power_of_two().trailing_zeros() as usize
}

// ---------------------------------------------------------------------------
// The transcript: one step per duplex permutation, as DuplexChallenger in
// p3-challenger 0.6.3 performs it. Elements absorbed overwrite the rate;
// a partial block zeroes the rest of the rate and adds its length into the
// first capacity element; a draw pops from the end of the rate the last
// permutation left.
// ---------------------------------------------------------------------------

fn duplex(s: &State, chunk: &[Val]) -> State {
    let mut t = *s;
    t[..chunk.len()].copy_from_slice(chunk);
    if !chunk.is_empty() {
        t[chunk.len()..RATE].fill(Val::ZERO);
        t[RATE] += Val::from_usize(chunk.len());
    }
    default_goldilocks_poseidon2_8().permute_mut(&mut t);
    t
}

pub struct Transcript {
    pub chunks: Vec<Vec<Val>>,
    /// Each draw: the permutation it comes after, and its place in the rate.
    pub draws: Vec<(usize, usize)>,
    /// Every draw the replay makes equals the one the verifier made.
    pub agrees: bool,
}

fn transcript(ops: &[Op]) -> Transcript {
    let mut state = [Val::ZERO; 8];
    let (mut input, mut output): (Vec<Val>, Vec<Val>) = (Vec::new(), Vec::new());
    let mut chunks = Vec::new();
    let mut draws = Vec::new();
    let mut agrees = true;
    let go = |input: &mut Vec<Val>, output: &mut Vec<Val>, state: &mut State, chunks: &mut Vec<Vec<Val>>| {
        let c: Vec<Val> = std::mem::take(input);
        *state = duplex(state, &c);
        chunks.push(c);
        output.clear();
        output.extend_from_slice(&state[..RATE]);
    };
    for op in ops {
        match *op {
            Op::In(v) => {
                output.clear();
                input.push(v);
                if input.len() == RATE {
                    go(&mut input, &mut output, &mut state, &mut chunks);
                }
            }
            Op::Out(v) => {
                if !input.is_empty() || output.is_empty() {
                    go(&mut input, &mut output, &mut state, &mut chunks);
                }
                let place = output.len() - 1;
                agrees &= output.pop() == Some(v);
                draws.push((chunks.len(), place));
            }
        }
    }
    Transcript { chunks, draws, agrees }
}

// ---------------------------------------------------------------------------
// A leaf hash: one step per permutation of the overwrite sponge of rate four
// (p3-symmetric PaddingFreeSponge). A last partial block overwrites only what
// it holds; nothing is padded or tagged.
// ---------------------------------------------------------------------------

fn sponge(s: &State, chunk: &[Val]) -> State {
    let mut t = *s;
    t[..chunk.len()].copy_from_slice(chunk);
    default_goldilocks_poseidon2_8().permute_mut(&mut t);
    t
}

// ---------------------------------------------------------------------------
// The out-of-domain identity: one step per constraint, acc * alpha + c_k,
// with c_k evaluated alone from its symbolic expression at the opened values.
// This is what an adjudicator evaluates for one constraint, and it is a
// second evaluator beside the folder of part two.
// ---------------------------------------------------------------------------

type Expr = SymbolicExpr<BaseLeaf<Val>>;

struct Point<'a> {
    local: &'a [Challenge],
    next: &'a [Challenge],
    pv: &'a [Val],
    first: Challenge,
    last: Challenge,
    transition: Challenge,
}

fn eval(e: &Expr, at: &Point, memo: &mut HashMap<*const Expr, Challenge>) -> Challenge {
    let key = e as *const Expr;
    if let Some(v) = memo.get(&key) {
        return *v;
    }
    let v = match e {
        SymbolicExpr::Leaf(BaseLeaf::Variable(v)) => match v.entry {
            BaseEntry::Main { offset: 0 } => at.local[v.index],
            BaseEntry::Main { .. } => at.next[v.index],
            BaseEntry::Public => Challenge::from(at.pv[v.index]),
            BaseEntry::Preprocessed { .. } | BaseEntry::Periodic => unreachable!("not in this AIR"),
        },
        SymbolicExpr::Leaf(BaseLeaf::IsFirstRow) => at.first,
        SymbolicExpr::Leaf(BaseLeaf::IsLastRow) => at.last,
        SymbolicExpr::Leaf(BaseLeaf::IsTransition) => at.transition,
        SymbolicExpr::Leaf(BaseLeaf::Constant(c)) => Challenge::from(*c),
        SymbolicExpr::Add { x, y, .. } => eval(x, at, memo) + eval(y, at, memo),
        SymbolicExpr::Sub { x, y, .. } => eval(x, at, memo) - eval(y, at, memo),
        SymbolicExpr::Mul { x, y, .. } => eval(x, at, memo) * eval(y, at, memo),
        SymbolicExpr::Neg { x, .. } => -eval(x, at, memo),
    };
    memo.insert(key, v);
    v
}

struct Identity {
    values: Vec<Challenge>,
    alpha: Challenge,
    /// The folded side the end is compared with: quotient divided by the
    /// inverse vanishing polynomial at zeta, so end == target exactly when
    /// the identity holds.
    target: Challenge,
    end_matches_folder: bool,
    values_match_folder: bool,
}

fn drawn_ext(ops: &[Op], i: usize) -> Challenge {
    let outs: Vec<Val> = ops.iter().filter_map(|o| if let Op::Out(v) = o { Some(*v) } else { None }).collect();
    Challenge::from_basis_coefficients_slice(&outs[2 * i..2 * i + 2]).expect("two")
}

fn identity(air: &Air, proof: &RProof, pv: &[Val], ops: &[Op]) -> Identity {
    let (alpha, zeta) = (drawn_ext(ops, 0), drawn_ext(ops, 1));
    let ov = &proof.opened_values;
    let local = &ov.trace_local;
    let next = ov.trace_next.as_deref().expect("next row");
    let pcs = deployed_pcs();
    let init = <Pcs as p3_commit::Pcs<Challenge, Recording>>::natural_domain_for_degree(&pcs, 1 << (proof.degree_bits - 1));
    let sels = init.selectors_at_point(zeta);
    let at = Point { local, next, pv, first: sels.is_first_row, last: sels.is_last_row, transition: sels.is_transition };

    let cs = p3_air::get_symbolic_constraints::<Val, _>(air, p3_air::AirLayout::from_air::<Val>(air));
    let mut memo = HashMap::new();
    let values: Vec<Challenge> = cs.iter().map(|c| eval(c, &at, &mut memo)).collect();
    let (lhs, rhs, folder) = sides(air, local, next, &ov.quotient_chunks, pv, alpha, zeta, proof.degree_bits);
    let mut acc = Challenge::ZERO;
    for v in &values {
        acc = acc * alpha + *v;
    }
    Identity {
        values_match_folder: values == folder,
        end_matches_folder: acc * sels.inv_vanishing == lhs,
        target: rhs * sels.inv_vanishing.inverse(),
        values,
        alpha,
    }
}

// ---------------------------------------------------------------------------
// A query's reduced opening: one step per (column, point) term, in the order
// open_input sums them, with the running power of the batching alpha.
// ---------------------------------------------------------------------------

/// Bits of the largest committed domain, which query positions index.
fn log_global(proof: &RProof) -> usize {
    proof.opening_proof.1.query_proofs[0].commit_phase_openings.iter().map(|s| s.log_arity as usize).sum::<usize>()
        + LOG_BLOWUP
        + LOG_FINAL_POLY_LEN
}

struct Term {
    at_x: Val,
    at_z: Challenge,
    inv: Challenge,
}

fn reduced_terms(proof: &RProof, out: &Outputs, q: usize) -> Vec<Term> {
    let rs = rounds(proof, out.zeta);
    let qp = &proof.opening_proof.1.query_proofs[q];
    let log_global = log_global(proof);
    let index = out.positions[q];
    let mut terms = Vec::new();
    for (opening, mats) in qp.input_proof.iter().zip(&rs) {
        for (row, m) in opening.opened_values.iter().zip(mats) {
            let lh = m.log_size + LOG_BLOWUP;
            let rev = reverse_bits_len(index >> (log_global - lh), lh);
            let x = Val::GENERATOR * Val::two_adic_generator(lh).exp_u64(rev as u64);
            for (z, at_z) in &m.points {
                let inv = (*z - x).inverse();
                for (&px, &pz) in row.iter().zip(at_z) {
                    terms.push(Term { at_x: px, at_z: pz, inv });
                }
            }
        }
    }
    terms
}

/// A target's shape: steps, the field elements in one state, and what the
/// defender posts interactively (one state a round) against all at once.
pub struct Size {
    pub name: &'static str,
    pub steps: usize,
    pub state: usize,
}

impl Size {
    pub fn rounds(&self) -> usize {
        rounds_for(self.steps)
    }
    pub fn interactive(&self) -> usize {
        self.rounds() * self.state
    }
    pub fn full(&self) -> usize {
        (self.steps + 1) * self.state
    }
}

/// One played game: which chain, where the defender lied, where bisection
/// ended, and whether the leaf exposed it.
pub struct Played {
    pub chain: &'static str,
    pub lie: String,
    pub steps: usize,
    pub rounds: usize,
    pub found: bool,
    pub rejects: bool,
}

pub struct AssertionReport {
    pub sizes: Vec<Size>,
    pub transcript_agrees: bool,
    pub transcript_draws: usize,
    pub identity_values_agree: bool,
    pub identity_end_agrees: bool,
    pub identity_holds: bool,
    pub reduced_agree: usize,
    pub leaves_agree: usize,
    pub queries: usize,
    pub games: Vec<Played>,
    /// Forgeries of part four, with the defender lying to cover them.
    pub forgeries: Vec<Played>,
    /// The constant-size check a folded-honestly forgery cannot pass: the
    /// defender's claimed last fold, against the fold the adjudicator computes.
    pub final_fold_rejects: bool,
    pub smoothed_root_passes_with_lie: bool,
}

fn play<S: Clone + PartialEq, F: Fn(usize, &S) -> S>(
    games: &mut Vec<Played>,
    name: &'static str,
    chain: &Chain<S, F>,
    lie: String,
    claimed: Vec<S>,
    j: usize,
) {
    let g = chain.bisect(&claimed);
    games.push(Played {
        chain: name,
        lie,
        steps: chain.steps(),
        rounds: g.rounds,
        found: g.leaf + 1 == j,
        rejects: g.rejects,
    });
}

/// A changed sponge state. The change goes in the capacity: the next block
/// overwrites the rate, so a change there can vanish before the end.
fn bump8(s: &State) -> State {
    let mut t = *s;
    t[7] += Val::ONE;
    t
}

pub fn run() -> AssertionReport {
    let air = Air::new();
    let (t, pv) = composed_case::<{ crate::prover::REGISTERS }, 16, 32, 16, 64>(ROWS, None);
    let proof: RProof = prove(&config().0, &air, t, &pv);
    let (ev, ops, verdict) = record_ops(&air, &proof, &pv);
    assert!(verdict.is_ok(), "honest proof must verify");
    let fri = &proof.opening_proof.1;
    let out = outputs(&ev, fri.commit_phase_commits.len());
    let (runs, _) = run_queries(&proof, &out);

    let mut sizes = Vec::new();
    let mut games = Vec::new();

    // Transcript.
    let tr = transcript(&ops);
    let chunks = tr.chunks.clone();
    let tc = Chain::build([Val::ZERO; 8], chunks.len(), |k, s: &State| duplex(s, &chunks[k]));
    sizes.push(Size { name: "transcript, one permutation a step", steps: tc.steps(), state: 8 });
    for j in [1, tc.steps() / 2, tc.steps()] {
        play(&mut games, "transcript", &tc, format!("state {j}"), tc.lie_at(j, bump8), j);
    }

    // Out-of-domain identity.
    let id = identity(&air, &proof, &pv, &ops);
    let values = id.values.clone();
    let alpha = id.alpha;
    let ic = Chain::build(Challenge::ZERO, values.len(), |k, a: &Challenge| *a * alpha + values[k]);
    sizes.push(Size { name: "identity, one constraint a step", steps: ic.steps(), state: 2 });
    for j in [1, ic.steps() / 2, ic.steps()] {
        play(&mut games, "identity", &ic, format!("sum {j}"), ic.lie_at(j, |a| *a + Challenge::ONE), j);
    }

    // Each query: the reduced opening and the three input leaves.
    let mut reduced_agree = 0;
    let mut leaves_agree = 0;
    for (q, r) in runs.iter().enumerate() {
        let terms = reduced_terms(&proof, &out, q);
        let fa = out.fri_alpha;
        let rc = Chain::build((Challenge::ONE, Challenge::ZERO), terms.len(), |k, s: &(Challenge, Challenge)| {
            let t = &terms[k];
            (s.0 * fa, s.1 + s.0 * (t.at_z - t.at_x) * t.inv)
        });
        reduced_agree += (rc.end().1 == r.reduced) as usize;
        let mut all = true;
        for (b, opening) in fri.query_proofs[q].input_proof.iter().enumerate() {
            let flat: Vec<Val> = opening
                .opened_values
                .iter()
                .zip(&opening.opening_proof.0)
                .flat_map(|(row, salt)| row.iter().chain(salt.iter()).copied())
                .collect();
            let blocks: Vec<&[Val]> = flat.chunks(RATE).collect();
            let lc = Chain::build([Val::ZERO; 8], blocks.len(), |k, s: &State| sponge(s, blocks[k]));
            all &= lc.end()[..4] == r.leaves[b][..];
            if q == 0 {
                sizes.push(Size {
                    name: ["random input leaf", "trace input leaf", "quotient input leaf"][b],
                    steps: lc.steps(),
                    state: 8,
                });
                if b == 1 {
                    for j in [1, lc.steps() / 2, lc.steps()] {
                        play(&mut games, "trace leaf", &lc, format!("state {j}"), lc.lie_at(j, bump8), j);
                    }
                }
            }
        }
        leaves_agree += all as usize;
        if q == 0 {
            sizes.push(Size { name: "reduced opening, one term a step", steps: rc.steps(), state: 4 });
            for j in [1, rc.steps() / 2, rc.steps()] {
                play(
                    &mut games,
                    "reduced opening",
                    &rc,
                    format!("sum {j}"),
                    rc.lie_at(j, |s| (s.0, s.1 + Challenge::ONE)),
                    j,
                );
            }
        }
    }

    // The forgeries of part four, the defender covering each with a lie
    // solved for so its chain ends where the forgery needs it to.
    let mut forgeries = Vec::new();
    let (tb, pvb) = composed_case::<{ crate::prover::REGISTERS }, 16, 32, 16, 64>(ROWS, Some(ComposedBreak::RunStartMismatch));

    // No lie at zeta: the identity's true end misses its target. The sum is
    // affine in each state, so a change of d at state j reaches the end as
    // d * alpha^(n - j).
    let (pa, _) = forge_with_layer0(&air, tb.clone(), &pvb, Lie::None);
    let (_, opsa, _) = record_ops(&air, &pa, &pvb);
    let ida = identity(&air, &pa, &pvb, &opsa);
    let va = ida.values.clone();
    let aa = ida.alpha;
    let ica = Chain::build(Challenge::ZERO, va.len(), |k, a: &Challenge| *a * aa + va[k]);
    let n = ica.steps();
    for j in [1, n / 3, n] {
        let d = (ida.target - *ica.end()) * aa.exp_u64((n - j) as u64).inverse();
        let claimed = ica.lie_at(j, |a| *a + d);
        assert!(claimed[n] == ida.target, "the lie reaches the target");
        play(&mut forgeries, "identity", &ica, format!("false payment, no lie at zeta; covered at sum {j}"), claimed, j);
    }

    // Balanced and smoothed: the honest reduced opening fails layer root 0.
    // The defender asserts the value it committed there instead, and must
    // then cover the difference inside the running sum, where a change of d
    // carries to the end unchanged.
    let (pc, layer0) = forge_with_layer0(&air, tb.clone(), &pvb, Lie::BalanceAndSmooth);
    let (evc, _, _) = record_ops(&air, &pc, &pvb);
    let fc = &pc.opening_proof.1;
    let mut outc = outputs(&evc, fc.commit_phase_commits.len());
    outc.positions = all_positions(&evc, log_global(&pc), fc.query_proofs.len());
    let terms = reduced_terms(&pc, &outc, 0);
    let fa = outc.fri_alpha;
    let rcc = Chain::build((Challenge::ONE, Challenge::ZERO), terms.len(), |k, s: &(Challenge, Challenge)| {
        let t = &terms[k];
        (s.0 * fa, s.1 + s.0 * (t.at_z - t.at_x) * t.inv)
    });
    let index = outc.positions[0];
    let committed = layer0[index];
    // With the committed value in place of the reduced opening, layer root 0
    // opens: the lie moves out of the Merkle check and into the sum.
    let step0 = &fc.query_proofs[0].commit_phase_openings[0];
    let la = step0.log_arity as usize;
    let arity = 1usize << la;
    let mut evals = vec![Challenge::ZERO; arity];
    let mut sib = step0.sibling_values.iter();
    for (k, e) in evals.iter_mut().enumerate() {
        *e = if k == index % arity { committed } else { *sib.next().expect("sibling") };
    }
    let perm = default_goldilocks_poseidon2_8();
    let (hash, compress) = (Hash::new(perm.clone()), Compress::new(perm));
    let leaf_in: Vec<Val> = evals
        .iter()
        .flat_map(|e| e.as_basis_coefficients_slice().to_vec())
        .chain(step0.opening_proof.0.iter().flatten().copied())
        .collect();
    let leaf = p3_symmetric::CryptographicHasher::hash_iter(&hash, leaf_in);
    let smoothed_root_passes_with_lie =
        at_root(&fc.commit_phase_commits[0], walk(leaf, &step0.opening_proof.1, index >> la, &compress))
            && committed != rcc.end().1;
    let n = rcc.steps();
    for j in [1, n / 2, n] {
        let d = committed - rcc.end().1;
        let claimed = rcc.lie_at(j, |s| (s.0, s.1 + d));
        play(
            &mut forgeries,
            "reduced opening",
            &rcc,
            format!("false payment, smoothed; covered at sum {j}"),
            claimed,
            j,
        );
    }

    // Balanced and folded honestly: the last fold misses the final
    // polynomial. A defender asserting the value the final polynomial gives
    // is refuted by the fold step itself, from the authenticated row of the
    // last layer.
    let (pb, _) = forge_with_layer0(&air, tb, &pvb, Lie::BalanceIdentity);
    let (evb, _, _) = record_ops(&air, &pb, &pvb);
    let fb = &pb.opening_proof.1;
    let lgc = log_global(&pb);
    let mut outb = outputs(&evb, fb.commit_phase_commits.len());
    outb.positions = all_positions(&evb, lgc, fb.query_proofs.len());
    let (rb, _) = run_queries(&pb, &outb);
    let q = rb.iter().position(|r| !r.failed.is_empty()).expect("a failing query");
    let qp = &fb.query_proofs[q];
    let rounds_n = qp.commit_phase_openings.len();
    let mut di = outb.positions[q];
    let mut lh = lgc;
    let mut folded = rb[q].reduced;
    let mut last_evals = Vec::new();
    for (r, st) in qp.commit_phase_openings.iter().enumerate() {
        let la = st.log_arity as usize;
        let arity = 1usize << la;
        let mut ev = vec![Challenge::ZERO; arity];
        let mut sib = st.sibling_values.iter();
        for (k, e) in ev.iter_mut().enumerate() {
            *e = if k == di % arity { folded } else { *sib.next().expect("sibling") };
        }
        lh -= la;
        di >>= la;
        folded = fold(di, lh, la, outb.betas[r], &ev);
        if r + 1 == rounds_n {
            last_evals = ev;
        }
    }
    let x = Val::two_adic_generator(lgc).exp_u64(reverse_bits_len(di, lgc) as u64);
    let mut claim = Challenge::ZERO;
    for &c in fb.final_poly.iter().rev() {
        claim = claim * x + c;
    }
    let la_last = qp.commit_phase_openings[rounds_n - 1].log_arity as usize;
    let final_fold_rejects = claim != folded && fold(di, lh, la_last, outb.betas[rounds_n - 1], &last_evals) != claim;

    AssertionReport {
        sizes,
        transcript_agrees: tr.agrees,
        transcript_draws: tr.draws.len(),
        identity_values_agree: id.values_match_folder,
        identity_end_agrees: id.end_matches_folder,
        identity_holds: *ic.end() == id.target,
        reduced_agree,
        leaves_agree,
        queries: runs.len(),
        games,
        forgeries,
        final_fold_rejects,
        smoothed_root_passes_with_lie,
    }
}
