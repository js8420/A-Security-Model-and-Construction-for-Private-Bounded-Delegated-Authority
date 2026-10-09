//! Stage one of disputing a proof by its structure: what a defender would
//! assert when challenged, and which check a false proof fails.
//!
//! The verifier accepts only if every one of its checks holds, so a false proof
//! fails at least one. A dispute first fixes the Fiat-Shamir transcript, the
//! defender asserting each challenge and the sponge state it was drawn from,
//! and then names one failing check. This module records that transcript from
//! the real verifier, by running it with a challenger that writes down what it
//! is asked, and maps every way of corrupting a proof to the check Plonky3
//! itself rejects it at. Query positions are cross-checked against the ones an
//! attacker finds with no transcript at all, by searching the commitment.

use std::sync::{Arc, Mutex};

use p3_air::BaseAir;
use p3_challenger::{CanObserve, CanSample, CanSampleBits, FieldChallenger, GrindingChallenger};
use p3_commit::{BatchOpeningRef, Mmcs};
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing};
use p3_goldilocks::default_goldilocks_poseidon2_8;
use p3_matrix::Dimensions;
use p3_symmetric::MerkleCap;
use p3_uni_stark::{prove, verify, Proof, StarkConfig};

use crate::composed::ComposedAir;
use crate::prover::{
    deployed_pcs, Challenge, Challenger, Compress, Hash, Pcs, SaltRng, Val, ValMmcs, LOG_BLOWUP,
    LOG_FINAL_POLY_LEN, NUM_RANDOM_CODEWORDS, ROWS,
};
use crate::trace::{composed_case, ComposedBreak};

/// One thing the verifier did with its transcript.
#[derive(Clone)]
pub enum Event {
    /// Base-field elements absorbed since the last event.
    Absorbed(usize),
    /// A challenge drawn, with the challenger as it stood just before.
    Drawn { value: Vec<Val>, before: Challenger },
    /// Query position bits drawn.
    Bits { bits: usize, value: usize, before: Challenger },
}

/// The deployed challenger, writing down what it is asked.
#[derive(Clone)]
pub struct Recording {
    inner: Challenger,
    log: Arc<Mutex<Vec<Event>>>,
}

impl Recording {
    fn new() -> Self {
        Self {
            inner: Challenger::new(default_goldilocks_poseidon2_8()),
            log: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn absorbed(&self, n: usize) {
        let mut log = self.log.lock().expect("log");
        if let Some(Event::Absorbed(k)) = log.last_mut() {
            *k += n;
        } else {
            log.push(Event::Absorbed(n));
        }
    }

    fn take(&self) -> Vec<Event> {
        std::mem::take(&mut *self.log.lock().expect("log"))
    }
}

impl CanObserve<Val> for Recording {
    fn observe(&mut self, value: Val) {
        self.absorbed(1);
        self.inner.observe(value);
    }
}

impl CanObserve<MerkleCap<Val, [Val; 4]>> for Recording {
    fn observe(&mut self, value: MerkleCap<Val, [Val; 4]>) {
        let n = value.as_ref().len() * 4;
        self.absorbed(n);
        self.inner.observe(value);
    }
}

impl CanSample<Val> for Recording {
    fn sample(&mut self) -> Val {
        let before = self.inner.clone();
        let v: Val = self.inner.sample();
        self.log.lock().expect("log").push(Event::Drawn { value: vec![v], before });
        v
    }
}

impl CanSample<Challenge> for Recording {
    fn sample(&mut self) -> Challenge {
        let before = self.inner.clone();
        let v: Challenge = self.inner.sample();
        self.log
            .lock()
            .expect("log")
            .push(Event::Drawn { value: v.as_basis_coefficients_slice().to_vec(), before });
        v
    }
}

impl CanSampleBits<usize> for Recording {
    fn sample_bits(&mut self, bits: usize) -> usize {
        let before = self.inner.clone();
        let value = self.inner.sample_bits(bits);
        self.log.lock().expect("log").push(Event::Bits { bits, value, before });
        value
    }
}

impl FieldChallenger<Val> for Recording {}

impl GrindingChallenger for Recording {
    type Witness = Val;

    fn grind(&mut self, bits: usize) -> Val {
        self.inner.grind(bits)
    }
}

pub(crate) type RConfig = StarkConfig<Pcs, Challenge, Recording>;
pub(crate) type RProof = Proof<RConfig>;

/// A configuration and a handle on its challenger's log. Every challenger the
/// configuration hands out is a clone sharing that log.
pub(crate) fn config() -> (RConfig, Recording) {
    let r = Recording::new();
    (StarkConfig::new(deployed_pcs(), r.clone()), r)
}

pub(crate) type Air = ComposedAir<{ crate::prover::REGISTERS }, 16, 32, 16, 64>;

/// What a challenged defender asserts: every challenge, in order, with the
/// state it was drawn from.
pub struct Transcript {
    pub absorbed: usize,
    pub challenges: usize,
    pub challenge_elements: usize,
    pub positions: Vec<usize>,
    pub position_bits: usize,
    pub checkpoints: usize,
    /// Field elements the defender posts for all checkpoints: each sponge
    /// state with whatever its buffers hold.
    pub checkpoint_elements: usize,
    /// Every challenge, drawn again from its asserted state, comes out the
    /// same. This is the leaf a transcript dispute ends at.
    pub replays: bool,
}

fn summarise(events: &[Event]) -> Transcript {
    let mut t = Transcript {
        absorbed: 0,
        challenges: 0,
        challenge_elements: 0,
        positions: Vec::new(),
        position_bits: 0,
        checkpoints: 0,
        checkpoint_elements: 0,
        replays: true,
    };
    let size = |c: &Challenger| c.sponge_state.len() + c.input_buffer.len() + c.output_buffer.len();
    for e in events {
        match e {
            Event::Absorbed(n) => t.absorbed += n,
            Event::Drawn { value, before } => {
                t.challenges += 1;
                t.challenge_elements += value.len();
                t.checkpoints += 1;
                t.checkpoint_elements += size(before);
                let mut c = before.clone();
                let again: Vec<Val> = if value.len() == 1 {
                    vec![CanSample::<Val>::sample(&mut c)]
                } else {
                    let e: Challenge = c.sample();
                    e.as_basis_coefficients_slice().to_vec()
                };
                t.replays &= again == *value;
            }
            Event::Bits { bits, value, before } => {
                t.checkpoints += 1;
                t.checkpoint_elements += size(before);
                let mut c = before.clone();
                t.replays &= c.sample_bits(*bits) == *value;
                // The query proof-of-work draws its bits first; positions follow.
                if *bits == crate::prover::POW_BITS && t.positions.is_empty() {
                    t.challenges += 1;
                } else {
                    t.positions.push(*value);
                    t.position_bits = *bits;
                }
            }
        }
    }
    t
}

/// The sponge as it stood when the query proof-of-work was checked, which is
/// the state every query position is drawn from. None if verification
/// stopped before reaching it.
fn pow_state(events: &[Event]) -> Option<Vec<Val>> {
    events.iter().find_map(|e| match e {
        Event::Bits { bits, before, .. } if *bits == crate::prover::POW_BITS => Some(
            before
                .sponge_state
                .iter()
                .chain(&before.input_buffer)
                .chain(&before.output_buffer)
                .copied()
                .collect(),
        ),
        _ => None,
    })
}

/// Every query position, drawn from the state the proof-of-work was checked
/// in, as verify_fri draws them. A recording stops where the verifier stopped,
/// which for a failing query phase is before the last position.
pub(crate) fn all_positions(events: &[Event], log_global: usize, queries: usize) -> Vec<usize> {
    let Some(mut c) = events.iter().find_map(|e| match e {
        Event::Bits { bits, before, .. } if *bits == crate::prover::POW_BITS => Some(before.clone()),
        _ => None,
    }) else {
        return Vec::new();
    };
    c.sample_bits(crate::prover::POW_BITS);
    (0..queries).map(|_| c.sample_bits(log_global)).collect()
}

/// Verify with the recording challenger; the transcript and the verdict.
pub(crate) fn record(air: &Air, proof: &RProof, pv: &[Val]) -> (Vec<Event>, Result<(), String>) {
    let (cfg, log) = config();
    let r = verify(&cfg, air, proof, pv).map_err(|e| format!("{:?}", e));
    (log.take(), r)
}

/// The query positions, found the attacker's way: no transcript, only the
/// commitment, by trying every index until the opened row opens.
fn positions_by_search(proof: &RProof, width: usize) -> Vec<usize> {
    let perm = default_goldilocks_poseidon2_8();
    let mmcs = ValMmcs::new(Hash::new(perm.clone()), Compress::new(perm), 0, SaltRng::seeded(0));
    let log_lde = (2 * ROWS).trailing_zeros() as usize + LOG_BLOWUP;
    let height = 1usize << log_lde;
    let committed = width + NUM_RANDOM_CODEWORDS;
    let dims = [Dimensions { width: committed, height }];
    let mut out = Vec::new();
    for q in &proof.opening_proof.1.query_proofs {
        let Some(b) = q.input_proof.iter().find(|b| {
            b.opened_values.len() == 1 && b.opened_values[0].len() == committed
        }) else {
            out.push(usize::MAX);
            continue;
        };
        let found = (0..height)
            .find(|&i| mmcs.verify_batch(&proof.commitments.trace, &dims, i, BatchOpeningRef::from(b)).is_ok());
        out.push(found.unwrap_or(usize::MAX));
    }
    out
}

/// A proof is not Clone; a serialisation round trip is an exact copy.
fn dup(p: &RProof) -> RProof {
    bincode::deserialize(&bincode::serialize(p).expect("serialise")).expect("deserialise")
}

/// Where a corruption lands, in Plonky3's own words.
pub struct Landing {
    pub label: &'static str,
    pub rejected: bool,
    pub error: String,
    pub positions_moved: bool,
}

pub(crate) fn first_word(e: &str) -> String {
    e.split(|c: char| !c.is_alphanumeric()).filter(|w| !w.is_empty()).take(3).collect::<Vec<_>>().join(" ")
}

pub struct Report {
    pub honest_verifies: bool,
    pub transcript: Transcript,
    pub search_agrees: usize,
    pub search_total: usize,
    pub landings: Vec<Landing>,
}

pub fn run() -> Report {
    let air = Air::new();
    let width = BaseAir::<Val>::width(&air);
    let (t, pv) = composed_case::<{ crate::prover::REGISTERS }, 16, 32, 16, 64>(ROWS, None);
    let proof: RProof = prove(&config().0, &air, t, &pv);

    let (events, honest) = record(&air, &proof, &pv);
    let transcript = summarise(&events);
    let honest_state = pow_state(&events);

    // The trace lives on a domain of 2n rows extended by the blowup; the
    // positions FRI draws index the largest committed domain, which may be
    // taller, so compare after shifting down to the trace's height.
    let log_trace_lde = (2 * ROWS).trailing_zeros() as usize + LOG_BLOWUP;
    let shift = transcript.position_bits.saturating_sub(log_trace_lde);
    let searched = positions_by_search(&proof, width);
    let search_agrees = transcript
        .positions
        .iter()
        .zip(&searched)
        .filter(|(a, b)| (*a >> shift) == **b)
        .count();

    let mut landings = Vec::new();
    let mut land = |label: &'static str, p: &RProof, pvs: &[Val]| {
        let (ev, r) = record(&air, p, pvs);
        // Positions move exactly when the state they are drawn from does.
        // Comparing the positions themselves would mislead: Plonky3 stops at
        // the first failing query or at the proof-of-work, so fewer are drawn.
        let moved = pow_state(&ev) != honest_state;
        landings.push(Landing {
            label,
            rejected: r.is_err(),
            error: r.err().map(|e| first_word(&e)).unwrap_or_else(|| "accepted".into()),
            positions_moved: moved,
        });
    };

    let one = Challenge::ONE;
    let mut p = dup(&proof);
    p.opened_values.trace_local[0] += one;
    land("opened trace value at zeta", &p, &pv);

    let mut p = dup(&proof);
    if let Some(n) = p.opened_values.trace_next.as_mut() {
        n[0] += one;
    }
    land("opened trace value at the next row", &p, &pv);

    let mut p = dup(&proof);
    p.opened_values.quotient_chunks[0][0] += one;
    land("opened quotient chunk", &p, &pv);

    let mut p = dup(&proof);
    p.opening_proof.1.final_poly[0] += one;
    land("final polynomial", &p, &pv);

    let mut p = dup(&proof);
    p.opening_proof.1.query_pow_witness += Val::ONE;
    land("query proof-of-work witness", &p, &pv);

    let mut p = dup(&proof);
    p.opening_proof.1.query_proofs[7].commit_phase_openings[0].sibling_values[0] += one;
    land("a fold's sibling value, one query", &p, &pv);

    let mut p = dup(&proof);
    p.opening_proof.1.query_proofs[7].input_proof[0].opened_values[0][0] += Val::ONE;
    land("an opened input row, one query", &p, &pv);

    let mut pvs = pv.clone();
    pvs[0] += Val::ONE;
    land("a public value", &proof, &pvs);

    for (label, b) in [
        ("control: run start disagrees with C8", ComposedBreak::RunStartMismatch),
        ("control: amount exceeds the units", ComposedBreak::AmountRaised),
        ("control: shares under another domain", ComposedBreak::ShareDomain),
    ] {
        let (t, pvb) = composed_case::<{ crate::prover::REGISTERS }, 16, 32, 16, 64>(ROWS, Some(b));
        let pb: RProof = prove(&config().0, &air, t, &pvb);
        land(label, &pb, &pvb);
    }

    Report {
        honest_verifies: honest.is_ok(),
        transcript,
        search_agrees,
        search_total: searched.len(),
        landings,
    }
}

// ---------------------------------------------------------------------------
// The out-of-domain identity, constraint by constraint.
//
// Plonky3 folds every constraint at zeta into one accumulator and compares it
// with the quotient. A dispute over that comparison needs what the fold is
// made of: each constraint's value at zeta and the running sum after it. This
// builder evaluates the AIR exactly as the verifier's folder does and keeps
// both, so the defender's assertion for this target can be generated and its
// total checked against the verifier's own verdict.
// ---------------------------------------------------------------------------

use p3_air::{Air as _, AirBuilder, RowWindow};
use p3_commit::PolynomialSpace;
use p3_uni_stark::recompose_quotient_from_chunks;

pub struct PerConstraint<'a> {
    current: &'a [Challenge],
    next: &'a [Challenge],
    empty: RowWindow<'a, Challenge>,
    public_values: &'a [Val],
    is_first_row: Challenge,
    is_last_row: Challenge,
    is_transition: Challenge,
    alpha: Challenge,
    pub accumulator: Challenge,
    pub values: Vec<Challenge>,
    pub sums: Vec<Challenge>,
}

impl<'a> AirBuilder for PerConstraint<'a> {
    type F = Val;
    type Expr = Challenge;
    type Var = Challenge;
    type PreprocessedWindow = RowWindow<'a, Challenge>;
    type MainWindow = RowWindow<'a, Challenge>;
    type PublicVar = Val;
    type PeriodicVar = Challenge;

    fn main(&self) -> Self::MainWindow {
        RowWindow::from_two_rows(self.current, self.next)
    }

    fn preprocessed(&self) -> &Self::PreprocessedWindow {
        &self.empty
    }

    fn is_first_row(&self) -> Challenge {
        self.is_first_row
    }

    fn is_last_row(&self) -> Challenge {
        self.is_last_row
    }

    fn is_transition(&self) -> Challenge {
        self.is_transition
    }

    fn assert_zero<I: Into<Challenge>>(&mut self, x: I) {
        let v = x.into();
        self.accumulator = self.accumulator * self.alpha + v;
        self.values.push(v);
        self.sums.push(self.accumulator);
    }

    fn public_values(&self) -> &[Val] {
        self.public_values
    }

    fn periodic_values(&self) -> &[Challenge] {
        &[]
    }
}

pub struct Identity {
    pub constraints: usize,
    pub holds: bool,
    /// Field elements in the defender's assertion for this target: every
    /// constraint's value and every running sum, both in the extension.
    pub assertion_elements: usize,
}

fn drawn(events: &[Event]) -> Vec<Val> {
    events
        .iter()
        .filter_map(|e| match e {
            Event::Drawn { value, .. } => Some(value.clone()),
            _ => None,
        })
        .flatten()
        .collect()
}

/// Both sides of the identity at zeta, from opened values: the constraints
/// folded by alpha over the vanishing polynomial, and the quotient
/// recomposed from its chunks. Also the number of constraints.
#[allow(clippy::too_many_arguments)]
pub(crate) fn sides(
    air: &Air,
    local: &[Challenge],
    next: &[Challenge],
    chunks: &[Vec<Challenge>],
    pv: &[Val],
    alpha: Challenge,
    zeta: Challenge,
    degree_bits: usize,
) -> (Challenge, Challenge, usize) {
    let pcs = deployed_pcs();
    let degree = 1usize << degree_bits;
    let init = <Pcs as p3_commit::Pcs<Challenge, Recording>>::natural_domain_for_degree(&pcs, degree >> 1);
    let sels = init.selectors_at_point(zeta);

    let trace_domain = <Pcs as p3_commit::Pcs<Challenge, Recording>>::natural_domain_for_degree(&pcs, degree);
    let log_chunks = chunks.len().trailing_zeros() as usize - 1;
    let quotient_domain = trace_domain.create_disjoint_domain(1usize << (degree_bits + log_chunks));
    let domains = quotient_domain.split_domains(chunks.len());
    let quotient = recompose_quotient_from_chunks::<RConfig>(&domains, chunks, zeta);

    let mut b = PerConstraint {
        current: local,
        next,
        empty: RowWindow::from_two_rows(&[], &[]),
        public_values: pv,
        is_first_row: sels.is_first_row,
        is_last_row: sels.is_last_row,
        is_transition: sels.is_transition,
        alpha,
        accumulator: Challenge::ZERO,
        values: Vec::new(),
        sums: Vec::new(),
    };
    air.eval(&mut b);
    (b.accumulator * sels.inv_vanishing, quotient, b.values.len())
}

/// The identity at zeta from the opened values alone, with alpha and zeta
/// taken from the recorded transcript.
pub(crate) fn identity(air: &Air, proof: &RProof, pv: &[Val], events: &[Event]) -> Identity {
    let e = drawn(events);
    let ext = |i: usize| Challenge::from_basis_coefficients_slice(&e[i..i + 2]).expect("two");
    let (alpha, zeta) = (ext(0), ext(2));
    let local = &proof.opened_values.trace_local;
    let zeros = vec![Challenge::ZERO; local.len()];
    let next = proof.opened_values.trace_next.as_deref().unwrap_or(&zeros);
    let (lhs, rhs, n) =
        sides(air, local, next, &proof.opened_values.quotient_chunks, pv, alpha, zeta, proof.degree_bits);
    Identity { constraints: n, holds: lhs == rhs, assertion_elements: 4 * n }
}

/// What deciding one constraint on chain would read and compute: its own
/// operations, counting a subexpression it uses twice once, and the distinct
/// opened values it reads.
pub struct LeafCost {
    pub max_ops: usize,
    pub median_ops: usize,
    pub max_reads: usize,
    pub median_reads: usize,
}

fn leaf_costs(air: &Air) -> LeafCost {
    use p3_air::symbolic::SymbolicExpr;
    use p3_air::{BaseEntry, BaseLeaf};
    use std::collections::HashSet;
    type E = SymbolicExpr<BaseLeaf<Val>>;
    fn walk(e: &E, seen: &mut HashSet<*const E>, ops: &mut usize, reads: &mut HashSet<(usize, usize)>) {
        let kids: Vec<&std::sync::Arc<E>> = match e {
            SymbolicExpr::Leaf(BaseLeaf::Variable(v)) => {
                if let BaseEntry::Main { offset } = v.entry {
                    reads.insert((offset, v.index));
                }
                return;
            }
            SymbolicExpr::Leaf(_) => return,
            SymbolicExpr::Add { x, y, .. }
            | SymbolicExpr::Sub { x, y, .. }
            | SymbolicExpr::Mul { x, y, .. } => vec![x, y],
            SymbolicExpr::Neg { x, .. } => vec![x],
        };
        *ops += 1;
        for k in kids {
            if seen.insert(std::sync::Arc::as_ptr(k)) {
                walk(k, seen, ops, reads);
            }
        }
    }
    let cs = p3_air::get_symbolic_constraints::<Val, _>(air, p3_air::AirLayout::from_air::<Val>(air));
    let mut ops_all = Vec::with_capacity(cs.len());
    let mut reads_all = Vec::with_capacity(cs.len());
    for c in &cs {
        let (mut seen, mut ops, mut reads) = (HashSet::new(), 0usize, HashSet::new());
        walk(c, &mut seen, &mut ops, &mut reads);
        ops_all.push(ops);
        reads_all.push(reads.len());
    }
    ops_all.sort_unstable();
    reads_all.sort_unstable();
    LeafCost {
        max_ops: *ops_all.last().unwrap_or(&0),
        median_ops: ops_all[ops_all.len() / 2],
        max_reads: *reads_all.last().unwrap_or(&0),
        median_reads: reads_all[reads_all.len() / 2],
    }
}

pub struct OodReport {
    pub honest: Identity,
    pub controls: Vec<(&'static str, bool, bool)>,
    pub leaf: LeafCost,
}

/// The identity for the honest proof and for the three controls, each judged
/// both by this decomposition and by Plonky3.
pub fn run_identity() -> OodReport {
    let air = Air::new();
    let (t, pv) = composed_case::<{ crate::prover::REGISTERS }, 16, 32, 16, 64>(ROWS, None);
    let proof: RProof = prove(&config().0, &air, t, &pv);
    let (ev, _) = record(&air, &proof, &pv);
    let honest = identity(&air, &proof, &pv, &ev);

    let mut controls = Vec::new();
    for (label, b) in [
        ("run start disagrees with C8", ComposedBreak::RunStartMismatch),
        ("amount exceeds the units", ComposedBreak::AmountRaised),
        ("shares under another domain", ComposedBreak::ShareDomain),
    ] {
        let (t, pvb) = composed_case::<{ crate::prover::REGISTERS }, 16, 32, 16, 64>(ROWS, Some(b));
        let pb: RProof = prove(&config().0, &air, t, &pvb);
        let (ev, verdict) = record(&air, &pb, &pvb);
        let ours = identity(&air, &pb, &pvb, &ev).holds;
        let theirs = !verdict.err().map(|e| e.contains("OodEvaluationMismatch")).unwrap_or(false);
        controls.push((label, ours, theirs));
    }
    OodReport { honest, controls, leaf: leaf_costs(&air) }
}

// ---------------------------------------------------------------------------
// The query phase, one query at a time.
//
// verify_query and open_input are private in p3-fri 0.6.3, so they are ported
// here from src/verifier.rs, with the hiding wrapper's merge of public and
// random openings from src/hiding_pcs.rs and the three rounds uni-stark hands
// the PCS (randomisation, trace at zeta and its successor, quotient chunks on
// their randomised domains).
//
// A query computes and compares. The computations (a row's leaf hash, a path
// of compressions, the reduced opening, each fold) cannot fail on their own;
// a false proof fails only where a computed value meets one the prover
// committed to. Those comparisons are what a naysayer points at. The values
// the computations produce are what a challenged defender asserts, so a
// lying defender is caught on a computation and an honest one on a
// comparison. The port runs every comparison of every query rather than
// stopping at the first, because a naysayer may choose the cheapest.
// ---------------------------------------------------------------------------

use std::collections::BTreeMap;
use std::marker::PhantomData;

use p3_commit::BatchOpening;
use p3_field::{Field, HornerIter, TwoAdicField};
use p3_fri::{FriFoldingStrategy, TwoAdicFriFolding};
use p3_symmetric::{CryptographicHasher, PseudoCompressionFunction};
use p3_util::{log2_strict_usize, reverse_bits_len, reverse_slice_index_bits};

use crate::prover::ChallengeMmcs;

/// Where a query's computed value meets a committed one.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Point {
    /// An opening point equals the query point, so (z - x) has no inverse.
    Coincides,
    /// The opened rows of one input round, salted and hashed, walked up their
    /// path, against that round's root.
    InputRoot(usize),
    /// One commit-phase layer: the folded value and its siblings, against
    /// that layer's root.
    LayerRoot(usize),
    /// The last folded value against the final polynomial.
    Final,
}

impl Point {
    /// The FriError variant Plonky3 returns when this comparison fails first.
    pub fn plonky3(&self) -> &'static str {
        match self {
            Point::Coincides => "OpeningPointMatchesQueryPoint",
            Point::InputRoot(_) => "InputError",
            Point::LayerRoot(_) => "CommitPhaseMmcsError",
            Point::Final => "FinalPolyMismatch",
        }
    }

    pub fn name(&self) -> String {
        match self {
            Point::Coincides => "opening point".into(),
            Point::InputRoot(b) => format!("input root {b}"),
            Point::LayerRoot(r) => format!("layer root {r}"),
            Point::Final => "final value".into(),
        }
    }
}

/// One query, run through.
pub struct QueryRun {
    pub index: usize,
    /// What a defender asserts for this query: the reduced opening, the value
    /// after each fold, and every leaf digest (input rounds, then layers).
    pub reduced: Challenge,
    pub folds: Vec<Challenge>,
    pub leaves: Vec<[Val; 4]>,
    /// Every comparison that fails, in the verifier's order.
    pub failed: Vec<Point>,
    /// Each comparison judged a second time by the library itself, and each
    /// fold and the final evaluation recomputed by it: true when all agree.
    pub library_agrees: bool,
    /// The query's index in the last layer, which the final polynomial is
    /// checked at.
    pub final_index: usize,
}

/// The FRI transcript outputs a query needs, read from a recorded run.
pub struct Outputs {
    pub zeta: Challenge,
    pub fri_alpha: Challenge,
    pub betas: Vec<Challenge>,
    pub positions: Vec<usize>,
}

pub(crate) fn outputs(events: &[Event], rounds: usize) -> Outputs {
    let e = drawn(events);
    let ext = |i: usize| Challenge::from_basis_coefficients_slice(&e[2 * i..2 * i + 2]).expect("two");
    // Drawn in order: the constraint alpha, zeta, the FRI batching alpha,
    // then one folding challenge per commit-phase layer.
    Outputs {
        zeta: ext(1),
        fri_alpha: ext(2),
        betas: (0..rounds).map(|r| ext(3 + r)).collect(),
        positions: summarise(events).positions,
    }
}

type InputOpening = BatchOpening<Val, ValMmcs>;

/// One matrix of one input round: its domain's log size and, per opening
/// point, the point and every value at it (public, then the random codewords).
struct Matrix {
    log_size: usize,
    points: Vec<(Challenge, Vec<Challenge>)>,
}

/// The rounds uni-stark hands the PCS, with the hiding wrapper's random
/// openings appended as its verify does.
fn rounds(proof: &RProof, zeta: Challenge) -> Vec<Vec<Matrix>> {
    let pcs = deployed_pcs();
    let degree = 1usize << proof.degree_bits;
    let nd = |d: usize| <Pcs as p3_commit::Pcs<Challenge, Recording>>::natural_domain_for_degree(&pcs, d);
    let trace_domain = nd(degree);
    let zeta_next = nd(degree >> 1).next_point(zeta).expect("next point");
    let chunks = proof.opened_values.quotient_chunks.len();
    let log_chunks = chunks.trailing_zeros() as usize - 1;
    let quotient_domain = trace_domain.create_disjoint_domain(1usize << (proof.degree_bits + log_chunks));
    let hidden = &proof.opening_proof.0;
    let join = |v: &Vec<Challenge>, b: usize, m: usize, p: usize| {
        let mut out = v.clone();
        out.extend_from_slice(&hidden[b][m][p]);
        out
    };
    let ov = &proof.opened_values;
    let random = vec![Matrix {
        log_size: log2_strict_usize(trace_domain.size()),
        points: vec![(zeta, join(ov.random.as_ref().expect("zk"), 0, 0, 0))],
    }];
    let mut tp = vec![(zeta, join(&ov.trace_local, 1, 0, 0))];
    if let Some(n) = &ov.trace_next {
        tp.push((zeta_next, join(n, 1, 0, 1)));
    }
    let trace = vec![Matrix { log_size: log2_strict_usize(trace_domain.size()), points: tp }];
    let quotient = quotient_domain
        .split_domains(chunks)
        .iter()
        .enumerate()
        .map(|(i, d)| Matrix {
            log_size: log2_strict_usize(nd(d.size() << 1).size()),
            points: vec![(zeta, join(&ov.quotient_chunks[i], 2, i, 0))],
        })
        .collect();
    vec![random, trace, quotient]
}

fn mmcs() -> ValMmcs {
    let perm = default_goldilocks_poseidon2_8();
    ValMmcs::new(Hash::new(perm.clone()), Compress::new(perm), 0, SaltRng::seeded(0))
}

/// A leaf digest walked up a binary path; the root reached and the index
/// left over, which names the cap entry.
fn walk(leaf: [Val; 4], siblings: &[[Val; 4]], mut index: usize, c: &Compress) -> ([Val; 4], usize) {
    let mut d = leaf;
    for s in siblings {
        d = if index & 1 == 0 { c.compress([d, *s]) } else { c.compress([*s, d]) };
        index >>= 1;
    }
    (d, index)
}

fn at_root(cap: &MerkleCap<Val, [Val; 4]>, (root, i): ([Val; 4], usize)) -> bool {
    i < cap.num_roots() && cap[i] == root
}

/// Lagrange interpolation at beta through the arity points of one coset, in
/// product form. The library uses the barycentric form; the two are compared
/// on every fold.
fn interpolate(xs: &[Val], ys: &[Challenge], beta: Challenge) -> Challenge {
    let mut out = Challenge::ZERO;
    for (i, (&xi, &yi)) in xs.iter().zip(ys).enumerate() {
        let mut term = yi;
        for (j, &xj) in xs.iter().enumerate() {
            if i != j {
                term *= (beta - xj) * (xi - xj).inverse();
            }
        }
        out += term;
    }
    out
}

fn fold(index: usize, log_folded: usize, log_arity: usize, beta: Challenge, evals: &[Challenge]) -> Challenge {
    let start = Val::two_adic_generator(log_folded + log_arity).exp_u64(reverse_bits_len(index, log_folded) as u64);
    let mut xs: Vec<Val> = Val::two_adic_generator(log_arity).shifted_powers(start).take(1 << log_arity).collect();
    reverse_slice_index_bits(&mut xs);
    interpolate(&xs, evals, beta)
}

/// Shape of the query phase, which the parameters fix.
pub struct Shape {
    pub log_global: usize,
    pub log_arities: Vec<usize>,
    /// Base elements hashed into each input round's leaf, salts included.
    pub input_leaf: Vec<usize>,
    pub input_path: usize,
    /// Base elements hashed into each layer's leaf, salt included, and its path.
    pub layer_leaf: Vec<usize>,
    pub layer_path: Vec<usize>,
    /// (column, point) pairs the reduced opening sums over.
    pub reduced_terms: usize,
}

/// Every comparison of one query, mirroring open_input then verify_query.
fn run_query(
    proof: &RProof,
    rounds: &[Vec<Matrix>],
    out: &Outputs,
    q: usize,
    shape: &mut Option<Shape>,
) -> QueryRun {
    let perm = default_goldilocks_poseidon2_8();
    let (hash, compress) = (Hash::new(perm.clone()), Compress::new(perm));
    let lib = mmcs();
    let lib_layer = ChallengeMmcs::new(mmcs());
    let fri = &proof.opening_proof.1;
    let qp = &fri.query_proofs[q];
    let log_arities: Vec<usize> = qp.commit_phase_openings.iter().map(|s| s.log_arity as usize).collect();
    let log_global = log_arities.iter().sum::<usize>() + LOG_BLOWUP + LOG_FINAL_POLY_LEN;
    let index = out.positions[q];
    let roots = [proof.commitments.random.as_ref().expect("zk"), &proof.commitments.trace, &proof.commitments.quotient_chunks];

    let mut failed = Vec::new();
    let mut agrees = true;
    let mut leaves = Vec::new();
    let mut input_leaf = Vec::new();
    let mut input_path = 0;
    let mut terms = 0;

    // Opening points against the query point, all before any hashing, as the
    // library does when it batches the inverses.
    let x_of = |log_height: usize| {
        let rev = reverse_bits_len(index >> (log_global - log_height), log_height);
        Val::GENERATOR * Val::two_adic_generator(log_height).exp_u64(rev as u64)
    };
    let coincides = rounds.iter().flatten().any(|m| {
        let x = x_of(m.log_size + LOG_BLOWUP);
        m.points.iter().any(|(z, _)| (*z - x).is_zero())
    });
    if coincides {
        failed.push(Point::Coincides);
    }

    let mut reduced = BTreeMap::<usize, (Challenge, Challenge)>::new();
    let openings: &Vec<InputOpening> = &qp.input_proof;
    for (b, (opening, mats)) in openings.iter().zip(rounds).enumerate() {
        let (salts, siblings) = &opening.opening_proof;
        let heights: Vec<usize> = mats.iter().map(|m| m.log_size + LOG_BLOWUP).collect();
        let top = *heights.iter().max().expect("a matrix");
        assert!(heights.iter().all(|&h| h == top), "every matrix of a round shares one height here");
        let idx = index >> (log_global - top);
        let widths_ok = opening.opened_values.len() == mats.len()
            && opening.opened_values.iter().zip(mats).all(|(r, m)| r.len() == m.points[0].1.len())
            && salts.len() == mats.len();
        let salted: Vec<Vec<Val>> = opening
            .opened_values
            .iter()
            .zip(salts)
            .map(|(r, s)| r.iter().chain(s.iter()).copied().collect())
            .collect();
        let leaf = hash.hash_iter_slices(salted.iter().map(|r| r.as_slice()));
        leaves.push(leaf);
        input_leaf.push(salted.iter().map(Vec::len).sum());
        input_path = siblings.len();
        let ours = widths_ok && siblings.len() == top && at_root(roots[b], walk(leaf, siblings, idx, &compress));
        let dims: Vec<Dimensions> =
            mats.iter().map(|m| Dimensions { width: m.points[0].1.len(), height: 1 << (m.log_size + LOG_BLOWUP) }).collect();
        let theirs = lib.verify_batch(roots[b], &dims, idx, BatchOpeningRef::from(opening)).is_ok();
        agrees &= ours == theirs;
        if !ours {
            failed.push(Point::InputRoot(b));
        }

        // (f(z) - f(x)) / (z - x), scaled by powers of the batching alpha, one
        // running sum per height shared across rounds.
        for (row, m) in opening.opened_values.iter().zip(mats) {
            let lh = m.log_size + LOG_BLOWUP;
            let x = x_of(lh);
            let (pow, ro) = reduced.entry(lh).or_insert((Challenge::ONE, Challenge::ZERO));
            for (z, at_z) in &m.points {
                let inv = (*z - x).try_inverse().unwrap_or(Challenge::ZERO);
                for (&px, &pz) in row.iter().zip(at_z) {
                    *ro += *pow * (pz - px) * inv;
                    *pow *= out.fri_alpha;
                    terms += 1;
                }
            }
        }
    }
    let mut ro_iter = reduced.into_iter().rev().map(|(h, (_, v))| (h, v)).peekable();
    let (first_h, first) = ro_iter.next().expect("a reduced opening");
    assert_eq!(first_h, log_global, "the tallest round sets the global height");

    let library_fold: TwoAdicFriFolding<(), ()> = TwoAdicFriFolding(PhantomData);
    let mut folded = first;
    let mut folds = Vec::new();
    let mut layer_leaf = Vec::new();
    let mut layer_path = Vec::new();
    let mut di = index;
    let mut lh = log_global;
    for (r, step) in qp.commit_phase_openings.iter().enumerate() {
        let la = step.log_arity as usize;
        let arity = 1usize << la;
        let pos = di % arity;
        let mut evals = vec![Challenge::ZERO; arity];
        let mut s = step.sibling_values.iter();
        for (j, e) in evals.iter_mut().enumerate() {
            *e = if j == pos { folded } else { *s.next().unwrap_or(&Challenge::ZERO) };
        }
        let lf = lh - la;
        di >>= la;
        let (salts, siblings) = &step.opening_proof;
        let flat: Vec<Val> = evals
            .iter()
            .flat_map(|e| e.as_basis_coefficients_slice().to_vec())
            .chain(salts.iter().flatten().copied())
            .collect();
        let leaf = hash.hash_iter(flat.iter().copied());
        leaves.push(leaf);
        layer_leaf.push(flat.len());
        layer_path.push(siblings.len());
        let ours = step.sibling_values.len() == arity - 1
            && siblings.len() == lf
            && at_root(&fri.commit_phase_commits[r], walk(leaf, siblings, di, &compress));
        let dims = [Dimensions { width: arity, height: 1 << lf }];
        let theirs = lib_layer
            .verify_batch(&fri.commit_phase_commits[r], &dims, di, BatchOpeningRef::new(&[evals.clone()], &step.opening_proof))
            .is_ok();
        agrees &= ours == theirs;
        if !ours {
            failed.push(Point::LayerRoot(r));
        }
        folded = fold(di, lf, la, out.betas[r], &evals);
        let theirs = FriFoldingStrategy::<Val, Challenge>::fold_row(&library_fold, di, lf, la, out.betas[r], evals.into_iter());
        agrees &= folded == theirs;
        lh = lf;
        if let Some((_, ro)) = ro_iter.next_if(|(h, _)| *h == lf) {
            folded += out.betas[r].exp_power_of_2(la) * ro;
        }
        folds.push(folded);
    }

    let x = Val::two_adic_generator(log_global).exp_u64(reverse_bits_len(di, log_global) as u64);
    let mut eval = Challenge::ZERO;
    for &c in fri.final_poly.iter().rev() {
        eval = eval * x + c;
    }
    agrees &= eval == fri.final_poly.iter().copied().horner(x);
    if lh != LOG_BLOWUP + LOG_FINAL_POLY_LEN || ro_iter.next().is_some() || eval != folded {
        failed.push(Point::Final);
    }

    if shape.is_none() {
        *shape = Some(Shape {
            log_global,
            log_arities,
            input_leaf,
            input_path,
            layer_leaf,
            layer_path,
            reduced_terms: terms,
        });
    }
    QueryRun { index, reduced: first, folds, leaves, failed, library_agrees: agrees, final_index: di }
}

/// Every query of one proof, given the transcript outputs it was verified
/// under.
pub fn run_queries(proof: &RProof, out: &Outputs) -> (Vec<QueryRun>, Shape) {
    let rs = rounds(proof, out.zeta);
    let mut shape = None;
    let runs = (0..proof.opening_proof.1.query_proofs.len())
        .map(|q| run_query(proof, &rs, out, q, &mut shape))
        .collect();
    (runs, shape.expect("at least one query"))
}

/// One way of corrupting one query, and where each side says it fails.
pub struct QueryLanding {
    pub label: String,
    pub query: usize,
    /// Plonky3's error, first words.
    pub plonky3: String,
    /// The first comparison the port finds failing, and every one.
    pub first: Option<(usize, Point)>,
    pub all: Vec<Point>,
    /// Only the corrupted query fails, and the transcript the corruption was
    /// verified under is the honest one up to where Plonky3 stopped.
    pub isolated: bool,
    pub transcript_unchanged: bool,
    pub library_agrees: bool,
}

impl QueryLanding {
    /// The port and Plonky3 reject at the same kind of comparison, in the
    /// corrupted query.
    pub fn agrees(&self) -> bool {
        match self.first {
            Some((q, p)) => q == self.query && self.plonky3.contains(p.plonky3()),
            None => self.plonky3 == "accepted",
        }
    }
}

pub struct QueryReport {
    pub honest_all_hold: bool,
    pub honest_library_agrees: bool,
    pub queries: usize,
    pub shape: Shape,
    /// Field elements a defender asserts per query: the reduced opening and
    /// every folded value (extension), and every leaf digest.
    pub assertion_per_query: usize,
    pub controls: Vec<(&'static str, bool, String)>,
    pub landings: Vec<QueryLanding>,
    /// The honest positions, and how many extension values one query's chain holds.
    pub indices: Vec<usize>,
    pub chain_len: usize,
}

/// The query phase of the honest proof, of the three controls, and of every
/// corruption that leaves the transcript untouched.
pub fn run_query_phase() -> QueryReport {
    let air = Air::new();
    let (t, pv) = composed_case::<{ crate::prover::REGISTERS }, 16, 32, 16, 64>(ROWS, None);
    let proof: RProof = prove(&config().0, &air, t, &pv);
    let (ev, verdict) = record(&air, &proof, &pv);
    assert!(verdict.is_ok(), "honest proof must verify");
    let rounds_n = proof.opening_proof.1.commit_phase_commits.len();
    let out = outputs(&ev, rounds_n);
    let (runs, shape) = run_queries(&proof, &out);
    let honest_all_hold = runs.iter().all(|r| r.failed.is_empty());
    let honest_library_agrees = runs.iter().all(|r| r.library_agrees);
    let assertion_per_query = 2 * (1 + runs[0].folds.len()) + 4 * runs[0].leaves.len();

    let mut controls = Vec::new();
    for (label, b) in [
        ("run start disagrees with C8", ComposedBreak::RunStartMismatch),
        ("amount exceeds the units", ComposedBreak::AmountRaised),
        ("shares under another domain", ComposedBreak::ShareDomain),
    ] {
        let (t, pvb) = composed_case::<{ crate::prover::REGISTERS }, 16, 32, 16, 64>(ROWS, Some(b));
        let pb: RProof = prove(&config().0, &air, t, &pvb);
        let (evb, vb) = record(&air, &pb, &pvb);
        let ob = outputs(&evb, pb.opening_proof.1.commit_phase_commits.len());
        let (rb, _) = run_queries(&pb, &ob);
        let held = rb.iter().all(|r| r.failed.is_empty() && r.library_agrees);
        controls.push((label, held, vb.err().map(|e| first_word(&e)).unwrap_or_else(|| "accepted".into())));
    }

    let mut landings = Vec::new();
    let mut land = |label: String, query: usize, p: &RProof| {
        let (evc, vc) = record(&air, p, &pv);
        // Query proofs are never absorbed, so a corrupted query is verified
        // under the honest transcript. Checked, not assumed.
        let transcript_unchanged = pow_state(&evc).is_some() && pow_state(&evc) == pow_state(&ev);
        let (rc, _) = run_queries(p, &out);
        let first = rc.iter().enumerate().find_map(|(q, r)| r.failed.first().map(|pt| (q, *pt)));
        let isolated = rc.iter().enumerate().all(|(q, r)| (q == query) != r.failed.is_empty());
        landings.push(QueryLanding {
            label,
            query,
            plonky3: vc.err().map(|e| first_word(&e)).unwrap_or_else(|| "accepted".into()),
            first,
            all: rc[query].failed.clone(),
            isolated,
            transcript_unchanged,
            library_agrees: rc.iter().all(|r| r.library_agrees),
        });
    };

    let nq = proof.opening_proof.1.query_proofs.len();
    for &q in &[0usize, 7, nq - 1] {
        for (b, name) in ["randomisation", "trace", "quotient"].iter().enumerate() {
            let mut p = dup(&proof);
            p.opening_proof.1.query_proofs[q].input_proof[b].opened_values[0][0] += Val::ONE;
            land(format!("opened {name} row"), q, &p);
        }
        let mut p = dup(&proof);
        p.opening_proof.1.query_proofs[q].input_proof[1].opening_proof.0[0][0] += Val::ONE;
        land("trace row's salt".into(), q, &p);
        for level in [0usize, shape.input_path - 1] {
            let mut p = dup(&proof);
            p.opening_proof.1.query_proofs[q].input_proof[1].opening_proof.1[level][0] += Val::ONE;
            land(format!("trace path, level {level}"), q, &p);
        }
        for r in 0..rounds_n {
            let mut p = dup(&proof);
            p.opening_proof.1.query_proofs[q].commit_phase_openings[r].sibling_values[0] += Challenge::ONE;
            land(format!("layer {r} sibling value"), q, &p);
            let mut p = dup(&proof);
            p.opening_proof.1.query_proofs[q].commit_phase_openings[r].opening_proof.0[0][0] += Val::ONE;
            land(format!("layer {r} salt"), q, &p);
            let mut p = dup(&proof);
            p.opening_proof.1.query_proofs[q].commit_phase_openings[r].opening_proof.1[0][0] += Val::ONE;
            land(format!("layer {r} path, level 0"), q, &p);
        }
    }

    QueryReport {
        honest_all_hold,
        honest_library_agrees,
        queries: runs.len(),
        shape,
        assertion_per_query,
        controls,
        landings,
        indices: runs.iter().map(|r| r.index).collect(),
        chain_len: std::iter::once(runs[0].reduced).chain(runs[0].folds.iter().copied()).count(),
    }
}
