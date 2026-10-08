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
    NUM_RANDOM_CODEWORDS, ROWS,
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

type RConfig = StarkConfig<Pcs, Challenge, Recording>;
type RProof = Proof<RConfig>;

/// A configuration and a handle on its challenger's log. Every challenger the
/// configuration hands out is a clone sharing that log.
fn config() -> (RConfig, Recording) {
    let r = Recording::new();
    (StarkConfig::new(deployed_pcs(), r.clone()), r)
}

type Air = ComposedAir<{ crate::prover::REGISTERS }, 16, 32, 16, 64>;

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

/// Verify with the recording challenger; the transcript and the verdict.
fn record(air: &Air, proof: &RProof, pv: &[Val]) -> (Vec<Event>, Result<(), String>) {
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

fn first_word(e: &str) -> String {
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
        let moved = summarise(&ev).positions != transcript.positions;
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
