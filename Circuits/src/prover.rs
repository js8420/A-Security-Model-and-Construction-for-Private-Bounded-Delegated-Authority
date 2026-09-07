use std::thread::sleep;
use std::time::{Duration, Instant};

use p3_air::BaseAir;
use p3_challenger::DuplexChallenger;
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::extension::BinomialExtensionField;
use p3_field::Field;
use p3_fri::{FriParameters, HidingFriPcs, TwoAdicFriPcs};
use p3_goldilocks::{default_goldilocks_poseidon2_8, Goldilocks, Poseidon2Goldilocks};
use p3_merkle_tree::{MerkleTreeHidingMmcs, MerkleTreeMmcs};
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use p3_uni_stark::{prove, verify, StarkConfig};
use rand10::rngs::ChaCha12Rng;
use rand_core::{Infallible, SeedableRng, TryCryptoRng, TryRng};

use crate::air::{PolicyAir, ALL_CLAUSES};
use crate::hash::new_hash_air;
use crate::containment::ContainmentAir;
use crate::full::FullAir;
use crate::composed::ComposedAir;
use crate::vacuous::VacuousAir;
use crate::whole::WholeAir;
use crate::merkle::MerkleAir;
use crate::revocation::NonMembershipAir;
use crate::trace::{full_public_values, vacuous_trace, whole_public_values, broken_composed, broken_composed_air, broken_nonmembership, broken_trace, composed_air_trace, composed_trace, corrupt, containment_public_values, containment_trace, merkle_trace, nonmembership_trace, policy_trace, whole_trace, Break, ComposedBreak, RevokeBreak};

// Goldilocks at width 8: a digest of four elements is 256 bits.
type Val = Goldilocks;
type Challenge = BinomialExtensionField<Val, 2>;
type Perm = Poseidon2Goldilocks<8>;
type Hash = PaddingFreeSponge<Perm, 8, 4, 4>;
type Compress = TruncatedPermutation<Perm, 2, 4, 8>;

/// Salt elements per leaf. The crate's rule is that SALT_ELEMS times the size
/// of a value must reach the target security parameter; at 64 bits a piece,
/// two elements give 128 against a claimed 88. One would give 64 and be short.
pub const SALT_ELEMS: usize = 2;

/// Random codewords the hiding PCS appends per matrix. Must exceed zero, and
/// the quotient decomposition panics below two.
pub const NUM_RANDOM_CODEWORDS: usize = 2;

const INPUT_SALT_SEED: u64 = 0x5350_454e_4400_0001;
const FRI_SALT_SEED: u64 = 0x5350_454e_4400_0004;
const CODEWORD_SEED: u64 = 0x5350_454e_4400_0002;

// Both MMCSs are hiding. p3-fri says so in a doc comment and does not enforce
// it, and its own test does not obey it: the upstream configuration encloses a
// plain MerkleTreeMmcs and is not hiding. ChaCha12 is the cipher StdRng uses,
// named directly because StdRng is neither Clone nor portable across releases.
// SmallRng, which the upstream tests use for salts, is documented as insecure.
type ValMmcs = MerkleTreeHidingMmcs<
    <Val as Field>::Packing,
    <Val as Field>::Packing,
    Hash,
    Compress,
    SaltRng,
    2,
    4,
    SALT_ELEMS,
>;
type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
type Dft = Radix2DitParallel<Val>;
type Pcs = HidingFriPcs<Val, Dft, ValMmcs, ChallengeMmcs, SaltRng>;

/// ChaCha12 with a Clone that reconstructs the stream rather than approximating
/// it. chacha20 derives nothing on its RNGs, and the only Clone generator in the
/// dependency tree is Xoshiro, which the rand documentation calls insecure. The
/// three values copied here are exactly the three the crate's own PartialEq
/// compares, so a clone and its original are equal by that definition.
pub struct SaltRng(ChaCha12Rng);

impl SaltRng {
    fn seeded(seed: u64) -> Self {
        Self(ChaCha12Rng::seed_from_u64(seed))
    }
}

impl Clone for SaltRng {
    fn clone(&self) -> Self {
        let mut r = ChaCha12Rng::from_seed(self.0.get_seed());
        r.set_stream(self.0.get_stream());
        r.set_word_pos(self.0.get_word_pos());
        Self(r)
    }
}

impl core::fmt::Debug for SaltRng {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "SaltRng {{ ... }}")
    }
}

impl TryRng for SaltRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        self.0.try_next_u32()
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        self.0.try_next_u64()
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        self.0.try_fill_bytes(dst)
    }
}

impl TryCryptoRng for SaltRng {}
type Challenger = DuplexChallenger<Val, Perm, 8, 4>;
type Config = StarkConfig<Pcs, Challenge, Challenger>;

// The non-hiding pair, kept only so the cost of zero knowledge can be measured
// end to end rather than inferred from column counts. Nothing in the paper's
// claims may be measured on this configuration; it exists to be the comparison.
type PlainValMmcs =
    MerkleTreeMmcs<<Val as Field>::Packing, <Val as Field>::Packing, Hash, Compress, 2, 4>;
type PlainChallengeMmcs = ExtensionMmcs<Val, Challenge, PlainValMmcs>;
type PlainPcs = TwoAdicFriPcs<Val, Dft, PlainValMmcs, PlainChallengeMmcs>;
type PlainConfig = StarkConfig<PlainPcs, Challenge, Challenger>;

fn config_plain() -> PlainConfig {
    let perm = default_goldilocks_poseidon2_8();
    let hash = Hash::new(perm.clone());
    let compress = Compress::new(perm.clone());
    let val_mmcs = PlainValMmcs::new(hash, compress, 0);
    let challenge_mmcs = PlainChallengeMmcs::new(val_mmcs.clone());
    let fri_params = FriParameters {
        log_blowup: LOG_BLOWUP,
        log_final_poly_len: 3,
        max_log_arity: 2,
        num_queries: NUM_QUERIES,
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: POW_BITS,
        mmcs: challenge_mmcs,
    };
    let pcs = PlainPcs::new(Dft::default(), val_mmcs, fri_params);
    StarkConfig::new(pcs, Challenger::new(perm))
}

/// 40 queries at blowup 4 with 8 proof-of-work bits is about 88 bits, which is
/// the setting the upstream tests use. Report it alongside any timing.
pub const NUM_QUERIES: usize = 40;
pub const LOG_BLOWUP: usize = 2;
pub const POW_BITS: usize = 8;

fn config() -> Config {
    let perm = default_goldilocks_poseidon2_8();
    let hash = Hash::new(perm.clone());
    let compress = Compress::new(perm.clone());
    // Separate seeds. Cloning one MMCS into the other would blind both
    // commitments from an identical stream, which is not independent blinding.
    let val_mmcs = ValMmcs::new(
        hash.clone(),
        compress.clone(),
        0,
        SaltRng::seeded(INPUT_SALT_SEED),
    );
    let fri_mmcs = ValMmcs::new(hash, compress, 0, SaltRng::seeded(FRI_SALT_SEED));
    let challenge_mmcs = ChallengeMmcs::new(fri_mmcs);
    let fri_params = FriParameters {
        log_blowup: LOG_BLOWUP,
        log_final_poly_len: 3,
        max_log_arity: 2,
        num_queries: NUM_QUERIES,
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: POW_BITS,
        mmcs: challenge_mmcs,
    };
    let pcs = Pcs::new(
        Dft::default(),
        val_mmcs,
        fri_params,
        NUM_RANDOM_CODEWORDS,
        SaltRng::seeded(CODEWORD_SEED),
    );
    StarkConfig::new(pcs, Challenger::new(perm))
}

/// One proof over a genuine satisfying trace of `1 << log_rows` permutations.
fn once<const R: usize>(cfg: &Config, log_rows: usize) -> u128 {
    let air = new_hash_air::<R>();
    let trace = air.generate_trace_rows(1usize << log_rows, 0);
    let t = Instant::now();
    let _proof = prove(cfg, &air, trace, &vec![]);
    t.elapsed().as_micros()
}

pub struct Stats {
    pub min: f64,
    pub median: f64,
    pub q1: f64,
    pub q3: f64,
    pub mean: f64,
}

fn summarise(mut v: Vec<u128>, perms: usize) -> Stats {
    v.sort_unstable();
    let per = |x: u128| x as f64 / 1000.0 / perms as f64;
    let pick = |f: f64| per(v[((v.len() - 1) as f64 * f).round() as usize]);
    Stats {
        min: per(v[0]),
        median: pick(0.5),
        q1: pick(0.25),
        q3: pick(0.75),
        mean: v.iter().map(|&x| per(x)).sum::<f64>() / v.len() as f64,
    }
}

/// Interleaved within each batch so drift hits every configuration equally,
/// and batched with a pause between so drift can be observed rather than only
/// mitigated. Running configurations in blocks is what produced the earlier
/// 1.6x that did not reproduce.
pub fn compare(batches: usize, per_batch: usize, pause_secs: u64)
    -> (Stats, Stats, Stats, Vec<(f64, f64, f64)>)
{
    let cfg = config();

    let _ = once::<0>(&cfg, 8);
    let _ = once::<1>(&cfg, 8);
    let _ = once::<0>(&cfg, 10);

    let mut a = Vec::new();
    let mut b = Vec::new();
    let mut c = Vec::new();
    let mut per_batch_median = Vec::with_capacity(batches);

    for batch in 0..batches {
        if batch > 0 {
            sleep(Duration::from_secs(pause_secs));
        }
        let (mut ba, mut bb, mut bc) = (Vec::new(), Vec::new(), Vec::new());
        for _ in 0..per_batch {
            ba.push(once::<0>(&cfg, 8));
            bb.push(once::<1>(&cfg, 8));
            bc.push(once::<0>(&cfg, 10));
        }
        per_batch_median.push((
            summarise(ba.clone(), 256).median,
            summarise(bb.clone(), 256).median,
            summarise(bc.clone(), 1024).median,
        ));
        a.extend(ba);
        b.extend(bb);
        c.extend(bc);
    }

    (summarise(a, 256), summarise(b, 256), summarise(c, 1024), per_batch_median)
}

/// Prove and verify the policy AIR over a supplied trace. Returns whether the
/// round trip succeeded, which is false exactly when the trace does not
/// satisfy the constraints.
pub fn roundtrip(rows: usize, corrupt: bool) -> bool {
    let air = PolicyAir::new(&ALL_CLAUSES);
    let trace = if corrupt { broken_trace(rows) } else { policy_trace(rows) };
    let cfg = config();
    let proof = prove(&cfg, &air, trace, &vec![]);
    verify(&cfg, &air, &proof, &vec![]).is_ok()
}

/// Prove and verify the policy AIR composed with the C9 opening, over a trace
/// whose sponge absorbs the very values the policy columns carry.
pub fn roundtrip_composed<const R: usize>(rows: usize, how: Option<Break>) -> bool {
    let air = FullAir::<R>::new();
    let cfg = config();
    let trace = match how {
        None => composed_trace::<R>(rows),
        Some(b) => broken_composed::<R>(rows, b),
    };
    let pv = full_public_values::<R>();
    let proof = prove(&cfg, &air, trace, &pv);
    verify(&cfg, &air, &proof, &pv).is_ok()
}


pub fn roundtrip_merkle<const R: usize, const DEPTH: usize>(rows: usize, bad: Option<usize>) -> bool {
    let air = MerkleAir::<R, DEPTH>::new();
    let cfg = config();
    let t = merkle_trace::<R, DEPTH>(rows);
    let t = match bad { None => t, Some(c) => corrupt(t, c) };
    verify(&cfg, &air, &prove(&cfg, &air, t, &vec![]), &vec![]).is_ok()
}

/// Prove and verify C8. The controls are trace-level rather than column-level:
/// a corrupted column breaks a decomposition, which the previous form of this
/// component could already detect, whereas these build a coherent trace in which
/// the run and the revoked range genuinely overlap.
pub fn roundtrip_nonmembership<const R: usize, const DEPTH: usize>(
    rows: usize,
    how: Option<RevokeBreak>,
) -> bool {
    let air = NonMembershipAir::<R, DEPTH>::new();
    let cfg = config();
    let t = match how {
        None => nonmembership_trace::<R, DEPTH>(rows),
        Some(b) => broken_nonmembership::<R, DEPTH>(rows, b),
    };
    verify(&cfg, &air, &prove(&cfg, &air, t, &vec![]), &vec![]).is_ok()
}


pub fn roundtrip_containment<const R: usize, const DEPTH: usize>(rows: usize, bad: Option<usize>) -> bool {
    let air = ContainmentAir::<R, DEPTH>::new();
    let cfg = config();
    let t = containment_trace::<R, DEPTH>(rows);
    let t = match bad { None => t, Some(c) => corrupt(t, c) };
    let pv = containment_public_values::<R, DEPTH>();
    verify(&cfg, &air, &prove(&cfg, &air, t, &pv), &pv).is_ok()
}

/// Prove and verify the whole circuit at full parameters, and time it. This is
/// the figure Section VII projects rather than measures.
pub fn roundtrip_whole<const R: usize>(rows: usize, bad: Option<usize>) -> (bool, u128) {
    let air = WholeAir::<R, 16, 32>::new();
    let cfg = config();
    let pv = whole_public_values::<R, 16, 32>();
    let t = whole_trace::<R, 16, 32>(rows);
    let t = match bad { None => t, Some(c) => corrupt(t, c) };
    let start = Instant::now();
    let proof = prove(&cfg, &air, t, &pv);
    let ms = start.elapsed().as_millis();
    (verify(&cfg, &air, &proof, &pv).is_ok(), ms)
}

/// The second-invocation variant: same payment, nullifier from its own
/// permutation. Proved and verified so the variant is measured as a circuit
/// that works rather than as a layout that would.
pub fn roundtrip_spend_two<const R: usize, const DEPTH: usize, const COVER: usize>(
    rows: usize,
) -> bool {
    use p3_field::PrimeCharacteristicRing;
    let air = crate::spend2::SpendTwoAir::<R, DEPTH, COVER>::new();
    let cfg = config();
    let pv = vec![Goldilocks::from_u64(crate::spend_trace::PAYLOAD)];
    let t = crate::spend_trace::spend_two_trace::<R, DEPTH, COVER>(rows);
    verify(&cfg, &air, &prove(&cfg, &air, t, &pv), &pv).is_ok()
}

/// The vacuity demonstration, in two halves. The same trace --- a policy in the
/// columns that the commitment does not open to --- is proved against the
/// circuit with C9's binding and against the circuit without it. The first must
/// fail and the second must succeed, and the pair is the evidence for the claim
/// that a missing constraint is invisible to every other check.
pub fn roundtrip_vacuous<const R: usize, const MD: usize, const RD: usize>(
    rows: usize,
    bind_policy: bool,
) -> bool {
    let cfg = config();
    let pv = whole_public_values::<R, MD, RD>();
    let t = vacuous_trace::<R, MD, RD>(rows);
    if bind_policy {
        let air = WholeAir::<R, MD, RD>::new();
        verify(&cfg, &air, &prove(&cfg, &air, t, &pv), &pv).is_ok()
    } else {
        let air = VacuousAir::<R, MD, RD>::new();
        verify(&cfg, &air, &prove(&cfg, &air, t, &pv), &pv).is_ok()
    }
}

/// Prove and verify the composed circuit, in which the compliance and
/// accountability halves are one statement about one payment. Every control
/// leaves both halves internally satisfied and breaks only the binding, so each
/// of these traces would verify if the halves were still proved separately.
pub fn roundtrip_composed_air<
    const R: usize,
    const MD: usize,
    const RD: usize,
    const DEPTH: usize,
    const COVER: usize,
>(
    rows: usize,
    how: Option<ComposedBreak>,
) -> (bool, u128) {
    let air = ComposedAir::<R, MD, RD, DEPTH, COVER>::new();
    let cfg = config();
    let pv = whole_public_values::<R, MD, RD>();
    let t = match how {
        None => composed_air_trace::<R, MD, RD, DEPTH, COVER>(rows),
        Some(b) => broken_composed_air::<R, MD, RD, DEPTH, COVER>(rows, b),
    };
    let start = Instant::now();
    let proof = prove(&cfg, &air, t, &pv);
    let ms = start.elapsed().as_millis();
    (verify(&cfg, &air, &proof, &pv).is_ok(), ms)
}

/// Proof size for the composed circuit, against the sum of the two separate
/// proofs. Deterministic at fixed parameters.
pub fn composed_proof_bytes<
    const R: usize,
    const MD: usize,
    const RD: usize,
    const DEPTH: usize,
    const COVER: usize,
>(
    rows: usize,
) -> usize {
    let air = ComposedAir::<R, MD, RD, DEPTH, COVER>::new();
    let cfg = config();
    let pv = whole_public_values::<R, MD, RD>();
    let proof = prove(&cfg, &air, composed_air_trace::<R, MD, RD, DEPTH, COVER>(rows), &pv);
    bincode::serialize(&proof).expect("proof serialises").len()
}

/// Proof size for the accountability half on its own, so the comparison with
/// the composed proof is two measurements rather than one measurement and an
/// extrapolation from the affine law.
pub fn spend_proof_bytes<const R: usize, const DEPTH: usize, const COVER: usize>(
    rows: usize,
) -> usize {
    use p3_field::PrimeCharacteristicRing;
    let air = crate::spend::SpendAir::<R, DEPTH, COVER>::new();
    let cfg = config();
    let pv = vec![Goldilocks::from_u64(crate::spend_trace::PAYLOAD)];
    let t = crate::spend_trace::spend_trace::<R, DEPTH, COVER>(rows);
    let proof = prove(&cfg, &air, t, &pv);
    bincode::serialize(&proof).expect("proof serialises").len()
}

/// Prove and verify the spend component. The payload digest is the single
/// public value, and the share index is bound to it.
pub fn roundtrip_spend<const R: usize, const DEPTH: usize, const COVER: usize>(
    rows: usize,
    bad: Option<crate::spend_trace::SpendBreak>,
    payload: u64,
) -> bool {
    use p3_field::PrimeCharacteristicRing;
    let air = crate::spend::SpendAir::<R, DEPTH, COVER>::new();
    let cfg = config();
    let t = match bad {
        None => crate::spend_trace::spend_trace::<R, DEPTH, COVER>(rows),
        Some(b) => crate::spend_trace::broken_spend::<R, DEPTH, COVER>(rows, b),
    };
    let pv = vec![Goldilocks::from_u64(payload)];
    let proof = prove(&cfg, &air, t, &pv);
    verify(&cfg, &air, &proof, &pv).is_ok()
}

/// Whether the configuration in use is actually a zero-knowledge one. The PCS
/// reports this through the Pcs trait, so it reflects the type in play rather
/// than an intention.
pub fn zk_enabled() -> bool {
    <Pcs as p3_commit::Pcs<Challenge, Challenger>>::ZK
}

/// The degree bound on zero-knowledge proving in p3-uni-stark 0.6.3, kept as a
/// standing check rather than a note. A bare Poseidon2 AIR generated by the
/// upstream crate verifies at one S-box register, where every constraint is
/// degree 3, and fails at zero, where the S-box makes them degree 7. Nothing of
/// ours appears in either case.
pub fn zk_degree_bound() -> (bool, bool) {
    let cfg = config();
    let deg7 = {
        let air = new_hash_air::<0>();
        let trace = air.generate_trace_rows(64, 0);
        let proof = prove(&cfg, &air, trace, &vec![]);
        verify(&cfg, &air, &proof, &vec![]).is_ok()
    };
    let deg3 = {
        let air = new_hash_air::<1>();
        let trace = air.generate_trace_rows(64, 0);
        let proof = prove(&cfg, &air, trace, &vec![]);
        verify(&cfg, &air, &proof, &vec![]).is_ok()
    };
    (deg7, deg3)
}

/// Whole-circuit proving cost under the 13.1 protocol: heights interleaved
/// inside each batch so drift hits them equally, batched with a pause so drift
/// can be seen rather than only mitigated, and reported as min and quartiles.
/// A single sample of this quantity has moved by 38% between runs on an
/// unchanged circuit, so nothing here is drawn from one.
pub fn whole_timing<const R: usize>(batches: usize, per_batch: usize, pause_secs: u64,
    heights: &[usize]) -> (Vec<(usize, Stats)>, Vec<Vec<f64>>)
{
    let cfg = config();
    let air = WholeAir::<R, 16, 32>::new();
    let pv = whole_public_values::<R, 16, 32>();

    for &h in heights {
        let _ = prove(&cfg, &air, whole_trace::<R, 16, 32>(h), &pv);
    }

    let mut samples: Vec<Vec<u128>> = vec![Vec::new(); heights.len()];
    let mut per_batch_median: Vec<Vec<f64>> = Vec::with_capacity(batches);

    for batch in 0..batches {
        if batch > 0 {
            sleep(Duration::from_secs(pause_secs));
        }
        let mut this: Vec<Vec<u128>> = vec![Vec::new(); heights.len()];
        for _ in 0..per_batch {
            for (i, &h) in heights.iter().enumerate() {
                let trace = whole_trace::<R, 16, 32>(h);
                let t = Instant::now();
                let _ = prove(&cfg, &air, trace, &pv);
                this[i].push(t.elapsed().as_micros());
            }
        }
        per_batch_median.push(
            heights.iter().zip(&this).map(|(&h, v)| summarise(v.clone(), h).median).collect());
        for (i, v) in this.into_iter().enumerate() {
            samples[i].extend(v);
        }
    }

    (heights.iter().zip(samples).map(|(&h, v)| (h, summarise(v, h))).collect(), per_batch_median)
}

/// Proof size at fixed parameters. Deterministic, so one run is a measurement.
/// Reported as a bincode encoding, which is close to a wire format; JSON would
/// overstate it by roughly a factor of three. The breakdown matters because the
/// opening proof is what a verifier contract must carry, and the random-codeword
/// openings the hiding PCS adds appear inside it.
pub fn proof_bytes<const R: usize>(rows: usize) -> (usize, usize, usize, usize) {
    let air = WholeAir::<R, 16, 32>::new();
    let cfg = config();
    let pv = whole_public_values::<R, 16, 32>();
    let proof = prove(&cfg, &air, whole_trace::<R, 16, 32>(rows), &pv);
    let whole = bincode::serialize(&proof).expect("proof serialises").len();
    let commit = bincode::serialize(&proof.commitments).expect("commitments").len();
    let opened = bincode::serialize(&proof.opened_values).expect("opened values").len();
    let opening = bincode::serialize(&proof.opening_proof).expect("opening proof").len();
    (whole, commit, opened, opening)
}

/// Verification cost under the 13.1 protocol. The prover pays once; a settlement
/// contract pays this on every payment, so it is the figure the construction
/// actually turns on. Proofs are built outside the timed region.
pub fn verify_timing<const R: usize>(batches: usize, per_batch: usize, pause_secs: u64,
    heights: &[usize]) -> (Vec<(usize, Stats)>, Vec<Vec<f64>>)
{
    let cfg = config();
    let air = WholeAir::<R, 16, 32>::new();

    let pv = whole_public_values::<R, 16, 32>();
    let proofs: Vec<_> = heights.iter()
        .map(|&h| prove(&cfg, &air, whole_trace::<R, 16, 32>(h), &pv))
        .collect();

    for p in &proofs {
        let _ = verify(&cfg, &air, p, &pv);
    }

    let mut samples: Vec<Vec<u128>> = vec![Vec::new(); heights.len()];
    let mut per_batch_median: Vec<Vec<f64>> = Vec::with_capacity(batches);

    for batch in 0..batches {
        if batch > 0 {
            sleep(Duration::from_secs(pause_secs));
        }
        let mut this: Vec<Vec<u128>> = vec![Vec::new(); heights.len()];
        for _ in 0..per_batch {
            for (i, p) in proofs.iter().enumerate() {
                let t = Instant::now();
                let ok = verify(&cfg, &air, p, &pv).is_ok();
                this[i].push(t.elapsed().as_micros());
                assert!(ok, "a proof that verified during setup must verify when timed");
            }
        }
        per_batch_median.push(
            heights.iter().zip(&this).map(|(&h, v)| summarise(v.clone(), h).median).collect());
        for (i, v) in this.into_iter().enumerate() {
            samples[i].extend(v);
        }
    }

    (heights.iter().zip(samples).map(|(&h, v)| (h, summarise(v, h))).collect(), per_batch_median)
}

/// The smallest trace the FRI parameters admit. Height must satisfy
/// log2(height) + log_blowup + is_zk > log_final_poly_len + log_blowup, and with
/// zero-knowledge doubling the domain the floor moves. Computed rather than
/// asserted, because it decides whether a single-payment proof can be measured
/// at all.
pub fn min_admissible_height() -> usize {
    let mut h = 1usize;
    while h.trailing_zeros() as usize + LOG_BLOWUP + 1 <= 3 + LOG_BLOWUP {
        h <<= 1;
    }
    h
}

/// One row of the cost-structure study.
pub struct CostRow {
    pub label: &'static str,
    pub columns: usize,
    pub bytes: usize,
    pub prove: Stats,
    pub verify: Stats,
    /// Median per batch, so drift is visible here as it is in the proving and
    /// verification tables. This study reported none until 3 September, which
    /// left its figures resting on an assumption the other two tables test.
    pub prove_batches: Vec<f64>,
    pub verify_batches: Vec<f64>,
}

/// What each design decision costs, in columns, proving time, proof bytes and
/// verification time. Variants are interleaved inside each batch so drift hits
/// them equally, exactly as elsewhere.
///
/// Every variant is a real AIR proved at 32 rows, not an arithmetic combination
/// of other rows. The marginal costs are differences between measured rows.
pub fn cost_structure(batches: usize, per_batch: usize, pause_secs: u64) -> Vec<CostRow> {
    use p3_field::PrimeCharacteristicRing;
    const ROWS: usize = 32;

    let zk = config();
    let plain = config_plain();
    let pv: Vec<Goldilocks> = vec![Goldilocks::from_u64(crate::spend_trace::PAYLOAD)];
    let pv_full = full_public_values::<1>();

    // Declared before the closure vectors below, so that the closures which
    // borrow them are dropped first.
    let pv_w32 = whole_public_values::<1, 16, 32>();
    let pv_wpp = whole_public_values::<1, 0, 32>();
    let pv_w20 = whole_public_values::<1, 16, 20>();
    let pv_w32z = whole_public_values::<0, 16, 32>();

    let mut labels: Vec<&'static str> = Vec::new();
    let mut cols: Vec<usize> = Vec::new();
    let mut bytes: Vec<usize> = Vec::new();
    let mut provers: Vec<Box<dyn Fn() -> u128 + '_>> = Vec::new();
    let mut verifiers: Vec<Box<dyn Fn() -> u128 + '_>> = Vec::new();

    // The config and public values are rebound as references before the closures
    // capture them. A move closure captures the variable it names, so writing
    // `&zk` inside one would move `zk` rather than borrow it.
    macro_rules! variant {
        ($label:expr, $mk:expr, $trace:expr, $cfg:expr, $pubs:expr) => {{
            let cfg = $cfg;
            let pubs = $pubs;
            let air0 = $mk;
            let width = BaseAir::<Val>::width(&air0);
            // Built once. Expanding the trace expression inside the closure put
            // trace generation inside the timed region, which charged each
            // variant for building its own witness: the composed row builds two
            // sponges and three sub-traces and was charged for all of them.
            let base_trace = $trace;
            let proof = prove(cfg, &air0, base_trace.clone(), pubs);
            let sz = bincode::serialize(&proof).expect("proof serialises").len();
            labels.push($label);
            cols.push(width);
            bytes.push(sz);

            let air1 = $mk;
            let tr1 = base_trace.clone();
            provers.push(Box::new(move || {
                let ready = tr1.clone();
                let t = Instant::now();
                let _ = prove(cfg, &air1, ready, pubs);
                t.elapsed().as_micros()
            }));

            let air2 = $mk;
            verifiers.push(Box::new(move || {
                let t = Instant::now();
                let ok = verify(cfg, &air2, &proof, pubs).is_ok();
                let e = t.elapsed().as_micros();
                assert!(ok, "a proof built during setup must verify when timed");
                e
            }));
        }};
    }

    variant!("policy + C9 only", FullAir::<1>::new(), composed_trace::<1>(ROWS), &zk, &pv_full);
    variant!("+ allowlists + revocation d32", WholeAir::<1, 16, 32>::new(),
             whole_trace::<1, 16, 32>(ROWS), &zk, &pv_w32);
    variant!("  same, revocation d20", WholeAir::<1, 16, 20>::new(),
             whole_trace::<1, 16, 20>(ROWS), &zk, &pv_w20);
    variant!("  allowlists outside the proof", WholeAir::<1, 0, 32>::new(),
             whole_trace::<1, 0, 32>(ROWS), &zk, &pv_wpp);
    variant!("accountability, grain 1/64", crate::spend::SpendAir::<1, 16, 64>::new(),
             crate::spend_trace::spend_trace::<1, 16, 64>(ROWS), &zk, &pv);
    variant!("  coarser, grain 1/30", crate::spend::SpendAir::<1, 16, 30>::new(),
             crate::spend_trace::spend_trace::<1, 16, 30>(ROWS), &zk, &pv);
    variant!("  finer, grain 1/128", crate::spend::SpendAir::<1, 16, 128>::new(),
             crate::spend_trace::spend_trace::<1, 16, 128>(ROWS), &zk, &pv);
    variant!("whole, no zero knowledge", WholeAir::<0, 16, 32>::new(),
             whole_trace::<0, 16, 32>(ROWS), &plain, &pv_w32z);
    variant!("accountability, no zk", crate::spend::SpendAir::<0, 16, 64>::new(),
             crate::spend_trace::spend_trace::<0, 16, 64>(ROWS), &plain, &pv);
    // The composed circuit is what a settlement actually costs: one proof
    // covering both halves of one payment, rather than a compliance figure that
    // has to be added to an accountability figure the abstract never added.
    variant!("composed, one proof per payment", ComposedAir::<1, 16, 32, 16, 64>::new(),
             composed_air_trace::<1, 16, 32, 16, 64>(ROWS), &zk, &pv_w32);

    // The arrangement the manuscript describes, timed as one thing. Adding the
    // medians of two separately measured rows is not the median of their sum,
    // and the claim that composition costs a tenth more to prove rests on the
    // difference between this row and the one above it.
    {
        let cfgp = &zk;
        let pw = &pv_w32;
        let ps = &pv;
        let wair = WholeAir::<1, 16, 32>::new();
        let sair = crate::spend::SpendAir::<1, 16, 64>::new();
        let wtr = whole_trace::<1, 16, 32>(ROWS);
        let str_ = crate::spend_trace::spend_trace::<1, 16, 64>(ROWS);
        let wproof = prove(cfgp, &wair, wtr.clone(), pw);
        let sproof = prove(cfgp, &sair, str_.clone(), ps);
        labels.push("two halves, one timed region");
        cols.push(BaseAir::<Val>::width(&wair) + BaseAir::<Val>::width(&sair));
        bytes.push(
            bincode::serialize(&wproof).expect("proof serialises").len()
                + bincode::serialize(&sproof).expect("proof serialises").len(),
        );

        let w1 = WholeAir::<1, 16, 32>::new();
        let s1 = crate::spend::SpendAir::<1, 16, 64>::new();
        provers.push(Box::new(move || {
            let a = wtr.clone();
            let b = str_.clone();
            let t = Instant::now();
            let _ = prove(cfgp, &w1, a, pw);
            let _ = prove(cfgp, &s1, b, ps);
            t.elapsed().as_micros()
        }));

        let w2 = WholeAir::<1, 16, 32>::new();
        let s2 = crate::spend::SpendAir::<1, 16, 64>::new();
        verifiers.push(Box::new(move || {
            let t = Instant::now();
            let ok = verify(cfgp, &w2, &wproof, pw).is_ok()
                && verify(cfgp, &s2, &sproof, ps).is_ok();
            let e = t.elapsed().as_micros();
            assert!(ok, "a proof built during setup must verify when timed");
            e
        }));
    }

    let n = labels.len();
    for f in &provers {
        let _ = f();
    }
    for f in &verifiers {
        let _ = f();
    }

    let mut psamples: Vec<Vec<u128>> = vec![Vec::new(); n];
    let mut vsamples: Vec<Vec<u128>> = vec![Vec::new(); n];
    let mut pbatch: Vec<Vec<f64>> = vec![Vec::new(); n];
    let mut vbatch: Vec<Vec<f64>> = vec![Vec::new(); n];

    for batch in 0..batches {
        if batch > 0 {
            sleep(Duration::from_secs(pause_secs));
        }
        let mut pthis: Vec<Vec<u128>> = vec![Vec::new(); n];
        let mut vthis: Vec<Vec<u128>> = vec![Vec::new(); n];
        for _ in 0..per_batch {
            for i in 0..n {
                pthis[i].push(provers[i]());
                vthis[i].push(verifiers[i]());
            }
        }
        for i in 0..n {
            pbatch[i].push(summarise(pthis[i].clone(), ROWS).median);
            vbatch[i].push(summarise(vthis[i].clone(), ROWS).median);
            psamples[i].extend(pthis[i].clone());
            vsamples[i].extend(vthis[i].clone());
        }
    }

    (0..n)
        .map(|i| CostRow {
            label: labels[i],
            columns: cols[i],
            bytes: bytes[i],
            prove: summarise(psamples[i].clone(), ROWS),
            verify: summarise(vsamples[i].clone(), ROWS),
            prove_batches: pbatch[i].clone(),
            verify_batches: vbatch[i].clone(),
        })
        .collect()
}
