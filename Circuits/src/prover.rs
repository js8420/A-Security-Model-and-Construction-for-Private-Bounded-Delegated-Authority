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
use crate::full::FullAir;
use crate::composed::ComposedAir;
use crate::vacuous::VacuousAir;
use crate::whole::WholeAir;
use crate::merkle::MerkleAir;
use crate::revocation::NonMembershipAir;
use crate::trace::{composed_case, composed_public_values, full_public_values, vacuous_trace, whole_public_values, broken_composed, broken_nonmembership, broken_trace, composed_air_trace, composed_trace, corrupt, merkle_trace, nonmembership_trace, policy_trace, whole_trace, Break, ComposedBreak, RevokeBreak};

// Goldilocks at width 8: a digest of four elements is 256 bits.
pub(crate) type Val = Goldilocks;
pub(crate) type Challenge = BinomialExtensionField<Val, 2>;
pub(crate) type Perm = Poseidon2Goldilocks<8>;
pub(crate) type Hash = PaddingFreeSponge<Perm, 8, 4, 4>;
pub(crate) type Compress = TruncatedPermutation<Perm, 2, 4, 8>;

/// Salt elements per leaf. The crate's rule is that SALT_ELEMS times the size
/// of a value must reach the target security parameter; at 64 bits a piece,
/// two elements give 128 against a claimed 88. One would give 64 and be short.
pub const SALT_ELEMS: usize = 2;

/// Random codewords the hiding PCS appends per matrix. Must exceed zero, and
/// the quotient decomposition panics below two.
pub const NUM_RANDOM_CODEWORDS: usize = 2;

// Fixed seeds survive only in config_fixed_seed, which exists to show what
// they cost: two proofs made under one seed share their blinding. Every proof
// the paper reports is made under fresh randomness from the operating system.
const INPUT_SALT_SEED: u64 = 0x5350_454e_4400_0001;
const FRI_SALT_SEED: u64 = 0x5350_454e_4400_0004;
const CODEWORD_SEED: u64 = 0x5350_454e_4400_0002;

// Both MMCSs are hiding. p3-fri says so in a doc comment and does not enforce
// it, and its own test does not obey it: the upstream configuration encloses a
// plain MerkleTreeMmcs and is not hiding. ChaCha12 is the cipher StdRng uses,
// named directly because StdRng is neither Clone nor portable across releases.
// SmallRng, which the upstream tests use for salts, is documented as insecure.
pub(crate) type ValMmcs = MerkleTreeHidingMmcs<
    <Val as Field>::Packing,
    <Val as Field>::Packing,
    Hash,
    Compress,
    SaltRng,
    2,
    4,
    SALT_ELEMS,
>;
pub(crate) type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
pub(crate) type Dft = Radix2DitParallel<Val>;
pub(crate) type Pcs = HidingFriPcs<Val, Dft, ValMmcs, ChallengeMmcs, SaltRng>;

/// ChaCha12 with a Clone that reconstructs the stream rather than approximating
/// it. chacha20 derives nothing on its RNGs, and the only Clone generator in the
/// dependency tree is Xoshiro, which the rand documentation calls insecure. The
/// three values copied here are exactly the three the crate's own PartialEq
/// compares, so a clone and its original are equal by that definition.
pub struct SaltRng(ChaCha12Rng);

impl SaltRng {
    pub(crate) fn seeded(seed: u64) -> Self {
        Self(ChaCha12Rng::seed_from_u64(seed))
    }

    /// Seeded from the operating system, so no two proofs share blinding.
    pub(crate) fn fresh() -> Self {
        Self(ChaCha12Rng::try_from_rng(&mut rand10::rngs::SysRng).expect("operating-system randomness"))
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
pub(crate) type Challenger = DuplexChallenger<Val, Perm, 8, 4>;
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
        // Grinding off, as in the hiding rows of the cost study it is
        // compared with, which is its only use.
        query_proof_of_work_bits: 0,
        mmcs: challenge_mmcs,
    };
    let pcs = PlainPcs::new(Dft::default(), val_mmcs, fri_params);
    StarkConfig::new(pcs, Challenger::new(perm))
}

/// 40 queries at blowup 16 with 20 grinding bits: 126 bits under the FRI
/// list-decoding conjecture, and 100 without it. The earlier setting was the
/// upstream test default --- 40 queries at blowup 4 with 8 grinding bits ---
/// which is 88 conjectured and 48 provable, and was never chosen for this
/// construction. The sweep of `sweep.rs` is why these three numbers and not
/// others: grinding costs nothing in proof size, rate costs almost nothing,
/// and queries cost about 208 kB each. Reaching 100 provable bits this way
/// adds 12,800 bytes to a proof and takes proving from 1.7 s to 6.2 s for a
/// 32-payment batch.
/// S-box registers in the Poseidon2 AIR. One register witnesses an
/// intermediate value and holds every S-box constraint at degree 3; zero
/// registers leaves them at degree 7 and removes the columns. Both verify under
/// the hiding commitment at the rate below, and zero is 44.8% narrower on the
/// composed circuit, so zero is what the construction is built with. The
/// ablation rows in main.rs name their register count literally and must stay
/// that way; everything that means "as built" reads this.
pub const REGISTERS: usize = 0;

pub const NUM_QUERIES: usize = 40;
pub const LOG_BLOWUP: usize = 4;
pub const POW_BITS: usize = 20;

/// Degree of the challenge field over Goldilocks.
pub const EXT_DEGREE: usize = 2;

/// The hiding commitment blinds a trace of height n with n random rows, so
/// each column has n random values to hide what a proof opens of it: one
/// value per FRI query, and the out-of-domain points, of which the verifier
/// opens two (zeta and the next row), each an extension element worth
/// EXT_DEGREE base values. Haboeck and Kindi, "A note on adding zero-knowledge
/// to STARKs", conditions (19) and (20), state the requirement as
/// n >= 2 (e + q); counting both out-of-domain points it is n >= 2 (2e + q).
/// The second is the stricter, and the height is the next power of two.
pub const ZK_MIN_ROWS: usize = (2 * (2 * EXT_DEGREE + NUM_QUERIES)).next_power_of_two();

/// The height every proof in the paper is made at.
pub const ROWS: usize = 128;
const _: () = assert!(ROWS >= ZK_MIN_ROWS, "trace too short for zero knowledge");

/// The hiding configuration at a chosen FRI setting. `config` is this at the
/// deployment's parameters; the sweep of `sweep.rs` is this at others. There is
/// one constructor so a parameter added here cannot be missed there.
pub(crate) fn config_with(num_queries: usize, log_blowup: usize, pow_bits: usize) -> Config {
    config_seeded(num_queries, log_blowup, pow_bits, false)
}

/// The deployed configuration with the constant seeds this crate used to
/// build every proof with. Kept only so the harness can show what they cost.
pub(crate) fn config_fixed_seed() -> Config {
    config_seeded(NUM_QUERIES, LOG_BLOWUP, POW_BITS, true)
}

fn config_seeded(num_queries: usize, log_blowup: usize, pow_bits: usize, fixed: bool) -> Config {
    StarkConfig::new(
        pcs_seeded(num_queries, log_blowup, pow_bits, fixed),
        Challenger::new(default_goldilocks_poseidon2_8()),
    )
}

/// The deployed commitment scheme, fresh randomness, for code that pairs it
/// with a challenger of its own.
pub(crate) fn deployed_pcs() -> Pcs {
    pcs_seeded(NUM_QUERIES, LOG_BLOWUP, POW_BITS, false)
}

fn pcs_seeded(num_queries: usize, log_blowup: usize, pow_bits: usize, fixed: bool) -> Pcs {
    let rng = |seed: u64| if fixed { SaltRng::seeded(seed) } else { SaltRng::fresh() };
    let perm = default_goldilocks_poseidon2_8();
    let hash = Hash::new(perm.clone());
    let compress = Compress::new(perm.clone());
    // Separate seeds. Cloning one MMCS into the other would blind both
    // commitments from an identical stream, which is not independent blinding.
    let val_mmcs = ValMmcs::new(
        hash.clone(),
        compress.clone(),
        0,
        rng(INPUT_SALT_SEED),
    );
    let fri_mmcs = ValMmcs::new(hash, compress, 0, rng(FRI_SALT_SEED));
    let challenge_mmcs = ChallengeMmcs::new(fri_mmcs);
    let fri_params = FriParameters {
        log_blowup,
        log_final_poly_len: 3,
        max_log_arity: 2,
        num_queries,
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: pow_bits,
        mmcs: challenge_mmcs,
    };
    let pcs = Pcs::new(
        Dft::default(),
        val_mmcs,
        fri_params,
        NUM_RANDOM_CODEWORDS,
        rng(CODEWORD_SEED),
    );
    pcs
}

fn config() -> Config {
    config_with(NUM_QUERIES, LOG_BLOWUP, POW_BITS)
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
    let air = crate::spend2::SpendTwoAir::<R, DEPTH, COVER>::new();
    let cfg = config();
    let pv = crate::spend_trace::spend_public_values();
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
    let (t, pv) = composed_case::<R, MD, RD, DEPTH, COVER>(rows, how);
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
    let pv = composed_public_values::<R, MD, RD>();
    let proof = prove(&cfg, &air, composed_air_trace::<R, MD, RD, DEPTH, COVER>(rows), &pv);
    bincode::serialize(&proof).expect("proof serialises").len()
}

/// Proof size for the accountability half on its own, so the comparison with
/// the composed proof is two measurements rather than one measurement and an
/// extrapolation from the affine law.
pub fn spend_proof_bytes<const R: usize, const DEPTH: usize, const COVER: usize>(
    rows: usize,
) -> usize {
    let air = crate::spend::SpendAir::<R, DEPTH, COVER>::new();
    let cfg = config();
    let pv = crate::spend_trace::spend_public_values();
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
    dom: u64,
) -> bool {
    use p3_field::PrimeCharacteristicRing;
    let air = crate::spend::SpendAir::<R, DEPTH, COVER>::new();
    let cfg = config();
    let t = match bad {
        None => crate::spend_trace::spend_trace::<R, DEPTH, COVER>(rows),
        Some(b) => crate::spend_trace::broken_spend::<R, DEPTH, COVER>(rows, b),
    };
    let pv = vec![Goldilocks::from_u64(payload), Goldilocks::from_u64(dom)];
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
        let trace = air.generate_trace_rows(ROWS, 0);
        let proof = prove(&cfg, &air, trace, &vec![]);
        verify(&cfg, &air, &proof, &vec![]).is_ok()
    };
    let deg3 = {
        let air = new_hash_air::<1>();
        let trace = air.generate_trace_rows(ROWS, 0);
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
/// Every variant is a real AIR proved at the deployed height, not an arithmetic combination
/// of other rows. The marginal costs are differences between measured rows.
pub fn cost_structure(batches: usize, per_batch: usize, pause_secs: u64) -> Vec<CostRow> {

    // Proved with grinding off. The search adds a random cost whose spread
    // swamps the differences between variants; it is the same search for
    // every variant, so it is measured once, by grinding_cost, and added back
    // as a known quantity rather than sampled inside each row. Proof bytes do
    // not depend on the grinding bits.
    let zk = config_with(NUM_QUERIES, LOG_BLOWUP, 0);
    let plain = config_plain();
    let pv: Vec<Goldilocks> = crate::spend_trace::spend_public_values();
    let pv_c = composed_public_values::<{ REGISTERS }, 16, 32>();
    let pv_full = full_public_values::<{ REGISTERS }>();

    // Declared before the closure vectors below, so that the closures which
    // borrow them are dropped first.
    let pv_w32 = whole_public_values::<{ REGISTERS }, 16, 32>();
    let pv_wpp = whole_public_values::<{ REGISTERS }, 0, 32>();
    let pv_w20 = whole_public_values::<{ REGISTERS }, 16, 20>();
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

    variant!("policy + C9 only", FullAir::<{ REGISTERS }>::new(), composed_trace::<{ REGISTERS }>(ROWS), &zk, &pv_full);
    variant!("+ allowlists + revocation d32", WholeAir::<{ REGISTERS }, 16, 32>::new(),
             whole_trace::<{ REGISTERS }, 16, 32>(ROWS), &zk, &pv_w32);
    variant!("  same, revocation d20", WholeAir::<{ REGISTERS }, 16, 20>::new(),
             whole_trace::<{ REGISTERS }, 16, 20>(ROWS), &zk, &pv_w20);
    variant!("  allowlists outside the proof", WholeAir::<{ REGISTERS }, 0, 32>::new(),
             whole_trace::<{ REGISTERS }, 0, 32>(ROWS), &zk, &pv_wpp);
    variant!("accountability, grain 1/64", crate::spend::SpendAir::<{ REGISTERS }, 16, 64>::new(),
             crate::spend_trace::spend_trace::<{ REGISTERS }, 16, 64>(ROWS), &zk, &pv);
    variant!("  coarser, grain 1/30", crate::spend::SpendAir::<{ REGISTERS }, 16, 30>::new(),
             crate::spend_trace::spend_trace::<{ REGISTERS }, 16, 30>(ROWS), &zk, &pv);
    variant!("  finer, grain 1/128", crate::spend::SpendAir::<{ REGISTERS }, 16, 128>::new(),
             crate::spend_trace::spend_trace::<{ REGISTERS }, 16, 128>(ROWS), &zk, &pv);
    variant!("whole, no zero knowledge", WholeAir::<0, 16, 32>::new(),
             whole_trace::<0, 16, 32>(ROWS), &plain, &pv_w32z);
    variant!("accountability, no zk", crate::spend::SpendAir::<0, 16, 64>::new(),
             crate::spend_trace::spend_trace::<0, 16, 64>(ROWS), &plain, &pv);
    // The composed circuit is what a settlement actually costs: one proof
    // covering both halves of one payment, rather than a compliance figure that
    // has to be added to an accountability figure the abstract never added.
    variant!("composed, one proof per payment", ComposedAir::<{ REGISTERS }, 16, 32, 16, 64>::new(),
             composed_air_trace::<{ REGISTERS }, 16, 32, 16, 64>(ROWS), &zk, &pv_c);

    // The arrangement the manuscript describes, timed as one thing. Adding the
    // medians of two separately measured rows is not the median of their sum,
    // and the claim that composition costs a tenth more to prove rests on the
    // difference between this row and the one above it.
    {
        let cfgp = &zk;
        let pw = &pv_w32;
        let ps = &pv;
        let wair = WholeAir::<{ REGISTERS }, 16, 32>::new();
        let sair = crate::spend::SpendAir::<{ REGISTERS }, 16, 64>::new();
        let wtr = whole_trace::<{ REGISTERS }, 16, 32>(ROWS);
        let str_ = crate::spend_trace::spend_trace::<{ REGISTERS }, 16, 64>(ROWS);
        let wproof = prove(cfgp, &wair, wtr.clone(), pw);
        let sproof = prove(cfgp, &sair, str_.clone(), ps);
        labels.push("two halves, one timed region");
        cols.push(BaseAir::<Val>::width(&wair) + BaseAir::<Val>::width(&sair));
        bytes.push(
            bincode::serialize(&wproof).expect("proof serialises").len()
                + bincode::serialize(&sproof).expect("proof serialises").len(),
        );

        let w1 = WholeAir::<{ REGISTERS }, 16, 32>::new();
        let s1 = crate::spend::SpendAir::<{ REGISTERS }, 16, 64>::new();
        provers.push(Box::new(move || {
            let a = wtr.clone();
            let b = str_.clone();
            let t = Instant::now();
            let _ = prove(cfgp, &w1, a, pw);
            let _ = prove(cfgp, &s1, b, ps);
            t.elapsed().as_micros()
        }));

        let w2 = WholeAir::<{ REGISTERS }, 16, 32>::new();
        let s2 = crate::spend::SpendAir::<{ REGISTERS }, 16, 64>::new();
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
        // A variant's iterations run consecutively, and the order of variants
        // rotates with the batch. Interleaving at the iteration level put a
        // proof of 520 columns between two of 14,197 and charged each timed
        // region for the allocator and cache behaviour of its neighbours: the
        // same circuits timed as whole proofs elsewhere in this harness are
        // stable to one percent, and here they were not. Rotating keeps the
        // drift control that interleaving was for, since no variant is always
        // measured first, and per-batch medians still expose drift if any.
        for k in 0..n {
            let i = (k + batch) % n;
            for _ in 0..per_batch {
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


/// One composed proof at a chosen FRI setting, with the size broken into the
/// parts a wrapper would have to replace. Deterministic at fixed parameters.
pub fn composed_proof_at<
    const R: usize,
    const MD: usize,
    const RD: usize,
    const DEPTH: usize,
    const COVER: usize,
>(
    rows: usize,
    num_queries: usize,
    log_blowup: usize,
    pow_bits: usize,
) -> (usize, usize, usize, usize, u128, u128, bool) {
    let air = ComposedAir::<R, MD, RD, DEPTH, COVER>::new();
    let cfg = config_with(num_queries, log_blowup, pow_bits);
    let pv = composed_public_values::<R, MD, RD>();
    let trace = composed_air_trace::<R, MD, RD, DEPTH, COVER>(rows);

    let t0 = Instant::now();
    let proof = prove(&cfg, &air, trace, &pv);
    let prove_us = t0.elapsed().as_micros();

    let whole = bincode::serialize(&proof).expect("proof serialises").len();
    let commit = bincode::serialize(&proof.commitments).expect("commitments").len();
    let opened = bincode::serialize(&proof.opened_values).expect("opened values").len();
    let opening = bincode::serialize(&proof.opening_proof).expect("opening proof").len();

    let t1 = Instant::now();
    let ok = verify(&cfg, &air, &proof, &pv).is_ok();
    let verify_us = t1.elapsed().as_micros();

    (whole, commit, opened, opening, prove_us, verify_us, ok)
}

/// Proving times for the same circuit and the same prebuilt trace, with the
/// hiding configuration either shared across every iteration or rebuilt for
/// each. The cost study shares one; the parameter sweep rebuilds. Their
/// dispersions differ twentyfold and this is the only difference left between
/// them, so it is measured here rather than argued about.
pub fn composed_times<
    const R: usize,
    const MD: usize,
    const RD: usize,
    const DEPTH: usize,
    const COVER: usize,
>(
    rows: usize,
    iters: usize,
    share_config: bool,
) -> Vec<u128> {
    let air = ComposedAir::<R, MD, RD, DEPTH, COVER>::new();
    let pv = composed_public_values::<R, MD, RD>();
    let base = composed_air_trace::<R, MD, RD, DEPTH, COVER>(rows);
    let shared = config();
    let mut out = Vec::with_capacity(iters);
    for _ in 0..iters {
        let ready = base.clone();
        if share_config {
            let t = Instant::now();
            let _ = prove(&shared, &air, ready, &pv);
            out.push(t.elapsed().as_micros());
        } else {
            let cfg = config();
            let t = Instant::now();
            let _ = prove(&cfg, &air, ready, &pv);
            out.push(t.elapsed().as_micros());
        }
    }
    out
}

/// Does a composed configuration actually verify? `composed_proof_bytes`
/// proves without verifying, so a size can be reported for a statement no
/// verifier accepts. This exists so that cannot happen silently again.
pub fn composed_verifies<
    const R: usize,
    const MD: usize,
    const RD: usize,
    const DEPTH: usize,
    const COVER: usize,
>(
    rows: usize,
) -> bool {
    composed_verifies_at::<R, MD, RD, DEPTH, COVER>(rows, NUM_QUERIES, LOG_BLOWUP, POW_BITS)
}

/// The same question at a chosen rate. The degree a hiding commitment can
/// carry is bounded by the rate, so the smallest rate admitting a zero-register
/// circuit is what the register actually costs.
pub fn composed_verifies_at<
    const R: usize,
    const MD: usize,
    const RD: usize,
    const DEPTH: usize,
    const COVER: usize,
>(
    rows: usize,
    num_queries: usize,
    log_blowup: usize,
    pow_bits: usize,
) -> bool {
    let air = ComposedAir::<R, MD, RD, DEPTH, COVER>::new();
    let cfg = config_with(num_queries, log_blowup, pow_bits);
    let pv = composed_public_values::<R, MD, RD>();
    let proof = prove(&cfg, &air, composed_air_trace::<R, MD, RD, DEPTH, COVER>(rows), &pv);
    verify(&cfg, &air, &proof, &pv).is_ok()
}

// ---------------------------------------------------------------------------
// How much work one verification is, counted rather than derived from the FRI
// shape. The dispute bisects this work, so its length sets the round count.
// ---------------------------------------------------------------------------

static PERMUTATIONS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// The deployed permutation with a counter in front of it. Same outputs, so a
/// proof made under it is the proof the deployment makes.
#[derive(Clone)]
pub struct Counting<P>(P);

impl<T: Clone, P: p3_symmetric::Permutation<T>> p3_symmetric::Permutation<T> for Counting<P> {
    fn permute_mut(&self, input: &mut T) {
        PERMUTATIONS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.0.permute_mut(input);
    }
}

impl<T: Clone, P: p3_symmetric::CryptographicPermutation<T>> p3_symmetric::CryptographicPermutation<T>
    for Counting<P>
{
}

type CPerm = Counting<Perm>;
type CHash = PaddingFreeSponge<CPerm, 8, 4, 4>;
type CCompress = TruncatedPermutation<CPerm, 2, 4, 8>;
type CValMmcs = MerkleTreeHidingMmcs<
    <Val as Field>::Packing,
    <Val as Field>::Packing,
    CHash,
    CCompress,
    SaltRng,
    2,
    4,
    SALT_ELEMS,
>;
type CChallengeMmcs = ExtensionMmcs<Val, Challenge, CValMmcs>;
type CPcs = HidingFriPcs<Val, Dft, CValMmcs, CChallengeMmcs, SaltRng>;
type CChallenger = DuplexChallenger<Val, CPerm, 8, 4>;
type CConfig = StarkConfig<CPcs, Challenge, CChallenger>;

fn counting_config() -> CConfig {
    let perm = Counting(default_goldilocks_poseidon2_8());
    let hash = CHash::new(perm.clone());
    let compress = CCompress::new(perm.clone());
    let val_mmcs = CValMmcs::new(hash.clone(), compress.clone(), 0, SaltRng::fresh());
    let fri_mmcs = CValMmcs::new(hash, compress, 0, SaltRng::fresh());
    let fri_params = FriParameters {
        log_blowup: LOG_BLOWUP,
        log_final_poly_len: 3,
        max_log_arity: 2,
        num_queries: NUM_QUERIES,
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: POW_BITS,
        mmcs: CChallengeMmcs::new(fri_mmcs),
    };
    let pcs = CPcs::new(
        Dft::default(),
        val_mmcs,
        fri_params,
        NUM_RANDOM_CODEWORDS,
        SaltRng::fresh(),
    );
    StarkConfig::new(pcs, CChallenger::new(perm))
}

/// Distinct arithmetic operations in the constraint system, counting a shared
/// subexpression once, as a verifier evaluating it at one point does.
fn constraint_ops(cs: &[p3_air::SymbolicExpression<Val>]) -> usize {
    use p3_air::symbolic::SymbolicExpr;
    use std::collections::HashSet;
    type E = SymbolicExpr<p3_air::BaseLeaf<Val>>;
    fn walk(e: &E, seen: &mut HashSet<*const E>, n: &mut usize) {
        let kids: Vec<&std::sync::Arc<E>> = match e {
            SymbolicExpr::Leaf(_) => return,
            SymbolicExpr::Add { x, y, .. }
            | SymbolicExpr::Sub { x, y, .. }
            | SymbolicExpr::Mul { x, y, .. } => vec![x, y],
            SymbolicExpr::Neg { x, .. } => vec![x],
        };
        *n += 1;
        for k in kids {
            if seen.insert(std::sync::Arc::as_ptr(k)) {
                walk(k, seen, n);
            }
        }
    }
    let mut seen = HashSet::new();
    let mut n = 0;
    for c in cs {
        walk(c, &mut seen, &mut n);
    }
    n
}

pub struct VerifierWork {
    pub verifies: bool,
    pub permutations: u64,
    pub constraints: usize,
    pub constraint_ops: usize,
    pub proof_bytes: usize,
}

/// One verification of the composed circuit as deployed, with every Poseidon2
/// permutation the verifier runs counted and the constraint evaluation sized.
pub fn verifier_work<
    const R: usize,
    const MD: usize,
    const RD: usize,
    const DEPTH: usize,
    const COVER: usize,
>(
    rows: usize,
) -> VerifierWork {
    let air = ComposedAir::<R, MD, RD, DEPTH, COVER>::new();
    let cfg = counting_config();
    let pv = composed_public_values::<R, MD, RD>();
    let proof = prove(&cfg, &air, composed_air_trace::<R, MD, RD, DEPTH, COVER>(rows), &pv);
    PERMUTATIONS.store(0, std::sync::atomic::Ordering::Relaxed);
    let verifies = verify(&cfg, &air, &proof, &pv).is_ok();
    let permutations = PERMUTATIONS.load(std::sync::atomic::Ordering::Relaxed);
    let proof_bytes = bincode::serialize(&proof).expect("proof serialises").len();
    let cs = p3_air::get_symbolic_constraints::<Val, _>(&air, p3_air::AirLayout::from_air::<Val>(&air));
    VerifierWork {
        verifies,
        permutations,
        constraints: cs.len(),
        constraint_ops: constraint_ops(&cs),
        proof_bytes,
    }
}

/// The proof-of-work search a deployed proof performs, timed on its own.
/// Each sample grinds a fresh transcript, so the samples are independent draws
/// of the search's running time.
pub fn grinding_cost(samples: usize) -> Stats {
    use p3_challenger::{CanObserve, GrindingChallenger};
    use p3_field::PrimeCharacteristicRing;
    let perm = default_goldilocks_poseidon2_8();
    let mut us: Vec<u128> = Vec::with_capacity(samples);
    for i in 0..samples {
        let mut ch = Challenger::new(perm.clone());
        ch.observe(Goldilocks::from_u64(0x9E37_79B9_7F4A_7C15 ^ i as u64));
        let t = Instant::now();
        let _ = ch.grind(POW_BITS);
        us.push(t.elapsed().as_micros());
    }
    summarise(us, 1)
}

// ---------------------------------------------------------------------------
// Does a proof hide its trace? An attack, run against a real proof.
//
// The hiding commitment interleaves the trace with as many random rows as it
// has real ones and commits to the polynomial through all of them, of degree
// below 2n. A column that holds the same value in every real row --- the
// agent's secret, its root key, the budget, every policy field, since one
// delegation proves all its payments --- is then fixed by n + 1 unknowns: the
// value, and the n random entries. A proof opens the column at one point per
// FRI query. If the openings outnumber the unknowns, the value is the unique
// solution of a linear system anyone holding the proof can write down.
//
// The attacker uses nothing but the proof. It finds each query's position by
// trying every index of the extended domain until the commitment accepts the
// opened row, and it never reads the trace except to score its answer.
// ---------------------------------------------------------------------------

pub struct LeakReport {
    pub rows: usize,
    pub openings: usize,
    pub unknowns: usize,
    pub rank: usize,
    pub columns: usize,
    pub recovered: usize,
    pub secret_recovered: bool,
    pub budget_recovered: bool,
}

fn rev_bits(mut x: usize, bits: usize) -> usize {
    let mut r = 0;
    for _ in 0..bits {
        r = (r << 1) | (x & 1);
        x >>= 1;
    }
    r
}

pub fn zk_leak<
    const R: usize,
    const MD: usize,
    const RD: usize,
    const DEPTH: usize,
    const COVER: usize,
>(
    rows: usize,
) -> LeakReport {
    use p3_commit::{BatchOpeningRef, Mmcs};
    use p3_field::{PrimeCharacteristicRing, TwoAdicField};
    use p3_matrix::{Dimensions, Matrix};

    type F = Goldilocks;
    let air = ComposedAir::<R, MD, RD, DEPTH, COVER>::new();
    let width = BaseAir::<F>::width(&air);
    let (t, pv) = composed_case::<R, MD, RD, DEPTH, COVER>(rows, None);
    let truth: Vec<F> = t.row_slice(0).expect("row").to_vec();
    let proof = prove(&config(), &air, t, &pv);

    // Only what any holder of the proof has.
    let perm = default_goldilocks_poseidon2_8();
    let mmcs = ValMmcs::new(Hash::new(perm.clone()), Compress::new(perm), 0, SaltRng::seeded(0));
    let n2 = 2 * rows;
    let log_lde = n2.trailing_zeros() as usize + LOG_BLOWUP;
    let height = 1usize << log_lde;
    let committed = width + NUM_RANDOM_CODEWORDS;
    let dims = [Dimensions { width: committed, height }];

    let mut points: Vec<(usize, Vec<F>)> = Vec::new();
    for q in &proof.opening_proof.1.query_proofs {
        let Some(b) = q.input_proof.iter().find(|b| {
            b.opened_values.len() == 1 && b.opened_values[0].len() == committed
        }) else { continue };
        for idx in 0..height {
            if mmcs.verify_batch(&proof.commitments.trace, &dims, idx, BatchOpeningRef::from(b)).is_ok() {
                if !points.iter().any(|(i, _)| *i == idx) {
                    points.push((idx, b.opened_values[0].clone()));
                }
                break;
            }
        }
    }

    // Lagrange weights over the 2n-point domain the randomised trace lives on,
    // at each opened point of the extended coset. Even positions are real
    // rows, odd positions are random.
    let g = F::two_adic_generator(n2.trailing_zeros() as usize);
    let w = F::two_adic_generator(log_lde);
    let n_inv = F::from_u64(n2 as u64).inverse();
    let unknowns = rows + 1;
    let m = points.len();
    let mut a: Vec<Vec<F>> = Vec::with_capacity(m);
    let mut y: Vec<Vec<F>> = Vec::with_capacity(m);
    for (idx, vals) in &points {
        let x = F::GENERATOR * w.exp_u64(rev_bits(*idx, log_lde) as u64);
        let z = x.exp_u64(n2 as u64) - F::ONE;
        let mut row = vec![F::ZERO; unknowns];
        let mut gk = F::ONE;
        for k in 0..n2 {
            let l = gk * z * n_inv * (x - gk).inverse();
            if k % 2 == 0 { row[0] += l; } else { row[1 + k / 2] = l; }
            gk *= g;
        }
        a.push(row);
        y.push(vals[..width].to_vec());
    }

    // Row reduction, applied to every column's right-hand side at once.
    let mut rank = 0;
    let mut pivots: Vec<usize> = Vec::new();
    for c in 0..unknowns {
        let Some(p) = (rank..m).find(|&r| a[r][c] != F::ZERO) else { continue };
        a.swap(rank, p);
        y.swap(rank, p);
        let inv = a[rank][c].inverse();
        for j in 0..unknowns { a[rank][j] *= inv; }
        for j in 0..width { y[rank][j] *= inv; }
        for r in 0..m {
            if r != rank && a[r][c] != F::ZERO {
                let f = a[r][c];
                for j in 0..unknowns { let v = a[rank][j]; a[r][j] -= f * v; }
                for j in 0..width { let v = y[rank][j]; y[r][j] -= f * v; }
            }
        }
        pivots.push(c);
        rank += 1;
    }

    let mut recovered = 0;
    let mut answer = vec![None; width];
    if rank == unknowns && pivots[0] == 0 {
        for j in 0..width {
            answer[j] = Some(y[0][j]);
            if y[0][j] == truth[j] { recovered += 1; }
        }
    }
    let whole_w = BaseAir::<F>::width(&WholeAir::<R, MD, RD>::new());
    let hit = |col: usize| answer[col] == Some(truth[col]);
    LeakReport {
        rows,
        openings: m,
        unknowns,
        rank,
        columns: width,
        recovered,
        secret_recovered: (0..crate::spend::SECRET_ELEMS).all(|j| hit(whole_w + crate::spend::COL_SECRET + j)),
        budget_recovered: hit(crate::air::COL_B),
    }
}

/// Whether two proofs of one trace share their blinding.
pub fn blinding_reused(fixed: bool) -> bool {
    let air = ComposedAir::<{ REGISTERS }, 8, 8, 16, 14>::new();
    let (t, pv) = composed_case::<{ REGISTERS }, 8, 8, 16, 14>(ROWS, None);
    let (c1, c2) = if fixed { (config_fixed_seed(), config_fixed_seed()) } else { (config(), config()) };
    let p1 = prove(&c1, &air, t.clone(), &pv);
    let p2 = prove(&c2, &air, t, &pv);
    p1.commitments.trace == p2.commitments.trace
}
