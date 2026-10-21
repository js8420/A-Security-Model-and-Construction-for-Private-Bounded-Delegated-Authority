//! Proofs that are wrong in one place and right everywhere else, made by the
//! prover itself, so that a verifier reaches its deepest checks before it
//! refuses them. A bit flipped in a finished proof is almost always caught
//! by the first Merkle path or the grinding check after it; these are not.
//!
//! Five families, each one fault injected while the deployed prover runs:
//!
//! - `draw`: one base-field challenge the prover reads is shifted, while
//!   the transcript it absorbs stays honest. Every commitment, opening path,
//!   grinding witness and query index is then the verifier's own, and only
//!   the arithmetic that used the shifted challenge is wrong.
//! - `codeword`: one committed low-degree extension is changed before it
//!   is committed, so its Merkle tree is consistent and the codeword is no
//!   longer of low degree: in one entry, which leaves it next to the honest
//!   codeword, or in about half of them, which leaves it far from every one.
//! - `trace`: one cell of the honest trace is changed before proving.
//! - `public`: one public value is changed before proving.
//! - `grinding`: the query grinding witness is wrong, and absorbed as if it
//!   were right.
//!
//! The proofs are written in the deployed format, so the deployed verifier
//! reads them as it reads any other.

use std::io::Write as _;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use p3_challenger::{CanObserve, CanSample, CanSampleBits, FieldChallenger, GrindingChallenger};
use p3_dft::TwoAdicSubgroupDft;
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing, PrimeField64};
use p3_matrix::bitrev::BitReversibleMatrix;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use p3_uni_stark::{prove, StarkConfig};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

use crate::naysay::Air;
use crate::prover::{challenger, fri_fresh, keccak_mmcs, Challenge, Challenger, Dft, SaltRng, Val, NUM_RANDOM_CODEWORDS, ROWS};
use crate::trace::composed_batch;

/// The families, in the order the harness runs them.
pub const FAMILIES: [&str; 5] = ["draw", "codeword", "trace", "public", "grinding"];

fn nonzero(rng: &mut StdRng) -> Val {
    loop {
        let v = Val::from_u64(rng.gen::<u64>() % Val::ORDER_U64);
        if v != Val::ZERO {
            return v;
        }
    }
}

/// The deployed challenger, except that the base-field draw numbered
/// `shift.0` is returned plus `shift.1`, and, if `bad_pow` is set, the query
/// grinding witness is wrong. What it absorbs is always what the prover
/// sends, so the verifier's transcript matches it draw for draw.
#[derive(Clone)]
pub struct FaultChallenger {
    inner: Challenger,
    draws: Arc<AtomicUsize>,
    shift: Option<(usize, Val)>,
    bad_pow: bool,
}

impl<T> CanObserve<T> for FaultChallenger
where
    Challenger: CanObserve<T>,
{
    fn observe(&mut self, value: T) {
        self.inner.observe(value);
    }
}

impl<EF: BasedVectorSpace<Val>> CanSample<EF> for FaultChallenger {
    fn sample(&mut self) -> EF {
        EF::from_basis_coefficients_fn(|_| {
            let v: Val = self.inner.sample();
            match self.shift {
                Some((n, d)) if n == self.draws.fetch_add(1, Ordering::SeqCst) => v + d,
                _ => v,
            }
        })
    }
}

impl CanSampleBits<usize> for FaultChallenger {
    fn sample_bits(&mut self, bits: usize) -> usize {
        self.inner.sample_bits(bits)
    }
}

impl GrindingChallenger for FaultChallenger {
    type Witness = Val;

    fn grind(&mut self, bits: usize) -> Val {
        if bits == 0 || !self.bad_pow {
            return self.inner.grind(bits);
        }
        let good = self.inner.clone().grind(bits);
        let mut w = good + Val::ONE;
        while self.inner.clone().check_witness(bits, w) {
            w += Val::ONE;
        }
        self.inner.observe(w);
        let _ = self.inner.sample_bits(bits);
        w
    }
}

impl FieldChallenger<Val> for FaultChallenger {}

/// The deployed DFT, except that the low-degree extension it computes on its
/// call numbered `target.call` is changed by `target.by`: in entry
/// `target.at` alone, or in about half the entries, chosen by `target.at` as
/// a seed. Every call's shape is recorded.
#[derive(Clone, Copy)]
struct Target {
    call: usize,
    at: usize,
    by: Val,
    half: bool,
}

#[derive(Clone, Default)]
pub struct FaultDft {
    inner: Dft,
    calls: Arc<AtomicUsize>,
    target: Option<Target>,
    seen: Arc<Mutex<Vec<(usize, usize)>>>,
}

impl TwoAdicSubgroupDft<Val> for FaultDft {
    type Evaluations = <Dft as TwoAdicSubgroupDft<Val>>::Evaluations;

    fn dft_batch(&self, mat: RowMajorMatrix<Val>) -> Self::Evaluations {
        self.inner.dft_batch(mat)
    }

    fn coset_dft_batch(&self, mat: RowMajorMatrix<Val>, shift: Val) -> Self::Evaluations {
        self.inner.coset_dft_batch(mat, shift)
    }

    fn idft_batch(&self, mat: RowMajorMatrix<Val>) -> RowMajorMatrix<Val> {
        self.inner.idft_batch(mat)
    }

    fn coset_idft_batch(&self, mat: RowMajorMatrix<Val>, shift: Val) -> RowMajorMatrix<Val> {
        self.inner.coset_idft_batch(mat, shift)
    }

    fn coset_lde_batch(&self, mat: RowMajorMatrix<Val>, added_bits: usize, shift: Val) -> Self::Evaluations {
        let out = self.inner.coset_lde_batch(mat, added_bits, shift);
        let call = self.calls.fetch_add(1, Ordering::SeqCst);
        self.seen.lock().expect("lock").push((out.height(), out.width()));
        match self.target {
            Some(t) if t.call == call => {
                let mut m = out.bit_reverse_rows();
                if t.half {
                    let mut x = t.at as u64 | 1;
                    for v in m.values.iter_mut() {
                        x = x.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                        if x >> 63 == 1 {
                            *v += t.by;
                        }
                    }
                } else {
                    m.values[t.at] += t.by;
                }
                m.bit_reverse_rows()
            }
            _ => out,
        }
    }
}

type FaultPcs = p3_fri::HidingFriPcs<Val, FaultDft, crate::prover::ValMmcs, crate::prover::ChallengeMmcs, SaltRng>;
type FaultConfig = StarkConfig<FaultPcs, Challenge, FaultChallenger>;

fn config_with(dft: FaultDft, draws: Arc<AtomicUsize>, shift: Option<(usize, Val)>, bad_pow: bool) -> FaultConfig {
    let pcs = FaultPcs::new(dft, keccak_mmcs(SaltRng::fresh()), fri_fresh(), NUM_RANDOM_CODEWORDS, SaltRng::fresh());
    StarkConfig::new(pcs, FaultChallenger { inner: challenger(), draws, shift, bad_pow })
}

/// What one honest run draws and computes: the number of base-field draws,
/// and the shape of every low-degree extension, in call order.
pub fn census() -> (usize, Vec<(usize, usize)>) {
    let (t, pv) = composed_batch::<{ crate::prover::REGISTERS }, 16, 32, 16, 64>(ROWS, ROWS, None);
    let air = Air::from_public_values(&pv);
    let dft = FaultDft::default();
    let seen = dft.seen.clone();
    let draws = Arc::new(AtomicUsize::new(0));
    let cfg = config_with(dft, draws.clone(), Some((usize::MAX, Val::ZERO)), false);
    let _ = prove(&cfg, &air, t, &pv);
    let shapes = seen.lock().expect("lock").clone();
    (draws.load(Ordering::SeqCst), shapes)
}

/// One faulty proof of family `family`, variant `i`, written to `path`.
/// Returns where the fault was put, or why no proof was made.
fn one(family: &str, i: usize, draws: usize, shapes: &[(usize, usize)], path: &str) -> Result<String, String> {
    let mut rng = StdRng::seed_from_u64(0x0dee_9000 ^ ((FAMILIES.iter().position(|f| *f == family).expect("family") as u64) << 32) ^ i as u64);
    let (mut t, mut pv) = composed_batch::<{ crate::prover::REGISTERS }, 16, 32, 16, 64>(ROWS, ROWS, None);
    let mut dft = FaultDft::default();
    let mut shift = None;
    let mut bad_pow = false;
    let what = match family {
        "draw" => {
            let n = i % draws;
            shift = Some((n, nonzero(&mut rng)));
            format!("draw {n}")
        }
        "codeword" => {
            let c = (i / 2) % shapes.len();
            let (h, w) = shapes[c];
            let half = i % 2 == 1;
            let at = rng.gen_range(0..h * w);
            dft.target = Some(Target { call: c, at, by: nonzero(&mut rng), half });
            let kind = if c == 0 { "trace" } else { "quotient or randomisation" };
            let how = if half { "half the entries" } else { "one entry" };
            format!("{kind} extension, {how}: extension {c} ({h} x {w}), seed or entry {at}")
        }
        "trace" => {
            let w = t.width();
            let r = rng.gen_range(0..t.height());
            let c = rng.gen_range(0..w);
            t.values[r * w + c] += nonzero(&mut rng);
            format!("trace row {r} column {c}")
        }
        "public" => {
            let k = rng.gen_range(0..pv.len());
            pv[k] += nonzero(&mut rng);
            format!("public value {k}")
        }
        "grinding" => {
            bad_pow = true;
            "query grinding witness".to_string()
        }
        other => return Err(format!("no family {other}")),
    };
    let cfg = config_with(dft, Arc::new(AtomicUsize::new(0)), shift, bad_pow);
    let made = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let air = Air::from_public_values(&pv);
        prove(&cfg, &air, t, &pv)
    }));
    let proof = made.map_err(|_| format!("{what}: the prover refused"))?;
    let bytes = bincode::serialize(&(&proof, &pv)).expect("serialise");
    std::fs::write(path, &bytes).expect("write proof");
    Ok(what)
}

/// Writes `count` faulty proofs of `family`, variants `from` onward, into
/// `dir`, and appends one line per variant to `dir/manifest.tsv`: the
/// family, the variant, the file, where the fault is, and the deployed
/// verifier's verdict on the file as written.
pub fn export(dir: &str, family: &str, from: usize, count: usize) {
    let (draws, shapes) = census();
    let mut manifest = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(format!("{dir}/manifest.tsv"))
        .expect("manifest");
    for i in from..from + count {
        let file = format!("{dir}/deep_{family}_{i}.bin");
        let line = match one(family, i, draws, &shapes, &file) {
            Ok(what) => {
                let verdict = match crate::keccak::verify_file(&file, 1) {
                    Ok(_) => "accept".to_string(),
                    Err(why) => format!("reject {}", why.replace(['\n', '\t'], " ")),
                };
                format!("{family}\t{i}\t{file}\t{what}\t{verdict}")
            }
            Err(why) => format!("{family}\t{i}\t-\t{why}\tnone"),
        };
        writeln!(manifest, "{line}").expect("manifest");
    }
}
