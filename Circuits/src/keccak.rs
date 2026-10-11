//! The deployed circuit and FRI parameters with Keccak in place of Poseidon2
//! for the commitments and the transcript. Nothing else changes: the same
//! AIR, the same trace, the same hiding PCS, queries, blowup and grinding.
//! It exists to measure what the hash choice costs on both sides --- proving
//! a payment natively, and proving the verifier inside SP1, where Keccak has
//! a precompile and Poseidon2 over Goldilocks does not.

use std::time::Instant;

use p3_challenger::{HashChallenger, SerializingChallenger64};
use p3_commit::ExtensionMmcs;
use p3_fri::{FriParameters, HidingFriPcs};
use p3_keccak::{Keccak256Hash, KeccakF, VECTOR_LEN};
use p3_merkle_tree::MerkleTreeHidingMmcs;
use p3_symmetric::{CompressionFunctionFromHasher, PaddingFreeSponge, SerializingHasher};
use p3_uni_stark::{prove, verify, Proof, StarkConfig};

use crate::naysay::Air;
use crate::prover::{
    Challenge, Dft, SaltRng, Val, LOG_BLOWUP, LOG_FINAL_POLY_LEN, NUM_QUERIES, NUM_RANDOM_CODEWORDS, POW_BITS, ROWS,
    SALT_ELEMS,
};
use crate::trace::composed_case;

type U64Hash = PaddingFreeSponge<KeccakF, 25, 17, 4>;
type FieldHash = SerializingHasher<U64Hash>;
type KCompress = CompressionFunctionFromHasher<U64Hash, 2, 4>;
type KValMmcs = MerkleTreeHidingMmcs<
    [Val; VECTOR_LEN],
    [u64; VECTOR_LEN],
    FieldHash,
    KCompress,
    SaltRng,
    2,
    4,
    SALT_ELEMS,
>;
type KChallengeMmcs = ExtensionMmcs<Val, Challenge, KValMmcs>;
type KPcs = HidingFriPcs<Val, Dft, KValMmcs, KChallengeMmcs, SaltRng>;
type KChallenger = SerializingChallenger64<Val, HashChallenger<u8, Keccak256Hash, 32>>;
pub(crate) type KConfig = StarkConfig<KPcs, Challenge, KChallenger>;

fn mmcs() -> KValMmcs {
    let u64_hash = U64Hash::new(KeccakF {});
    KValMmcs::new(FieldHash::new(u64_hash), KCompress::new(u64_hash), 0, SaltRng::fresh())
}

pub(crate) fn config() -> KConfig {
    let fri = FriParameters {
        log_blowup: LOG_BLOWUP,
        log_final_poly_len: LOG_FINAL_POLY_LEN,
        max_log_arity: 2,
        num_queries: NUM_QUERIES,
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: POW_BITS,
        mmcs: KChallengeMmcs::new(mmcs()),
    };
    let pcs = KPcs::new(Dft::default(), mmcs(), fri, NUM_RANDOM_CODEWORDS, SaltRng::fresh());
    StarkConfig::new(pcs, KChallenger::from_hasher(vec![], Keccak256Hash {}))
}

/// One 128-row proof under the Keccak configuration, written as the Poseidon2
/// export is, for the zkVM verifier built against the same configuration.
/// Returns the bytes written, whether it verifies natively, and the seconds
/// proving took.
pub fn export(path: &str) -> (usize, bool, f64) {
    let air = Air::new();
    let (t, pv) = composed_case::<{ crate::prover::REGISTERS }, 16, 32, 16, 64>(ROWS, None);
    let cfg = config();
    let start = Instant::now();
    let proof: Proof<KConfig> = prove(&cfg, &air, t, &pv);
    let secs = start.elapsed().as_secs_f64();
    let ok = verify(&config(), &air, &proof, &pv).is_ok();
    let bytes = bincode::serialize(&(&proof, &pv)).expect("serialise");
    std::fs::write(path, &bytes).expect("write proof");
    (bytes.len(), ok, secs)
}

/// Proving and verifying one payment under each hash, timed in batches whose
/// order rotates, as the cost table is. Milliseconds.
pub fn hash_cost(batches: usize, per_batch: usize) {
    let air = Air::new();
    let (t, pv) = composed_case::<{ crate::prover::REGISTERS }, 16, 32, 16, 64>(ROWS, None);
    let pcfg = crate::prover::config();
    let kcfg = config();
    let pproof = prove(&pcfg, &air, t.clone(), &pv);
    let kproof: Proof<KConfig> = prove(&kcfg, &air, t.clone(), &pv);
    assert!(verify(&pcfg, &air, &pproof, &pv).is_ok());
    assert!(verify(&kcfg, &air, &kproof, &pv).is_ok());
    let pbytes = bincode::serialize(&pproof).expect("serialise").len();
    let kbytes = bincode::serialize(&kproof).expect("serialise").len();

    let ms = |s: Instant| s.elapsed().as_secs_f64() * 1000.0;
    let run = |k: usize| -> (f64, f64) {
        if k == 0 {
            let s = Instant::now();
            let _ = prove(&pcfg, &air, t.clone(), &pv);
            let p = ms(s);
            let s = Instant::now();
            assert!(verify(&pcfg, &air, &pproof, &pv).is_ok());
            (p, ms(s))
        } else {
            let s = Instant::now();
            let _: Proof<KConfig> = prove(&kcfg, &air, t.clone(), &pv);
            let p = ms(s);
            let s = Instant::now();
            assert!(verify(&kcfg, &air, &kproof, &pv).is_ok());
            (p, ms(s))
        }
    };
    let _ = run(0);
    let _ = run(1);

    let mut prove_ms = [Vec::new(), Vec::new()];
    let mut verify_ms = [Vec::new(), Vec::new()];
    let mut batch_med = [Vec::new(), Vec::new()];
    let med = |v: &[f64]| {
        let mut s = v.to_vec();
        s.sort_by(|a, b| a.partial_cmp(b).unwrap());
        s
    };
    let at = |s: &[f64], f: f64| s[((s.len() - 1) as f64 * f).round() as usize];
    for b in 0..batches {
        for j in 0..2 {
            let k = (j + b) % 2;
            let mut this = Vec::new();
            for _ in 0..per_batch {
                let (p, v) = run(k);
                this.push(p);
                prove_ms[k].push(p);
                verify_ms[k].push(v);
            }
            batch_med[k].push(at(&med(&this), 0.5));
        }
    }
    println!("ONE PAYMENT PROOF UNDER EACH HASH, COMPOSED CIRCUIT, {ROWS} ROWS");
    println!("{}", "=".repeat(78));
    println!("  {batches} batches of {per_batch}, order rotating, after one warm-up each; milliseconds");
    println!("  {:<10} {:>9} {:>9} {:>9} {:>9} {:>9} {:>10}", "hash", "bytes", "p min", "p q1", "p median", "p q3", "v median");
    for (k, name, bytes) in [(0, "Poseidon2", pbytes), (1, "Keccak", kbytes)] {
        let p = med(&prove_ms[k]);
        let v = med(&verify_ms[k]);
        println!("  {:<10} {:>9} {:>9.1} {:>9.1} {:>9.1} {:>9.1} {:>10.2}",
                 name, bytes, p[0], at(&p, 0.25), at(&p, 0.5), at(&p, 0.75), at(&v, 0.5));
    }
    for (k, name) in [(0, "Poseidon2"), (1, "Keccak")] {
        let b: Vec<String> = batch_med[k].iter().map(|x| format!("{x:.0}")).collect();
        println!("  {name} per-batch prove medians: {}", b.join(" "));
    }
}
