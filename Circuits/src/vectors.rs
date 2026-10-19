//! Known-answer vectors from Plonky3 itself for the independent verifier's
//! own tests: the Keccak sponge and compression of the commitments, the
//! Goldilocks field and its quadratic extension, the two-adic generators, and
//! the transcript's observe, sample, bit-sample and grinding steps.

use p3_challenger::{CanObserve, CanSample, CanSampleBits, FieldChallenger, GrindingChallenger};
use p3_field::{BasedVectorSpace, Field, PrimeCharacteristicRing, PrimeField64, TwoAdicField};
use p3_keccak::KeccakF;
use p3_symmetric::{CryptographicHasher, PseudoCompressionFunction};

use crate::prover::{challenger, Challenge, KCompress, KU64Hash, Val};

/// A fixed stream of 64-bit words, not all canonical field elements.
fn words(seed: u64, n: usize) -> Vec<u64> {
    let mut x = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add(1);
    (0..n)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        })
        .collect()
}

fn val(w: u64) -> Val {
    Val::from_u64(w % Val::ORDER_U64)
}

fn ext(a: u64, b: u64) -> Challenge {
    Challenge::from_basis_coefficients_slice(&[val(a), val(b)]).expect("two coefficients")
}

fn coeffs(e: Challenge) -> String {
    let c: &[Val] = e.as_basis_coefficients_slice();
    format!("[\"{}\",\"{}\"]", c[0].as_canonical_u64(), c[1].as_canonical_u64())
}

fn list(xs: &[u64]) -> String {
    format!("[{}]", xs.iter().map(|x| format!("\"{x}\"")).collect::<Vec<_>>().join(","))
}

/// Writes the vectors as JSON to `path`, every number as a decimal string.
pub fn export(path: &str) {
    let h = KU64Hash::new(KeccakF {});
    let c = KCompress::new(h);
    let mut out = Vec::new();

    let sponge: Vec<String> = (0..=52)
        .map(|n| {
            let input = words(n as u64, n);
            format!("{{\"input\":{},\"output\":{}}}", list(&input), list(&h.hash_iter(input.iter().copied())))
        })
        .collect();
    out.push(format!("\"sponge\":[{}]", sponge.join(",")));

    let compress: Vec<String> = (0..8)
        .map(|k| {
            let w = words(1000 + k, 8);
            let l = [w[0], w[1], w[2], w[3]];
            let r = [w[4], w[5], w[6], w[7]];
            format!("{{\"left\":{},\"right\":{},\"output\":{}}}", list(&l), list(&r), list(&c.compress([l, r])))
        })
        .collect();
    out.push(format!("\"compress\":[{}]", compress.join(",")));

    let mut field = Vec::new();
    for k in 0..24u64 {
        let w = words(2000 + k, 4);
        let (a, b) = if k == 0 { (Val::ORDER_U64 - 1, Val::ORDER_U64 - 2) } else { (w[0] % Val::ORDER_U64, w[1] % Val::ORDER_U64) };
        let (x, y) = (val(a), val(b));
        let (ea, eb) = (ext(a, w[2]), ext(b, w[3]));
        field.push(format!(
            "{{\"a\":\"{}\",\"b\":\"{}\",\"add\":\"{}\",\"sub\":\"{}\",\"mul\":\"{}\",\"inv\":\"{}\",\"ea\":{},\"eb\":{},\"emul\":{},\"einv\":{},\"epow\":{}}}",
            x.as_canonical_u64(), y.as_canonical_u64(),
            (x + y).as_canonical_u64(), (x - y).as_canonical_u64(), (x * y).as_canonical_u64(),
            x.inverse().as_canonical_u64(),
            coeffs(ea), coeffs(eb), coeffs(ea * eb), coeffs(ea.inverse()), coeffs(ea.exp_u64(b)),
        ));
    }
    out.push(format!("\"field\":[{}]", field.join(",")));

    let gens: Vec<u64> = (0..=32).map(|bits| Val::two_adic_generator(bits).as_canonical_u64()).collect();
    out.push(format!("\"twoAdic\":{}", list(&gens)));

    let mut t = challenger();
    let mut steps = Vec::new();
    for (i, w) in words(3000, 6).into_iter().enumerate() {
        t.observe(val(w));
        steps.push(format!("{{\"op\":\"observe\",\"value\":\"{}\"}}", val(w).as_canonical_u64()));
        if i % 2 == 1 {
            let s: Val = t.sample();
            steps.push(format!("{{\"op\":\"sample\",\"value\":\"{}\"}}", s.as_canonical_u64()));
        }
    }
    let e: Challenge = t.sample_algebra_element();
    steps.push(format!("{{\"op\":\"sampleExt\",\"value\":{}}}", coeffs(e)));
    t.observe_algebra_element(ext(5, 6));
    steps.push("{\"op\":\"observeExt\",\"value\":[\"5\",\"6\"]}".to_string());
    for bits in [1usize, 7, 20, 32] {
        let b = t.sample_bits(bits);
        steps.push(format!("{{\"op\":\"sampleBits\",\"bits\":{bits},\"value\":\"{b}\"}}"));
    }
    for _ in 0..40 {
        let s: Val = t.sample();
        steps.push(format!("{{\"op\":\"sample\",\"value\":\"{}\"}}", s.as_canonical_u64()));
    }
    let mut g = t.clone();
    let witness = g.grind(12);
    let mut ok = t.clone();
    assert!(ok.check_witness(12, witness));
    steps.push(format!("{{\"op\":\"witness\",\"bits\":12,\"value\":\"{}\",\"holds\":true}}", witness.as_canonical_u64()));
    let wrong = witness + Val::ONE;
    let mut bad = t.clone();
    let holds = bad.check_witness(12, wrong);
    steps.push(format!("{{\"op\":\"witnessAlone\",\"bits\":12,\"value\":\"{}\",\"holds\":{holds}}}", wrong.as_canonical_u64()));
    let after: Val = ok.sample();
    steps.push(format!("{{\"op\":\"sampleAfterWitness\",\"value\":\"{}\"}}", after.as_canonical_u64()));
    out.push(format!("\"transcript\":[{}]", steps.join(",")));

    std::fs::write(path, format!("{{{}}}\n", out.join(","))).expect("write vectors");
}
