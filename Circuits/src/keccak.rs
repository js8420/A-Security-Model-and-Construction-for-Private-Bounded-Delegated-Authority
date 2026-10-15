//! Exports of the deployed proof, whose commitments and transcript are Keccak,
//! for the zkVM verifiers, and the comparison with the Poseidon2 commitments
//! the crate was first built with: the same AIR, trace, hiding PCS, queries,
//! blowup and grinding, only the hash differs.

use std::time::Instant;

use p3_field::PrimeField64;
use p3_uni_stark::{prove, verify, Proof};

use crate::naysay::Air;
use crate::prover::{config, p2_config, Config as KConfig, ROWS};
use crate::trace::composed_case;

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
    write_statement(&pv);
    (bytes.len(), ok, secs)
}

/// Where the reserve's tests read the exported payment's statement: what a
/// settlement of it pays, to whom, when, and the shares it publishes.
pub const STATEMENT_SOL: &str = "../SourceCode/Reserve/test/Statement.sol";

/// The exported payment's statement as Solidity constants, so a test can
/// settle exactly what the proof proves and nothing else.
fn write_statement(pv: &[p3_goldilocks::Goldilocks]) {
    use crate::composed::{PV_AMOUNT, PV_BASE, PV_ELEMS, PV_RANGE, PV_SECRET_HASH, PV_TIME, PV_UNIT};
    use crate::trace::PAYEE;
    let v: Vec<u64> = pv.iter().map(|x| x.as_canonical_u64()).collect();
    let addr: String = PAYEE.iter().map(|b| format!("{b:02x}")).collect();
    let hash: String = crate::statement::elems_hash(&v[PV_ELEMS..]).iter().map(|b| format!("{b:02x}")).collect();
    let mut s = String::new();
    s.push_str("// SPDX-License-Identifier: MIT\npragma solidity ^0.8.28;\n\n");
    s.push_str("/// The statement of the payment proof `delegation-circuit export-keccak` wrote.\n");
    s.push_str("/// Generated with the proof; do not edit.\nlibrary Statement {\n");
    s.push_str(&format!("    uint64 internal constant DIGEST = {};\n", v[0]));
    s.push_str(&format!("    uint64 internal constant AMOUNT = {};\n", v[PV_AMOUNT]));
    s.push_str(&format!("    address internal constant PAYEE = address(uint160(0x00{addr}));\n"));
    s.push_str(&format!("    uint64 internal constant TIME = {};\n", v[PV_TIME]));
    s.push_str(&format!("    uint64 internal constant UNIT = {};\n", v[PV_UNIT]));
    s.push_str(&format!("    uint64 internal constant RANGE_BASE = {};\n", v[PV_BASE]));
    s.push_str(&format!("    uint64 internal constant RANGE_LEN = {};\n", v[PV_RANGE]));
    let lanes: String = (0..4).rev().map(|j| format!("{:016x}", v[PV_SECRET_HASH + j])).collect();
    s.push_str("    /// H(s), four lanes packed low lane first, as the reserve stores it.\n");
    s.push_str(&format!("    bytes32 internal constant SECRET_HASH = 0x{lanes};\n"));
    let sec = crate::spend_trace::SECRET;
    s.push_str(&format!("    uint64 internal constant SECRET0 = {};\n", sec[0]));
    s.push_str(&format!("    uint64 internal constant SECRET1 = {};\n", sec[1]));
    s.push_str(&format!("    bytes32 internal constant ELEMS_HASH = 0x{hash};\n\n"));
    let c = crate::statement::committed(&v);
    s.push_str("    /// What the dispute program commits for this payment, as the guest computes it.\n");
    s.push_str("    function committed() internal pure returns (uint64[] memory c) {\n");
    s.push_str(&format!("        c = new uint64[]({});\n", c.len()));
    for (i, x) in c.iter().enumerate() {
        s.push_str(&format!("        c[{i}] = {x};\n"));
    }
    s.push_str("    }\n\n");
    s.push_str("    function elems() internal pure returns (uint64[] memory e) {\n");
    s.push_str(&format!("        e = new uint64[]({});\n", v.len() - PV_ELEMS));
    for (i, x) in v[PV_ELEMS..].iter().enumerate() {
        s.push_str(&format!("        e[{i}] = {x};\n"));
    }
    s.push_str("    }\n}\n");
    std::fs::write(STATEMENT_SOL, s).expect("write Statement.sol");
}

/// Proving and verifying one payment under each hash, timed in batches whose
/// order rotates, as the cost table is. Milliseconds.
pub fn hash_cost(batches: usize, per_batch: usize) {
    let air = Air::new();
    let (t, pv) = composed_case::<{ crate::prover::REGISTERS }, 16, 32, 16, 64>(ROWS, None);
    let pcfg = p2_config();
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

/// `n` fresh proofs of the same payment, each serialised as `export` writes
/// one, gathered into one file for the batch verifier.
pub fn export_batch(path: &str, n: usize) -> (usize, bool) {
    let air = Air::new();
    let (t, pv) = composed_case::<{ crate::prover::REGISTERS }, 16, 32, 16, 64>(ROWS, None);
    let mut all: Vec<Vec<u8>> = Vec::with_capacity(n);
    let mut ok = true;
    for _ in 0..n {
        let proof: Proof<KConfig> = prove(&config(), &air, t.clone(), &pv);
        ok &= verify(&config(), &air, &proof, &pv).is_ok();
        all.push(bincode::serialize(&(&proof, &pv)).expect("serialise"));
    }
    let bytes = bincode::serialize(&all).expect("serialise");
    std::fs::write(path, &bytes).expect("write batch");
    write_statement(&pv);
    (bytes.len(), ok)
}
