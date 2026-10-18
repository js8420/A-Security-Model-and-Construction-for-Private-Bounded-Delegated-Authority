//! Exports of the deployed proof, whose commitments and transcript are Keccak,
//! for the zkVM verifiers, and the comparison with the Poseidon2 commitments
//! the crate was first built with: the same AIR, trace, hiding PCS, queries,
//! blowup and grinding, only the hash differs.

use std::time::Instant;

use p3_field::PrimeField64;
use p3_uni_stark::{prove, verify, Proof};

use crate::naysay::Air;
use crate::prover::{config, p2_config, Config as KConfig, ROWS};
use crate::trace::{composed_batch, composed_case};

/// One 128-row proof of a batch of k payments under the Keccak configuration,
/// for the zkVM verifier built against the same configuration. Returns the
/// bytes written, whether it verifies natively, and the seconds proving took.
pub fn export(path: &str, k: usize) -> (usize, bool, f64) {
    let (t, pv) = composed_batch::<{ crate::prover::REGISTERS }, 16, 32, 16, 64>(ROWS, k, None);
    let air = Air::from_public_values(&pv);
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

/// Proofs of statements with no valid witness, made by running the prover on
/// traces that break one constraint each, so that the transcript, every
/// commitment and the grinding are honest and only the constraint fails.
/// Each file goes to `dir`; returns each break's name and whether the
/// deployed verifier accepts it.
pub fn export_broken(dir: &str) -> Vec<(&'static str, bool)> {
    use crate::trace::ComposedBreak as B;
    let cases = [
        ("cap_above_budget", B::CapAboveBudget),
        ("run_start_mismatch", B::RunStartMismatch),
        ("root_key_free", B::RootKeyFree),
        ("amount_raised", B::AmountRaised),
        ("share_domain", B::ShareDomain),
    ];
    let cfg = config();
    cases
        .into_iter()
        .map(|(name, how)| {
            let (t, pv) = composed_case::<{ crate::prover::REGISTERS }, 16, 32, 16, 64>(ROWS, Some(how));
            let air = Air::from_public_values(&pv);
            let proof: Proof<KConfig> = prove(&cfg, &air, t, &pv);
            let ok = verify(&config(), &air, &proof, &pv).is_ok();
            let bytes = bincode::serialize(&(&proof, &pv)).expect("serialise");
            std::fs::write(format!("{dir}/broken_{name}.bin"), &bytes).expect("write proof");
            (name, ok)
        })
        .collect()
}

/// Verifies an exported file with the deployed verifier, as the monitor's
/// first check. Returns the milliseconds verification took, or why the file
/// was refused: unreadable, trailing bytes, or rejected.
pub fn verify_file(path: &str) -> Result<f64, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("unreadable: {e}"))?;
    let mut cursor = std::io::Cursor::new(&bytes[..]);
    let (proof, pv): (Proof<KConfig>, Vec<p3_goldilocks::Goldilocks>) =
        bincode::deserialize_from(&mut cursor).map_err(|e| format!("malformed: {e}"))?;
    if cursor.position() as usize != bytes.len() {
        return Err("malformed: trailing bytes".into());
    }
    let air = std::panic::catch_unwind(|| Air::from_public_values(&pv)).map_err(|_| "malformed: public values".to_string())?;
    let start = Instant::now();
    let r = verify(&config(), &air, &proof, &pv);
    let ms = start.elapsed().as_secs_f64() * 1000.0;
    r.map(|_| ms).map_err(|e| format!("rejected: {e:?}"))
}

/// Where the reserve's tests read the exported batch's statements: what each
/// settlement pays, to whom, when, the shares it publishes, its leaf and its
/// path to the root the answer commits.
pub const STATEMENT_SOL: &str = "../SourceCode/Reserve/test/Statement.sol";

fn hex64(vals: impl IntoIterator<Item = u64>) -> String {
    vals.into_iter().map(|v| format!("{v:016x}")).collect()
}

fn hex32(words: impl IntoIterator<Item = [u8; 32]>) -> String {
    words.into_iter().flat_map(|w| w.into_iter()).map(|b| format!("{b:02x}")).collect()
}

/// The exported batch's statements as Solidity constants, so a test can settle
/// exactly what the proof proves and nothing else. Lists are packed big-endian
/// in hex and read back by the accessors.
fn write_statement(pv: &[p3_goldilocks::Goldilocks]) {
    use crate::composed::{row_width, GLOBALS, G_BASE, G_RANGE, G_SECRET_HASH, G_UNIT, R_AMOUNT, R_DIGEST, R_TIME};
    use crate::statement::{committed, leaf, path, payments, published, COMMITTED};
    use crate::trace::batch_payments;
    const COVER: usize = 64;
    let v: Vec<u64> = pv.iter().map(|x| x.as_canonical_u64()).collect();
    let k = payments(&v, COVER);
    let depth = k.trailing_zeros() as usize;
    let rw = row_width(COVER);
    let field = |i: usize, off: usize| v[GLOBALS + i * rw + off];
    let pays = batch_payments(k);
    let mut starts = Vec::with_capacity(k + 1);
    let mut flat = Vec::new();
    for i in 0..k {
        starts.push(flat.len() as u64);
        flat.extend(published(&v, COVER, i));
    }
    starts.push(flat.len() as u64);
    let payees: String = pays.iter().flat_map(|(_, a)| a.iter()).map(|b| format!("{b:02x}")).collect();
    let mut s = String::new();
    s.push_str("// SPDX-License-Identifier: MIT\npragma solidity ^0.8.28;\n\n");
    s.push_str("/// The statements of the batch proof `delegation-circuit export-keccak` wrote.\n");
    s.push_str("/// Generated with the proof; do not edit.\nlibrary Statement {\n");
    s.push_str(&format!("    uint256 internal constant PAYMENTS = {k};\n"));
    s.push_str(&format!("    uint256 internal constant DEPTH = {depth};\n"));
    s.push_str(&format!("    uint256 internal constant LEAF = {COMMITTED};\n"));
    s.push_str(&format!("    uint64 internal constant UNIT = {};\n", v[G_UNIT]));
    s.push_str(&format!("    uint64 internal constant RANGE_BASE = {};\n", v[G_BASE]));
    s.push_str(&format!("    uint64 internal constant RANGE_LEN = {};\n", v[G_RANGE]));
    let lanes: String = (0..4).rev().map(|j| format!("{:016x}", v[G_SECRET_HASH + j])).collect();
    s.push_str("    /// H(s), four lanes packed low lane first, as the reserve stores it.\n");
    s.push_str(&format!("    bytes32 internal constant SECRET_HASH = 0x{lanes};\n"));
    let sec = crate::spend_trace::SECRET;
    s.push_str(&format!("    uint64 internal constant SECRET0 = {};\n", sec[0]));
    s.push_str(&format!("    uint64 internal constant SECRET1 = {};\n", sec[1]));
    s.push_str(&format!("    bytes32 internal constant ROOT = 0x{};\n\n", hex32([committed(&v, COVER)])));
    s.push_str(&format!("    bytes internal constant DIGESTS = hex\"{}\";\n", hex64((0..k).map(|i| field(i, R_DIGEST)))));
    s.push_str(&format!("    bytes internal constant AMOUNTS = hex\"{}\";\n", hex64((0..k).map(|i| field(i, R_AMOUNT)))));
    s.push_str(&format!("    bytes internal constant TIMES = hex\"{}\";\n", hex64((0..k).map(|i| field(i, R_TIME)))));
    s.push_str(&format!("    bytes internal constant PAYEES = hex\"{payees}\";\n"));
    s.push_str(&format!("    bytes internal constant STARTS = hex\"{}\";\n", hex64(starts)));
    s.push_str(&format!("    bytes internal constant ELEMS = hex\"{}\";\n", hex64(flat)));
    s.push_str(&format!("    bytes internal constant LEAVES = hex\"{}\";\n", hex64((0..k).flat_map(|i| leaf(&v, COVER, i)))));
    s.push_str(&format!("    bytes internal constant PATHS = hex\"{}\";\n\n", hex32((0..k).flat_map(|i| path(&v, COVER, i)))));
    s.push_str(r#"    /// Every list at once. Each read of a constant copies it whole, so a
    /// caller reading many payments loads once and reads from the copy.
    struct Data {
        bytes digests;
        bytes amounts;
        bytes times;
        bytes payees;
        bytes starts;
        bytes elems;
        bytes leaves;
        bytes paths;
    }

    function load() internal pure returns (Data memory d) {
        d = Data(DIGESTS, AMOUNTS, TIMES, PAYEES, STARTS, ELEMS, LEAVES, PATHS);
    }

    function _u64(bytes memory b, uint256 i) private pure returns (uint64 x) {
        assembly {
            x := shr(192, mload(add(add(b, 32), mul(i, 8))))
        }
    }

    function digest(Data memory d, uint256 i) internal pure returns (uint64) {
        return _u64(d.digests, i);
    }

    function amount(Data memory d, uint256 i) internal pure returns (uint64) {
        return _u64(d.amounts, i);
    }

    function time(Data memory d, uint256 i) internal pure returns (uint64) {
        return _u64(d.times, i);
    }

    function payee(Data memory d, uint256 i) internal pure returns (address a) {
        bytes memory b = d.payees;
        assembly {
            a := shr(96, mload(add(add(b, 32), mul(i, 20))))
        }
    }

    /// The shares and nullifiers payment i publishes: its first n slots.
    function elems(Data memory d, uint256 i) internal pure returns (uint64[] memory e) {
        uint256 a = _u64(d.starts, i);
        uint256 z = _u64(d.starts, i + 1);
        e = new uint64[](z - a);
        for (uint256 j = 0; j < z - a; j++) {
            e[j] = _u64(d.elems, a + j);
        }
    }

    /// Payment i's leaf, as the guest computes it.
    function leaf(Data memory d, uint256 i) internal pure returns (uint64[] memory c) {
        c = new uint64[](LEAF);
        for (uint256 j = 0; j < LEAF; j++) {
            c[j] = _u64(d.leaves, i * LEAF + j);
        }
    }

    /// The siblings from payment i's leaf to ROOT, lowest first.
    function path(Data memory d, uint256 i) internal pure returns (bytes32[] memory p) {
        bytes memory all = d.paths;
        p = new bytes32[](DEPTH);
        for (uint256 j = 0; j < DEPTH; j++) {
            bytes32 w;
            uint256 at = 32 + (i * DEPTH + j) * 32;
            assembly {
                w := mload(add(all, at))
            }
            p[j] = w;
        }
    }
}
"#);
    std::fs::write(STATEMENT_SOL, s).expect("write Statement.sol");
}

/// Proving and verifying one payment under each hash, timed in batches whose
/// order rotates, as the cost table is. Milliseconds.
pub fn hash_cost(batches: usize, per_batch: usize) {
    let (t, pv) = composed_case::<{ crate::prover::REGISTERS }, 16, 32, 16, 64>(ROWS, None);
    let air = Air::from_public_values(&pv);
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
