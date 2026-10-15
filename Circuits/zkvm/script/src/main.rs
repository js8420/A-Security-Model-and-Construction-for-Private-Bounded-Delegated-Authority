//! Runs the dispute verifier inside the zkVM on a proof the circuit crate
//! exported, and reports what proving it would take. Execution only; nothing
//! is proved.
//!
//! Three passes. The light prover runs the guest and returns its public
//! values, which shows the proof verifies inside the zkVM. The minimal
//! executor counts the instructions. The prover gas the Succinct network
//! bills by is metered as the SDK meters it, chunk by chunk through SP1's gas
//! VM at the SDK's own chunk size, but one chunk at a time, so it fits in a
//! few gigabytes. A tampered proof must make the guest fail.

use std::sync::Arc;

use sp1_core_executor::{ExecutionReport, GasEstimatingVMEnum, MinimalExecutorEnum, Program, SP1CoreOpts};
use sp1_sdk::blocking::{LightProver, Prover};
use sp1_sdk::{include_elf, Elf, SP1Stdin};

const ELF_POSEIDON2: Elf = include_elf!("dispute-verifier");
const ELF_KECCAK: Elf = include_elf!("dispute-verifier-keccak");
const ELF_BATCH: Elf = include_elf!("dispute-verifier-batch");

/// Values each keccak or batch answer commits per settlement: twenty-two
/// statement values and the four words of the shares' hash. The Poseidon2
/// verifier still commits the public values whole.
const COMMITTED: usize = 26;

/// `<proof file>` for the Poseidon2 verifier, `<proof file> keccak`, or
/// `<batch file> batch <n>` for the batch verifier on the first n proofs.
fn main() {
    let args: Vec<String> = std::env::args().collect();
    let path = args.get(1).cloned().unwrap_or_else(|| "../../target/proof_128.bin".into());
    let mode = args.get(2).map(String::as_str).unwrap_or("poseidon2");
    let raw = std::fs::read(&path).expect("exported proof");
    let (elf, proofs, label) = match mode {
        "keccak" => (ELF_KECCAK, vec![raw], "KECCAK COMMITMENTS".to_string()),
        "batch" => {
            let n: usize = args.get(3).expect("batch size").parse().expect("batch size");
            let all: Vec<Vec<u8>> = bincode::deserialize(&raw).expect("batch file");
            assert!(n >= 1 && n <= all.len(), "the batch file holds {} proofs", all.len());
            (ELF_BATCH, all[..n].to_vec(), format!("BATCH OF {n}, KECCAK COMMITMENTS"))
        }
        _ => (ELF_POSEIDON2, vec![raw], "POSEIDON2 COMMITMENTS".to_string()),
    };
    let batch = mode == "batch";
    let n = proofs.len();
    let input = |ps: &[Vec<u8>]| {
        let mut s = SP1Stdin::new();
        if batch {
            s.write(&(ps.len() as u32));
        }
        for p in ps {
            s.write_vec(p.clone());
        }
        s
    };
    let stdin = || input(&proofs);

    let t = std::time::Instant::now();
    let (out, _) = LightProver::new().execute(elf.clone(), stdin()).run().expect("the guest runs to completion");
    let light_secs = t.elapsed().as_secs_f64();
    let pv = values(out.as_slice());

    let program = Arc::new(Program::from(&elf).expect("elf"));
    let buffers = stdin().buffer;
    let mut ex = MinimalExecutorEnum::new(program.clone(), false, None);
    for b in &buffers {
        ex.with_input(b);
    }
    let t = std::time::Instant::now();
    while ex.execute_chunk().is_some() {}
    let count_secs = t.elapsed().as_secs_f64();

    let opts = SP1CoreOpts::default();
    let mut metered = MinimalExecutorEnum::new(program.clone(), false, Some(opts.gas_trace_chunk_threshold));
    for b in &buffers {
        metered.with_input(b);
    }
    let mut report = ExecutionReport::default();
    let mut chunks = 0;
    let t = std::time::Instant::now();
    while let Some(chunk) = metered.execute_chunk() {
        let mut vm = GasEstimatingVMEnum::new(&chunk, program.clone(), [0; 4], opts.clone());
        report += vm.execute().expect("gas metering");
        chunks += 1;
    }
    let gas_secs = t.elapsed().as_secs_f64();

    // One byte of the last proof's last public value changed: the transcript
    // differs, that proof no longer verifies, and the guest must not finish
    // cleanly.
    let mut bad = proofs.clone();
    let last = bad[n - 1].len() - 1;
    bad[n - 1][last] ^= 1;
    let mut tampered = MinimalExecutorEnum::new(program.clone(), false, None);
    for b in &input(&bad).buffer {
        tampered.with_input(b);
    }
    let refused = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        while tampered.execute_chunk().is_some() {}
        tampered.exit_code()
    }))
    .map(|code| code != 0)
    .unwrap_or(true);

    println!("DISPUTE BY VALIDITY PROOF: THE VERIFIER INSIDE SP1, {label}");
    println!("{}", "=".repeat(78));
    println!("  proofs verified                              {:>14}", n);
    println!("  proof bytes read                             {:>14}", proofs.iter().map(Vec::len).sum::<usize>());
    println!("  every proof verifies inside the zkVM         {:>14}", ex.exit_code() == 0 && (mode == "poseidon2" || pv.len() == COMMITTED * n));
    println!("  public values committed                      {:>14}", pv.len());
    println!("  instructions executed                        {:>14}", ex.global_clk());
    println!("  light execution, seconds                     {:>14.1}", light_secs);
    println!("  counting execution, seconds                  {:>14.1}", count_secs);
    println!("  instructions, gas metering                   {:>14}", report.total_instruction_count());
    println!("  trace chunks metered                         {:>14}", chunks);
    println!("  prover gas                                   {:>14}", report.gas().unwrap_or(0));
    println!("  syscalls                                     {:>14}", report.total_syscall_count());
    println!("  gas metering, seconds                        {:>14.1}", gas_secs);
    println!("  a tampered proof is refused inside the zkVM  {:>14}", refused);
}

// The committed values are a bincode Vec<u64>: an 8-byte length, then the values.
fn values(b: &[u8]) -> Vec<u64> {
    let n = u64::from_le_bytes(b[..8].try_into().expect("length")) as usize;
    (0..n).map(|i| u64::from_le_bytes(b[8 + 8 * i..16 + 8 * i].try_into().expect("value"))).collect()
}
