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

const ELF: Elf = include_elf!("dispute-verifier");

fn main() {
    let path = std::env::args().nth(1).unwrap_or_else(|| "../../target/proof_128.bin".into());
    let bytes = std::fs::read(&path).expect("exported proof");
    let stdin = || {
        let mut s = SP1Stdin::new();
        s.write_vec(bytes.clone());
        s
    };

    let t = std::time::Instant::now();
    let (out, _) = LightProver::new().execute(ELF, stdin()).run().expect("the guest runs to completion");
    let light_secs = t.elapsed().as_secs_f64();
    let pv = values(out.as_slice());

    let program = Arc::new(Program::from(&ELF).expect("elf"));
    let mut ex = MinimalExecutorEnum::new(program.clone(), false, None);
    ex.with_input(&bytes);
    let t = std::time::Instant::now();
    while ex.execute_chunk().is_some() {}
    let count_secs = t.elapsed().as_secs_f64();

    let opts = SP1CoreOpts::default();
    let mut metered = MinimalExecutorEnum::new(program.clone(), false, Some(opts.gas_trace_chunk_threshold));
    metered.with_input(&bytes);
    let mut report = ExecutionReport::default();
    let mut chunks = 0;
    let t = std::time::Instant::now();
    while let Some(chunk) = metered.execute_chunk() {
        let mut vm = GasEstimatingVMEnum::new(&chunk, program.clone(), [0; 4], opts.clone());
        report += vm.execute().expect("gas metering");
        chunks += 1;
    }
    let gas_secs = t.elapsed().as_secs_f64();

    // One byte of the last public value changed: the transcript differs, the
    // proof no longer verifies, and the guest must not finish cleanly.
    let mut bad = bytes.clone();
    let last = bad.len() - 1;
    bad[last] ^= 1;
    let mut tampered = MinimalExecutorEnum::new(program.clone(), false, None);
    tampered.with_input(&bad);
    let refused = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        while tampered.execute_chunk().is_some() {}
        tampered.exit_code()
    }))
    .map(|code| code != 0)
    .unwrap_or(true);

    println!("DISPUTE BY VALIDITY PROOF: THE VERIFIER INSIDE SP1");
    println!("{}", "=".repeat(78));
    println!("  proof bytes read                             {:>14}", bytes.len());
    println!("  the proof verifies inside the zkVM           {:>14}", ex.exit_code() == 0 && pv.len() == 10);
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
