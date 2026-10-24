//! Runs the dispute verifier inside the zkVM on a batch proof the circuit
//! crate exported, and reports what proving it would take. Execution only;
//! nothing is proved.
//!
//!   dispute-verifier-script <proof file>
//!
//! Three passes. The light prover runs the guest and returns its public
//! values, the 32-byte root of the batch's statements, which shows the proof
//! verifies inside the zkVM. The minimal executor counts the instructions.
//! The prover gas the Succinct network bills by is metered as the SDK meters
//! it, chunk by chunk through SP1's gas VM at the SDK's own chunk size, but one
//! chunk at a time, so it fits in a few gigabytes. A tampered proof must make
//! the guest fail.

use std::sync::Arc;

use sp1_core_executor::{ExecutionReport, GasEstimatingVMEnum, MinimalExecutorEnum, Program, SP1CoreOpts};
use sp1_sdk::blocking::{LightProver, Prover};
use sp1_sdk::{include_elf, Elf, SP1Stdin};

const ELF: Elf = include_elf!("dispute-verifier-keccak");

/// An answer commits one Keccak root, whatever the batch size.
const COMMITTED_BYTES: usize = 32;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("verdicts") {
        verdicts(&args[2..]);
        return;
    }
    let path = args.get(1).cloned().unwrap_or_else(|| "../../target/proof_keccak.bin".into());
    let proof = std::fs::read(&path).expect("exported proof");
    let input = |p: &[u8]| {
        let mut s = SP1Stdin::new();
        s.write_vec(p.to_vec());
        s
    };

    let t = std::time::Instant::now();
    let (out, _) = LightProver::new().execute(ELF.clone(), input(&proof)).run().expect("the guest runs to completion");
    let light_secs = t.elapsed().as_secs_f64();
    let root = out.as_slice().to_vec();

    let program = Arc::new(Program::from(&ELF).expect("elf"));
    let buffers = input(&proof).buffer;
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

    // One byte of the last public value changed: the transcript differs, the
    // proof no longer verifies, and the guest must not finish cleanly.
    let mut bad = proof.clone();
    let last = bad.len() - 1;
    bad[last] ^= 1;
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

    println!("DISPUTE BY VALIDITY PROOF: THE VERIFIER INSIDE SP1, KECCAK COMMITMENTS");
    println!("{}", "=".repeat(78));
    println!("  proof bytes read                             {:>14}", proof.len());
    println!("  the proof verifies inside the zkVM           {:>14}", ex.exit_code() == 0 && root.len() == COMMITTED_BYTES);
    println!("  committed root                               0x{}", root.iter().map(|b| format!("{b:02x}")).collect::<String>());
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

/// The guest's verdict on each proof file named, one line each, for comparison
/// with the native verifier's on the same files.
fn verdicts(paths: &[String]) {
    let program = Arc::new(Program::from(&ELF).expect("elf"));
    for path in paths {
        let proof = std::fs::read(path).expect("proof file");
        let mut s = SP1Stdin::new();
        s.write_vec(proof);
        let mut ex = MinimalExecutorEnum::new(program.clone(), false, None);
        for b in &s.buffer {
            ex.with_input(b);
        }
        let accepted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            while ex.execute_chunk().is_some() {}
            ex.exit_code()
        }))
        .map(|code| code == 0)
        .unwrap_or(false);
        println!("{} {path}", if accepted { "accept" } else { "refuse" });
    }
}
