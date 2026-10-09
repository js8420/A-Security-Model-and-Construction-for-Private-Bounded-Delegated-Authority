//! One real Groth16 proof that the dispute verifier accepts a settlement's
//! STARK, made on the CPU, checked, and written out for the on-chain test.
//!
//!   prove fetch                  download the Groth16 circuit files (needs internet)
//!   prove <proof file> <out dir> prove, verify, and write the results
//!
//! The out directory receives proof_groth16.bin (the SDK's own format),
//! and onchain.txt: the program's verifying key hash, the public values and
//! the proof bytes, all hex, as the Solidity verifier takes them, with the
//! time each stage took.

use std::io::Write;
use std::time::Instant;

use sp1_sdk::blocking::{CpuProver, ProveRequest, Prover};
use sp1_sdk::{include_elf, Elf, HashableKey, ProvingKey, SP1Stdin};

const ELF: Elf = include_elf!("dispute-verifier");

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("fetch") {
        let rt = tokio_runtime();
        let dir = rt.block_on(sp1_sdk::install::try_install_circuit_artifacts("groth16")).expect("groth16 artifacts");
        println!("groth16 circuit files at {}", dir.display());
        return;
    }
    let input = args.get(1).expect("proof file");
    let out = std::path::PathBuf::from(args.get(2).expect("out directory"));
    std::fs::create_dir_all(&out).expect("out directory");
    let bytes = std::fs::read(input).expect("exported proof");
    let mut stdin = SP1Stdin::new();
    stdin.write_vec(bytes.clone());

    let t = Instant::now();
    let prover = CpuProver::new();
    let pk = prover.setup(ELF).expect("setup");
    let setup_secs = t.elapsed().as_secs_f64();
    println!("setup, seconds                              {:>12.1}", setup_secs);

    let t = Instant::now();
    let proof = prover.prove(&pk, stdin).groth16().run().expect("groth16 proof");
    let prove_secs = t.elapsed().as_secs_f64();
    println!("groth16 proof, seconds                      {:>12.1}", prove_secs);

    let vk = pk.verifying_key();
    let ok = prover.verify(&proof, vk, None).is_ok();
    println!("the groth16 proof verifies                  {:>12}", ok);
    proof.save(out.join("proof_groth16.bin")).expect("save proof");

    let onchain = proof.bytes();
    let pv = proof.public_values.to_vec();
    let mut f = std::fs::File::create(out.join("onchain.txt")).expect("onchain.txt");
    writeln!(f, "vkey {}", vk.bytes32()).ok();
    writeln!(f, "public_values 0x{}", hex(&pv)).ok();
    writeln!(f, "proof 0x{}", hex(&onchain)).ok();
    writeln!(f, "stark_bytes {}", bytes.len()).ok();
    writeln!(f, "setup_seconds {setup_secs:.1}").ok();
    writeln!(f, "prove_seconds {prove_secs:.1}").ok();
    writeln!(f, "verifies {ok}").ok();
    println!("program verifying key                       {}", vk.bytes32());
    println!("public value bytes                          {:>12}", pv.len());
    println!("on-chain proof bytes                        {:>12}", onchain.len());
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn tokio_runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread().enable_all().build().expect("runtime")
}
