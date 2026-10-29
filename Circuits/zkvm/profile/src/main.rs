//! Where the dispute verifier's instructions go. Runs the guest once under
//! SP1's own profiler, one sample every SAMPLE instructions, then reads the
//! profile back and charges each sample to the functions on its call stack.
//!
//!   dispute-verifier-profile <guest elf> <proof file> <profile.json>
//!
//! Inclusive counts: a sample counts once for every distinct function on its
//! stack. Phases: a sample goes to the first phase, in the order listed,
//! whose marker appears anywhere on its stack.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use serde_json::Value;
use sp1_core_executor::{MinimalExecutorEnum, Program};

/// The clock advances eight per ordinary instruction, so this samples about
/// every thousandth instruction.
const SAMPLE: u64 = 8 * 1000;

const PHASES: [(&str, &[&str]); 9] = [
    ("reading the proof (bincode)", &["bincode", "serde::de"]),
    ("symbolic constraint analysis", &["SymbolicAirBuilder", "get_max_constraint_degree", "get_symbolic_constraints"]),
    ("Merkle path checks", &["verify_batch"]),
    ("transcript (duplex challenger)", &["DuplexChallenger"]),
    ("constraint evaluation at zeta", &["VerifierConstraintFolder"]),
    ("FRI folding and openings", &["p3_fri"]),
    ("quotient recomposition", &["batch_multiplicative_inverse", "interpolate", "selectors_at_point"]),
    ("other verifier work", &["p3_uni_stark"]),
    ("guest main, outside the verifier", &["dispute_verifier::main"]),
];

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let elf = std::fs::read(args.get(1).expect("guest elf")).expect("guest elf");
    let input = args.get(2).expect("proof file");
    let out = args.get(3).expect("profile json");
    let bytes = std::fs::read(input).expect("exported proof");

    std::env::set_var("TRACE_FILE", out);
    std::env::set_var("TRACE_SAMPLE_RATE", SAMPLE.to_string());
    let program = Arc::new(Program::from(&elf).expect("elf"));
    let mut ex = MinimalExecutorEnum::new(program, false, None);
    // The guest reads how many proofs follow, a bincode u32, then each proof.
    ex.with_input(&1u32.to_le_bytes());
    ex.with_input(&bytes);
    while ex.execute_chunk().is_some() {}
    let instructions = ex.global_clk();
    let verified = ex.exit_code() == 0;

    let profile: Value = serde_json::from_reader(std::io::BufReader::new(std::fs::File::open(out).expect("profile")))
        .expect("profile json");
    let thread = &profile["threads"][0];
    let strings: Vec<String> = thread["stringTable"].as_array().expect("strings").iter()
        .map(|s| s.as_str().unwrap_or("").to_string()).collect();
    let col = |table: &Value, name: &str| table["schema"][name].as_u64().expect("schema") as usize;
    let frames = &thread["frameTable"];
    let fl = col(frames, "location");
    let frame_name: Vec<usize> = frames["data"].as_array().expect("frames").iter()
        .map(|r| r[fl].as_u64().expect("location") as usize).collect();
    let stacks = &thread["stackTable"];
    let (sp, sf) = (col(stacks, "prefix"), col(stacks, "frame"));
    let stack_rows: Vec<(Option<usize>, usize)> = stacks["data"].as_array().expect("stacks").iter()
        .map(|r| (r[sp].as_u64().map(|x| x as usize), r[sf].as_u64().expect("frame") as usize)).collect();
    let samples = &thread["samples"];
    let ss = col(samples, "stack");
    let sample_stacks: Vec<usize> = samples["data"].as_array().expect("samples").iter()
        .filter_map(|r| r[ss].as_u64().map(|x| x as usize)).collect();

    let names_of = |mut s: usize| {
        let mut v = Vec::new();
        loop {
            let (prefix, f) = stack_rows[s];
            v.push(strings[frame_name[f]].as_str());
            match prefix { Some(p) => s = p, None => break }
        }
        v
    };

    let total = sample_stacks.len() as f64;
    let mut inclusive: HashMap<String, u64> = HashMap::new();
    let mut leaf: HashMap<String, u64> = HashMap::new();
    let mut phase = vec![0u64; PHASES.len() + 1];
    for &s in &sample_stacks {
        let names = names_of(s);
        let mut seen = HashSet::new();
        for n in &names {
            let short = shorten(n);
            if seen.insert(short.clone()) { *inclusive.entry(short).or_default() += 1; }
        }
        *leaf.entry(shorten(names[0])).or_default() += 1;
        let p = PHASES.iter().position(|(_, marks)| names.iter().any(|n| marks.iter().any(|m| n.contains(m))))
            .unwrap_or(PHASES.len());
        phase[p] += 1;
    }

    println!("WHERE THE DISPUTE VERIFIER'S INSTRUCTIONS GO");
    println!("{}", "=".repeat(78));
    println!("  instructions executed                        {:>14}", instructions);
    println!("  the proof verifies                           {:>14}", verified);
    println!("  samples, one per {} instructions            {:>14}", SAMPLE / 8, sample_stacks.len());
    println!();
    println!("  phase                                      share   instructions");
    for (i, (name, _)) in PHASES.iter().enumerate() {
        println!("  {:<40} {:>6.2}%  {:>13.0}", name, 100.0 * phase[i] as f64 / total, phase[i] as f64 / total * instructions as f64);
    }
    println!("  {:<40} {:>6.2}%  {:>13.0}", "unattributed", 100.0 * phase[PHASES.len()] as f64 / total,
             phase[PHASES.len()] as f64 / total * instructions as f64);
    for (title, map) in [("functions by inclusive share", &inclusive), ("functions by self share", &leaf)] {
        println!();
        println!("  {}", title);
        let mut v: Vec<_> = map.iter().collect();
        v.sort_by(|a, b| b.1.cmp(a.1));
        for (n, c) in v.into_iter().take(25) {
            println!("  {:>6.2}%  {}", 100.0 * *c as f64 / total, n);
        }
    }
}

/// Generic parameters make the names unreadable; keep the path and drop them.
fn shorten(name: &str) -> String {
    let mut out = String::new();
    let mut depth = 0;
    for c in name.chars() {
        match c {
            '<' => { depth += 1; if depth == 1 { out.push_str("<..>"); } }
            '>' => depth -= 1,
            _ if depth == 0 => out.push(c),
            _ => {}
        }
    }
    out
}
