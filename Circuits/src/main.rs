use p3_field::PrimeCharacteristicRing;

/// A verification line that also enforces itself. `want` is what the round trip
/// must return; a mismatch aborts the run rather than printing a value someone
/// has to notice. Positive cases must verify, controls must be rejected.
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

/// Every verdict, in order, so the manuscript's table can be emitted rather
/// than transcribed. Table X was maintained by hand and drifted three columns
/// short of the harness while its caption claimed a count that was wrong twice.
static VERDICTS: Mutex<Vec<(String, bool)>> = Mutex::new(Vec::new());

/// Counted rather than tallied by hand. The manuscript quotes how many controls
/// there are, and that number was wrong twice because it was maintained in
/// prose while the harness grew. A check whose expected verdict is false is a
/// control; one whose expected verdict is true is a positive.
static CONTROLS: AtomicUsize = AtomicUsize::new(0);
static POSITIVES: AtomicUsize = AtomicUsize::new(0);

/// A property of the proving system rather than of this construction. Asserted
/// like a control, but not counted as one and not tabulated: these two lines
/// were being reported among the paper's controls, which is how the count came
/// out four too high.
fn diagnostic(label: &str, got: bool, want: bool) {
    println!("  {:<44} {:>12}", label, got);
    assert_eq!(got, want, "COMMITMENT SCHEME INVARIANT BROKEN: {label}");
}

fn check(label: &str, got: bool, want: bool) {
    println!("  {:<44} {:>12}", label, got);
    if want { &POSITIVES } else { &CONTROLS }.fetch_add(1, Ordering::Relaxed);
    VERDICTS.lock().unwrap().push((label.to_string(), want));
    assert_eq!(got, want, "VERIFICATION INVARIANT BROKEN: {label}");
}


mod air;
mod hash;
mod full;
mod merkle;
mod revocation;
mod whole;
mod prover;
mod trace;
mod gen;
mod spend;
mod spend_trace;
mod composed;
mod vacuous;
mod spend2;

use air::{Clause, PolicyAir, ALL_CLAUSES, EVERY_CLAUSE, RANGE_BITS};
use p3_uni_stark::{get_max_constraint_degree, get_symbolic_constraints, AirLayout};
use p3_air::BaseAir;
use p3_goldilocks::Goldilocks;

type F = Goldilocks;

fn measure(clauses: &[Clause]) -> (usize, usize, usize) {
    let a = PolicyAir::new(clauses);
    let constraints =
        get_symbolic_constraints::<F, _>(&a, AirLayout::from_air::<F>(&a));
    let degree = get_max_constraint_degree::<F, _>(&a, AirLayout::from_air::<F>(&a));
    (BaseAir::<F>::width(&a), constraints.len(), degree)
}

const TIMING_BATCHES: usize = 10;
const TIMING_PER_BATCH: usize = 30;
const COST_BATCHES: usize = 5;
const COST_PER_BATCH: usize = 20;

/// The body of the manuscript's verification table, in the form it is pasted
/// in. A check whose label begins with an ellipsis is a row under the component
/// above it; anything else opens a group. Controls read yes, properties hold.
fn emit_verify_table() {
    println!("TABLE X BODY, GENERATED --- PASTE BETWEEN THE MIDRULES OF tab:verify");
    println!("{}", "=".repeat(78));
    let verdicts = VERDICTS.lock().unwrap();
    let mut group_open = false;
    for (label, want) in verdicts.iter() {
        let trimmed = label.trim();
        if let Some(rest) = trimmed.strip_prefix("... ") {
            // A row under the component above it.
            println!("                           & {:<34} & {} \\\\",
                     rest, if *want { "holds" } else { "yes" });
        } else if trimmed.contains(" rows") {
            // A component: its label names the trace height it was proved at.
            if group_open {
                println!("\\midrule");
            }
            group_open = true;
            let raw = trimmed.split(',').next().unwrap_or(trimmed);
            let name = match raw {
                "satisfying assignment" => "C1 and C5 policy clauses",
                "policy composed with C9" => "Policy clauses with C9",
                "merkle inclusion" => "Merkle inclusion",
                "non-revocation" => "C8 non-revocation",
                "spend component" => "Spend",
                "second-invocation nullifier" => "Spend, second invocation",
                "COMPOSED CIRCUIT" => "Composed circuit",
                "WHOLE CIRCUIT at full parameters" => "Whole circuit",
                other => other,
            };
            println!("{:<26} & {:<34} & {} \\\\",
                     name, "satisfying trace", if *want { "verifies" } else { "yes" });
        } else {
            // A standalone check: a property compared across two executions, or
            // a circuit that must reject a trace no component owns. It belongs
            // to the group it follows, so it opens nothing and closes nothing.
            // Emitting a rule here put each property in a group of its own.
            println!("{:<26} & {:<34} & {} \\\\",
                     "", trimmed, if *want { "holds" } else { "yes" });
        }
    }
}

fn main() {
    println!("COMMITMENT SCHEME AND VERIFICATION UNDER IT");
    println!("{}", "=".repeat(78));
    println!("  {:<44} {:>12}", "hiding PCS reported by the Pcs trait", prover::zk_enabled());
    println!("  {:<44} {:>12}", "salt elements per leaf", prover::SALT_ELEMS);
    println!("  {:<44} {:>12}", "random codewords per matrix", prover::NUM_RANDOM_CODEWORDS);
    let (deg7, deg3) = prover::zk_degree_bound();
    diagnostic("bare poseidon2, degree 7, zero registers", deg7, false);
    diagnostic("bare poseidon2, degree 3, one register", deg3, true);
    println!();
    println!("  Zero registers makes every S-box constraint degree 7 and no proof");
    println!("  verifies under the hiding PCS. One register makes them degree 3 and");
    println!("  every proof verifies. Both cases above are upstream code with an");
    println!("  upstream trace, so the bound belongs to p3-uni-stark 0.6.3. One");
    println!("  register is therefore the only admissible setting, and the widths");
    println!("  below are measured there.");
    println!();

    println!();
    println!("POLICY CIRCUIT COST, PLONKY3 0.6.3, GOLDILOCKS, {RANGE_BITS}-BIT RANGE CHECKS");
    println!("{}", "=".repeat(78));
    println!("  {:<26} {:>8} {:>14} {:>8}", "clause", "width", "constraints", "degree");
    println!("  {:<26} {:>8} {:>14} {:>8}", "-".repeat(26), "-".repeat(8), "-".repeat(14), "-".repeat(8));

    for c in EVERY_CLAUSE {
        if ALL_CLAUSES.contains(&c) {
            let (w, n, d) = measure(&[c]);
            println!("  {:<26} {:>8} {:>14} {:>8}", c.name(), w, n, d);
        } else {
            println!("  {:<26} {:>8} {:>14} {:>8}", c.name(), "--", "--", "--");
        }
    }

    let (w, n, d) = measure(&ALL_CLAUSES);
    println!("  {:<26} {:>8} {:>14} {:>8}", "-".repeat(26), "-".repeat(8), "-".repeat(14), "-".repeat(8));
    println!("  {:<26} {:>8} {:>14} {:>8}", "circuit clauses combined", w, n, d);
    println!();
    println!("  C2 and C6 are policy fields but not circuit clauses. A cumulative");
    println!("  total supplied by the prover is a value the prover chooses, so a");
    println!("  constraint over it binds nothing; the budget is enforced by the");
    println!("  tree, where exceeding it consumes a node twice. The rate limit is");
    println!("  public and is counted by the reserve, the only party that sees");
    println!("  every settlement.");

    println!();
    println!("ONE POSEIDON2 PERMUTATION, GOLDILOCKS, WIDTH {}, S-BOX DEGREE {}",
             hash::WIDTH, hash::SBOX_DEGREE);
    println!("{}", "=".repeat(78));
    println!("  {:<26} {:>8} {:>14} {:>8}", "sbox registers", "columns", "constraints", "degree");
    println!("  {:<26} {:>8} {:>14} {:>8}", "-".repeat(26), "-".repeat(8), "-".repeat(14), "-".repeat(8));
    // p3-poseidon2-air only accepts certain (SBOX_DEGREE, SBOX_REGISTERS)
    // pairs and panics on the rest; at degree 7 these two are what it takes.
    let rows = [
        (0usize, hash::measure::<0>()),
        (1, hash::measure::<1>()),
    ];
    for (r, (c, n, d)) in rows {
        println!("  {:<26} {:>8} {:>14} {:>8}", r, c, n, d);
    }

    println!();
    println!("POLICY CLAUSES PLUS C9 OPENING, {} PERMUTATIONS FOR {} ABSORBED ELEMENTS",
             full::C9_PERMUTATIONS, full::C9_ELEMENTS);
    println!("{}", "=".repeat(78));
    println!("  {:<26} {:>8} {:>14} {:>8}", "sbox registers", "width", "constraints", "degree");
    println!("  {:<26} {:>8} {:>14} {:>8}", "-".repeat(26), "-".repeat(8), "-".repeat(14), "-".repeat(8));
    for (r, (w, n, d)) in [(0usize, full::measure::<0>()), (1, full::measure::<1>())] {
        println!("  {:<26} {:>8} {:>14} {:>8}", r, w, n, d);
    }
    println!();
    println!("MERKLE INCLUSION (C3 OR C4), ONE PERMUTATION PER LEVEL");
    println!("{}", "=".repeat(78));
    println!("  {:<26} {:>8} {:>14} {:>8}", "depth / registers", "width", "constraints", "degree");
    println!("  {:<26} {:>8} {:>14} {:>8}", "-".repeat(26), "-".repeat(8), "-".repeat(14), "-".repeat(8));
    let mk = [
        ("4  / 1", merkle::measure::<1, 4>()),
        ("8  / 1", merkle::measure::<1, 8>()),
        ("16 / 1", merkle::measure::<1, 16>()),
        ("16 / 0 (not ZK-admissible)", merkle::measure::<0, 16>()),
    ];
    for (label, (w, n, d)) in mk {
        println!("  {:<26} {:>8} {:>14} {:>8}", label, w, n, d);
    }

    println!();
    println!("C8 NON-REVOCATION, PATH PLUS FOUR COMPARISONS AGAINST THE CONSUMED RUN");
    println!("{}", "=".repeat(78));
    println!("  {:<26} {:>8} {:>14} {:>8}", "depth / registers", "width", "constraints", "degree");
    println!("  {:<26} {:>8} {:>14} {:>8}", "-".repeat(26), "-".repeat(8), "-".repeat(14), "-".repeat(8));
    let rv = [
        ("20 / 1", revocation::measure::<1, 20>()),
        ("24 / 1", revocation::measure::<1, 24>()),
        ("32 / 1", revocation::measure::<1, 32>()),
        ("32 / 0 (not ZK-admissible)", revocation::measure::<0, 32>()),
    ];
    for (label, (w, n, d)) in rv {
        println!("  {:<26} {:>8} {:>14} {:>8}", label, w, n, d);
    }

    let (pw, pn, _) = measure(&ALL_CLAUSES);
    let (_, _, _) = (pw, pn, 0);
    let (fw, fn_, _) = full::measure::<1>();
    let (mw, mn, _) = merkle::measure::<1, 16>();
    let (rw, rn, _) = revocation::measure::<1, 32>();
    println!();
    println!("WHOLE CIRCUIT, DEPTH 16 ALLOWLISTS, DEPTH 32 REVOCATION, REGISTERS 1");
    println!("{}", "=".repeat(78));
    println!("  {:<30} {:>10} {:>14} {:>7}", "component", "columns", "constraints", "share");
    println!("  {:<30} {:>10} {:>14} {:>7}", "-".repeat(30), "-".repeat(10), "-".repeat(14), "-".repeat(7));
    let c7w = whole::WholeAir::<1, 16, 32>::new().payload_cols();
    let total_w = fw + c7w + 2 * mw + rw;
    let items = [
        ("policy clauses plus C9", fw, fn_),
        ("C3 merchant, depth 16", mw, mn),
        ("C4 category, depth 16", mw, mn),
        ("C8 revocation, depth 32", rw, rn),
    ];
    let mut tn = 0usize;
    for (name, w, n) in items {
        tn += n;
        println!("  {:<30} {:>10} {:>14} {:>6.0}%", name, w, n, 100.0 * w as f64 / total_w as f64);
    }
    println!("  {:<30} {:>10} {:>14} {:>6.0}%", "C7 payload sponge", c7w, "--",
             100.0 * c7w as f64 / total_w as f64);
    println!("  {:<30} {:>10} {:>14}", "-".repeat(30), "-".repeat(10), "-".repeat(14));
    println!("  {:<30} {:>10} {:>14}", "components", total_w, "--");
    println!();
    println!("  C7 has no standalone AIR, so its columns come from the layout and");
    println!("  its constraints are reported below with the glue rather than split");
    println!("  by a count kept in this file. Components without C7 sum to {} / {}.",
             fw + 2 * mw + rw, tn);
    println!();
    println!("  C7 is its own sponge over the six payload fields, in {} permutations.",
             whole::PAYLOAD_PERMUTATIONS);
    println!("  C9 absorbs {} policy elements and stops there, so the commitment is",
             whole::ABSORBED);
    println!("  the same for every payment under one policy.");

    println!();
    println!("WHOLE CIRCUIT AS ONE AIR, WITH CROSS-COMPONENT BINDINGS");
    println!("{}", "=".repeat(78));
    println!("  {:<30} {:>10} {:>14} {:>7}", "allowlist / revocation depth", "width", "constraints", "degree");
    println!("  {:<30} {:>10} {:>14} {:>7}", "-".repeat(30), "-".repeat(10), "-".repeat(14), "-".repeat(7));
    for (label, (w, n, d)) in [
        ("16 / 20, registers 1", whole::measure::<1, 16, 20>()),
        ("16 / 32, registers 1", whole::measure::<1, 16, 32>()),
        ("16 / 32, registers 0 (not ZK)", whole::measure::<0, 16, 32>()),
        ("public payee, no allowlists", whole::measure::<1, 0, 32>()),
    ] {
        println!("  {:<30} {:>10} {:>14} {:>7}", label, w, n, d);
    }
    println!();
    let (whw, whn, _) = whole::measure::<1, 16, 32>();
    println!("  Summed components gave {} / {} at 16 / 32 registers 1; the whole",
             fw + 2 * mw + rw, fn_ + 2 * mn + rn);
    println!("  AIR is {} / {}. Of the {} column difference, {} are C7's sponge",
             whw, whn, whw as i64 - (fw + 2 * mw + rw) as i64, c7w);
    println!("  and {} are glue; the {} constraint difference is C7 and the glue",
             whole::GLUE, whn as i64 - (fn_ + 2 * mn + rn) as i64);
    println!("  together. Every figure here is a difference of measured widths");
    println!("  rather than a count maintained by hand, which is what let the");
    println!("  glue row in Table VI drift to 14 columns while GLUE was 6.");

    println!();
    println!();
    println!();
    println!("SPEND COMPONENT: unit run, per-slot key derivation, shares and nullifiers");
    println!("THE WIDTH LAW IS 172 + 187c: NO TERM IN THE TREE DEPTH SURVIVES RESERVING");
    println!("{}", "=".repeat(78));
    println!("  {:<26} {:>8} {:>12} {:>7}", "depth / cover / registers", "width", "constraints", "degree");
    println!("  {:<26} {:>8} {:>12} {:>7}", "-".repeat(26), "-".repeat(8), "-".repeat(12), "-".repeat(7));
    for (label, (w, n, d)) in [
        ("16 / 30  / 1", spend::measure::<1, 16, 30>()),
        ("16 / 64  / 1", spend::measure::<1, 16, 64>()),
        ("16 / 128 / 1", spend::measure::<1, 16, 128>()),
        ("16 / 8   / 1", spend::measure::<1, 16, 8>()),
        ("16 / 1   / 1", spend::measure::<1, 16, 1>()),
        ("16 / 64  / 0 (not ZK)", spend::measure::<0, 16, 64>()),
    ] {
        println!("  {:<26} {:>8} {:>12} {:>7}", label, w, n, d);
    }

    println!();
    let (vw, vn, _) = vacuous::measure::<1, 16, 32>();
    let (rw, rn, _) = whole::measure::<1, 16, 32>();
    println!("NULLIFIER FROM A SECOND INVOCATION: THE PRICE OF DROPPING AN ASSUMPTION");
    println!("{}", "=".repeat(78));
    println!("  {:<34} {:>10} {:>14}", "depth / cover", "width", "constraints");
    println!("  {:<34} {:>10} {:>14}", "-".repeat(34), "-".repeat(10), "-".repeat(14));
    for (label, (w, n, _)) in [
        ("16 / 64, as built", spend::measure::<1, 16, 64>()),
        ("16 / 64, second invocation", spend2::measure::<1, 16, 64>()),
        ("16 / 30, second invocation", spend2::measure::<1, 16, 30>()),
        ("16 / 128, second invocation", spend2::measure::<1, 16, 128>()),
    ] {
        println!("  {:<34} {:>10} {:>14}", label, w, n);
    }
    let (a1, _, _) = spend::measure::<1, 16, 64>();
    let (a2, _, _) = spend2::measure::<1, 16, 64>();
    let (wh, _, _) = whole::measure::<1, 16, 32>();
    println!();
    println!("  The accountability half grows {} to {}, and the composed circuit",
             a1, a2);
    let (cw, _, _) = composed::measure::<1, 16, 32, 16, 64>();
    let bind = cw - (wh + a1);
    println!("  from {} to about {}, which is {:+.0}%. What it buys is that the",
             wh + a1 + bind, wh + a2 + bind,
             100.0 * ((wh + a2 + bind) as f64 / (wh + a1 + bind) as f64 - 1.0));
    println!("  nullifier is a pseudorandom function of the key rather than a");
    println!("  lane published beside it, so exculpability and bound privacy need");
    println!("  no joint-lane assumption. We report the price; we do not pay it.");
    println!();
    println!("WHAT ONE MISSING BINDING COSTS: C9 WITHOUT ITS POLICY BINDING");
    println!("{}", "=".repeat(78));
    println!("  {:<34} {:>10} {:>14}", "", "width", "constraints");
    println!("  {:<34} {:>10} {:>14}", "-".repeat(34), "-".repeat(10), "-".repeat(14));
    println!("  {:<34} {:>10} {:>14}", "compliance half, as built", rw, rn);
    println!("  {:<34} {:>10} {:>14}", "with C9's binding removed", vw, vn);
    println!("  {:<34} {:>10} {:>14}", "difference", rw as i64 - vw as i64, rn as i64 - vn as i64);
    println!();
    println!("  The width is identical and the constraint count differs by the");
    println!("  {} absorbed lanes. No cost table distinguishes these two", rn - vn);
    println!("  circuits, and the second proves compliance with a policy the");
    println!("  principal never committed to.");
    println!();
    println!("COMPOSED CIRCUIT: COMPLIANCE AND ACCOUNTABILITY AS ONE STATEMENT");
    println!("{}", "=".repeat(78));
    println!("  {:<34} {:>10} {:>14} {:>7}", "allowlist / revocation / depth / cover", "width", "constraints", "degree");
    println!("  {:<34} {:>10} {:>14} {:>7}", "-".repeat(34), "-".repeat(10), "-".repeat(14), "-".repeat(7));
    for (label, (w, n, d)) in [
        ("16 / 32 / 16 / 14, registers 1", composed::measure::<1, 16, 32, 16, 14>()),
        ("16 / 32 / 16 / 64, registers 1", composed::measure::<1, 16, 32, 16, 64>()),
        ("8 / 8 / 16 / 14, registers 1", composed::measure::<1, 8, 8, 16, 14>()),
    ] {
        println!("  {:<34} {:>10} {:>14} {:>7}", label, w, n, d);
    }
    let (cw, _, _) = composed::measure::<1, 16, 32, 16, 64>();
    let (ww, _, _) = whole::measure::<1, 16, 32>();
    let (sw, _, _) = spend::measure::<1, 16, 64>();
    println!();
    println!("  Separately the two halves are {} + {} = {} columns; composed they",
             ww, sw, ww + sw);
    println!("  are {}, so the bindings cost {}. Nothing is shared between them:",
             cw, cw as i64 - (ww + sw) as i64);
    println!("  the witness sets are disjoint and the cost is the binding, not a");
    println!("  saving. What composition buys is one proof rather than two.");

    println!();
    println!("SATISFYING TRACE: PROVE AND VERIFY ROUND TRIP, POLICY AIR");
    println!("{}", "=".repeat(78));
    println!("  {:<44} {:>12}", "trace", "verifies");
    println!("  {:<44} {:>12}", "-".repeat(44), "-".repeat(12));
    check("satisfying assignment, 64 rows", prover::roundtrip(64, false), true);
    check("one gap decomposition corrupted", prover::roundtrip(64, true), false);
    check("policy composed with C9, 64 rows", prover::roundtrip_composed::<1>(64, None), true);
    check("  ... C9 binding broken", prover::roundtrip_composed::<1>(64, Some(trace::Break::Binding)), false);
    check("  ... sponge chaining broken", prover::roundtrip_composed::<1>(64, Some(trace::Break::Chaining)), false); 
    check("  ... permutation round state broken", prover::roundtrip_composed::<1>(64, Some(trace::Break::Permutation)), false);
    check("merkle inclusion, depth 8, 64 rows", prover::roundtrip_merkle::<1, 8>(64, None), true);
    check("  ... direction bit perturbed", prover::roundtrip_merkle::<1, 8>(64, Some(8)), false);
    check("  ... sibling digest perturbed", prover::roundtrip_merkle::<1, 8>(64, Some(4)), false);
    check("non-revocation, depth 8, 64 rows", prover::roundtrip_nonmembership::<1, 8>(64, None), true);
    for (label, b) in [
        ("  ... a gap decomposition perturbed", trace::RevokeBreak::GapDecomposition),
        ("  ... run starts inside the revoked range", trace::RevokeBreak::RunStartsInsideRange),
        ("  ... run reaches the next revoked range", trace::RevokeBreak::RunReachesNextRange),
        ("  ... run ends before it starts", trace::RevokeBreak::RunInverted),
    ] {
        check(label, prover::roundtrip_nonmembership::<1, 8>(64, Some(b)), false);
    }
    let pl = spend_trace::PAYLOAD;
    check("spend component, depth 16, 64 rows", prover::roundtrip_spend::<1, 16, 14>(64, None, pl), true);
    for (label, b) in [
        ("  ... published share altered", spend_trace::SpendBreak::Share),
        ("  ... key taken from another unit", spend_trace::SpendBreak::Key),
        ("  ... nullifier altered", spend_trace::SpendBreak::Nullifier),
        ("  ... a unit deactivated", spend_trace::SpendBreak::Deactivate),
        ("  ... run start moved", spend_trace::SpendBreak::RunStart),
        ("  ... committed unit count perturbed", spend_trace::SpendBreak::Modulus),
        ("  ... units understated", spend_trace::SpendBreak::Units),
        ("  ... range base moved", spend_trace::SpendBreak::RangeBase),
        ("  ... a slot spanning two units", spend_trace::SpendBreak::CoarseSpan),
        ("  ... run ends past the budget", spend_trace::SpendBreak::RunPastBudget),
        ("  ... run ends past the units kept for the delegation itself", spend_trace::SpendBreak::RunPastSelf),
        ("  ... self-region claimed larger than the holding", spend_trace::SpendBreak::SelfPastHolding),
    ] {
        check(label, prover::roundtrip_spend::<1, 16, 14>(64, Some(b), pl), false);
    }
    check("  ... wrong public payload digest", prover::roundtrip_spend::<1, 16, 14>(64, None, pl + 1), false);
    let a10 = trace::whole_public_values_amount::<1, 16, 32>(10);
    let a13 = trace::whole_public_values_amount::<1, 16, 32>(13);
    check("commitment does not move with the payment", a10[5..9] == a13[5..9], true);
    check("payload digest does move with the payment", a10[0] != a13[0], true);
    check("second-invocation nullifier, depth 16, cover 14, 64 rows",
          prover::roundtrip_spend_two::<1, 16, 14>(64), true);
    check("a policy the commitment does not open to, under the real circuit",
          prover::roundtrip_vacuous::<1, 8, 8>(64, true), false);
    check("  ... the same trace with C9's binding removed",
          prover::roundtrip_vacuous::<1, 8, 8>(64, false), true);
    let (okc, _) = prover::roundtrip_composed_air::<1, 8, 8, 16, 14>(64, None);
    check("COMPOSED CIRCUIT, depth 16, cover 14, 64 rows", okc, true);
    for (label, b) in [
        ("  ... run start disagrees with C8's run", trace::ComposedBreak::RunStartMismatch),
        ("  ... amount exceeds the units charged", trace::ComposedBreak::AmountRaised),
        ("  ... amount below the units charged", trace::ComposedBreak::AmountLowered),
        ("  ... unit size does not divide the budget", trace::ComposedBreak::UnitSizeWrong),
        ("  ... cap larger than the budget", trace::ComposedBreak::CapAboveBudget),
    ] {
        let (got, _) = prover::roundtrip_composed_air::<1, 8, 8, 16, 14>(64, Some(b));
        check(label, got, false);
    }
    let (ok32, ms32) = prover::roundtrip_whole::<1>(32, None);
    check("WHOLE CIRCUIT at full parameters, 32 rows", ok32, true);
    let (bad32, _) = prover::roundtrip_whole::<1>(32, Some(0));
    check("  ... a policy column perturbed", bad32, false);
    let (badpl, _) = prover::roundtrip_whole::<1>(32, Some(air::COL_NONCE));
    check("  ... a payment field altered, digest not recomputed", badpl, false);
    println!();
    println!("  Whole circuit proved and verified in {} ms at 32 rows, against the", ms32);
    println!("  554 ms projected from a per-cell rate, not measured.");
    println!();
    println!("  {} controls, every one rejected; {} positive checks, every one holding.",
             CONTROLS.load(Ordering::Relaxed), POSITIVES.load(Ordering::Relaxed));
    println!();
    emit_verify_table();
    println!();
    println!("  The second must read false. A generator that only produces valid");
    println!("  traces would tell us nothing about whether the check checks.");
    println!("  Height is 64: FRI requires log height > log_final_poly_len +");
    println!("  log_blowup, which is 5 at these parameters.");

    println!();
    println!("WHOLE-CIRCUIT PROVING COST, ONE REGISTER, HIDING PCS");
    println!("{}", "=".repeat(78));
    let heights = [8usize, 16, 32];
    let (rows, drift) = prover::whole_timing::<1>(TIMING_BATCHES, TIMING_PER_BATCH, 10, &heights);
    println!("  {:>6} {:>11} {:>11} {:>11} {:>11} {:>13}", "rows", "min", "q1", "median", "q3", "per payment");
    println!("  {:>6} {:>11} {:>11} {:>11} {:>11} {:>13}", "-".repeat(6), "-".repeat(11), "-".repeat(11), "-".repeat(11), "-".repeat(11), "-".repeat(13));
    for (h, st) in &rows {
        println!("  {:>6} {:>9.1}ms {:>9.1}ms {:>9.1}ms {:>9.1}ms {:>11.2}ms",
            h, st.min * *h as f64, st.q1 * *h as f64, st.median * *h as f64, st.q3 * *h as f64, st.median);
    }
    println!();
    println!("  Per payment is the median divided by the row count. {} iterations in",
        TIMING_BATCHES * TIMING_PER_BATCH);
    println!("  {} interleaved batches with a 10s pause. Heights are interleaved inside", TIMING_BATCHES);
    println!("  each batch so drift hits them equally.");
    println!();
    println!("  PER-BATCH MEDIANS, ms per payment. Flat means no thermal drift.");
    print!("   batch");
    for h in heights {
        print!(" {:>12}", format!("{} rows", h));
    }
    println!();
    for (b, row) in drift.iter().enumerate() {
        print!("  {:>5}", b + 1);
        for v in row {
            print!(" {:>12.4}", v);
        }
        println!();
    }

    println!();
    println!("PROOF SIZE AND VERIFICATION COST, ONE REGISTER, HIDING PCS");
    println!("{}", "=".repeat(78));
    println!("  smallest trace height these FRI parameters admit  {:>10}",
        prover::min_admissible_height());
    let (pw, pc, po, pp) = prover::proof_bytes::<1>(32);
    println!("  {:<48} {:>10}", "proof, bincode bytes, 32-row trace", pw);
    println!("  {:<48} {:>10}", "  of which commitments", pc);
    println!("  {:<48} {:>10}", "  of which opened values", po);
    println!("  {:<48} {:>10}", "  of which opening proof", pp);
    println!("  {:<48} {:>10.0}", "bytes per payment at 32 rows", pw as f64 / 32.0);
    println!();
    println!("  Deterministic at fixed parameters, so one run is a measurement.");
    println!();
    let cbytes = prover::composed_proof_bytes::<1, 16, 32, 16, 64>(32);
    let (cw2, _, _) = composed::measure::<1, 16, 32, 16, 64>();
    let sep = prover::proof_bytes::<1>(32).0 + prover::spend_proof_bytes::<1, 16, 64>(32);
    println!("  {:<48} {:>10}", "composed proof, bincode bytes, 32-row trace", cbytes);
    println!("  {:<48} {:>10}", "two separate proofs, same payments", sep);
    println!("  {:<48} {:>10}", "saved by proving once", sep as i64 - cbytes as i64);
    println!("  {:<48} {:>10}", "composed width for reference", cw2);
    println!();
    let (vrows, vdrift) = prover::verify_timing::<1>(TIMING_BATCHES, TIMING_PER_BATCH, 10, &heights);
    println!("  {:>6} {:>11} {:>11} {:>11} {:>11} {:>13}", "rows", "min", "q1", "median", "q3", "per payment");
    println!("  {:>6} {:>11} {:>11} {:>11} {:>11} {:>13}", "-".repeat(6), "-".repeat(11), "-".repeat(11), "-".repeat(11), "-".repeat(11), "-".repeat(13));
    for (h, st) in &vrows {
        println!("  {:>6} {:>9.2}ms {:>9.2}ms {:>9.2}ms {:>9.2}ms {:>11.3}ms",
            h, st.min * *h as f64, st.q1 * *h as f64, st.median * *h as f64, st.q3 * *h as f64, st.median);
    }
    println!();
    println!("  Verification, not proving. Proofs are built outside the timed region.");
    println!("  PER-BATCH MEDIANS, ms per payment.");
    print!("   batch");
    for h in heights {
        print!(" {:>12}", format!("{} rows", h));
    }
    println!();
    for (b, row) in vdrift.iter().enumerate() {
        print!("  {:>5}", b + 1);
        for v in row {
            print!(" {:>12.5}", v);
        }
        println!();
    }

    println!();
    println!("COST STRUCTURE: WHAT EACH DESIGN DECISION BUYS, 32-ROW TRACES");
    println!("{}", "=".repeat(78));
    println!("  {:<30} {:>8} {:>11} {:>12} {:>11}",
             "variant", "columns", "prove/pmt", "proof bytes", "verify/pmt");
    println!("  {:<30} {:>8} {:>11} {:>12} {:>11}",
             "-".repeat(30), "-".repeat(8), "-".repeat(11), "-".repeat(12), "-".repeat(11));
    let study = prover::cost_structure(COST_BATCHES, COST_PER_BATCH, 10);
    for r in &study {
        println!("  {:<30} {:>8} {:>9.2}ms {:>12} {:>9.3}ms",
                 r.label, r.columns, r.prove.median, r.bytes, r.verify.median);
    }
    println!();
    println!("  Medians of {} iterations, variants interleaved inside each batch.",
             COST_BATCHES * COST_PER_BATCH);
    println!("  Traces are built once and cloned before the timer starts, so no row");
    println!("  is charged for generating its own witness.");
    println!("  Every row is a real AIR proved at 32 rows, not a sum of other rows.");
    println!("  Marginal costs are differences between measured rows:");
    let find = |lab: &str| study.iter().find(|r| r.label == lab)
        .unwrap_or_else(|| panic!("cost-structure row missing: {lab}"));
    let base = find("policy + C9 only");
    let full = find("+ allowlists + revocation d32");
    let d20 = find("  same, revocation d20");
    let pubp = find("  allowlists outside the proof");
    let acc_std = find("accountability, grain 1/64");
    let acc_coarse = find("  coarser, grain 1/30");
    let nozk = find("whole, no zero knowledge");
    let accnozk = find("accountability, no zk");
    let line = |lab: &str, a: &prover::CostRow, b: &prover::CostRow, t: bool| {
        if t {
            println!("    {:<24} {:>8} cols {:>9.2}ms {:>12} bytes",
                lab, a.columns as i64 - b.columns as i64,
                a.prove.median - b.prove.median, a.bytes as i64 - b.bytes as i64);
        } else {
            println!("    {:<24} {:>8} cols {:>32} bytes",
                lab, a.columns as i64 - b.columns as i64, a.bytes as i64 - b.bytes as i64);
        }
    };
    line("C7, allowlists, revocation", full, base, true);
    line("allowlists alone", full, pubp, true);
    line("revocation d32 over d20", full, d20, false);
    line("grain 1/64 over 1/30", acc_std, acc_coarse, false);
    line("zero knowledge, policy", full, nozk, true);
    line("zero knowledge, accnt.", acc_std, accnozk, false);

    if let (Some(c), Some(p)) = (
        study.iter().find(|r| r.label == "composed, one proof per payment"),
        study.iter().find(|r| r.label == "two halves, one timed region"),
    ) {
        println!();
        println!("WHAT ONE PAYMENT COSTS, COMPOSED AGAINST THE TWO HALVES SEPARATELY");
        println!("{}", "=".repeat(78));
        println!("  {:<28} {:>9} {:>9} {:>9} {:>9} {:>12}",
                 "", "min", "q1", "median", "q3", "proof bytes");
        println!("  {:<28} {:>9} {:>9} {:>9} {:>9} {:>12}",
                 "-".repeat(28), "-".repeat(9), "-".repeat(9), "-".repeat(9), "-".repeat(9), "-".repeat(12));
        println!("  {:<28} {:>8.2} {:>8.2} {:>8.2} {:>8.2} {:>12}",
                 "composed, proving", c.prove.min, c.prove.q1, c.prove.median, c.prove.q3, c.bytes);
        println!("  {:<28} {:>8.2} {:>8.2} {:>8.2} {:>8.2} {:>12}",
                 "composed, verification", c.verify.min, c.verify.q1, c.verify.median, c.verify.q3, "");
        println!("  {:<28} {:>8.2} {:>8.2} {:>8.2} {:>8.2} {:>12}",
                 "two halves, proving", p.prove.min, p.prove.q1, p.prove.median, p.prove.q3, p.bytes);
        println!("  {:<28} {:>8.2} {:>8.2} {:>8.2} {:>8.2} {:>12}",
                 "two halves, verification", p.verify.min, p.verify.q1, p.verify.median, p.verify.q3, "");
        println!();
        println!("  Milliseconds per payment at 32 rows. Both rows are timed the same");
        println!("  way: one region covering everything a settlement pays for. The two");
        println!("  halves are two proofs inside one region rather than two medians");
        println!("  added, which is not the median of a sum.");
        println!("  Proving  {:+.1}%   verification  {:+.1}%   proof bytes {:+.1}%",
                 100.0 * (c.prove.median / p.prove.median - 1.0),
                 100.0 * (c.verify.median / p.verify.median - 1.0),
                 100.0 * (c.bytes as f64 / p.bytes as f64 - 1.0));
        let overlap = c.prove.q1 <= p.prove.q3 && p.prove.q1 <= c.prove.q3;
        println!("  Interquartile ranges {} on proving, so the difference is {}.",
                 if overlap { "OVERLAP" } else { "do not overlap" },
                 if overlap { "not established" } else { "real within this run" });
        println!();
        println!("  PER-BATCH MEDIANS, ms per payment. Flat means no thermal drift.");
        println!("  {:>6} {:>14} {:>14} {:>14} {:>14}",
                 "batch", "composed pr", "halves pr", "composed vf", "halves vf");
        println!("  {:>6} {:>14} {:>14} {:>14} {:>14}",
                 "-".repeat(6), "-".repeat(14), "-".repeat(14), "-".repeat(14), "-".repeat(14));
        for i in 0..c.prove_batches.len() {
            println!("  {:>6} {:>14.3} {:>14.3} {:>14.3} {:>14.3}",
                     i + 1, c.prove_batches[i], p.prove_batches[i],
                     c.verify_batches[i], p.verify_batches[i]);
        }
    }

    println!();

    println!();
    println!("POSEIDON2 SUB-TRACE GENERATION, SANITY CHECKS");
    println!("{}", "=".repeat(78));
    let r = gen::perm_row::<0>([p3_goldilocks::Goldilocks::ZERO; 8]);
    println!("  {:<46} {:>10}", "row width equals num_cols", r.len());
    let out = gen::perm_output::<0>(&r);
    println!("  {:<46} {:>10}", "output differs from all-zero input", out.iter().any(|x| *x != p3_goldilocks::Goldilocks::ZERO));
    let sp = gen::sponge::<0>(&vec![p3_goldilocks::Goldilocks::ONE; 10], 4, hash::DOMAIN_OPENING);
    println!("  {:<46} {:>10}", "ten elements absorb in three permutations", sp.len());
    let chained = gen::perm_output::<0>(&sp[0])[4..] == sp[1][4..8];
    println!("  {:<46} {:>10}", "capacity carries from perm 0 into perm 1", chained);
    println!();


    const BATCHES: usize = 10;
    const PER_BATCH: usize = 100;
    const PAUSE: u64 = 10;
    println!("PROVING TIME, {} ITERATIONS IN {} INTERLEAVED BATCHES, {}s PAUSE",
             BATCHES * PER_BATCH, BATCHES, PAUSE);
    println!("{} QUERIES AT BLOWUP 2^{}, {} POW BITS",
             prover::NUM_QUERIES, prover::LOG_BLOWUP, prover::POW_BITS);
    println!("{}", "=".repeat(78));
    println!("  {:<24} {:>8} {:>9} {:>9} {:>9} {:>9}",
             "configuration", "min", "q1", "median", "q3", "mean");
    println!("  {:<24} {:>8} {:>9} {:>9} {:>9} {:>9}",
             "-".repeat(24), "-".repeat(8), "-".repeat(9), "-".repeat(9), "-".repeat(9), "-".repeat(9));
    let (r0, r1, r0big, batch_medians) = prover::compare(BATCHES, PER_BATCH, PAUSE);
    for (label, s) in [("256 perms, 0 registers", &r0), ("256 perms, 1 register", &r1), ("1024 perms, 0 registers", &r0big)] {
        println!("  {:<24} {:>8.4} {:>9.4} {:>9.4} {:>9.4} {:>9.4}",
                 label, s.min, s.q1, s.median, s.q3, s.mean);
    }
    println!();
    println!("  Milliseconds per permutation. Configurations are interleaved so");
    println!("  drift hits each equally; minimum is the most robust statistic,");
    println!("  since interference can only ever slow a run down.");
    println!("  Register verdict: {:.4} vs {:.4} ms/perm at matched height, ratio {:.2}x.",
             r0.median, r1.median, r1.median / r0.median);
    println!();
    println!("  PER-BATCH MEDIANS, ms per permutation. Flat means no thermal drift;");
    println!("  a rising trend means the machine throttled over the run.");
    println!("  {:>6} {:>12} {:>12} {:>12}", "batch", "256/0", "256/1", "1024/0");
    println!("  {:>6} {:>12} {:>12} {:>12}", "-".repeat(6), "-".repeat(12), "-".repeat(12), "-".repeat(12));
    for (i, (x, y, z)) in batch_medians.iter().enumerate() {
        println!("  {:>6} {:>12.4} {:>12.4} {:>12.4}", i + 1, x, y, z);
    }

    println!("  Soundness gaps closed: C6 uses the field constant one in-circuit");
    println!("  rather than a witness adjustment; share indices are forced non-zero");
    println!("  by a witnessed inverse; and each sponge carries every lane its");
    println!("  chunk does not absorb, not only the capacity, so a partial final");
    println!("  chunk leaves no rate lane for a prover to choose.");
    println!();
}
