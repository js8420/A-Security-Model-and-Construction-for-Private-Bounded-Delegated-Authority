//! One constraint of the out-of-domain identity as a program a contract runs.
//!
//! The identity's leaf step evaluates a single constraint at the opened
//! values. A contract cannot hold the whole AIR, so each constraint is
//! compiled from its symbolic expression into a short program: the values it
//! reads, the constants it uses, and its operations in order, each naming two
//! earlier slots. A contract is given one program and the values it reads,
//! and runs it. This module compiles every constraint, runs each program in
//! Rust against the verifier's own folder, measures what one leaf reads and
//! computes, and writes the worst and median programs, with real values, as
//! Solidity test vectors for the contract that runs them.

use std::collections::HashMap;
use std::fmt::Write as _;

use p3_air::symbolic::SymbolicExpr;
use p3_air::{BaseEntry, BaseLeaf};
use p3_commit::PolynomialSpace;
use p3_field::{BasedVectorSpace, PrimeField64};
use p3_uni_stark::prove;

use crate::naysay::{config, record_ops, sides, Air, Op, RProof, Recording};
use crate::prover::{deployed_pcs, Challenge, Pcs, Val, ROWS};
use crate::trace::composed_case;

type Expr = SymbolicExpr<BaseLeaf<Val>>;

/// A value a program reads from outside: an opened column at zeta or at the
/// next row, a public value, or a selector at zeta.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Read {
    Local(usize),
    Next(usize),
    Public(usize),
    First,
    Last,
    Transition,
}

pub const ADD: u8 = 0;
pub const SUB: u8 = 1;
pub const MUL: u8 = 2;
pub const NEG: u8 = 3;

/// Slots are numbered reads first, then constants, then one per operation.
/// The result is the slot `out`: usually the last operation, but a
/// constraint that asserts a column is zero is the column itself.
pub struct Program {
    pub reads: Vec<Read>,
    pub consts: Vec<Val>,
    pub ops: Vec<(u8, u16, u16)>,
    pub out: u16,
}

impl Program {
    /// Five bytes an operation: kind, then two slot numbers, big-endian.
    pub fn bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.ops.len() * 5);
        for &(k, a, b) in &self.ops {
            out.push(k);
            out.extend_from_slice(&a.to_be_bytes());
            out.extend_from_slice(&b.to_be_bytes());
        }
        out
    }
}

struct Compiler {
    reads: Vec<Read>,
    read_slot: HashMap<Read, usize>,
    consts: Vec<Val>,
    const_slot: HashMap<u64, usize>,
    ops: Vec<(u8, usize, usize)>,
    memo: HashMap<*const Expr, Slot>,
}

#[derive(Clone, Copy)]
enum Slot {
    Read(usize),
    Const(usize),
    Op(usize),
}

impl Compiler {
    fn leaf(&mut self, r: Read) -> Slot {
        let n = self.reads.len();
        let i = *self.read_slot.entry(r).or_insert(n);
        if i == n {
            self.reads.push(r);
        }
        Slot::Read(i)
    }

    fn constant(&mut self, c: Val) -> Slot {
        let n = self.consts.len();
        let i = *self.const_slot.entry(c.as_canonical_u64()).or_insert(n);
        if i == n {
            self.consts.push(c);
        }
        Slot::Const(i)
    }

    fn walk(&mut self, e: &Expr) -> Slot {
        let key = e as *const Expr;
        if let Some(s) = self.memo.get(&key) {
            return *s;
        }
        let s = match e {
            SymbolicExpr::Leaf(BaseLeaf::Variable(v)) => match v.entry {
                BaseEntry::Main { offset: 0 } => self.leaf(Read::Local(v.index)),
                BaseEntry::Main { .. } => self.leaf(Read::Next(v.index)),
                BaseEntry::Public => self.leaf(Read::Public(v.index)),
                BaseEntry::Preprocessed { .. } | BaseEntry::Periodic => unreachable!("not in this AIR"),
            },
            SymbolicExpr::Leaf(BaseLeaf::IsFirstRow) => self.leaf(Read::First),
            SymbolicExpr::Leaf(BaseLeaf::IsLastRow) => self.leaf(Read::Last),
            SymbolicExpr::Leaf(BaseLeaf::IsTransition) => self.leaf(Read::Transition),
            SymbolicExpr::Leaf(BaseLeaf::Constant(c)) => self.constant(*c),
            SymbolicExpr::Add { x, y, .. } => self.op(ADD, x, Some(y)),
            SymbolicExpr::Sub { x, y, .. } => self.op(SUB, x, Some(y)),
            SymbolicExpr::Mul { x, y, .. } => self.op(MUL, x, Some(y)),
            SymbolicExpr::Neg { x, .. } => self.op(NEG, x, None),
        };
        self.memo.insert(key, s);
        s
    }

    fn op(&mut self, kind: u8, x: &Expr, y: Option<&std::sync::Arc<Expr>>) -> Slot {
        let a = self.walk(x);
        let b = y.map(|y| self.walk(y)).unwrap_or(a);
        self.ops.push((kind, self.raw(a), self.raw(b)));
        Slot::Op(self.ops.len() - 1)
    }

    // Slots are renumbered once the read and constant counts are final.
    fn raw(&self, s: Slot) -> usize {
        match s {
            Slot::Read(i) => i,
            Slot::Const(i) => (1 << 20) + i,
            Slot::Op(i) => (1 << 21) + i,
        }
    }
}

pub fn compile(e: &Expr) -> Program {
    let mut c = Compiler {
        reads: Vec::new(),
        read_slot: HashMap::new(),
        consts: Vec::new(),
        const_slot: HashMap::new(),
        ops: Vec::new(),
        memo: HashMap::new(),
    };
    let out = c.walk(e);
    let (nr, nc) = (c.reads.len(), c.consts.len());
    let fix = |s: usize| -> u16 {
        let v = if s >= 1 << 21 { nr + nc + (s - (1 << 21)) } else if s >= 1 << 20 { nr + (s - (1 << 20)) } else { s };
        u16::try_from(v).expect("slots fit in two bytes")
    };
    let ops = c.ops.iter().map(|&(k, a, b)| (k, fix(a), fix(b))).collect();
    let out = fix(c.raw(out));
    Program { reads: c.reads, consts: c.consts, ops, out }
}

/// What the contract does, in Rust: the reference the Solidity is held to.
pub fn run(p: &Program, inputs: &[Challenge]) -> Challenge {
    let mut v: Vec<Challenge> = inputs.to_vec();
    v.extend(p.consts.iter().map(|&c| Challenge::from(c)));
    for &(k, a, b) in &p.ops {
        let (x, y) = (v[a as usize], v[b as usize]);
        v.push(match k {
            ADD => x + y,
            SUB => x - y,
            MUL => x * y,
            _ => -x,
        });
    }
    v[p.out as usize]
}

struct At<'a> {
    local: &'a [Challenge],
    next: &'a [Challenge],
    pv: &'a [Val],
    first: Challenge,
    last: Challenge,
    transition: Challenge,
}

fn inputs(p: &Program, at: &At) -> Vec<Challenge> {
    p.reads
        .iter()
        .map(|r| match *r {
            Read::Local(i) => at.local[i],
            Read::Next(i) => at.next[i],
            Read::Public(i) => Challenge::from(at.pv[i]),
            Read::First => at.first,
            Read::Last => at.last,
            Read::Transition => at.transition,
        })
        .collect()
}

/// Leaves of 32 bytes, four Goldilocks lanes each, over the opened values
/// laid out as every column at zeta and then every column at the next row,
/// two lanes a value. The siblings a multiproof of the leaves a constraint
/// touches needs, in a tree over just that section.
fn siblings(p: &Program, width: usize) -> usize {
    let mut level: Vec<usize> = p
        .reads
        .iter()
        .filter_map(|r| match *r {
            Read::Local(i) => Some(i / 2),
            Read::Next(i) => Some((width + i) / 2),
            _ => None,
        })
        .collect();
    level.sort_unstable();
    level.dedup();
    let depth = (width.div_ceil(2) * 2).next_power_of_two().trailing_zeros() as usize;
    let mut count = 0;
    for _ in 0..depth {
        let mut up = Vec::new();
        let mut k = 0;
        while k < level.len() {
            let n = level[k];
            if k + 1 < level.len() && level[k + 1] == n ^ 1 {
                k += 2;
            } else {
                count += 1;
                k += 1;
            }
            up.push(n >> 1);
        }
        up.dedup();
        level = up;
    }
    count
}

pub struct Profile {
    pub constraints: usize,
    pub agree: bool,
    /// (p50, p90, p99, max) of operations, of opened values read, of
    /// program bytes, and of multiproof siblings.
    pub ops: [usize; 4],
    pub reads: [usize; 4],
    pub bytes: [usize; 4],
    pub siblings: [usize; 4],
    pub total_ops: usize,
    pub worst_ops: usize,
    pub worst_reads_index: usize,
    pub median_index: usize,
}

fn quantiles(mut v: Vec<usize>) -> [usize; 4] {
    v.sort_unstable();
    let q = |f: f64| v[((v.len() - 1) as f64 * f).round() as usize];
    [q(0.5), q(0.9), q(0.99), *v.last().expect("constraints")]
}

fn hex_ext(c: Challenge) -> String {
    let l: &[Val] = c.as_basis_coefficients_slice();
    format!("0x{:016x}{:016x}", l[1].as_canonical_u64(), l[0].as_canonical_u64())
}

/// Every constraint compiled and run on a real proof; the profile, and the
/// Solidity vectors written to `vectors`.
pub fn profile(vectors: &str) -> Profile {
    let air = Air::new();
    let (t, pv) = composed_case::<{ crate::prover::REGISTERS }, 16, 32, 16, 64>(ROWS, None);
    let proof: RProof = prove(&config().0, &air, t, &pv);
    let (_, ops, verdict) = record_ops(&air, &proof, &pv);
    assert!(verdict.is_ok(), "honest proof must verify");
    let outs: Vec<Val> = ops.iter().filter_map(|o| if let Op::Out(v) = o { Some(*v) } else { None }).collect();
    let ext = |i: usize| Challenge::from_basis_coefficients_slice(&outs[2 * i..2 * i + 2]).expect("two");
    let (alpha, zeta) = (ext(0), ext(1));
    let ov = &proof.opened_values;
    let next = ov.trace_next.as_deref().expect("next row");
    let pcs = deployed_pcs();
    let init = <Pcs as p3_commit::Pcs<Challenge, Recording>>::natural_domain_for_degree(&pcs, 1 << (proof.degree_bits - 1));
    let sels = init.selectors_at_point(zeta);
    let at = At {
        local: &ov.trace_local,
        next,
        pv: &pv,
        first: sels.is_first_row,
        last: sels.is_last_row,
        transition: sels.is_transition,
    };
    let (_, _, folder) = sides(&air, &ov.trace_local, next, &ov.quotient_chunks, &pv, alpha, zeta, proof.degree_bits);

    let cs = p3_air::get_symbolic_constraints::<Val, _>(&air, p3_air::AirLayout::from_air::<Val>(&air));
    let width = ov.trace_local.len();
    let progs: Vec<Program> = cs.iter().map(compile).collect();
    let mut agree = true;
    for (p, want) in progs.iter().zip(&folder) {
        agree &= run(p, &inputs(p, &at)) == *want;
    }
    let opened = |p: &Program| p.reads.iter().filter(|r| matches!(r, Read::Local(_) | Read::Next(_))).count();
    let n_ops: Vec<usize> = progs.iter().map(|p| p.ops.len()).collect();
    let n_reads: Vec<usize> = progs.iter().map(opened).collect();
    let n_bytes: Vec<usize> = progs.iter().map(|p| p.ops.len() * 5).collect();
    let n_sib: Vec<usize> = progs.iter().map(|p| siblings(p, width)).collect();
    let worst = (0..progs.len()).max_by_key(|&i| (n_ops[i], n_reads[i])).expect("constraints");
    let worst_reads = (0..progs.len()).max_by_key(|&i| (n_reads[i], n_ops[i])).expect("constraints");
    let mut order: Vec<usize> = (0..progs.len()).collect();
    order.sort_by_key(|&i| n_ops[i]);
    let median = order[order.len() / 2];

    let mut s = String::new();
    writeln!(s, "// SPDX-License-Identifier: MIT").ok();
    writeln!(s, "pragma solidity ^0.8.28;").ok();
    writeln!(s).ok();
    writeln!(s, "/// Constraints of the composed circuit compiled to programs, with the values").ok();
    writeln!(s, "/// they read on a real 128-row proof and the value the verifier's folder").ok();
    writeln!(s, "/// gives them. Written by `cargo run --release -- leaf`.").ok();
    writeln!(s, "library ConstraintVectors {{").ok();
    for (name, i) in [("WORST", worst), ("READS", worst_reads), ("MEDIAN", median)] {
        let p = &progs[i];
        let ins = inputs(p, &at);
        let mut vals: Vec<String> = ins.iter().map(|c| hex_ext(*c)).collect();
        vals.extend(p.consts.iter().map(|c| hex_ext(Challenge::from(*c))));
        writeln!(s, "    uint256 internal constant {name}_INDEX = {i};").ok();
        writeln!(s, "    uint256 internal constant {name}_EXPECTED = {};", hex_ext(folder[i])).ok();
        writeln!(s, "    uint256 internal constant {name}_READS = {};", opened(p)).ok();
        writeln!(s, "    uint256 internal constant {name}_OUT = {};", p.out).ok();
        writeln!(s, "    bytes internal constant {name}_PROGRAM = hex\"{}\";", p.bytes().iter().map(|b| format!("{b:02x}")).collect::<String>()).ok();
        writeln!(s, "    function {}Inputs() internal pure returns (uint256[] memory v) {{", name.to_lowercase()).ok();
        writeln!(s, "        v = new uint256[]({});", vals.len()).ok();
        for (k, x) in vals.iter().enumerate() {
            writeln!(s, "        v[{k}] = {x};").ok();
        }
        writeln!(s, "    }}").ok();
    }
    writeln!(s, "}}").ok();
    std::fs::write(vectors, s).expect("write vectors");

    Profile {
        constraints: progs.len(),
        agree,
        ops: quantiles(n_ops.clone()),
        reads: quantiles(n_reads),
        bytes: quantiles(n_bytes),
        siblings: quantiles(n_sib),
        total_ops: n_ops.iter().sum(),
        worst_ops: worst,
        worst_reads_index: worst_reads,
        median_index: median,
    }
}
