//! The deployed AIR's constraints as a flat expression graph, for a verifier
//! written apart from Plonky3. The graph comes from p3-air's symbolic builder,
//! a different path from the folder Plonky3's verifier evaluates with. It does
//! not depend on the public values, so one file serves every batch size.

use std::collections::HashMap;
use std::sync::Arc;

use p3_air::{BaseAir, BaseEntry, BaseLeaf, SymbolicExpr, SymbolicExpression};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::Goldilocks;
use p3_uni_stark::{get_symbolic_constraints, AirLayout};

use crate::composed::{row_width, GLOBALS};
use crate::naysay::Air;

type F = Goldilocks;

pub const MAGIC: &[u8; 8] = b"PBDAG001";

const MAIN_LOCAL: u8 = 0;
const MAIN_NEXT: u8 = 1;
const PERIODIC: u8 = 2;
const PUBLIC: u8 = 3;
const FIRST_ROW: u8 = 4;
const LAST_ROW: u8 = 5;
const TRANSITION: u8 = 6;
const CONSTANT: u8 = 7;
const ADD: u8 = 8;
const SUB: u8 = 9;
const NEG: u8 = 10;
const MUL: u8 = 11;

struct Graph {
    out: Vec<u8>,
    nodes: u32,
    shared: HashMap<usize, u32>,
    leaves: HashMap<(u8, u64), u32>,
}

impl Graph {
    fn emit(&mut self, op: u8, words: &[u64]) -> u32 {
        self.out.push(op);
        for &w in words {
            if op == CONSTANT {
                self.out.extend_from_slice(&w.to_le_bytes());
            } else {
                self.out.extend_from_slice(&(w as u32).to_le_bytes());
            }
        }
        self.nodes += 1;
        self.nodes - 1
    }

    fn leaf(&mut self, op: u8, value: u64) -> u32 {
        if let Some(&id) = self.leaves.get(&(op, value)) {
            return id;
        }
        let words: &[u64] = match op {
            FIRST_ROW | LAST_ROW | TRANSITION => &[],
            _ => &[value],
        };
        let id = self.emit(op, words);
        self.leaves.insert((op, value), id);
        id
    }

    fn node(&mut self, e: &Arc<SymbolicExpression<F>>) -> u32 {
        let key = Arc::as_ptr(e) as usize;
        if let Some(&id) = self.shared.get(&key) {
            return id;
        }
        let id = self.expr(e);
        self.shared.insert(key, id);
        id
    }

    fn expr(&mut self, e: &SymbolicExpression<F>) -> u32 {
        match e {
            SymbolicExpr::Leaf(leaf) => match leaf {
                BaseLeaf::Variable(v) => match v.entry {
                    BaseEntry::Main { offset: 0 } => self.leaf(MAIN_LOCAL, v.index as u64),
                    BaseEntry::Main { offset: 1 } => self.leaf(MAIN_NEXT, v.index as u64),
                    BaseEntry::Periodic => self.leaf(PERIODIC, v.index as u64),
                    BaseEntry::Public => self.leaf(PUBLIC, v.index as u64),
                    other => panic!("the deployed AIR has no {other:?} entries"),
                },
                BaseLeaf::IsFirstRow => self.leaf(FIRST_ROW, 0),
                BaseLeaf::IsLastRow => self.leaf(LAST_ROW, 0),
                BaseLeaf::IsTransition => self.leaf(TRANSITION, 0),
                BaseLeaf::Constant(c) => self.leaf(CONSTANT, c.as_canonical_u64()),
            },
            SymbolicExpr::Add { x, y, .. } => {
                let (a, b) = (self.node(x), self.node(y));
                self.emit(ADD, &[a as u64, b as u64])
            }
            SymbolicExpr::Sub { x, y, .. } => {
                let (a, b) = (self.node(x), self.node(y));
                self.emit(SUB, &[a as u64, b as u64])
            }
            SymbolicExpr::Neg { x, .. } => {
                let a = self.node(x);
                self.emit(NEG, &[a as u64])
            }
            SymbolicExpr::Mul { x, y, .. } => {
                let (a, b) = (self.node(x), self.node(y));
                self.emit(MUL, &[a as u64, b as u64])
            }
        }
    }
}

/// Writes the graph and returns its size in bytes, its node count and its
/// constraint count. The layout is the magic, then five little-endian u32s
/// (width, global public values, values per payment, which is also the
/// number of periodic columns, nodes, constraints),
/// then the nodes in an order where every child precedes its parent, then
/// the root node of each constraint in the order the AIR asserts them.
pub fn export(path: &str) -> (usize, u32, usize) {
    let air = Air::from_public_values(&vec![F::ZERO; GLOBALS + row_width(64)]);
    let layout = AirLayout::from_air::<F>(&air);
    let constraints = get_symbolic_constraints::<F, _>(&air, layout);
    let mut g = Graph { out: Vec::new(), nodes: 0, shared: HashMap::new(), leaves: HashMap::new() };
    let roots: Vec<u32> = constraints.iter().map(|c| g.expr(c)).collect();
    let mut bytes = MAGIC.to_vec();
    for v in [
        BaseAir::<F>::width(&air) as u32,
        GLOBALS as u32,
        BaseAir::<F>::num_periodic_columns(&air) as u32,
        g.nodes,
        roots.len() as u32,
    ] {
        bytes.extend_from_slice(&v.to_le_bytes());
    }
    bytes.extend_from_slice(&g.out);
    for r in &roots {
        bytes.extend_from_slice(&r.to_le_bytes());
    }
    std::fs::write(path, &bytes).expect("write constraint graph");
    (bytes.len(), g.nodes, roots.len())
}
