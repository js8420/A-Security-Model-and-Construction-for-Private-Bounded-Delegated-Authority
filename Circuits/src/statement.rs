//! What an answer to a challenge commits: the Keccak root of a tree whose
//! leaves are the statements of the payments one proof proves. A leaf is a
//! payment's scalar values, the delegation's terms, and the Keccak hash of the
//! shares and nullifiers it publishes, 26 values. A payment of n units
//! publishes its first n slots and no others, so the hash is over 3n values.
//!
//! Every hash is taken over the encoding the reserve hashes, abi.encodePacked
//! of a uint64 array, which puts each value big-endian in the low eight bytes
//! of a 32-byte word. An inner node is the hash of its two children, 64 bytes.
//! The answer's public input is the 32-byte root at any batch size.

use p3_keccak::Keccak256Hash;
use p3_symmetric::CryptographicHasher;

use crate::composed::{
    row_width, ELEMS_PER_SLOT, GLOBALS, G_BASE, G_COM, G_RANGE, G_SECRET_HASH, G_UNIT,
    R_AMOUNT, R_DIGEST, R_DOMAIN, R_ELEMS, R_PAYEE, R_ROOT, R_TIME, SECRET_HASH_LANES,
};
use crate::merkle::DIGEST;
use crate::whole::PAYEE_LIMBS;

/// The values of one leaf, in this order: digest, revocation root, D.com,
/// domain, amount, payee limbs, time, unit size, range base, range length,
/// H(s), and the hash of the published slots in four words.
pub const COMMITTED: usize = 1 + DIGEST + DIGEST + 1 + 1 + PAYEE_LIMBS + 1 + 1 + 1 + 1 + SECRET_HASH_LANES + 4;

/// Where the leaf's elems hash starts.
pub const LEAF_ELEMS_HASH: usize = COMMITTED - 4;

pub fn elems_hash(elems: &[u64]) -> [u8; 32] {
    Keccak256Hash {}.hash_iter(elems.iter().flat_map(|e| {
        let mut w = [0u8; 32];
        w[24..].copy_from_slice(&e.to_be_bytes());
        w
    }))
}

fn node(l: &[u8; 32], r: &[u8; 32]) -> [u8; 32] {
    Keccak256Hash {}.hash_iter(l.iter().chain(r.iter()).copied())
}

/// The number of payments the public values carry.
pub fn payments(pv: &[u64], cover: usize) -> usize {
    (pv.len() - GLOBALS) / row_width(cover)
}

/// The units a payment of this amount consumes at this unit size.
pub fn units(amount: u64, unit: u64) -> usize {
    amount.div_ceil(unit) as usize
}

/// The shares and nullifiers payment i publishes: its first n slots.
pub fn published(pv: &[u64], cover: usize, i: usize) -> Vec<u64> {
    let b = GLOBALS + i * row_width(cover);
    let n = units(pv[b + R_AMOUNT], pv[G_UNIT]).min(cover);
    pv[b + R_ELEMS..b + R_ELEMS + ELEMS_PER_SLOT * n].to_vec()
}

/// Payment i's leaf.
pub fn leaf(pv: &[u64], cover: usize, i: usize) -> Vec<u64> {
    let b = GLOBALS + i * row_width(cover);
    let mut out = Vec::with_capacity(COMMITTED);
    out.push(pv[b + R_DIGEST]);
    out.extend_from_slice(&pv[b + R_ROOT..b + R_ROOT + DIGEST]);
    out.extend_from_slice(&pv[G_COM..G_COM + DIGEST]);
    out.push(pv[b + R_DOMAIN]);
    out.push(pv[b + R_AMOUNT]);
    out.extend_from_slice(&pv[b + R_PAYEE..b + R_PAYEE + PAYEE_LIMBS]);
    out.push(pv[b + R_TIME]);
    out.push(pv[G_UNIT]);
    out.push(pv[G_BASE]);
    out.push(pv[G_RANGE]);
    out.extend_from_slice(&pv[G_SECRET_HASH..G_SECRET_HASH + SECRET_HASH_LANES]);
    let h = elems_hash(&published(pv, cover, i));
    for j in 0..4 {
        out.push(u64::from_be_bytes(h[8 * j..8 * j + 8].try_into().expect("eight bytes")));
    }
    out
}

fn levels(pv: &[u64], cover: usize) -> Vec<Vec<[u8; 32]>> {
    let k = payments(pv, cover);
    assert!(k.is_power_of_two(), "a batch is a power of two of payments");
    let mut level: Vec<[u8; 32]> = (0..k).map(|i| elems_hash(&leaf(pv, cover, i))).collect();
    let mut all = vec![level.clone()];
    while level.len() > 1 {
        level = level.chunks(2).map(|p| node(&p[0], &p[1])).collect();
        all.push(level.clone());
    }
    all
}

/// The root an answer commits.
pub fn committed(pv: &[u64], cover: usize) -> [u8; 32] {
    levels(pv, cover).last().expect("a level")[0]
}

/// The siblings from payment i's leaf to the root, lowest first.
pub fn path(pv: &[u64], cover: usize, i: usize) -> Vec<[u8; 32]> {
    let all = levels(pv, cover);
    let mut at = i;
    let mut out = Vec::new();
    for level in &all[..all.len() - 1] {
        out.push(level[at ^ 1]);
        at >>= 1;
    }
    out
}

/// The root from a leaf, its position and its path, as the reserve computes it.
pub fn root_from(leaf: &[u64], mut at: usize, path: &[[u8; 32]]) -> [u8; 32] {
    let mut h = elems_hash(leaf);
    for s in path {
        h = if at & 1 == 0 { node(&h, s) } else { node(s, &h) };
        at >>= 1;
    }
    h
}
