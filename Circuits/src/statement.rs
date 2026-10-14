//! What an answer to a challenge commits: the statement's scalar values, then
//! the Keccak hash of the published shares and nullifiers in four words. The
//! hash is taken over the encoding the reserve hashes when it settles,
//! abi.encodePacked of a uint64 array, which puts each value big-endian in the
//! low eight bytes of a 32-byte word. Committing the hash rather than the 192
//! values keeps the answer's public input the same size at any slot cover.

use p3_keccak::Keccak256Hash;
use p3_symmetric::CryptographicHasher;

use crate::composed::PV_ELEMS;

/// Values committed per settlement.
pub const COMMITTED: usize = PV_ELEMS + 4;

pub fn elems_hash(elems: &[u64]) -> [u8; 32] {
    Keccak256Hash {}.hash_iter(elems.iter().flat_map(|e| {
        let mut w = [0u8; 32];
        w[24..].copy_from_slice(&e.to_be_bytes());
        w
    }))
}

pub fn committed(pv: &[u64]) -> Vec<u64> {
    let h = elems_hash(&pv[PV_ELEMS..]);
    let mut out = pv[..PV_ELEMS].to_vec();
    for j in 0..4 {
        out.push(u64::from_be_bytes(h[8 * j..8 * j + 8].try_into().expect("eight bytes")));
    }
    out
}
