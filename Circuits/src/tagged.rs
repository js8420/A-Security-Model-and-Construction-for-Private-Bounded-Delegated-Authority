//! The Merkle trees' sponge: Plonky3's padding-free overwrite sponge over
//! Keccak-f, started from a state whose last capacity lane holds a fixed tag
//! instead of zero. Keccak-256, which the transcript hashes with, starts every
//! message from the all-zero state, so no Keccak-f input of a Merkle hash's
//! first block equals one of a transcript hash's first block, and after the
//! first block the two meet only if their capacities collide.

use p3_symmetric::{CryptographicHasher, CryptographicPermutation};

/// "merkle1" in ASCII, as a little-endian lane.
pub const TAG: u64 = 0x3165_6c6b_7265_6d;

pub trait Tagged: Default + Copy {
    fn tag() -> Self;
}

impl Tagged for u64 {
    fn tag() -> Self {
        TAG
    }
}

macro_rules! tagged_lanes {
    ($($n:literal),*) => {$(
        impl Tagged for [u64; $n] {
            fn tag() -> Self {
                [TAG; $n]
            }
        }
    )*};
}

// The packed widths p3-keccak uses on the targets it supports.
tagged_lanes!(1, 2, 4, 8);

#[derive(Copy, Clone, Debug)]
pub struct TaggedSponge<P, const WIDTH: usize, const RATE: usize, const OUT: usize> {
    permutation: P,
}

impl<P, const WIDTH: usize, const RATE: usize, const OUT: usize> TaggedSponge<P, WIDTH, RATE, OUT> {
    pub const fn new(permutation: P) -> Self {
        const {
            assert!(RATE > 0);
            assert!(RATE < WIDTH);
            assert!(OUT <= WIDTH);
        }
        Self { permutation }
    }
}

impl<T, P, const WIDTH: usize, const RATE: usize, const OUT: usize> CryptographicHasher<T, [T; OUT]>
    for TaggedSponge<P, WIDTH, RATE, OUT>
where
    T: Tagged,
    P: CryptographicPermutation<[T; WIDTH]>,
{
    fn hash_iter<I>(&self, input: I) -> [T; OUT]
    where
        I: IntoIterator<Item = T>,
    {
        let mut state = [T::default(); WIDTH];
        state[WIDTH - 1] = T::tag();
        let mut input = input.into_iter();
        'outer: loop {
            for i in 0..RATE {
                if let Some(x) = input.next() {
                    state[i] = x;
                } else {
                    if i != 0 {
                        self.permutation.permute_mut(&mut state);
                    }
                    break 'outer;
                }
            }
            self.permutation.permute_mut(&mut state);
        }
        state[..OUT].try_into().unwrap()
    }
}
