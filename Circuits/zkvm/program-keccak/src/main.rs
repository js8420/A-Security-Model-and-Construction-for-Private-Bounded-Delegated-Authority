//! Inside the zkVM: the Plonky3 verifier with Keccak commitments and a Keccak
//! transcript, otherwise the deployed parameters, run on one proof of a batch
//! of payments against the composed circuit. It commits the Keccak root of the
//! payments' statements, each the leaf the reserve rebuilds from its record.
//! Keccak reaches SP1's precompile through the patched tiny-keccak.
//!
//! The circuit's own source files are compiled in unchanged, so the AIR the
//! zkVM checks is the AIR the agent proved.

#![no_main]
sp1_zkvm::entrypoint!(main);

#[path = "../../../src/air.rs"]
#[allow(dead_code)]
mod air;
#[path = "../../../src/composed.rs"]
#[allow(dead_code)]
mod composed;
#[path = "../../../src/full.rs"]
#[allow(dead_code)]
mod full;
#[path = "../../../src/hash.rs"]
#[allow(dead_code)]
mod hash;
#[path = "../../../src/merkle.rs"]
#[allow(dead_code)]
mod merkle;
#[path = "../../../src/revocation.rs"]
#[allow(dead_code)]
mod revocation;
#[path = "../../../src/spend.rs"]
#[allow(dead_code)]
mod spend;
#[path = "../../../src/statement.rs"]
#[allow(dead_code)]
mod statement;
#[path = "../../../src/whole.rs"]
#[allow(dead_code)]
mod whole;

use core::convert::Infallible;

use p3_challenger::{HashChallenger, SerializingChallenger64};
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::extension::BinomialExtensionField;
use p3_field::PrimeField64;
use p3_fri::{FriParameters, HidingFriPcs};
use p3_goldilocks::Goldilocks;
use p3_keccak::{Keccak256Hash, KeccakF, VECTOR_LEN};
use p3_merkle_tree::MerkleTreeHidingMmcs;
use p3_symmetric::{CompressionFunctionFromHasher, PaddingFreeSponge, SerializingHasher};
use p3_uni_stark::{verify, Proof, StarkConfig};
use rand_core::{TryCryptoRng, TryRng};

type Val = Goldilocks;
type Challenge = BinomialExtensionField<Val, 2>;
type U64Hash = PaddingFreeSponge<KeccakF, 25, 17, 4>;
type FieldHash = SerializingHasher<U64Hash>;
type Compress = CompressionFunctionFromHasher<U64Hash, 2, 4>;
type ValMmcs = MerkleTreeHidingMmcs<[Val; VECTOR_LEN], [u64; VECTOR_LEN], FieldHash, Compress, NoRng, 2, 4, 2>;
type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
type Pcs = HidingFriPcs<Val, Radix2DitParallel<Val>, ValMmcs, ChallengeMmcs, NoRng>;
type Config = StarkConfig<Pcs, Challenge, SerializingChallenger64<Val, HashChallenger<u8, Keccak256Hash, 32>>>;

/// Verification draws no randomness; the hiding types still name a source.
#[derive(Clone, Debug)]
struct NoRng;

impl TryRng for NoRng {
    type Error = Infallible;
    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        unreachable!("verification draws no randomness")
    }
    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        unreachable!("verification draws no randomness")
    }
    fn try_fill_bytes(&mut self, _: &mut [u8]) -> Result<(), Infallible> {
        unreachable!("verification draws no randomness")
    }
}

impl TryCryptoRng for NoRng {}

// The deployed parameters, as Circuits/src/prover.rs sets them. A mismatch
// fails verification, so the run checks them.
const LOG_BLOWUP: usize = 4;
const LOG_FINAL_POLY_LEN: usize = 3;
const NUM_QUERIES: usize = 40;
const POW_BITS: usize = 20;
const NUM_RANDOM_CODEWORDS: usize = 2;

fn config() -> Config {
    let u64_hash = U64Hash::new(KeccakF {});
    let mmcs = || ValMmcs::new(FieldHash::new(u64_hash), Compress::new(u64_hash), 0, NoRng);
    let fri = FriParameters {
        log_blowup: LOG_BLOWUP,
        log_final_poly_len: LOG_FINAL_POLY_LEN,
        max_log_arity: 2,
        num_queries: NUM_QUERIES,
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: POW_BITS,
        mmcs: ChallengeMmcs::new(mmcs()),
    };
    let pcs = Pcs::new(Radix2DitParallel::default(), mmcs(), fri, NUM_RANDOM_CODEWORDS, NoRng);
    StarkConfig::new(pcs, SerializingChallenger64::from_hasher(vec![], Keccak256Hash {}))
}

pub fn main() {
    let bytes = sp1_zkvm::io::read_vec();
    let (proof, pv): (Proof<Config>, Vec<Val>) = bincode::deserialize(&bytes).expect("proof and public values");
    let air = composed::ComposedAir::<0, 16, 32, 16, 64>::from_public_values(&pv);
    verify(&config(), &air, &proof, &pv).expect("the proof verifies");
    let values: Vec<u64> = pv.iter().map(|v| v.as_canonical_u64()).collect();
    sp1_zkvm::io::commit_slice(&statement::committed(&values, 64));
}
