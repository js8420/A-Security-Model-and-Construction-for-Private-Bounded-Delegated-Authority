# Transcript audit: Plonky3 0.6.3 against the independent verifier

This file lists every message the deployed verifier absorbs into its
Fiat-Shamir transcript, and every challenge it draws, in order. Each row names
the Plonky3 0.6.3 source line and the line of the independent verifier in this
package that does the same thing. To repeat the audit for a later Plonky3
release, open the same functions in that release and check each row.

Plonky3 paths are inside the crates as published on crates.io, version 0.6.3:
`p3-uni-stark/src/verifier.rs`, `p3-fri/src/hiding_pcs.rs`,
`p3-fri/src/two_adic_pcs.rs`, `p3-fri/src/verifier.rs`,
`p3-challenger/src/serializing_challenger.rs`,
`p3-challenger/src/hash_challenger.rs` and
`p3-challenger/src/grinding_challenger.rs`. The independent verifier's paths
are under `src/stark/` in this package.

## The challenger

The deployed challenger is `SerializingChallenger64<Goldilocks, HashChallenger<u8, Keccak256Hash, 32>>`.

| Step | Plonky3 0.6.3 | Independent verifier |
|---|---|---|
| A field element is absorbed as the 8 little-endian bytes of its canonical value | serializing_challenger.rs 264 to 267 | transcript.ts 28 to 34 |
| A Merkle cap of `[u64; 4]` digests is absorbed lane by lane, 8 little-endian bytes a lane | serializing_challenger.rs 313 to 317 | transcript.ts 46 to 47 |
| Absorbing clears any output not yet handed out | hash_challenger.rs 51 to 53 | transcript.ts 29 |
| A draw with no output pending hashes the whole input with Keccak-256; the digest becomes both the new input and the output | hash_challenger.rs 36 to 43 | transcript.ts 51 to 55 |
| Output bytes are handed out from the last one back | hash_challenger.rs 130 to 136 | transcript.ts 57 |
| A base-field sample reads 8 bytes little-endian and rejects values at or above p | serializing_challenger.rs 343 to 352 | transcript.ts 6 and 60 to 72 |
| An extension sample is two base samples, the constant coefficient first | serializing_challenger.rs 336 to 354 | transcript.ts 74 to 78 |
| A bit sample masks the low bits of one 8-byte draw | serializing_challenger.rs 362 to 367 | transcript.ts 80 to 83 |
| A grinding check with zero bits passes without absorbing anything | grinding_challenger.rs 43 to 45 | transcript.ts 87 |
| Otherwise it absorbs the witness and requires the next bits drawn to be zero | grinding_challenger.rs 46 to 47 | transcript.ts 88 to 89 |

## The order of absorption and challenges

| # | Message or challenge | Plonky3 0.6.3 | Independent verifier |
|---|---|---|---|
| 1 | degree_bits of the extended trace | uni-stark verifier.rs 400 | verify.ts 160 |
| 2 | base_degree_bits of the trace | uni-stark verifier.rs 401 | verify.ts 161 |
| 3 | preprocessed width, zero here | uni-stark verifier.rs 402 | verify.ts 162 |
| 4 | the trace commitment | uni-stark verifier.rs 408 | verify.ts 163 |
| 5 | no preprocessed commitment, as the width is zero | uni-stark verifier.rs 409 to 411 | verify.ts 151 refuses one |
| 6 | every public value, in order | uni-stark verifier.rs 412 | verify.ts 164 |
| 7 | challenge alpha, which folds the constraints | uni-stark verifier.rs 418 | verify.ts 165 |
| 8 | the quotient commitment | uni-stark verifier.rs 419 | verify.ts 166 |
| 9 | the random commitment of the hiding PCS | uni-stark verifier.rs 423 to 425 | verify.ts 167 |
| 10 | challenge zeta, the out-of-domain point | uni-stark verifier.rs 430 | verify.ts 168 |
| 11 | zeta on the trace domain is refused | uni-stark verifier.rs 435 to 437 | verify.ts 170 to 171 |
| 12 | the rounds in order: random, trace (at zeta and at the next point), quotient chunks | uni-stark verifier.rs 453 to 510 | verify.ts 181 to 185 |
| 13 | each point's hidden values appended to its public values, every level's count checked first | hiding_pcs.rs 397 to 433 | verify.ts 187 to 198 |
| 14 | every opened value of every point of every matrix of every round, in that order | two_adic_pcs.rs 696 to 702 | verify.ts 199 |
| 15 | challenge alpha of FRI, which batches the openings | fri verifier.rs 195 | verify.ts 232 |
| 16 | for each fold round: its commitment, its grinding check, then challenge beta | fri verifier.rs 301 to 311 | verify.ts 247 to 251 |
| 17 | the final polynomial's length checked, then its coefficients absorbed | fri verifier.rs 314 to 323 | verify.ts 252 to 253 |
| 18 | the query count checked | fri verifier.rs 326 to 331 | verify.ts 234 |
| 19 | every fold's log arity, in order | fri verifier.rs 333 to 336 | verify.ts 254 |
| 20 | the query grinding check | fri verifier.rs 339 to 341 | verify.ts 255 |
| 21 | for each query, its index: bits of the tallest height, with no extra bits for this folding | fri verifier.rs 352 to 353 | verify.ts 259 |

## The advisory this audit checks for

GHSA-vrmm-4mm5-38vm, published on 27 January 2025, reported that Plonky3 did
not absorb the opened values into the transcript before drawing the batching
challenge. It was fixed by pull request 627, commit
b5ec4d96bc752e78990db0707f6b60c4f3d9930a. In 0.6.3 the values are absorbed at
row 14, before the batching challenge at row 15. The independent verifier does
the same at verify.ts 199 and 232.

## How each row is tested

The vectors file the circuit binary writes with `export-vectors` holds the
outputs of Plonky3's own challenger for a fixed run of observations, samples,
bit samples and grinding checks. `e2e/stark_control.ts` replays that run
through the independent transcript and requires every output to match. It
also holds one observed value after which the first 64-bit draw is at or
above p, found by search, so the rejection step of a sample is tested
against Plonky3 as well. The
order of rows 1 to 21 is tested by the honest proofs: any step out of place
changes every later challenge, and the proof is refused.
