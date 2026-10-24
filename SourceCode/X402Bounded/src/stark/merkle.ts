import { keccakP } from "@noble/hashes/sha3";
import type { Digest } from "./proof.js";

const RATE = 17;
const MASK = 0xffffffffn;

/** "merkle1" in ASCII, the last capacity lane's starting value. */
const TAG = 0x31656c6b72656dn;

/**
 * The deployed leaf and node hash: a sponge over Keccak-f[1600] that starts
 * with the tag in its last lane, whose first 17 lanes are overwritten by the
 * input, 64 bits a lane, permuted after every full block and after a final
 * partial one, then read out as four lanes.
 */
export function sponge(words: Iterable<bigint>): Digest {
  const s = new Uint32Array(50);
  s[48] = Number(TAG & MASK);
  s[49] = Number(TAG >> 32n);
  let i = 0;
  for (const w of words) {
    s[2 * i] = Number(w & MASK);
    s[2 * i + 1] = Number(w >> 32n);
    i += 1;
    if (i === RATE) {
      keccakP(s);
      i = 0;
    }
  }
  if (i !== 0) keccakP(s);
  const lane = (k: number) => (BigInt(s[2 * k + 1]) << 32n) | BigInt(s[2 * k]);
  return [lane(0), lane(1), lane(2), lane(3)];
}

export function compress(left: Digest, right: Digest): Digest {
  return sponge([...left, ...right]);
}

const same = (a: Digest, b: Digest) => a[0] === b[0] && a[1] === b[1] && a[2] === b[2] && a[3] === b[3];

/**
 * Checks one salted opening against a commitment whose matrices all have the
 * same power-of-two height: the leaf hashes every matrix's row followed by its
 * salt, in matrix order, and the path climbs by pairs to a single root. Any
 * other shape is refused, since the deployed proofs have no other. Returns
 * null if the opening holds, and otherwise why it does not.
 */
export function verifyOpening(
  cap: readonly Digest[],
  height: number,
  index: number,
  rows: readonly (readonly bigint[])[],
  salts: readonly (readonly bigint[])[],
  siblings: readonly Digest[],
  saltElems: number,
): string | null {
  if (cap.length !== 1) return "cap is not a single root";
  if (height < 1 || (height & (height - 1)) !== 0) return "height is not a power of two";
  if (index < 0 || index >= height) return "index outside the tree";
  if (rows.length === 0) return "no matrix opened";
  if (rows.length !== salts.length) return "one salt per matrix";
  if (salts.some((s) => s.length !== saltElems)) return "salt length";
  if (siblings.length !== Math.log2(height)) return "path length";
  function* leaf() {
    for (let m = 0; m < rows.length; m++) {
      yield* rows[m];
      yield* salts[m];
    }
  }
  let d = sponge(leaf());
  let at = index;
  for (const sib of siblings) {
    d = at % 2 === 0 ? compress(d, sib) : compress(sib, d);
    at = Math.floor(at / 2);
  }
  return same(d, cap[0]) ? null : "root differs";
}
