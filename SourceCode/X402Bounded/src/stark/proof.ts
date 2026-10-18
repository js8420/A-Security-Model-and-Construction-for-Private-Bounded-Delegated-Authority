import { P, type E } from "./field.js";

/** A Merkle digest: four 64-bit lanes of a Keccak-f state. */
export type Digest = readonly [bigint, bigint, bigint, bigint];

/** A salted Merkle opening: one row per matrix, its salt, and the sibling digests from leaf to root. */
export interface Opening<T> {
  rows: T[][];
  salts: bigint[][];
  siblings: Digest[];
}

export interface FoldStep {
  logArity: number;
  siblings: E[];
  opening: { salts: bigint[][]; siblings: Digest[] };
}

export interface Query {
  inputs: Opening<bigint>[];
  steps: FoldStep[];
}

/** A proof of the deployed configuration, field by field in the order it is encoded. */
export interface StarkProof {
  traceCap: Digest[];
  quotientCap: Digest[];
  randomCap: Digest[] | null;
  traceLocal: E[];
  traceNext: E[] | null;
  preprocessedLocal: E[] | null;
  preprocessedNext: E[] | null;
  quotientChunks: E[][];
  random: E[] | null;
  randomOpenings: E[][][][];
  friCaps: Digest[][];
  commitPow: bigint[];
  queries: Query[];
  finalPoly: E[];
  queryPow: bigint;
  degreeBits: number;
}

/** Where some fields sit in the encoding, so that tests can change one byte range and nothing else. */
export interface Offsets {
  degreeBits: number;
  traceLocal: number;
  quotientChunk: number;
  queryPow: number;
  finalPoly: number;
  inputRow: number;
  inputSalt: number;
  inputSibling: number;
  foldSibling: number;
  publicValue: number;
}

class Reader {
  at = 0;
  constructor(private readonly b: Uint8Array) {}

  private need(n: number) {
    if (this.at + n > this.b.length) throw new Error("malformed: truncated");
  }

  u8(): number {
    this.need(1);
    return this.b[this.at++];
  }

  u64(): bigint {
    this.need(8);
    let v = 0n;
    for (let i = 7; i >= 0; i--) v = (v << 8n) | BigInt(this.b[this.at + i]);
    this.at += 8;
    return v;
  }

  len(): number {
    const n = this.u64();
    if (n > BigInt(this.b.length - this.at)) throw new Error("malformed: length");
    return Number(n);
  }

  f(): bigint {
    const v = this.u64();
    if (v >= P) throw new Error("malformed: non-canonical field element");
    return v;
  }

  e(): E {
    return [this.f(), this.f()];
  }

  vec<T>(item: () => T): T[] {
    const n = this.len();
    const out: T[] = new Array(n);
    for (let i = 0; i < n; i++) out[i] = item();
    return out;
  }

  option<T>(item: () => T): T | null {
    const tag = this.u8();
    if (tag === 0) return null;
    if (tag === 1) return item();
    throw new Error("malformed: option tag");
  }

  digest(): Digest {
    return [this.u64(), this.u64(), this.u64(), this.u64()];
  }

  cap(): Digest[] {
    return this.vec(() => this.digest());
  }

  done(): boolean {
    return this.at === this.b.length;
  }
}

/** Reads the exported file, which is bincode of (proof, public values), and refuses anything else. */
export function parse(bytes: Uint8Array): { proof: StarkProof; pv: bigint[]; offsets: Offsets } {
  const r = new Reader(bytes);
  const o: Partial<Offsets> = {};
  const traceCap = r.cap();
  const quotientCap = r.cap();
  const randomCap = r.option(() => r.cap());
  o.traceLocal = r.at + 8;
  const traceLocal = r.vec(() => r.e());
  const traceNext = r.option(() => r.vec(() => r.e()));
  const preprocessedLocal = r.option(() => r.vec(() => r.e()));
  const preprocessedNext = r.option(() => r.vec(() => r.e()));
  o.quotientChunk = r.at + 16;
  const quotientChunks = r.vec(() => r.vec(() => r.e()));
  const random = r.option(() => r.vec(() => r.e()));
  const randomOpenings = r.vec(() => r.vec(() => r.vec(() => r.vec(() => r.e()))));
  const friCaps = r.vec(() => r.cap());
  const commitPow = r.vec(() => r.f());
  const queries = r.vec((): Query => {
    const first = o.inputRow === undefined;
    const inputs = r.vec((): Opening<bigint> => {
      if (first && o.inputRow === undefined) o.inputRow = r.at + 16;
      const rows = r.vec(() => r.vec(() => r.f()));
      if (first && o.inputSalt === undefined) o.inputSalt = r.at + 16;
      const salts = r.vec(() => r.vec(() => r.f()));
      if (first && o.inputSibling === undefined) o.inputSibling = r.at + 8;
      const siblings = r.vec(() => r.digest());
      return { rows, salts, siblings };
    });
    const steps = r.vec((): FoldStep => {
      const logArity = r.u8();
      if (first && o.foldSibling === undefined) o.foldSibling = r.at + 8;
      const siblings = r.vec(() => r.e());
      const salts = r.vec(() => r.vec(() => r.f()));
      const sibs = r.vec(() => r.digest());
      return { logArity, siblings, opening: { salts, siblings: sibs } };
    });
    return { inputs, steps };
  });
  o.finalPoly = r.at + 8;
  const finalPoly = r.vec(() => r.e());
  o.queryPow = r.at;
  const queryPow = r.f();
  o.degreeBits = r.at;
  const degreeBits = r.u64();
  if (degreeBits > 32n) throw new Error("malformed: degree");
  o.publicValue = r.at + 8;
  const pv = r.vec(() => r.f());
  if (!r.done()) throw new Error("malformed: trailing bytes");
  const proof: StarkProof = {
    traceCap, quotientCap, randomCap, traceLocal, traceNext, preprocessedLocal, preprocessedNext,
    quotientChunks, random, randomOpenings, friCaps, commitPow, queries, finalPoly, queryPow,
    degreeBits: Number(degreeBits),
  };
  return { proof, pv, offsets: o as Offsets };
}
