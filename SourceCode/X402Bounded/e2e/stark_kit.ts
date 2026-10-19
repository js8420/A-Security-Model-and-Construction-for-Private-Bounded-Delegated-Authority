import type { E } from "../src/stark/field.js";
import type { Digest, StarkProof } from "../src/stark/proof.js";

/** The inverse of parse: a proof and its public values back to the bincode the deployed prover writes. */
export function encode(p: StarkProof, pv: readonly bigint[]): Uint8Array {
  const out: number[] = [];
  const u8 = (v: number) => out.push(v & 0xff);
  const u64 = (v: bigint) => {
    let x = BigInt.asUintN(64, v);
    for (let i = 0; i < 8; i++) {
      out.push(Number(x & 0xffn));
      x >>= 8n;
    }
  };
  const vec = <T>(xs: readonly T[], item: (x: T) => void) => {
    u64(BigInt(xs.length));
    for (const x of xs) item(x);
  };
  const option = <T>(x: T | null, item: (x: T) => void) => {
    if (x === null) u8(0);
    else {
      u8(1);
      item(x);
    }
  };
  const e = (x: E) => {
    u64(x[0]);
    u64(x[1]);
  };
  const digest = (d: Digest) => d.forEach(u64);
  const cap = (c: readonly Digest[]) => vec(c, digest);
  cap(p.traceCap);
  cap(p.quotientCap);
  option(p.randomCap, cap);
  vec(p.traceLocal, e);
  option(p.traceNext, (x) => vec(x, e));
  option(p.preprocessedLocal, (x) => vec(x, e));
  option(p.preprocessedNext, (x) => vec(x, e));
  vec(p.quotientChunks, (c) => vec(c, e));
  option(p.random, (x) => vec(x, e));
  vec(p.randomOpenings, (a) => vec(a, (b) => vec(b, (c) => vec(c, e))));
  vec(p.friCaps, cap);
  vec(p.commitPow, u64);
  vec(p.queries, (q) => {
    vec(q.inputs, (o) => {
      vec(o.rows, (r) => vec(r, u64));
      vec(o.salts, (s) => vec(s, u64));
      vec(o.siblings, digest);
    });
    vec(q.steps, (s) => {
      u8(s.logArity);
      vec(s.siblings, e);
      vec(s.opening.salts, (x) => vec(x, u64));
      vec(s.opening.siblings, digest);
    });
  });
  vec(p.finalPoly, e);
  u64(p.queryPow);
  u64(BigInt(p.degreeBits));
  vec(pv, u64);
  return Uint8Array.from(out);
}

/** A deep copy, so that a test can change one field and leave the original whole. */
export const copy = (p: StarkProof): StarkProof => structuredClone(p) as StarkProof;
