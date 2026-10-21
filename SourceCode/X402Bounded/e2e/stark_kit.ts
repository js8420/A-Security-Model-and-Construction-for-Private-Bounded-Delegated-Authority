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

/** Where some fields sit in the encoding, so that a test can change one byte range and nothing else. */
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

/** Walks the encoding as the parser does, without checking it, and records the offsets of the first of each field. */
export function offsets(b: Uint8Array): Offsets {
  let at = 0;
  const u64 = () => {
    let v = 0n;
    for (let i = 7; i >= 0; i--) v = (v << 8n) | BigInt(b[at + i]);
    at += 8;
    return v;
  };
  const vec = (item: () => void) => {
    const n = Number(u64());
    for (let i = 0; i < n; i++) item();
  };
  const option = (item: () => void) => {
    if (b[at++] === 1) item();
  };
  const skip = (n: number) => () => {
    at += n;
  };
  const cap = () => vec(skip(32));
  const o: Partial<Offsets> = {};
  cap();
  cap();
  option(cap);
  o.traceLocal = at + 8;
  vec(skip(16));
  option(() => vec(skip(16)));
  option(() => vec(skip(16)));
  option(() => vec(skip(16)));
  o.quotientChunk = at + 16;
  vec(() => vec(skip(16)));
  option(() => vec(skip(16)));
  vec(() => vec(() => vec(() => vec(skip(16)))));
  vec(cap);
  vec(skip(8));
  vec(() => {
    const first = o.inputRow === undefined;
    vec(() => {
      if (first && o.inputRow === undefined) o.inputRow = at + 16;
      vec(() => vec(skip(8)));
      if (first && o.inputSalt === undefined) o.inputSalt = at + 16;
      vec(() => vec(skip(8)));
      if (first && o.inputSibling === undefined) o.inputSibling = at + 8;
      vec(skip(32));
    });
    vec(() => {
      at += 1;
      if (first && o.foldSibling === undefined) o.foldSibling = at + 8;
      vec(skip(16));
      vec(() => vec(skip(8)));
      vec(skip(32));
    });
  });
  o.finalPoly = at + 8;
  vec(skip(16));
  o.queryPow = at;
  at += 8;
  o.degreeBits = at;
  at += 8;
  o.publicValue = at + 8;
  return o as Offsets;
}

/** The checks a refusal is sorted into, in the order both verifiers make them. */
export const CHECKS = [
  "accepted", "parsing", "shape", "out-of-domain point", "grinding", "input opening", "fold opening", "final polynomial", "constraints",
] as const;
export type Check = (typeof CHECKS)[number];

/** The check behind the independent verifier's verdict. */
export function independentCheck(v: { ok: true } | { ok: false; reason: string }): Check {
  if (v.ok) return "accepted";
  const r = v.reason;
  if (r.startsWith("malformed")) return "parsing";
  if (r === "out-of-domain point on the trace domain") return "out-of-domain point";
  if (r === "commit grinding" || r === "query grinding") return "grinding";
  if (r.startsWith("input commitment opening")) return "input opening";
  if (r.startsWith("fold commitment opening")) return "fold opening";
  if (r === "final polynomial disagrees with the fold") return "final polynomial";
  if (r === "constraints do not match the quotient at the out-of-domain point") return "constraints";
  return "shape";
}

/** The check behind the deployed verifier's verdict, as `verify-file` prints it. */
export function deployedCheck(line: string): Check {
  const l = line.trim();
  if (l.startsWith("accept")) return "accepted";
  const r = l.replace(/^reject\s+/, "");
  if (r.startsWith("malformed")) return "parsing";
  if (r.includes("OodPointInDomain")) return "out-of-domain point";
  if (r.includes("InvalidPowWitness")) return "grinding";
  if (r.includes("InputError")) return "input opening";
  if (r.includes("CommitPhaseMmcsError")) return "fold opening";
  if (r.includes("FinalPolyMismatch")) return "final polynomial";
  if (r.includes("OodEvaluationMismatch")) return "constraints";
  return "shape";
}
