import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { PARAMS, loadConstraints, maxDegree, verifyStark } from "../src/index.js";
import {
  add, bitrev, ebatchInv, eeq, einv, emul, eneg, epow, escale, esquarings, esub, ezero, inv, mul, neg, pow, sub, twoAdic, type E,
} from "../src/stark/field.js";
import { compress, sponge, verifyOpening } from "../src/stark/merkle.js";
import { parse, type Digest } from "../src/stark/proof.js";
import { Transcript } from "../src/stark/transcript.js";
import { copy, encode } from "./stark_kit.js";

/**
 * The independent verifier's own test set, run alone. Its hash, field and
 * transcript must give the answers Plonky3 gives on the exported vectors; its
 * Merkle check must refuse every opening of the wrong shape; the honest proofs
 * must pass; and every altered proof, every proof of the wrong shape, every
 * proof of a statement with no witness and every altered constraint graph must
 * be refused. It stops at the first
 * check that fails and exits 1, so a mutation of the verifier that any check
 * notices is caught quickly.
 */
const P = 0xffffffff00000001n;
const env = (k: string) => {
  const v = process.env[k];
  if (!v) throw new Error(`${k} not set`);
  return v;
};
const air = loadConstraints(readFileSync(env("CONSTRAINTS")));
const full = new Uint8Array(readFileSync(env("PROOF_FULL")));
const small = new Uint8Array(readFileSync(env("PROOF_SMALL")));
const brokenDir = env("BROKEN_DIR");
const broken = readdirSync(brokenDir).filter((f) => f.startsWith("broken_") && f.endsWith(".bin")).sort()
  .map((f) => [f.slice(7, -4), new Uint8Array(readFileSync(join(brokenDir, f)))] as const);

let n = 0;
const need = (name: string, ok: boolean) => {
  n += 1;
  if (!ok) {
    console.log(`FAIL ${name}`);
    process.exit(1);
  }
};
const word = (b: Uint8Array, at: number) => {
  let v = 0n;
  for (let i = 7; i >= 0; i--) v = (v << 8n) | BigInt(b[at + i]);
  return v;
};
const withWord = (b: Uint8Array, at: number, v: bigint) => {
  const c = b.slice();
  for (let i = 0; i < 8; i++) c[at + i] = Number((v >> BigInt(8 * i)) & 0xffn);
  return c;
};
const bump = (b: Uint8Array, at: number) => withWord(b, at, (word(b, at) + 1n) % P);

const big = (x: string) => BigInt(x);
const ext = (x: readonly string[]): E => [big(x[0]), big(x[1])];
const sameD = (a: Digest, b: readonly string[]) => a.every((x, i) => x === big(b[i]));
const throws = (f: () => unknown) => {
  try {
    f();
    return false;
  } catch {
    return true;
  }
};
type Vectors = {
  sponge: { input: string[]; output: string[] }[];
  compress: { left: string[]; right: string[]; output: string[] }[];
  field: { a: string; b: string; add: string; sub: string; mul: string; inv: string; ea: string[]; eb: string[]; emul: string[]; einv: string[]; epow: string[] }[];
  twoAdic: string[];
  transcript: { op: string; value: string | string[]; bits?: number; holds?: boolean }[];
};
const vectors = JSON.parse(readFileSync(env("VECTORS"), "utf8")) as Vectors;

for (const v of vectors.sponge) need(`sponge of ${v.input.length} words`, sameD(sponge(v.input.map(big)), v.output));
for (const v of vectors.compress) {
  const d = (x: string[]) => x.map(big) as unknown as Digest;
  need("compression", sameD(compress(d(v.left), d(v.right)), v.output));
}
for (const v of vectors.field) {
  const a = big(v.a);
  const b = big(v.b);
  need("add", add(a, b) === big(v.add));
  need("sub", sub(a, b) === big(v.sub));
  need("mul", mul(a, b) === big(v.mul));
  need("inv", inv(a) === big(v.inv) && mul(a, inv(a)) === 1n);
  need("pow", pow(a, 3n) === mul(a, mul(a, a)) && pow(a, 0n) === 1n);
  need("neg", neg(a) === sub(0n, a) && add(a, neg(a)) === 0n);
  need("extension mul", eeq(emul(ext(v.ea), ext(v.eb)), ext(v.emul)));
  need("extension inverse", eeq(einv(ext(v.ea)), ext(v.einv)));
  need("extension power", eeq(epow(ext(v.ea), b), ext(v.epow)));
  need("extension negation", ezero(esub(eneg(ext(v.ea)), esub([0n, 0n], ext(v.ea)))));
  need("squarings", eeq(esquarings(ext(v.ea), 5), epow(ext(v.ea), 32n)));
  need("scale", eeq(escale(ext(v.ea), b), emul(ext(v.ea), [b, 0n])));
}
need("neg of zero", neg(0n) === 0n);
need("inverse of zero refused", throws(() => inv(0n)));
const batch = vectors.field.slice(1, 9).map((v) => ext(v.ea));
need("batch inverse", ebatchInv(batch).every((x, i) => eeq(x, einv(batch[i]))));
need("batch inverse of one element", eeq(ebatchInv([batch[0]])[0], einv(batch[0])));
for (let bits = 0; bits <= 32; bits++) need(`two-adic generator of order 2^${bits}`, twoAdic(bits) === big(vectors.twoAdic[bits]));
need("two-adic order above 32 refused", throws(() => twoAdic(33)) && throws(() => twoAdic(-1)));
need("bit reversal", bitrev(1, 3) === 4 && bitrev(6, 3) === 3 && bitrev(5, 4) === 10 && bitrev(0, 5) === 0 && bitrev(31, 5) === 31 && bitrev(1, 0) === 0);

{
  let t = new Transcript();
  const fork = (from: Transcript) => Object.assign(new Transcript(), structuredClone(from)) as Transcript;
  let before = t;
  for (const s of vectors.transcript) {
    if (s.op === "observe") t.observe(big(s.value as string));
    else if (s.op === "observeExt") t.observeExt(ext(s.value as string[]));
    else if (s.op === "sample") need("transcript sample", t.sample() === big(s.value as string));
    else if (s.op === "sampleExt") need("transcript extension sample", eeq(t.sampleExt(), ext(s.value as string[])));
    else if (s.op === "sampleBits") need(`transcript ${s.bits}-bit sample`, t.sampleBits(s.bits as number) === Number(s.value));
    else if (s.op === "witness") {
      before = fork(t);
      need("grinding witness accepted", t.checkWitness(s.bits as number, big(s.value as string)) === s.holds);
    } else if (s.op === "witnessAlone") need("a wrong grinding witness refused", fork(before).checkWitness(s.bits as number, big(s.value as string)) === s.holds);
    else if (s.op === "sampleAfterWitness") need("transcript after the witness", t.sample() === big(s.value as string));
  }
  need("bit samples above 52 refused", throws(() => new Transcript().sampleBits(53)) && throws(() => new Transcript().sampleBits(-1)));
  need("no grinding at zero bits", new Transcript().checkWitness(0, 12345n));
  const long = new Transcript();
  for (let i = 0; i < 9000; i++) long.observe(BigInt(i));
  const again = new Transcript();
  for (let i = 0; i < 9000; i++) again.observe(BigInt(i));
  again.observe(1n);
  need("a transcript past its first buffer still binds every word", long.sample() !== again.sample());
}

{
  const word = (k: number, i: number) => BigInt(k * 1000 + i);
  const leafOf = (rows: bigint[][], salts: bigint[][]) => sponge(rows.flatMap((r, m) => [...r, ...salts[m]]));
  const build = (n: number, saltLen: number, matrices: number) => {
    const rows = Array.from({ length: n }, (_, k) => Array.from({ length: matrices }, (_, m) => [word(k, 10 * m), word(k, 10 * m + 1), word(k, 10 * m + 2)]));
    const salts = Array.from({ length: n }, (_, k) => Array.from({ length: matrices }, (_, m) => Array.from({ length: saltLen }, (_, j) => word(k, 100 + 10 * m + j))));
    let level: Digest[] = rows.map((r, k) => leafOf(r, salts[k]));
    const levels: Digest[][] = [level];
    while (level.length > 1) {
      const up: Digest[] = [];
      for (let i = 0; i < level.length; i += 2) up.push(compress(level[i], level[i + 1]));
      level = up;
      levels.push(level);
    }
    const path = (index: number) => levels.slice(0, -1).map((l, j) => l[(index >> j) ^ 1]);
    return { rows, salts, root: level[0], path };
  };
  const t8 = build(8, 2, 2);
  const ok = (cap: Digest[], h: number, i: number, rows: bigint[][], salts: bigint[][], sib: Digest[], se = 2) => {
    try {
      return verifyOpening(cap, h, i, rows, salts, sib, se);
    } catch {
      return false;
    }
  };
  for (let i = 0; i < 8; i++) need(`honest opening ${i}`, ok([t8.root], 8, i, t8.rows[i], t8.salts[i], t8.path(i)));
  need("cap of two refused", !ok([t8.root, t8.root], 8, 3, t8.rows[3], t8.salts[3], t8.path(3)));
  need("empty cap refused", !ok([], 8, 3, t8.rows[3], t8.salts[3], t8.path(3)));
  for (let lane = 0; lane < 4; lane++) {
    const c = [...t8.root] as bigint[];
    c[lane] ^= 1n;
    need(`root differing in lane ${lane} refused`, !ok([c as unknown as Digest], 8, 3, t8.rows[3], t8.salts[3], t8.path(3)));
  }
  need("wrong index refused", !ok([t8.root], 8, 2, t8.rows[3], t8.salts[3], t8.path(3)));
  need("index at the height refused, though its low bits match", !ok([t8.root], 8, 8, t8.rows[0], t8.salts[0], t8.path(0)));
  need("negative index refused", !ok([t8.root], 8, -8, t8.rows[0], t8.salts[0], t8.path(0)));
  const t1 = build(1, 2, 2);
  need("a tree of one leaf opens with no siblings", ok([t1.root], 1, 0, t1.rows[0], t1.salts[0], []));
  need("height zero refused", !ok([t1.root], 0, 0, t1.rows[0], t1.salts[0], []));
  const t16 = build(16, 2, 2);
  need("siblings of a taller tree refused", !ok([t16.root], 8, 3, t16.rows[3], t16.salts[3], t16.path(3)));
  need("one sibling short refused", !ok([t8.root], 8, 3, t8.rows[3], t8.salts[3], t8.path(3).slice(0, 2)));
  need("height not a power of two refused", !ok([t8.root], 6, 3, t8.rows[3], t8.salts[3], t8.path(3)));
  const one = build(8, 2, 1);
  need("an extra salt beyond the matrices refused", !ok([one.root], 8, 3, one.rows[3], [one.salts[3][0], [5n, 6n]], one.path(3)));
  const t3 = build(8, 3, 2);
  need("salts of the wrong length refused", !ok([t3.root], 8, 3, t3.rows[3], t3.salts[3], t3.path(3), 2));
  const emptyLeaf = sponge([]);
  const sib = t8.path(0);
  let r = emptyLeaf;
  for (let j = 0; j < 3; j++) r = compress(r, sib[j]);
  need("an opening of no matrices refused", !ok([r], 8, 0, [], [], sib));
  need("one row and no salts refused", !ok([t8.root], 8, 3, t8.rows[3], [], t8.path(3)));
}

need("degree", maxDegree(air) === PARAMS.statedDegree);
need("honest 4", verifyStark(small, air).ok);
const o = parse(full).offsets;
const COL_CID = 2;
const R_AMOUNT = 6;
const tampered: [string, Uint8Array][] = [
  ["category opened", bump(full, o.traceLocal + 16 * COL_CID)],
  ["quotient chunk", bump(full, o.quotientChunk)],
  ["public amount", bump(full, o.publicValue + 8 * (air.globals + R_AMOUNT))],
  ["trace value at a query", bump(full, o.inputRow)],
  ["trace salt", bump(full, o.inputSalt)],
  ["trace sibling", bump(full, o.inputSibling)],
  ["fold sibling", bump(full, o.foldSibling)],
  ["final polynomial", bump(full, o.finalPoly)],
  ["query witness", bump(full, o.queryPow)],
  ["degree", withWord(full, o.degreeBits, word(full, o.degreeBits) + 1n)],
  ["witness + p", withWord(full, o.queryPow, word(full, o.queryPow) + P)],
  ["truncated", full.slice(0, full.length - 1)],
  ["appended", Uint8Array.from([...full, 0])],
];
for (const [name, b] of tampered) need(name, !verifyStark(b, air).ok);
const base = parse(full);
need("the encoder writes back the file it read", Buffer.from(encode(base.proof, base.pv)).equals(Buffer.from(full)));
const reshaped = (name: string, change: (p: ReturnType<typeof copy>, pv: bigint[]) => void) => {
  const p = copy(base.proof);
  const pv = [...base.pv];
  change(p, pv);
  need(name, !verifyStark(encode(p, pv), air).ok);
};
const at = <T>(xs: T[] | null) => xs as T[];
reshaped("trace opening one value short", (p) => at(p.traceLocal).pop());
reshaped("trace opening one value long", (p) => at(p.traceLocal).push([1n, 2n]));
reshaped("next-row opening missing", (p) => { p.traceNext = null; });
reshaped("next-row opening one value short", (p) => at(p.traceNext).pop());
reshaped("a preprocessed opening present", (p) => { p.preprocessedLocal = [[1n, 0n]]; });
reshaped("a preprocessed next-row opening present", (p) => { p.preprocessedNext = [[1n, 0n]]; });
reshaped("one quotient chunk missing", (p) => p.quotientChunks.pop());
reshaped("a quotient chunk of three values", (p) => p.quotientChunks[0].push([0n, 0n]));
reshaped("a quotient chunk of one value", (p) => p.quotientChunks[3].pop());
reshaped("random opening missing", (p) => { p.random = null; });
reshaped("random opening of one value", (p) => at(p.random).pop());
reshaped("random commitment missing", (p) => { p.randomCap = null; });
reshaped("hidden openings for two rounds", (p) => p.randomOpenings.pop());
reshaped("hidden openings for an extra matrix", (p) => p.randomOpenings[0].push(p.randomOpenings[0][0]));
reshaped("hidden openings for an extra point", (p) => p.randomOpenings[1][0].push(p.randomOpenings[1][0][0]));
reshaped("one hidden codeword short", (p) => p.randomOpenings[2][0][0].pop());
reshaped("one fold commitment missing", (p) => p.friCaps.pop());
reshaped("one commit grinding witness missing", (p) => p.commitPow.pop());
reshaped("one query missing", (p) => p.queries.pop());
reshaped("one query repeated", (p) => p.queries.push(p.queries[0]));
reshaped("one query's arity schedule different", (p) => { p.queries[5].steps[0].logArity = p.queries[5].steps[0].logArity === 1 ? 2 : 1; });
reshaped("arity three in every query", (p) => p.queries.forEach((q) => { q.steps[0].logArity = 3; }));
reshaped("arity zero in every query", (p) => p.queries.forEach((q) => { q.steps[0].logArity = 0; }));
reshaped("one fold step missing in every query", (p) => p.queries.forEach((q) => q.steps.pop()));
reshaped("one fold step missing in one query", (p) => p.queries[7].steps.pop());
reshaped("one fold sibling missing", (p) => p.queries[0].steps[0].siblings.pop());
reshaped("one input opening missing", (p) => p.queries[0].inputs.pop());
reshaped("one input row missing", (p) => p.queries[0].inputs[2].rows.pop());
reshaped("one opened value missing from a row", (p) => p.queries[0].inputs[1].rows[0].pop());
reshaped("final polynomial one coefficient short", (p) => p.finalPoly.pop());
reshaped("final polynomial one coefficient long", (p) => p.finalPoly.push([0n, 0n]));
reshaped("degree one", (p) => { p.degreeBits = 1; });
reshaped("degree twenty-nine", (p) => { p.degreeBits = 29; });
reshaped("one public value missing", (_, pv) => pv.pop());
reshaped("one payment missing from the public values", (_, pv) => pv.splice(pv.length - air.rowWidth, air.rowWidth));
reshaped("public values holding the terms alone", (_, pv) => pv.splice(air.globals));
reshaped("three payments in the public values", (_, pv) => pv.splice(air.globals + 3 * air.rowWidth));
need("five broken", broken.length === 5);
for (const [name, b] of broken) need(name, !verifyStark(b, air).ok);
const constant = [...air.constants.keys()].find((k) => air.constants.get(k) !== 0n) as number;
need("constant changed", !verifyStark(full, { ...air, constants: new Map(air.constants).set(constant, (air.constants.get(constant) as bigint) + 1n) }).ok);
need("last constraint dropped", !verifyStark(full, { ...air, roots: air.roots.subarray(0, air.roots.length - 1) }).ok);
need("two constraints exchanged", !verifyStark(full, { ...air, roots: Uint32Array.from([air.roots[1], air.roots[0], ...air.roots.subarray(2)]) }).ok);
need("honest 128", verifyStark(full, air).ok);
console.log(`all ${n} checks pass`);
