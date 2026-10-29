import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { PARAMS, loadConstraints, maxDegree, verifyStark } from "../src/index.js";
import { fold, type Constraints } from "../src/stark/constraints.js";
import { Batching, lagrange, logQuotientDegree, openInput, subgroupWeights } from "../src/stark/verify.js";
import {
  DEG, add, bitrev, eadd, ebatchInv, eeq, einv, emul, eneg, epow, escale, esquarings, esub, ezero, inv, lift, mul, neg, pow, sub, twoAdic, type E,
} from "../src/stark/field.js";
import { compress, sponge, verifyOpening } from "../src/stark/merkle.js";
import { parse, type Digest } from "../src/stark/proof.js";
import { Transcript, canonical } from "../src/stark/transcript.js";
import { copy, encode, offsets } from "./stark_kit.js";

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
const one1 = new Uint8Array(readFileSync(env("PROOF_ONE")));
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
const ext = (x: readonly string[]): E => [big(x[0]), big(x[1]), big(x[2]), big(x[3]), big(x[4])];
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
  rejection: { observed: string; sample: string };
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
  need("extension negation", ezero(esub(eneg(ext(v.ea)), esub([0n, 0n, 0n, 0n, 0n], ext(v.ea)))));
  need("squarings", eeq(esquarings(ext(v.ea), 5), epow(ext(v.ea), 32n)));
  need("scale", eeq(escale(ext(v.ea), b), emul(ext(v.ea), [b, 0n, 0n, 0n, 0n])));
}
need("neg of zero", neg(0n) === 0n);
need("inverse of zero refused", throws(() => inv(0n)));
const refusal = (f: () => unknown): string => {
  try {
    f();
    return "";
  } catch (e) {
    return (e as Error).message;
  }
};
need("extension inverse of zero refused as such", refusal(() => einv([0n, 0n, 0n, 0n, 0n])) === "inverse of zero");
for (const a of [[0n, 1n, 0n, 0n, 0n], [0n, 0n, 1n, 0n, 0n], [0n, 0n, 0n, 1n, 0n], [0n, 0n, 0n, 0n, 1n], [0n, 5n, 7n, 0n, 2n], [3n, 0n, 0n, 0n, 0n]] as E[]) {
  need(`extension inverse with a row exchange: ${a.join(", ")}`, eeq(emul(a, einv(a)), [1n, 0n, 0n, 0n, 0n]));
}
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
  const ok = (cap: Digest[], h: number, i: number, rows: bigint[][], salts: bigint[][], sib: Digest[], se = 2): string => {
    try {
      return verifyOpening(cap, h, i, rows, salts, sib, se) ?? "holds";
    } catch (e) {
      return `threw ${String(e)}`;
    }
  };
  for (let i = 0; i < 8; i++) need(`honest opening ${i}`, "holds" === ok([t8.root], 8, i, t8.rows[i], t8.salts[i], t8.path(i)));
  need("cap of two refused", "cap is not a single root" === ok([t8.root, t8.root], 8, 3, t8.rows[3], t8.salts[3], t8.path(3)));
  need("empty cap refused", "cap is not a single root" === ok([], 8, 3, t8.rows[3], t8.salts[3], t8.path(3)));
  for (let lane = 0; lane < 4; lane++) {
    const c = [...t8.root] as bigint[];
    c[lane] ^= 1n;
    need(`root differing in lane ${lane} refused`, "root differs" === ok([c as unknown as Digest], 8, 3, t8.rows[3], t8.salts[3], t8.path(3)));
  }
  need("wrong index refused", "root differs" === ok([t8.root], 8, 2, t8.rows[3], t8.salts[3], t8.path(3)));
  need("index at the height refused, though its low bits match", "index outside the tree" === ok([t8.root], 8, 8, t8.rows[0], t8.salts[0], t8.path(0)));
  need("negative index refused", "index outside the tree" === ok([t8.root], 8, -8, t8.rows[0], t8.salts[0], t8.path(0)));
  const t1 = build(1, 2, 2);
  need("a tree of one leaf opens with no siblings", "holds" === ok([t1.root], 1, 0, t1.rows[0], t1.salts[0], []));
  need("height zero refused", "height is not a power of two" === ok([t1.root], 0, 0, t1.rows[0], t1.salts[0], []));
  const t16 = build(16, 2, 2);
  need("siblings of a taller tree refused", "path length" === ok([t16.root], 8, 3, t16.rows[3], t16.salts[3], t16.path(3)));
  need("one sibling short refused", "path length" === ok([t8.root], 8, 3, t8.rows[3], t8.salts[3], t8.path(3).slice(0, 2)));
  need("height not a power of two refused", "height is not a power of two" === ok([t8.root], 6, 3, t8.rows[3], t8.salts[3], t8.path(3)));
  const one = build(8, 2, 1);
  need("an extra salt beyond the matrices refused", "one salt per matrix" === ok([one.root], 8, 3, one.rows[3], [one.salts[3][0], [5n, 6n]], one.path(3)));
  const t3 = build(8, 3, 2);
  need("salts of the wrong length refused", "salt length" === ok([t3.root], 8, 3, t3.rows[3], t3.salts[3], t3.path(3), 2));
  const emptyLeaf = sponge([]);
  const sib = t8.path(0);
  let r = emptyLeaf;
  for (let j = 0; j < 3; j++) r = compress(r, sib[j]);
  need("an opening of no matrices refused", "no matrix opened" === ok([r], 8, 0, [], [], sib));
  need("one row and no salts refused", "one salt per matrix" === ok([t8.root], 8, 3, t8.rows[3], [], t8.path(3)));
}

need("extension equality reads every coordinate", [0, 1, 2, 3, 4].every((i) => !eeq([1n, 2n, 3n, 4n, 5n], [1n, 2n, 3n, 4n, 5n].map((v, j) => (j === i ? v + 7n : v)) as unknown as E)) && eeq([4n, 5n, 6n, 7n, 8n], [4n, 5n, 6n, 7n, 8n]));
need("extension zero reads every coordinate", [0, 1, 2, 3, 4].every((i) => !ezero([0n, 0n, 0n, 0n, 0n].map((v, j) => (j === i ? 5n : v)) as unknown as E)) && ezero([0n, 0n, 0n, 0n, 0n]));
need("a draw of p - 1 is a field element and one of p is not", canonical(P - 1n) && !canonical(P) && !canonical(P + 1n));
need("bit samples of zero and of 52 bits", new Transcript().sampleBits(0) === 0 && new Transcript().sampleBits(52) >= 0);
{
  const r = vectors.rejection;
  const t = new Transcript();
  t.observe(big(r.observed));
  need("a draw at or above p is rejected and the next one taken", t.sample() === big(r.sample));
}

{
  const word = (k: number, i: number) => BigInt(k * 1000 + i);
  const rows = Array.from({ length: 8 }, (_, k) => [[word(k, 0), word(k, 1)], [word(k, 2)]]);
  const salts = Array.from({ length: 8 }, (_, k) => [[word(k, 10), word(k, 11)], [word(k, 12), word(k, 13), word(k, 14)]]);
  let level: Digest[] = rows.map((r, k) => sponge([...r[0], ...salts[k][0], ...r[1], ...salts[k][1]]));
  const levels: Digest[][] = [level];
  while (level.length > 1) {
    const up: Digest[] = [];
    for (let i = 0; i < level.length; i += 2) up.push(compress(level[i], level[i + 1]));
    level = up;
    levels.push(level);
  }
  const path = levels.slice(0, -1).map((l, j) => l[(5 >> j) ^ 1]);
  need("one matrix's salt of the wrong length refused, the other's right", verifyOpening([level[0]], 8, 5, rows[5], salts[5], path, 2) === "salt length");
}

{
  const g = twoAdic(2);
  const pts = [1n, g, mul(g, g), mul(mul(g, g), g)];
  const ys: E[] = [[3n, 1n, 2n, 0n, 0n], [5n, 9n, 10n, 0n, 0n], [7n, 2n, 3n, 0n, 0n], [11n, 4n, 5n, 0n, 0n]];
  const z: E = [123456789n, 987654321n, 987654322n, 0n, 0n];
  const w = subgroupWeights(4, z);
  need("subgroup weights, one per point", w.length === 4);
  const viaWeights = w.reduce((acc, wi, i) => eadd(acc, emul(wi, ys[i])), [0n, 0n, 0n, 0n, 0n] as E);
  need("subgroup interpolation agrees with Lagrange's formula", eeq(viaWeights, lagrange(pts, ys, z)));
  for (let i = 0; i < 4; i++) {
    const at = subgroupWeights(4, lift(pts[i]));
    need(`subgroup weights at point ${i} pick that point alone`, at.every((x, j) => eeq(x, j === i ? [1n, 0n, 0n, 0n, 0n] : [0n, 0n, 0n, 0n, 0n])));
    need(`Lagrange interpolation at node ${i} is its value`, eeq(lagrange(pts, ys, lift(pts[i])), ys[i]));
  }
}

{
  const MAGIC = new TextEncoder().encode("PBDAG001");
  type Node = { op: number; a?: number; b?: number; c?: bigint };
  const bytesOf = (nodes: Node[], roots: number[], tail: number[] = []) => {
    const out: number[] = [...MAGIC];
    const u32 = (v: number) => out.push(v & 0xff, (v >>> 8) & 0xff, (v >>> 16) & 0xff, (v >>> 24) & 0xff);
    const u64 = (v: bigint) => {
      for (let i = 0; i < 8; i++) out.push(Number((v >> BigInt(8 * i)) & 0xffn));
    };
    u32(2); u32(1); u32(1); u32(nodes.length); u32(roots.length);
    for (const n of nodes) {
      out.push(n.op);
      if (n.op === 7) u64(n.c as bigint);
      else if (n.op <= 3 || n.op === 10) u32(n.a as number);
      else if (n.op >= 8) { u32(n.a as number); u32(n.b as number); }
    }
    for (const r of roots) u32(r);
    out.push(...tail);
    return Uint8Array.from(out);
  };
  const nodes: Node[] = [
    { op: 0, a: 0 }, { op: 1, a: 1 }, { op: 2, a: 0 }, { op: 3, a: 0 }, { op: 4 }, { op: 5 }, { op: 6 },
    { op: 7, c: 5n }, { op: 7, c: P - 3n },
    { op: 10, a: 7 }, { op: 10, a: 0 },
    { op: 8, a: 7, b: 8 }, { op: 8, a: 0, b: 7 }, { op: 8, a: 4, b: 3 }, { op: 8, a: 7, b: 0 },
    { op: 9, a: 8, b: 7 }, { op: 9, a: 1, b: 2 }, { op: 9, a: 3, b: 5 },
    { op: 11, a: 7, b: 8 }, { op: 11, a: 7, b: 0 }, { op: 11, a: 1, b: 3 }, { op: 11, a: 0, b: 2 }, { op: 11, a: 21, b: 6 },
  ];
  const roots = Array.from({ length: nodes.length }, (_, i) => i);
  const good = bytesOf(nodes, roots);
  const g = loadConstraints(good);
  need("a constraint graph of every node kind loads as written",
    g.ops.length === nodes.length && nodes.every((n, i) => g.ops[i] === n.op && (n.a === undefined || g.a[i] === n.a) && (n.b === undefined || g.b[i] === n.b)) && g.constants.get(8) === P - 3n && g.roots.length === roots.length);
  const refused = (name: string, b: Uint8Array) => {
    let ok = false;
    try {
      loadConstraints(b);
    } catch {
      ok = true;
    }
    need(name, ok);
  };
  const bad = good.slice();
  bad[0] = 0x51;
  refused("a constraint graph with the wrong magic refused", bad);
  refused("an unknown node kind refused", bytesOf([...nodes, { op: 12 }], roots));
  refused("a constant equal to p refused", bytesOf([...nodes, { op: 7, c: P }], roots));
  refused("an addition reading a later node refused", bytesOf([...nodes, { op: 8, a: nodes.length, b: 0 }], roots));
  refused("a subtraction whose second child is later refused", bytesOf([...nodes, { op: 9, a: 0, b: nodes.length + 1 }], roots));
  refused("a negation of itself refused", bytesOf([...nodes, { op: 10, a: nodes.length }], roots));
  refused("a product whose second child is itself refused", bytesOf([...nodes, { op: 11, a: 0, b: nodes.length }], roots));
  refused("trailing bytes after a constraint graph refused", bytesOf(nodes, roots, [0]));

  const one = (r: number): Constraints => ({ ...g, roots: Uint32Array.from([r]) });
  const degrees = [1, 1, 1, 0, 1, 1, 0, 0, 0, 0, 1, 0, 1, 1, 1, 0, 1, 1, 0, 1, 1, 2, 2];
  need("the degree of every node kind", degrees.every((d, r) => maxDegree(one(r)) === d));

  const at = {
    local: [[11n, 12n, 13n, 0n, 0n], [13n, 14n, 15n, 0n, 0n]] as E[], next: [[21n, 22n, 23n, 0n, 0n], [23n, 24n, 25n, 0n, 0n]] as E[], periodic: [[31n, 32n, 33n, 0n, 0n]] as E[], publics: [41n],
    firstRow: [51n, 52n, 53n, 0n, 0n] as E, lastRow: [61n, 62n, 63n, 0n, 0n] as E, transition: [71n, 72n, 73n, 0n, 0n] as E,
  };
  const v: E[] = [];
  const val = (n: Node): E => {
    switch (n.op) {
      case 0: return at.local[n.a as number];
      case 1: return at.next[n.a as number];
      case 2: return at.periodic[n.a as number];
      case 3: return [at.publics[n.a as number], 0n, 0n, 0n, 0n];
      case 4: return at.firstRow;
      case 5: return at.lastRow;
      case 6: return at.transition;
      case 7: return [n.c as bigint, 0n, 0n, 0n, 0n];
      case 8: return eadd(v[n.a as number], v[n.b as number]);
      case 9: return esub(v[n.a as number], v[n.b as number]);
      case 10: return eneg(v[n.a as number]);
      default: return emul(v[n.a as number], v[n.b as number]);
    }
  };
  nodes.forEach((n) => v.push(val(n)));
  const alpha: E = [7n, 3n, 4n, 0n, 0n];
  const expect = v.reduce((acc, x) => eadd(emul(acc, alpha), x), [0n, 0n, 0n, 0n, 0n] as E);
  need("folding every node kind, base and extension values mixed", eeq(fold(g, at, alpha), expect));
  for (let r = 0; r < nodes.length; r++) need(`node ${r} alone folds to its value`, eeq(fold(one(r), at, alpha), v[r]));

  const n0 = air.ops.length;
  const ops = Uint8Array.from([...air.ops, 0, 9, ...Array(7).fill(11)]);
  const a = Uint32Array.from([...air.a, 0, n0, ...Array.from({ length: 7 }, (_, k) => n0 + 1 + k)]);
  const b = Uint32Array.from([...air.b, 0, n0, ...Array(7).fill(n0)]);
  const deg8: Constraints = { ...air, ops, a, b, roots: Uint32Array.from([n0 + 8, ...air.roots]) };
  need("a degree-8 constraint that vanishes, prepended to the AIR, makes the graph of degree 8", maxDegree(deg8) === 8);
  need("the honest proof against an AIR of degree 8 is refused, though the extra constraint vanishes", !verifyStark(small, deg8).ok);
}

need("degree", maxDegree(air) === PARAMS.statedDegree);
need("honest 4", verifyStark(small, air).ok);
const o = offsets(full);
const COL_CID = 2;
const R_AMOUNT = 6;
const tampered: [string, Uint8Array][] = [
  ["category opened", bump(full, o.traceLocal + 8 * DEG * COL_CID)],
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
for (const [name, why] of [
  ["trace value at a query", "input commitment opening: root differs"],
  ["trace salt", "input commitment opening: root differs"],
  ["trace sibling", "input commitment opening: root differs"],
  ["fold sibling", "fold commitment opening: root differs"],
] as const) need(`${name}: refused for ${why}`, (() => {
  const v = verifyStark((tampered.find(([n]) => n === name) as [string, Uint8Array])[1], air);
  return !v.ok && v.reason.startsWith(why);
})());
const reason = (b: Uint8Array, g = air) => {
  const v = verifyStark(b, g);
  return v.ok ? "accepted" : v.reason;
};
const refusedFor = (name: string, b: Uint8Array, why: string) => need(`${name}: refused for ${why}`, reason(b).startsWith(why));
const passes = (name: string, b: Uint8Array, check: string) => need(`${name}: not refused by the ${check} check`, !reason(b).startsWith(check));
refusedFor("the file less its last byte", full.slice(0, full.length - 1), "malformed: truncated");
refusedFor("the file with a byte appended", Uint8Array.from([...full, 0]), "malformed: trailing bytes");
refusedFor("a first length field of 2^40", withWord(full, 0, 1n << 40n), "malformed: length");
refusedFor("a public-value count one above the bytes left", withWord(full, o.publicValue - 8, BigInt(full.length - o.publicValue + 1)), "malformed: length");
refusedFor("a public-value count equal to the bytes left", withWord(full, o.publicValue - 8, BigInt(full.length - o.publicValue)), "malformed: truncated");
{
  const capLen = Number(word(full, 0));
  const second = 8 + 32 * capLen;
  const tag = second + 8 + 32 * Number(word(full, second));
  const c = full.slice();
  c[tag] = 2;
  refusedFor("an option tag of 2", c, "malformed: option tag");
}
refusedFor("a public value equal to p", withWord(full, o.publicValue, P), "malformed: non-canonical field element");
refusedFor("a public value above p", withWord(full, o.publicValue, P + 5n), "malformed: non-canonical field element");
refusedFor("a degree of 33", withWord(full, o.degreeBits, 33n), "malformed: degree");
refusedFor("a degree of 32", withWord(full, o.degreeBits, 32n), "degree out of range");

const base = parse(full);
need("the encoder writes back the file it read", Buffer.from(encode(base.proof, base.pv)).equals(Buffer.from(full)));
const shaped = (change: (p: ReturnType<typeof copy>, pv: bigint[]) => void) => {
  const p = copy(base.proof);
  const pv = [...base.pv];
  change(p, pv);
  return encode(p, pv);
};
const reshaped = (name: string, why: string, change: (p: ReturnType<typeof copy>, pv: bigint[]) => void) => refusedFor(name, shaped(change), why);
const at = <T>(xs: T[] | null) => xs as T[];
reshaped("trace opening one value short", "trace opening width", (p) => at(p.traceLocal).pop());
reshaped("trace opening one value long", "trace opening width", (p) => at(p.traceLocal).push([1n, 2n, 3n, 0n, 0n]));
reshaped("next-row opening missing", "next-row opening width", (p) => { p.traceNext = null; });
reshaped("next-row opening one value short", "next-row opening width", (p) => at(p.traceNext).pop());
reshaped("a preprocessed opening present", "unexpected preprocessed trace", (p) => { p.preprocessedLocal = [[1n, 0n, 0n, 0n, 0n]]; });
reshaped("a preprocessed next-row opening present", "unexpected preprocessed trace", (p) => { p.preprocessedNext = [[1n, 0n, 0n, 0n, 0n]]; });
reshaped("one quotient chunk missing", "quotient chunk shape", (p) => p.quotientChunks.pop());
reshaped("a quotient chunk of four values", "quotient chunk shape", (p) => p.quotientChunks[0].push([0n, 0n, 0n, 0n, 0n]));
reshaped("a quotient chunk of two values", "quotient chunk shape", (p) => p.quotientChunks[3].pop());
reshaped("random opening missing", "random opening shape", (p) => { p.random = null; });
reshaped("random opening of two values", "random opening shape", (p) => at(p.random).pop());
reshaped("random commitment missing", "missing random commitment", (p) => { p.randomCap = null; });
reshaped("hidden openings for two rounds", "hidden openings: round count", (p) => p.randomOpenings.pop());
reshaped("hidden openings for an extra matrix", "hidden openings: matrix count", (p) => p.randomOpenings[0].push(p.randomOpenings[0][0]));
reshaped("hidden openings for an extra point", "hidden openings: point count", (p) => p.randomOpenings[1][0].push(p.randomOpenings[1][0][0]));
reshaped("one hidden codeword short", "hidden openings: value count", (p) => p.randomOpenings[2][0][0].pop());
reshaped("one fold commitment missing", "fold count", (p) => p.friCaps.pop());
reshaped("one commit grinding witness missing", "commit grinding count", (p) => p.commitPow.pop());
reshaped("one query missing", "query count", (p) => p.queries.pop());
reshaped("one query repeated", "query count", (p) => p.queries.push(p.queries[0]));
reshaped("one query's arity schedule different", "arity schedule differs between queries", (p) => { p.queries[5].steps[0].logArity = p.queries[5].steps[0].logArity === 1 ? 2 : 1; });
reshaped("arity three in every query", "arity out of range", (p) => p.queries.forEach((q) => { q.steps[0].logArity = 3; }));
reshaped("arity zero in every query", "arity out of range", (p) => p.queries.forEach((q) => { q.steps[0].logArity = 0; }));
reshaped("arity three in the second fold of every query", "arity out of range", (p) => p.queries.forEach((q) => { q.steps[1].logArity = 3; }));
const arities = base.proof.queries[0].steps.map((x) => x.logArity);
const last = arities.length - 1;
need("the deployed fold schedule folds by four at every step", arities.every((a) => a === 2));
reshaped("the last fold's arity lowered to two in every query", "fold schedule does not reach the final polynomial", (p) => p.queries.forEach((q) => { q.steps[last].logArity = 1; }));
reshaped("one fold step missing in every query", "fold count", (p) => p.queries.forEach((q) => q.steps.pop()));
reshaped("one fold step missing in one query", "fold count", (p) => p.queries[7].steps.pop());
reshaped("one fold sibling missing", "sibling count", (p) => p.queries[0].steps[0].siblings.pop());
reshaped("one input opening missing", "input opening count", (p) => p.queries[0].inputs.pop());
reshaped("one input row missing", "opened matrix count", (p) => p.queries[0].inputs[2].rows.pop());
reshaped("one opened value missing from a row", "input commitment opening: root differs", (p) => p.queries[0].inputs[1].rows[0].pop());
reshaped("final polynomial one coefficient short", "final polynomial length", (p) => p.finalPoly.pop());
reshaped("final polynomial one coefficient long", "final polynomial length", (p) => p.finalPoly.push([0n, 0n, 0n, 0n, 0n]));
reshaped("degree one", "degree out of range", (p) => { p.degreeBits = 1; });
reshaped("degree twenty-nine", "degree out of range", (p) => { p.degreeBits = 29; });
passes("degree two", shaped((p) => { p.degreeBits = 2; }), "degree out of range");
passes("degree twenty-eight", shaped((p) => { p.degreeBits = 28; }), "degree out of range");
reshaped("one public value missing", "public values are not terms and whole payments", (_, pv) => pv.pop());
reshaped("no public values", "public values are not terms and whole payments", (_, pv) => pv.splice(0));
reshaped("public values holding the terms alone", "public values are not terms and whole payments", (_, pv) => pv.splice(air.globals));
reshaped("one payment missing from the public values", "batch size not a power of two", (_, pv) => pv.splice(pv.length - air.rowWidth, air.rowWidth));
reshaped("three payments in the public values", "batch size not a power of two", (_, pv) => pv.splice(air.globals + 3 * air.rowWidth));
reshaped("256 payments in the public values", "batch larger than the trace", (_, pv) => pv.push(...pv.slice(air.globals)));
need("the honest proof of one payment is accepted", verifyStark(one1, air).ok);
{
  const z: E = [5n, 6n, 7n, 0n, 0n];
  const leafRows = Array.from({ length: 8 }, (_, k) => [BigInt(k), BigInt(k + 100), BigInt(k + 200)]);
  const leafSalts = Array.from({ length: 8 }, (_, k) => Array.from({ length: PARAMS.saltElems }, (_, j) => BigInt(k + 300 + 100 * j)));
  let level: Digest[] = leafRows.map((r, k) => sponge([...r, ...leafSalts[k]]));
  const levels: Digest[][] = [level];
  while (level.length > 1) {
    const up: Digest[] = [];
    for (let i = 0; i < level.length; i += 2) up.push(compress(level[i], level[i + 1]));
    level = up;
    levels.push(level);
  }
  const path = levels.slice(0, -1).map((l, j) => l[(3 >> j) ^ 1]);
  const input = [{ rows: [leafRows[3]], salts: [leafSalts[3]], siblings: path }];
  const run = (values: E[]) => {
    try {
      openInput(input, [{ cap: [level[0]], mats: [{ points: [{ z, values }] }] }], 3, 3, new Batching([2n, 1n, 2n, 0n, 0n]));
      return "accepted";
    } catch (e) {
      return (e as Error).message;
    }
  };
  need("an input row of three columns against three claimed values is accepted", run([[1n, 0n, 0n, 0n, 0n], [2n, 0n, 0n, 0n, 0n], [3n, 0n, 0n, 0n, 0n]]) === "accepted");
  need("an input row of three columns against two claimed values is refused", run([[1n, 0n, 0n, 0n, 0n], [2n, 0n, 0n, 0n, 0n]]) === "claimed value count");
}
need("quotient degree as Plonky3 sets it", [1, 2, 3, 4, 5, 7, 8, 9, 16, 17].map(logQuotientDegree).join() === "0,1,2,2,3,3,3,4,4,5");
need("five broken", broken.length === 5);
for (const [name, b] of broken) need(name, !verifyStark(b, air).ok);
const constant = [...air.constants.keys()].find((k) => air.constants.get(k) !== 0n) as number;
need("constant changed", !verifyStark(full, { ...air, constants: new Map(air.constants).set(constant, (air.constants.get(constant) as bigint) + 1n) }).ok);
need("last constraint dropped", !verifyStark(full, { ...air, roots: air.roots.subarray(0, air.roots.length - 1) }).ok);
need("two constraints exchanged", !verifyStark(full, { ...air, roots: Uint32Array.from([air.roots[1], air.roots[0], ...air.roots.subarray(2)]) }).ok);
need("honest 256", verifyStark(full, air).ok);
console.log(`all ${n} checks pass`);
