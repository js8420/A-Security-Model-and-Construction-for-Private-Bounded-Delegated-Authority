import { fold, maxDegree, type Constraints } from "./constraints.js";
import {
  DEG, E0, E1, GENERATOR, X, bitrev, eadd, ebatchInv, eeq, einv, emul, escale, esquarings, esub, ezero,
  inv, lift, mul, pow, sub, twoAdic, type E,
} from "./field.js";
import { verifyOpening } from "./merkle.js";
import { parse, type Digest, type StarkProof } from "./proof.js";
import { Transcript } from "./transcript.js";

/** The deployed parameters. A proof made under any others is refused rather than interpreted. */
export const PARAMS = {
  queries: 74,
  logBlowup: 4,
  queryPowBits: 20,
  commitPowBits: 0,
  logFinalPolyLen: 3,
  maxLogArity: 2,
  saltElems: 4,
  randomCodewords: 2,
  statedDegree: 7,
} as const;

export type Verdict = { ok: true } | { ok: false; reason: string };

class Reject extends Error {}

/** log2 of the quotient's degree over the trace's for constraint degree d under a hiding commitment, as p3-uni-stark 0.6.3 sets it. */
export const logQuotientDegree = (d: number): number => Math.ceil(Math.log2(Math.max(d + 1, 2) - 1));

function need(cond: boolean, reason: string): asserts cond {
  if (!cond) throw new Reject(reason);
}

const log2 = (n: number) => {
  const l = Math.log2(n);
  need(Number.isInteger(l), "size not a power of two");
  return l;
};

/** A coset shift * <g> of size 2^logSize. */
interface Coset {
  shift: bigint;
  logSize: number;
}

/** Z(x) = (x / shift)^size - 1, which vanishes exactly on the coset. */
function vanishing(c: Coset, x: E): E {
  return esub(esquarings(escale(x, inv(c.shift)), c.logSize), E1);
}

/** The interpolant of `values` over a subgroup, given that subgroup's weights at the point. */
function interpolateSubgroup(values: readonly bigint[], weights: readonly E[]): E {
  let s = E0;
  for (let i = 0; i < values.length; i++) s = eadd(s, escale(weights[i], values[i]));
  return s;
}

/**
 * The Lagrange weights of the subgroup of order m at z: (z^m - 1)/m * w^i/(z - w^i).
 * If z is a point of the subgroup the interpolant is that point's value, which a
 * single weight of one at its position expresses.
 */
export function subgroupWeights(m: number, z: E): E[] {
  const g = twoAdic(log2(m));
  const pts: bigint[] = [];
  let p = 1n;
  for (let i = 0; i < m; i++) {
    pts.push(p);
    p = mul(p, g);
  }
  const hit = pts.findIndex((x) => eeq(z, lift(x)));
  if (hit >= 0) return pts.map((_, i) => (i === hit ? E1 : E0));
  const diffs = pts.map((x) => esub(z, lift(x)));
  const invs = ebatchInv(diffs);
  const scale = escale(esub(esquarings(z, log2(m)), E1), inv(BigInt(m)));
  return pts.map((x, i) => escale(emul(scale, invs[i]), x));
}

/** Lagrange interpolation through (xs[i], ys[i]) at z, from the definition, which holds at a node as well. */
export function lagrange(xs: readonly bigint[], ys: readonly E[], z: E): E {
  const k = xs.length;
  let out = E0;
  for (let i = 0; i < k; i++) {
    let num = E1;
    let den = 1n;
    for (let j = 0; j < k; j++) {
      if (j === i) continue;
      num = emul(num, esub(z, lift(xs[j])));
      den = mul(den, sub(xs[i], xs[j]));
    }
    out = eadd(out, emul(ys[i], escale(num, inv(den))));
  }
  return out;
}

/** The extension element whose basis coefficients are the given extension values: c0 + c1 X + ... + c4 X^4. */
const fromBasis = (c: readonly E[]): E => c.reduceRight((acc, ci) => eadd(ci, emul(acc, X)), E0);

/** Periodic column j of the batch: payment r's value j, for r over the batch. */
function periodicColumns(pv: readonly bigint[], globals: number, rowWidth: number): bigint[][] {
  need(pv.length > globals && (pv.length - globals) % rowWidth === 0, "public values are not terms and whole payments");
  const rows = (pv.length - globals) / rowWidth;
  need((rows & (rows - 1)) === 0, "batch size not a power of two");
  const cols: bigint[][] = [];
  for (let j = 0; j < rowWidth; j++) {
    const col: bigint[] = [];
    for (let r = 0; r < rows; r++) col.push(pv[globals + r * rowWidth + j]);
    cols.push(col);
  }
  return cols;
}

export interface Matrix {
  points: { z: E; values: E[] }[];
}

export interface Round {
  cap: readonly Digest[];
  mats: Matrix[];
}

/** Checks a proof against its public values and the AIR's constraints. Never throws. */
export function verifyStark(bytes: Uint8Array, air: Constraints): Verdict {
  try {
    const { proof, pv } = parse(bytes);
    check(proof, pv, air);
    return { ok: true };
  } catch (e) {
    if (e instanceof Reject) return { ok: false, reason: e.message };
    if (e instanceof Error) return { ok: false, reason: e.message };
    return { ok: false, reason: String(e) };
  }
}

export function check(proof: StarkProof, pv: readonly bigint[], air: Constraints): void {
  const prm = PARAMS;
  need(maxDegree(air) === prm.statedDegree, "constraint degree differs from the stated one");
  const D = proof.degreeBits;
  need(D >= 2 && D + prm.logBlowup <= 32, "degree out of range");
  const initLog = D - 1;
  const lq = logQuotientDegree(prm.statedDegree);
  const chunks = 2 ** (lq + 1);
  const quotientDomain: Coset = { shift: GENERATOR, logSize: D + lq };
  const chunkLog = quotientDomain.logSize - log2(chunks);
  const gq = twoAdic(quotientDomain.logSize);
  const chunkDomains: Coset[] = Array.from({ length: chunks }, (_, i) => ({ shift: mul(GENERATOR, pow(gq, BigInt(i))), logSize: chunkLog }));

  const W = air.width;
  need(proof.traceLocal.length === W, "trace opening width");
  need(proof.traceNext !== null && proof.traceNext.length === W, "next-row opening width");
  need(proof.preprocessedLocal === null && proof.preprocessedNext === null, "unexpected preprocessed trace");
  need(proof.quotientChunks.length === chunks && proof.quotientChunks.every((c) => c.length === DEG), "quotient chunk shape");
  need(proof.random !== null && proof.random.length === DEG, "random opening shape");
  need(proof.randomCap !== null, "missing random commitment");
  const periodic = periodicColumns(pv, air.globals, air.rowWidth);
  const period = periodic[0].length;
  need(log2(period) <= initLog, "batch larger than the trace");

  const t = new Transcript();
  t.observe(BigInt(D));
  t.observe(BigInt(initLog));
  t.observe(0n);
  t.observeCap(proof.traceCap);
  for (const v of pv) t.observe(v);
  const alpha = t.sampleExt();
  t.observeCap(proof.quotientCap);
  t.observeCap(proof.randomCap);
  const zeta = t.sampleExt();
  const initDomain: Coset = { shift: 1n, logSize: initLog };
  const zH = vanishing(initDomain, zeta);
  need(!ezero(zH), "out-of-domain point on the trace domain");

  const zPeriod = esquarings(zeta, initLog - log2(period));
  const weights = subgroupWeights(period, zPeriod);
  const periodicAtZeta = periodic.map((col) => interpolateSubgroup(col, weights));
  const zetaNext = escale(zeta, twoAdic(initLog));

  // Every matrix is opened over the extended trace domain: the quotient's chunks
  // have height 2^(chunkLog + 1), which is the trace's, before the blowup.
  const logLde = D + prm.logBlowup;
  const rounds: Round[] = [
    { cap: proof.randomCap, mats: [{ points: [{ z: zeta, values: [...proof.random] }] }] },
    { cap: proof.traceCap, mats: [{ points: [{ z: zeta, values: [...proof.traceLocal] }, { z: zetaNext, values: [...proof.traceNext] }] }] },
    { cap: proof.quotientCap, mats: proof.quotientChunks.map((c) => ({ points: [{ z: zeta, values: [...c] }] })) },
  ];

  need(proof.randomOpenings.length === rounds.length, "hidden openings: round count");
  rounds.forEach((r, ri) => {
    const hidden = proof.randomOpenings[ri];
    need(hidden.length === r.mats.length, "hidden openings: matrix count");
    r.mats.forEach((m, mi) => {
      need(hidden[mi].length === m.points.length, "hidden openings: point count");
      m.points.forEach((p, pi) => {
        need(hidden[mi][pi].length === prm.randomCodewords, "hidden openings: value count");
        p.values.push(...hidden[mi][pi]);
      });
    });
  });
  for (const r of rounds) for (const m of r.mats) for (const p of m.points) for (const v of p.values) t.observeExt(v);

  fri(proof, rounds, logLde, t);

  let quotient = E0;
  for (let i = 0; i < chunks; i++) {
    let zp = E1;
    for (let j = 0; j < chunks; j++) {
      if (j === i) continue;
      zp = emul(zp, emul(vanishing(chunkDomains[j], zeta), einv(vanishing(chunkDomains[j], lift(chunkDomains[i].shift)))));
    }
    quotient = eadd(quotient, emul(zp, fromBasis(proof.quotientChunks[i])));
  }

  const transition = esub(zeta, lift(inv(twoAdic(initLog))));
  const folded = fold(
    air,
    {
      local: proof.traceLocal,
      next: proof.traceNext,
      periodic: periodicAtZeta,
      publics: pv,
      firstRow: emul(zH, einv(esub(zeta, E1))),
      lastRow: emul(zH, einv(transition)),
      transition,
    },
    alpha,
  );
  need(eeq(emul(folded, einv(zH)), quotient), "constraints do not match the quotient at the out-of-domain point");
}

function fri(proof: StarkProof, rounds: Round[], logLde: number, t: Transcript): void {
  const prm = PARAMS;
  const alpha = t.sampleExt();
  const nRounds = proof.friCaps.length;
  need(proof.queries.length === prm.queries, "query count");
  const arities = proof.queries[0].steps.map((s) => s.logArity);
  for (const q of proof.queries) {
    need(q.steps.length === nRounds, "fold count");
    q.steps.forEach((s, i) => need(s.logArity === arities[i], "arity schedule differs between queries"));
  }
  need(arities.every((a) => a >= 1 && a <= prm.maxLogArity), "arity out of range");
  // The folds must take the extended domain down to the final polynomial's; this
  // also keeps every arity within the height it folds, and the last fold at it.
  const logFinal = prm.logBlowup + prm.logFinalPolyLen;
  need(arities.reduce((a, b) => a + b, 0) + logFinal === logLde, "fold schedule does not reach the final polynomial");
  need(proof.commitPow.length === nRounds, "commit grinding count");
  const betas: E[] = [];
  for (let i = 0; i < nRounds; i++) {
    t.observeCap(proof.friCaps[i]);
    need(t.checkWitness(prm.commitPowBits, proof.commitPow[i]), "commit grinding");
    betas.push(t.sampleExt());
  }
  need(proof.finalPoly.length === 2 ** prm.logFinalPolyLen, "final polynomial length");
  for (const c of proof.finalPoly) t.observeExt(c);
  for (const a of arities) t.observe(BigInt(a));
  need(t.checkWitness(prm.queryPowBits, proof.queryPow), "query grinding");

  const batching = new Batching(alpha);
  for (const q of proof.queries) {
    let index = t.sampleBits(logLde);
    let folded = openInput(q.inputs, rounds, index, logLde, batching);
    let logH = logLde;
    q.steps.forEach((s, ri) => {
      const arity = 2 ** s.logArity;
      need(s.siblings.length === arity - 1, "sibling count");
      const pos = index % arity;
      const evals: E[] = [];
      let k = 0;
      for (let j = 0; j < arity; j++) evals.push(j === pos ? folded : s.siblings[k++]);
      const logFolded = logH - s.logArity;
      index = Math.floor(index / arity);
      const row = evals.flatMap((e) => [...e]);
      const why = verifyOpening(proof.friCaps[ri], 2 ** logFolded, index, [row], s.opening.salts, s.opening.siblings, prm.saltElems);
      need(why === null, `fold commitment opening: ${why}`);
      const start = pow(twoAdic(logFolded + s.logArity), BigInt(bitrev(index, logFolded)));
      const ga = twoAdic(s.logArity);
      const natural: bigint[] = [];
      let x = start;
      for (let j = 0; j < arity; j++) {
        natural.push(x);
        x = mul(x, ga);
      }
      const xs = natural.map((_, j) => natural[bitrev(j, s.logArity)]);
      folded = lagrange(xs, evals, betas[ri]);
      logH = logFolded;
    });
    const x = lift(pow(twoAdic(logLde), BigInt(bitrev(index, logLde))));
    let acc = E0;
    for (let i = proof.finalPoly.length - 1; i >= 0; i--) acc = eadd(emul(acc, x), proof.finalPoly[i]);
    need(eeq(acc, folded), "final polynomial disagrees with the fold");
  }
}
/**
 * The powers of the batching challenge, and each claimed point's values summed
 * against them once, so that a query costs one pass over its opened row:
 * sum_c a^(o+c) (v_c - r_c) / (z - x) = a^o (V - R) / (z - x), with V and R
 * the claimed and the opened values weighted by a^c.
 */
export class Batching {
  readonly powers: E[] = [E1];
  private readonly claimed = new Map<object, E>();

  constructor(private readonly alpha: E) {}

  power(k: number): E {
    while (this.powers.length <= k) this.powers.push(emul(this.powers[this.powers.length - 1], this.alpha));
    return this.powers[k];
  }

  weighClaimed(p: { values: E[] }): E {
    const hit = this.claimed.get(p);
    if (hit) return hit;
    this.power(p.values.length);
    let s = E0;
    for (let c = 0; c < p.values.length; c++) s = eadd(s, emul(this.powers[c], p.values[c]));
    this.claimed.set(p, s);
    return s;
  }

  weighOpened(row: readonly bigint[]): E {
    this.power(row.length);
    let s = E0;
    for (let c = 0; c < row.length; c++) s = eadd(s, escale(this.powers[c], row[c]));
    return s;
  }
}

/**
 * The batched quotient (p(z) - p(x)) / (z - x) of every opened column at one
 * query. Every matrix lies over the extended domain, so the query's index is
 * every matrix's row and x is the same point for all of them.
 */
export function openInput(
  inputs: StarkProof["queries"][number]["inputs"],
  rounds: Round[],
  index: number,
  logLde: number,
  batching: Batching,
): E {
  const prm = PARAMS;
  need(inputs.length === rounds.length, "input opening count");
  const x = lift(mul(GENERATOR, pow(twoAdic(logLde), BigInt(bitrev(index, logLde)))));
  let sum = E0;
  let power = E1;
  rounds.forEach((r, bi) => {
    const op = inputs[bi];
    need(op.rows.length === r.mats.length, "opened matrix count");
    const why = verifyOpening(r.cap, 2 ** logLde, index, op.rows, op.salts, op.siblings, prm.saltElems);
    need(why === null, `input commitment opening: ${why}`);
    r.mats.forEach((m, mi) => {
      const row = op.rows[mi];
      const opened = batching.weighOpened(row);
      for (const p of m.points) {
        const den = esub(p.z, x);
        need(!ezero(den), "query point equals an opening point");
        need(row.length === p.values.length, "claimed value count");
        sum = eadd(sum, emul(power, emul(esub(batching.weighClaimed(p), opened), einv(den))));
        power = emul(power, batching.power(row.length));
      }
    });
  });
  return sum;
}
