import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { PARAMS, loadConstraints, maxDegree, verifyStark } from "../src/index.js";
import { offsets } from "./stark_kit.js";

/**
 * The smaller test set, kept so that its mutation score can be measured beside
 * that of stark_control.ts: the honest proofs must pass, and every altered
 * proof, every proof of a statement with no witness and every altered
 * constraint graph must be refused. It stops at the first
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

need("degree", maxDegree(air) === PARAMS.statedDegree);
need("honest 4", verifyStark(small, air).ok);
const o = offsets(full);
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
need("five broken", broken.length === 5);
for (const [name, b] of broken) need(name, !verifyStark(b, air).ok);
const constant = [...air.constants.keys()].find((k) => air.constants.get(k) !== 0n) as number;
need("constant changed", !verifyStark(full, { ...air, constants: new Map(air.constants).set(constant, (air.constants.get(constant) as bigint) + 1n) }).ok);
need("last constraint dropped", !verifyStark(full, { ...air, roots: air.roots.subarray(0, air.roots.length - 1) }).ok);
need("two constraints exchanged", !verifyStark(full, { ...air, roots: Uint32Array.from([air.roots[1], air.roots[0], ...air.roots.subarray(2)]) }).ok);
need("honest 128", verifyStark(full, air).ok);
console.log(`all ${n} checks pass`);
