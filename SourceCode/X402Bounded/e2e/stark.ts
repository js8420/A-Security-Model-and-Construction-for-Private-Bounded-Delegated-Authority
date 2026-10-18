import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import {
  PARAMS, ProofGate, deployedVerifier, independentVerifier, loadConstraints, maxDegree, verifyStark, type Check,
} from "../src/index.js";
import { parse } from "../src/stark/proof.js";

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
const broken = readdirSync(brokenDir)
  .filter((f) => f.startsWith("broken_") && f.endsWith(".bin"))
  .sort()
  .map((f) => [f.slice(7, -4).replaceAll("_", " "), new Uint8Array(readFileSync(join(brokenDir, f)))] as const);
const deployed = deployedVerifier(env("CIRCUIT_BIN"));
const independent = independentVerifier(air);

const lines: string[] = [];
let failures = 0;
const check = (name: string, ok: boolean, detail = "") => {
  lines.push(`  ${ok ? "PASS" : "FAIL"}  ${name}${detail ? `: ${detail}` : ""}`);
  if (!ok) failures += 1;
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

const COL_CID = 2;
const R_AMOUNT = 6;
const o = parse(full).offsets;
const powWitness = word(full, o.queryPow);
const tampered: [string, Uint8Array][] = [
  ["the category id opened at the out-of-domain point", bump(full, o.traceLocal + 16 * COL_CID)],
  ["a quotient chunk opened at the out-of-domain point", bump(full, o.quotientChunk)],
  ["a payment's amount in the public values", bump(full, o.publicValue + 8 * (air.globals + R_AMOUNT))],
  ["a trace value opened at a query", bump(full, o.inputRow)],
  ["a salt of a trace leaf", bump(full, o.inputSalt)],
  ["a sibling digest on a trace path", bump(full, o.inputSibling)],
  ["a sibling value in a fold", bump(full, o.foldSibling)],
  ["a coefficient of the final polynomial", bump(full, o.finalPoly)],
  ["the query grinding witness", bump(full, o.queryPow)],
  ["the degree", withWord(full, o.degreeBits, word(full, o.degreeBits) + 1n)],
  ["the grinding witness re-encoded as witness + p", withWord(full, o.queryPow, powWitness + P)],
  ["the file truncated by one byte", full.slice(0, full.length - 1)],
  ["the file with one byte appended", Uint8Array.from([...full, 0])],
];

async function both(b: Uint8Array) {
  const [d, i] = await Promise.all([deployed(b), independent(b)]);
  return { d, i };
}

const quartiles = (xs: number[]) => {
  const s = [...xs].sort((a, b) => a - b);
  const at = (q: number) => {
    const p = (s.length - 1) * q;
    const lo = Math.floor(p);
    return s[lo] + (s[Math.ceil(p)] - s[lo]) * (p - lo);
  };
  return { q1: at(0.25), median: at(0.5), q3: at(0.75) };
};

async function main() {
  check(`constraint graph: ${air.ops.length} nodes, ${air.roots.length} constraints, width ${air.width}`, air.width > 0);
  check("its degree equals the degree the AIR states", maxDegree(air) === PARAMS.statedDegree, String(maxDegree(air)));

  for (const [name, b] of [["128 payments", full], ["4 payments", small]] as const) {
    const r = await both(b);
    check(`honest proof of ${name}: the deployed verifier accepts`, r.d.ok);
    check(`honest proof of ${name}: the independent verifier accepts`, r.i.ok, r.i.ok ? "" : r.i.reason);
  }
  for (const [name, b] of tampered) {
    const r = await both(b);
    const why = (v: typeof r.i) => (v.ok ? "accepted" : v.reason);
    check(`${name}: both refuse`, !r.d.ok && !r.i.ok, `independent: ${why(r.i)}`);
  }

  check("five proofs of statements with no witness were exported", broken.length === 5, String(broken.length));
  for (const [name, b] of broken) {
    const r = await both(b);
    check(`no witness, ${name}: both refuse`, !r.d.ok && !r.i.ok, `independent: ${r.i.ok ? "accepted" : r.i.reason}`);
  }

  const constant = [...air.constants.keys()].find((k) => air.constants.get(k) !== 0n) as number;
  const variants: [string, typeof air][] = [
    ["one constant of the constraint graph changed", { ...air, constants: new Map(air.constants).set(constant, (air.constants.get(constant) as bigint) + 1n) }],
    ["the last constraint dropped", { ...air, roots: air.roots.subarray(0, air.roots.length - 1) }],
    ["the first two constraints exchanged", { ...air, roots: Uint32Array.from([air.roots[1], air.roots[0], ...air.roots.subarray(2)]) }],
  ];
  for (const [name, g] of variants) {
    const v = verifyStark(full, g);
    check(`honest proof against ${name}: refused`, !v.ok, v.ok ? "accepted" : v.reason);
  }

  const forged = (broken.find(([n]) => n === "cap above budget") ?? broken[0])[1];
  const buggy: Check = async () => ({ ok: true });
  const honestGate = new ProofGate([{ name: "deployed", check: deployed }, { name: "independent", check: independent }], air.globals, air.rowWidth);
  const h = await honestGate.deliver(full);
  check("the gate accepts the honest batch and backs its 128 settlements", h.accepted && h.digests.length === 128 && h.digests.every((d) => honestGate.backed(d)));
  const alone = new ProofGate([{ name: "deployed, with a bug that accepts", check: buggy }], air.globals, air.rowWidth);
  const a = await alone.deliver(forged);
  check("a verifier bug alone: the batch whose hidden cap exceeds the budget is accepted and backs its settlements", a.accepted && a.digests.length > 0);
  const guarded = new ProofGate([{ name: "deployed, with a bug that accepts", check: buggy }, { name: "independent", check: independent }], air.globals, air.rowWidth);
  const g = await guarded.deliver(forged);
  const first = parse(forged).pv[air.globals];
  check("the same bug beside the independent verifier: the batch is refused", !g.accepted && g.verdicts[1].verdict.ok === false);
  check("so its settlements stay unbacked and the monitor challenges them", !guarded.backed(first));

  const reps = Number(process.env.REPS ?? "11");
  const dMs: number[] = [];
  const iMs: number[] = [];
  const bin = env("CIRCUIT_BIN");
  const { execFileSync } = await import("node:child_process");
  for (let k = 0; k < reps; k++) {
    const out = execFileSync(bin, ["verify-file", env("PROOF_FULL")]).toString().trim();
    dMs.push(Number(out.split(" ")[1]));
    const t = performance.now();
    const v = verifyStark(full, air);
    iMs.push(performance.now() - t);
    if (!v.ok) check("timed run accepted", false, v.reason);
  }
  const dq = quartiles(dMs);
  const iq = quartiles(iMs);

  console.log("INDEPENDENT STARK VERIFIER AGAINST THE DEPLOYED ONE");
  console.log("=".repeat(78));
  for (const l of lines) console.log(l);
  console.log(`  verification of the 128-payment proof, ${reps} interleaved runs each, ms (q1 / median / q3):`);
  console.log(`    deployed Plonky3, in process   ${dq.q1.toFixed(1)} / ${dq.median.toFixed(1)} / ${dq.q3.toFixed(1)}`);
  console.log(`    independent, TypeScript        ${iq.q1.toFixed(1)} / ${iq.median.toFixed(1)} / ${iq.q3.toFixed(1)}`);
  console.log(`  ${failures === 0 ? "all checks pass" : `${failures} checks fail`}`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
