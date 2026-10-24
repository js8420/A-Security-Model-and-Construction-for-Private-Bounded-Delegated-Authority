import { execFile } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { loadConstraints, verifyStark } from "../src/index.js";
import { CHECKS, deployedCheck, independentCheck, offsets, type Check } from "./stark_kit.js";

/**
 * Differential testing of the two verifiers on randomly altered copies of the
 * honest 256-payment proof, from one seed. Four kinds of alteration, in turn:
 * one bit flipped anywhere; one 64-bit word replaced by a random field
 * element; one bit flipped in the commitments, opened values, final
 * polynomial, grinding witness, degree or public values, where the
 * transcript and the constraint check read; and the file cut short or
 * extended. Prints one line of counts, and every alteration on which the
 * verifiers disagree or which either accepts. With FUZZ_JSON set, also
 * writes how many alterations each verifier refused at each check, and how
 * many it refused at a different check from the other.
 */
const env = (k: string) => {
  const v = process.env[k];
  if (!v) throw new Error(`${k} not set`);
  return v;
};
const P = 0xffffffff00000001n;
const seed = Number(env("SEED"));
const count = Number(env("COUNT"));
const bin = env("CIRCUIT_BIN");
const air = loadConstraints(readFileSync(env("CONSTRAINTS")));
const honest = new Uint8Array(readFileSync(env("PROOF_FULL")));
const o = offsets(honest);

let state = BigInt(seed) * 0x9e3779b97f4a7c15n + 1n;
const next = () => {
  state = (state * 6364136223846793005n + 1442695040888963407n) & ((1n << 64n) - 1n);
  return state >> 11n;
};
const below = (n: number) => Number(next() % BigInt(n));

/** The byte ranges the transcript and the constraint check read before any query: the head up to the first query, and the tail from the final polynomial. */
const head = o.inputRow - 16;
const tail = o.finalPoly - 8;

function alter(kind: number): { bytes: Uint8Array; what: string } {
  const b = honest.slice();
  if (kind === 0) {
    const at = below(b.length);
    const bit = below(8);
    b[at] ^= 1 << bit;
    return { bytes: b, what: `bit ${bit} of byte ${at}` };
  }
  if (kind === 1) {
    const at = below(b.length - 8);
    let v = next() % P;
    const w = v;
    for (let i = 0; i < 8; i++) {
      b[at + i] = Number(v & 0xffn);
      v >>= 8n;
    }
    return { bytes: b, what: `word at byte ${at} set to ${w}` };
  }
  if (kind === 2) {
    const span = head + (b.length - tail);
    let at = below(span);
    if (at >= head) at = tail + (at - head);
    const bit = below(8);
    b[at] ^= 1 << bit;
    return { bytes: b, what: `bit ${bit} of byte ${at}, outside the queries` };
  }
  const n = 1 + below(64);
  if (below(2) === 0) return { bytes: honest.slice(0, honest.length - n), what: `cut by ${n} bytes` };
  const extra = Uint8Array.from({ length: n }, () => below(256));
  return { bytes: Uint8Array.from([...honest, ...extra]), what: `extended by ${n} bytes` };
}

const dir = mkdtempSync(join(tmpdir(), "fuzz-"));
const deployed = (bytes: Uint8Array) =>
  new Promise<string>((resolve) => {
    const file = join(dir, "p.bin");
    writeFileSync(file, bytes);
    execFile(bin, ["verify-file", file], (_err, stdout) => resolve(stdout.trim()));
  });

async function main() {
  const tally = { both: 0, neither: 0, deployedOnly: 0, independentOnly: 0, unchanged: 0 };
  const odd: string[] = [];
  const at = (): Record<Check, number> => Object.fromEntries(CHECKS.map((c) => [c, 0])) as Record<Check, number>;
  const checks = { deployed: at(), independent: at(), otherCheck: 0 };
  for (let i = 0; i < count; i++) {
    const kind = i % 4;
    const { bytes, what } = alter(kind);
    if (bytes.length === honest.length && bytes.every((x, j) => x === honest[j])) {
      tally.unchanged += 1;
      continue;
    }
    const dc = deployedCheck(await deployed(bytes));
    const ic = independentCheck(verifyStark(bytes, air));
    checks.deployed[dc] += 1;
    checks.independent[ic] += 1;
    if (dc !== ic) checks.otherCheck += 1;
    const d = dc === "accepted";
    const v = ic === "accepted";
    if (d && v) tally.both += 1;
    else if (!d && !v) tally.neither += 1;
    else if (d) tally.deployedOnly += 1;
    else tally.independentOnly += 1;
    if (d || v) odd.push(`  seed ${seed} #${i} kind ${kind}, ${what}: deployed ${d ? "accepts" : "refuses"}, independent ${v ? "accepts" : "refuses"}`);
  }
  rmSync(dir, { recursive: true, force: true });
  console.log(`seed ${seed}: ${count} alterations; both refuse ${tally.neither}, both accept ${tally.both}, only the deployed accepts ${tally.deployedOnly}, only the independent accepts ${tally.independentOnly}, left unchanged ${tally.unchanged}`);
  for (const l of odd) console.log(l);
  const out = process.env.FUZZ_JSON;
  if (out) writeFileSync(out, JSON.stringify({ seed, count, ...tally, checks }));
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
