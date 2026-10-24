import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { loadConstraints, verifyStark } from "../src/index.js";

const env = (k: string) => {
  const v = process.env[k];
  if (!v) throw new Error(`${k} not set`);
  return v;
};
const num = (k: string, d: number) => Number(process.env[k] ?? String(d));

const air = loadConstraints(readFileSync(env("CONSTRAINTS")));
const file = env("PROOF_FULL");
const proof = new Uint8Array(readFileSync(file));
const bin = env("CIRCUIT_BIN");
const batches = num("BATCHES", 12);
const perBatch = num("PER_BATCH", 25);
const coolMs = num("COOL_MS", 20000);
const passes = num("PASSES", 2);

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const stats = (xs: number[]) => {
  const s = [...xs].sort((a, b) => a - b);
  const at = (q: number) => {
    const p = (s.length - 1) * q;
    const lo = Math.floor(p);
    return s[lo] + (s[Math.ceil(p)] - s[lo]) * (p - lo);
  };
  return { min: s[0], q1: at(0.25), median: at(0.5), q3: at(0.75), max: s[s.length - 1] };
};
const f = (x: number) => x.toFixed(1);
const row = (name: string, xs: number[]) => {
  const t = stats(xs);
  return `    ${name.padEnd(30)} ${String(xs.length).padStart(5)} ${f(t.min).padStart(8)} ${f(t.q1).padStart(8)} ${f(t.median).padStart(8)} ${f(t.q3).padStart(8)} ${f(t.max).padStart(8)}`;
};

async function main() {
  const out: string[] = [];
  out.push("VERIFICATION TIME, DEPLOYED AGAINST INDEPENDENT, 256-PAYMENT PROOF");
  out.push("=".repeat(78));
  out.push(`  ${passes} passes; each ${batches} batches of ${perBatch} runs per verifier, the two alternating`);
  out.push(`  batch by batch, ${coolMs / 1000} s of idle between batches; deployed times are in process`);
  if (!verifyStark(proof, air).ok) throw new Error("the independent verifier refuses the timed proof");
  for (let p = 1; p <= passes; p++) {
    const d: number[] = [];
    const i: number[] = [];
    const dMed: number[] = [];
    const iMed: number[] = [];
    for (let b = 0; b < batches; b++) {
      const first = b % 2 === 0;
      const runDeployed = () => {
        const words = execFileSync(bin, ["verify-file", file, String(perBatch)]).toString().trim().split(" ");
        if (words[0] !== "accept") throw new Error("the deployed verifier refuses the timed proof");
        const xs = words.slice(1).map(Number);
        d.push(...xs);
        dMed.push(stats(xs).median);
      };
      const runIndependent = () => {
        const xs: number[] = [];
        for (let k = 0; k < perBatch; k++) {
          const t = performance.now();
          const v = verifyStark(proof, air);
          xs.push(performance.now() - t);
          if (!v.ok) throw new Error("the independent verifier refuses the timed proof");
        }
        i.push(...xs);
        iMed.push(stats(xs).median);
      };
      if (first) {
        runDeployed();
        runIndependent();
      } else {
        runIndependent();
        runDeployed();
      }
      if (b + 1 < batches) await sleep(coolMs);
    }
    out.push(`  pass ${p}, ms:                       runs      min       q1   median       q3      max`);
    out.push(row("deployed Plonky3", d));
    out.push(row("independent, TypeScript", i));
    out.push(`    per-batch medians, deployed:    ${dMed.map(f).join(" ")}`);
    out.push(`    per-batch medians, independent: ${iMed.map(f).join(" ")}`);
    const ds = stats(d);
    const is = stats(i);
    out.push(`    interquartile ranges overlap: ${ds.q3 >= is.q1 && is.q3 >= ds.q1 ? "yes" : "no"}; median ratio ${(is.median / ds.median).toFixed(1)}`);
    if (p < passes) await sleep(coolMs);
  }
  console.log(out.join("\n"));
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
