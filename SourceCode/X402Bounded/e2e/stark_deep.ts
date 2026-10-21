import { appendFileSync, existsSync, readFileSync, rmSync } from "node:fs";
import { loadConstraints, verifyStark } from "../src/index.js";
import { deployedCheck, independentCheck } from "./stark_kit.js";

/**
 * The independent verifier on the faulty proofs `delegation-circuit
 * deep-faults` wrote. For each line of the manifest of one family whose
 * proof is still on disk, it checks the proof, appends both verifiers'
 * checks to the results file as one JSON line, and deletes the proof.
 */
const env = (k: string) => {
  const v = process.env[k];
  if (!v) throw new Error(`${k} not set`);
  return v;
};
const air = loadConstraints(readFileSync(env("CONSTRAINTS")));
const dir = env("DEEP_DIR");
const family = env("FAMILY");
const results = env("DEEP_RESULTS");

for (const line of readFileSync(`${dir}/manifest.tsv`, "utf8").split("\n")) {
  if (!line.trim()) continue;
  const [fam, variant, file, where, verdict] = line.split("\t");
  if (fam !== family) continue;
  if (file === "-") {
    appendFileSync(results, JSON.stringify({ family: fam, variant: Number(variant), where, made: false }) + "\n");
    continue;
  }
  if (!existsSync(file)) continue;
  const independent = verifyStark(new Uint8Array(readFileSync(file)), air);
  appendFileSync(
    results,
    JSON.stringify({
      family: fam,
      variant: Number(variant),
      where,
      made: true,
      deployed: deployedCheck(verdict),
      independent: independentCheck(independent),
      reason: independent.ok ? "" : independent.reason,
    }) + "\n",
  );
  rmSync(file);
}
