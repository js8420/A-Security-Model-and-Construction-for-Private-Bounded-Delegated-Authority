import { execFile } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Constraints } from "./constraints.js";
import { parse } from "./proof.js";
import { verifyStark, type Verdict } from "./verify.js";

/** A payment's payload digest is the first of its public values. */
const R_DIGEST = 0;

export type Check = (bytes: Uint8Array) => Promise<Verdict>;

/** The deployed Plonky3 verifier, run as the circuit crate's binary on the delivered file. */
export function deployedVerifier(binary: string): Check {
  return (bytes) =>
    new Promise((resolve) => {
      const dir = mkdtempSync(join(tmpdir(), "proof-"));
      const file = join(dir, "proof.bin");
      writeFileSync(file, bytes);
      execFile(binary, ["verify-file", file], (err, stdout) => {
        rmSync(dir, { recursive: true, force: true });
        const out = stdout.trim();
        if (!err && out.startsWith("accept")) resolve({ ok: true });
        else resolve({ ok: false, reason: out.replace(/^reject /, "") || String(err) });
      });
    });
}

/** The verifier written apart from Plonky3, in this package. */
export function independentVerifier(air: Constraints): Check {
  return async (bytes) => verifyStark(bytes, air);
}

/**
 * The monitor's door for proofs. A delivered batch backs its settlements only
 * if every verifier accepts it, so a bug that makes one verifier accept a
 * forged proof leaves the batch's settlements unbacked, and the monitor
 * challenges them as it would an undelivered proof.
 */
export class ProofGate {
  private readonly backedDigests = new Set<bigint>();

  constructor(
    private readonly checks: readonly { name: string; check: Check }[],
    private readonly globals: number,
    private readonly rowWidth: number,
  ) {}

  async deliver(bytes: Uint8Array): Promise<{ accepted: boolean; verdicts: { name: string; verdict: Verdict }[]; digests: bigint[] }> {
    const verdicts = await Promise.all(this.checks.map(async (c) => ({ name: c.name, verdict: await c.check(bytes) })));
    const accepted = verdicts.every((v) => v.verdict.ok);
    let digests: bigint[] = [];
    if (accepted) {
      const { pv } = parse(bytes);
      const rows = (pv.length - this.globals) / this.rowWidth;
      digests = Array.from({ length: rows }, (_, r) => pv[this.globals + r * this.rowWidth + R_DIGEST]);
      for (const d of digests) this.backedDigests.add(d);
    }
    return { accepted, verdicts, digests };
  }

  /** Whether a settlement with this payload digest is backed by a delivered, accepted proof. */
  backed(digest: bigint): boolean {
    return this.backedDigests.has(digest);
  }
}
