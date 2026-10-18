import { execFile } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Constraints } from "./constraints.js";
import { getAddress } from "viem";
import { parse } from "./proof.js";
import { verifyStark, type Verdict } from "./verify.js";

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

/** What a proof states about the delegation, once for the batch. */
export interface Terms {
  commitment: `0x${string}`;
  unitSize: bigint;
  rangeBase: bigint;
  rangeLen: bigint;
  secretHash: `0x${string}`;
}

/** What a proof states about one payment: every value its settlement records or the reserve acts on. */
export interface Statement {
  digest: bigint;
  root: `0x${string}`;
  domain: bigint;
  amount: bigint;
  payee: `0x${string}`;
  time: bigint;
  elems: bigint[];
}

const G_COM = 0;
const G_UNIT = 4;
const G_BASE = 5;
const G_RANGE = 6;
const G_SECRET_HASH = 7;
const R_DIGEST = 0;
const R_ROOT = 1;
const R_DOMAIN = 5;
const R_AMOUNT = 6;
const R_PAYEE = 7;
const R_TIME = 10;
const R_ELEMS = 11;
const COVER = 64;

/** Four 64-bit lanes as the reserve stores them in a word, lowest lane in the lowest bits. */
const lanes = (v: readonly bigint[]): `0x${string}` =>
  `0x${v.reduce((w, x, j) => w | (x << BigInt(64 * j)), 0n).toString(16).padStart(64, "0")}`;

/** An address from the circuit's three limbs: bits 0 to 55, 56 to 111 and 112 to 159. */
const address = (l: readonly bigint[]): `0x${string}` =>
  getAddress(`0x${(l[0] | (l[1] << 56n) | (l[2] << 112n)).toString(16).padStart(40, "0")}`);

/** The terms and payment statements a proof's public values carry. */
export function statements(pv: readonly bigint[], globals: number, rowWidth: number): { terms: Terms; payments: Statement[] } {
  const terms: Terms = {
    commitment: lanes(pv.slice(G_COM, G_COM + 4)),
    unitSize: pv[G_UNIT],
    rangeBase: pv[G_BASE],
    rangeLen: pv[G_RANGE],
    secretHash: lanes(pv.slice(G_SECRET_HASH, G_SECRET_HASH + 4)),
  };
  const rows = (pv.length - globals) / rowWidth;
  const payments = Array.from({ length: rows }, (_, r) => {
    const b = globals + r * rowWidth;
    const amount = pv[b + R_AMOUNT];
    const units = Math.min(Number((amount + terms.unitSize - 1n) / terms.unitSize), COVER);
    return {
      digest: pv[b + R_DIGEST],
      root: lanes(pv.slice(b + R_ROOT, b + R_ROOT + 4)),
      domain: pv[b + R_DOMAIN],
      amount,
      payee: address(pv.slice(b + R_PAYEE, b + R_PAYEE + 3)),
      time: pv[b + R_TIME],
      elems: pv.slice(b + R_ELEMS, b + R_ELEMS + 3 * units),
    };
  });
  return { terms, payments };
}

/**
 * The monitor's door for proofs. A delivered batch counts only if every
 * verifier accepts it, so a bug that makes one verifier accept a forged proof
 * leaves the batch's settlements unbacked, and the monitor challenges them as
 * it would an undelivered proof.
 */
export class ProofGate {
  constructor(
    private readonly checks: readonly { name: string; check: Check }[],
    private readonly globals: number,
    private readonly rowWidth: number,
  ) {}

  async deliver(bytes: Uint8Array): Promise<{
    accepted: boolean;
    verdicts: { name: string; verdict: Verdict }[];
    terms: Terms | null;
    payments: Statement[];
  }> {
    const verdicts = await Promise.all(this.checks.map(async (c) => ({ name: c.name, verdict: await c.check(bytes) })));
    const accepted = verdicts.every((v) => v.verdict.ok);
    if (!accepted) return { accepted, verdicts, terms: null, payments: [] };
    const { terms, payments } = statements(parse(bytes).pv, this.globals, this.rowWidth);
    return { accepted, verdicts, terms, payments };
  }
}
