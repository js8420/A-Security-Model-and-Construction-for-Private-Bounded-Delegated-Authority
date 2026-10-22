import { bytesToHex, concat, encodePacked, keccak256, sha256, type Hex } from "viem";
import type { Monitor } from "./monitor.js";
import type { ProofGate } from "./stark/gate.js";

/** A payment's opening sealed to the monitor's key, and the settlement it belongs to. */
export interface Sealed {
  domain: bigint;
  digest: bigint;
  blob: Hex;
}

const ZERO = `0x${"00".repeat(32)}` as Hex;

/**
 * The tree an answerer's receipt names: one leaf per payment of the batch,
 * the Keccak hash of its sealed opening, in the batch's order, padded with
 * zero leaves to a power of two. An inner node hashes its two children.
 */
export function sealedTree(blobs: readonly Hex[]): { root: Hex; path: (i: number) => Hex[] } {
  let width = 1;
  while (width < blobs.length) width *= 2;
  const levels: Hex[][] = [[...blobs.map((b) => keccak256(b)), ...Array<Hex>(width - blobs.length).fill(ZERO)]];
  while (levels[levels.length - 1].length > 1) {
    const l = levels[levels.length - 1];
    levels.push(Array.from({ length: l.length / 2 }, (_, i) => keccak256(concat([l[2 * i], l[2 * i + 1]]))));
  }
  return {
    root: levels[levels.length - 1][0],
    path: (i: number) => levels.slice(0, -1).map((l, j) => l[(i >> j) ^ 1]),
  };
}

/** The size of every chunk of a posted proof but the last, as the dispute contract fixes it. */
export const CHUNK = 98304;

/** A proof cut into the chunks it is posted in. */
export function proofChunks(proof: Uint8Array): Uint8Array[] {
  const out: Uint8Array[] = [];
  for (let at = 0; at < proof.length; at += CHUNK) out.push(proof.subarray(at, Math.min(at + CHUNK, proof.length)));
  return out;
}

/** The hash a receipt names for a proof: chained over its chunks from zero, then its length. */
export function proofHash(proof: Uint8Array): Hex {
  let h = `0x${"00".repeat(32)}` as Hex;
  for (const c of proofChunks(proof)) h = keccak256(concat([h, bytesToHex(c)]));
  return keccak256(encodePacked(["bytes32", "uint256"], [h, BigInt(proof.length)]));
}

/**
 * The agent's answerer. With each batch the agent hands it the batch's proof
 * and every payment's opening sealed to the monitor's key, so that when the
 * agent is offline the answerer can still answer a challenge on chain and
 * deliver to the monitor everything that backs the batch. The answerer holds
 * the openings only as ciphertexts of one fixed length: it learns no field
 * the proof hides.
 *
 * Its receipt can slash its stake, so it signs only what it can stand
 * behind. It checks the proof with every verifier of its gate before it
 * signs, and refuses a proof any verifier rejects. It refuses sealed openings
 * that do not name the proof's payments one for one, in the proof's order.
 * It takes each payment once: a batch that repeats a proof it holds, or names
 * a payment of a batch it holds, is refused, since it would then receipt two
 * trees for one settlement and either receipt could slash it.
 */
export class Answerer {
  private readonly batches: { proof: Uint8Array; sealed: readonly Sealed[] }[] = [];
  private readonly proofs = new Set<Hex>();
  private readonly payments = new Set<string>();

  constructor(private readonly gate: ProofGate) {}

  /** Takes a batch and returns what its receipt signs: the root of its sealed openings and the proof's hash. */
  async receive(proof: Uint8Array, sealed: readonly Sealed[]): Promise<{ sealedRoot: Hex; proofHash: Hex }> {
    const id = sha256(proof);
    if (this.proofs.has(id)) throw new Error("batch already held");
    const r = await this.gate.deliver(proof);
    if (!r.accepted) {
      const why = r.verdicts.filter((v) => !v.verdict.ok).map((v) => v.name).join(", ");
      throw new Error(`proof refused by ${why}`);
    }
    const named = r.payments.map((p) => `${p.domain}/${p.digest}`);
    if (new Set(named).size !== named.length) throw new Error("proof names a payment twice");
    if (named.some((n) => this.payments.has(n))) throw new Error("batch overlaps a held batch");
    if (sealed.length > 0) {
      if (sealed.length !== r.payments.length) throw new Error("sealed openings do not match the proof's payments");
      sealed.forEach((s, i) => {
        if (s.domain !== r.payments[i].domain || s.digest !== r.payments[i].digest) {
          throw new Error(`sealed opening ${i} names another payment than the proof's`);
        }
      });
    }
    this.proofs.add(id);
    for (const n of named) this.payments.add(n);
    this.batches.push({ proof, sealed });
    return { sealedRoot: sealedTree(sealed.map((s) => s.blob)).root, proofHash: proofHash(proof) };
  }

  /** The proof of the batch holding a settlement. */
  proofOf(domain: bigint, digest: bigint): Uint8Array | undefined {
    return this.batches.find((b) => b.sealed.some((s) => s.domain === domain && s.digest === digest))?.proof;
  }

  /** Everything the answerer holds, as it stores it. */
  held(): { proofs: Uint8Array[]; sealed: Hex[] } {
    return { proofs: this.batches.map((b) => b.proof), sealed: this.batches.flatMap((b) => b.sealed.map((s) => s.blob)) };
  }

  /** The sealed opening it holds for a settlement, with its batch's openings, or nothing. */
  find(domain: bigint, digest: bigint): { sealed: Sealed; batch: readonly Sealed[]; index: number } | undefined {
    for (const b of this.batches) {
      const index = b.sealed.findIndex((s) => s.domain === domain && s.digest === digest);
      if (index >= 0) return { sealed: b.sealed[index], batch: b.sealed, index };
    }
    return undefined;
  }

  /** Delivers every proof it holds, and every sealed opening unless `proofsOnly`. Returns how many proofs every verifier accepted and how many openings opened. */
  async serve(m: Monitor, proofsOnly = false): Promise<{ proofs: number; opened: number }> {
    let proofs = 0;
    let opened = 0;
    for (const b of this.batches) {
      if (await m.deliverProof(b.proof)) proofs += 1;
      if (proofsOnly) continue;
      for (const s of b.sealed) if (await m.deliverSealed(s.blob, s.domain, s.digest)) opened += 1;
    }
    return { proofs, opened };
  }
}
