import { bytesToHex, concat, encodePacked, keccak256, sha256, type Hex } from "viem";
import type { Monitor } from "./monitor.js";

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
export const CHUNK = 262144;

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
 * the proof hides. It takes each batch once: a second set of openings for a
 * proof it holds is refused, since it would have to receipt two trees for
 * one batch, and either receipt could then slash it.
 */
export class Answerer {
  private readonly batches: { proof: Uint8Array; sealed: readonly Sealed[] }[] = [];
  private readonly proofs = new Set<Hex>();

  /** Takes a batch and returns what its receipt signs: the root of its sealed openings and the proof's hash. */
  receive(proof: Uint8Array, sealed: readonly Sealed[]): { sealedRoot: Hex; proofHash: Hex } {
    const id = sha256(proof);
    if (this.proofs.has(id)) throw new Error("batch already held");
    this.proofs.add(id);
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
