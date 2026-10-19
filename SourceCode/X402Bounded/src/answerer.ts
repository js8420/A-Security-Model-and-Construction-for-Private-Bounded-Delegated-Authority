import type { Hex } from "viem";
import type { Monitor } from "./monitor.js";

/**
 * The agent's answerer. With each batch the agent hands it the batch's proof
 * and every payment's opening sealed to the monitor's key, so that when the
 * agent is offline the answerer can still answer a challenge on chain and
 * deliver to the monitor everything that backs the batch. The answerer holds
 * the openings only as ciphertexts of one fixed length: it learns no field
 * the proof hides.
 */
export class Answerer {
  private readonly batches: { proof: Uint8Array; sealed: readonly Hex[] }[] = [];

  receive(proof: Uint8Array, sealed: readonly Hex[]): void {
    this.batches.push({ proof, sealed });
  }

  /** Everything the answerer holds, as it stores it. */
  held(): { proofs: Uint8Array[]; sealed: Hex[] } {
    return { proofs: this.batches.map((b) => b.proof), sealed: this.batches.flatMap((b) => [...b.sealed]) };
  }

  /** Delivers every proof and sealed opening it holds. Returns how many proofs every verifier accepted and how many openings opened. */
  async serve(m: Monitor): Promise<{ proofs: number; opened: number }> {
    let proofs = 0;
    let opened = 0;
    for (const b of this.batches) {
      if (await m.deliverProof(b.proof)) proofs += 1;
      for (const s of b.sealed) if (m.deliverSealed(s)) opened += 1;
    }
    return { proofs, opened };
  }
}
