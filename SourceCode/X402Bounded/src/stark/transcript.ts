import { keccak_256 } from "@noble/hashes/sha3";
import { P, type E } from "./field.js";
import type { Digest } from "./proof.js";

/** Whether a 64-bit draw is a field element as it stands. */
export const canonical = (v: bigint): boolean => v < P;

/**
 * The Fiat-Shamir transcript of the deployed configuration. Bytes absorbed
 * are buffered; a draw with no output pending hashes the whole buffer with
 * Keccak-256, keeps the digest as the new buffer, and hands out its bytes
 * from the last one back. Field elements travel as 8 little-endian bytes.
 */
export class Transcript {
  private input = new Uint8Array(1 << 16);
  private used = 0;
  private output: number[] = [];

  private absorb(byte: number) {
    if (this.used === this.input.length) {
      const grown = new Uint8Array(this.input.length * 2);
      grown.set(this.input);
      this.input = grown;
    }
    this.input[this.used++] = byte;
  }

  private word(v: bigint) {
    this.output = [];
    let x = v;
    for (let i = 0; i < 8; i++) {
      this.absorb(Number(x & 0xffn));
      x >>= 8n;
    }
  }

  observe(v: bigint) {
    this.word(v);
  }

  observeExt(v: E) {
    this.word(v[0]);
    this.word(v[1]);
  }

  observeCap(cap: readonly Digest[]) {
    for (const d of cap) for (const lane of d) this.word(lane);
  }

  private byte(): number {
    if (this.output.length === 0) {
      const h = keccak_256(this.input.subarray(0, this.used));
      this.input.set(h, 0);
      this.used = h.length;
      this.output = Array.from(h);
    }
    return this.output.pop() as number;
  }

  private draw64(): bigint {
    let v = 0n;
    for (let i = 0; i < 8; i++) v |= BigInt(this.byte()) << BigInt(8 * i);
    return v;
  }

  /** A uniform field element, by rejection of 64-bit draws at or above p. */
  sample(): bigint {
    for (;;) {
      const v = this.draw64();
      if (canonical(v)) return v;
    }
  }

  sampleExt(): E {
    const a = this.sample();
    const b = this.sample();
    return [a, b];
  }

  sampleBits(bits: number): number {
    if (bits < 0 || bits > 52) throw new Error("bit count out of range");
    return Number(this.draw64() & ((1n << BigInt(bits)) - 1n));
  }

  /** Grinding: absorbs the witness and requires the next `bits` drawn bits to be zero. */
  checkWitness(bits: number, witness: bigint): boolean {
    if (bits === 0) return true;
    this.observe(witness);
    return this.sampleBits(bits) === 0;
  }
}
