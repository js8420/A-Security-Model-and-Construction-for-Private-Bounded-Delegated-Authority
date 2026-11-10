import { loadKZG } from "kzg-wasm";
import {
  bytesToHex, concat, encodeFunctionData, encodePacked, fromRlp, hexToBytes, keccak256, parseAbi, sha256, toRlp,
  type Account, type Address, type Chain, type Hex, type PublicClient, type Transport, type WalletClient,
} from "viem";
import type { Sealed } from "./answerer.js";

/**
 * The second way an answerer posts what backs a batch: as blobs on Ethereum,
 * recorded by the BlobPosting contract there, which reports the blobs'
 * chained hash to the posting contract on the domain through a deposit the
 * domain must include. Anyone reads the blobs back from Ethereum's nodes and
 * checks them against the versioned hashes the transactions carried, so the
 * source of the bytes need not be trusted.
 */

/** The calls and events of BlobPosting.sol. */
export const blobPostingAbi = parseAbi([
  "function post(uint256 id, bytes32 root, uint256 count, bool last)",
  "event Carried(address indexed poster, uint256 indexed id, bytes32 indexed root, uint256 blobs)",
  "event Posted(address indexed poster, uint256 indexed id, bytes32 indexed root, bytes32 blobsHash, uint256 blobs, uint256 cost)",
]);

/** The most blobs one transaction may carry since Fusaka (EIP-7594). */
export const BLOBS_PER_TX = 6;
/**
 * Gas one call of `post` is given: the call with six blobs measured 75,000
 * gas, the closing one 229,000 with its message, besides 21,000 intrinsic and
 * its call data; a transaction pays only the gas it uses.
 */
const POST_GAS = 500_000n;
/** A sealed opening's length: every one is the same. */
const SEALED_BYTES = 349;

/** KZG as the posting needs it: a blob's commitment, its 128 cell proofs, and its one proof of the form before Fusaka. */
export interface Kzg {
  commitment(blob: Hex): Hex;
  cellProofs(blob: Hex): Hex[];
  blobProof(blob: Hex, commitment: Hex): Hex;
}

let loaded: Promise<Kzg> | undefined;

/** The KZG library with Ethereum's trusted setup, loaded once. */
export function loadKzg(): Promise<Kzg> {
  loaded ??= loadKZG().then((k) => ({
    commitment: (b: Hex) => k.blobToKZGCommitment(b) as Hex,
    cellProofs: (b: Hex) => k.computeCellsAndKZGProofs(b).proofs as Hex[],
    blobProof: (b: Hex, c: Hex) => k.computeBlobKZGProof(b, c) as Hex,
  }));
  return loaded;
}

/** A versioned hash as EIP-4844 defines it: version byte 1, then SHA-256 of the commitment without its first byte. */
export function versionedHash(commitment: Hex): Hex {
  const h = hexToBytes(sha256(commitment));
  h[0] = 1;
  return bytesToHex(h);
}

/** The hash BlobPosting reports and a receipt names: the versioned hashes chained from zero, then their count. */
export function blobsHash(versioned: readonly Hex[]): Hex {
  let acc = `0x${"00".repeat(32)}` as Hex;
  for (const v of versioned) acc = keccak256(concat([acc, v]));
  return keccak256(encodePacked(["bytes32", "uint256"], [acc, BigInt(versioned.length)]));
}

const u32 = (n: number) => Uint8Array.of(n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255);
const u64 = (n: bigint) => hexToBytes(`0x${n.toString(16).padStart(16, "0")}`);

/**
 * What the blobs of a batch carry: the proof's length and the proof, then
 * the number of sealed openings and each opening after its settlement's
 * digest, in the batch's order.
 */
export function blobPayload(proof: Uint8Array, sealed: readonly Sealed[]): Uint8Array {
  const parts: Uint8Array[] = [u32(proof.length), proof, u32(sealed.length)];
  for (const s of sealed) {
    const b = hexToBytes(s.blob);
    if (b.length !== SEALED_BYTES) throw new Error(`sealed opening of ${b.length} bytes`);
    parts.push(u64(s.digest), b);
  }
  return hexToBytes(concat(parts.map((p) => bytesToHex(p))));
}

/** The proof and the sealed openings a payload carries, or nothing if it is malformed. */
export function readPayload(p: Uint8Array): { proof: Uint8Array; sealed: { digest: bigint; blob: Hex }[] } | undefined {
  const view = new DataView(p.buffer, p.byteOffset, p.byteLength);
  if (p.length < 8) return undefined;
  const n = view.getUint32(0);
  if (p.length < 8 + n) return undefined;
  const proof = p.slice(4, 4 + n);
  const count = view.getUint32(4 + n);
  let at = 8 + n;
  if (p.length !== at + count * (8 + SEALED_BYTES)) return undefined;
  const sealed: { digest: bigint; blob: Hex }[] = [];
  for (let i = 0; i < count; i++, at += 8 + SEALED_BYTES) {
    sealed.push({ digest: view.getBigUint64(at), blob: bytesToHex(p.slice(at + 8, at + 8 + SEALED_BYTES)) });
  }
  return { proof, sealed };
}

const FIELD_ELEMENTS = 4096;
/** Bytes a blob carries: 31 of each field element's 32, its first byte zero so it stays below the field's modulus. */
export const BLOB_BYTES = 31 * FIELD_ELEMENTS;

/**
 * A payload cut into blobs, 31 bytes to each field element, ended by the
 * byte 0x80 and zeros, and the blobs' versioned hashes.
 */
export function blobsOf(payload: Uint8Array, kzg: Kzg): { blobs: Hex[]; versioned: Hex[] } {
  const data = new Uint8Array(payload.length + 1);
  data.set(payload);
  data[payload.length] = 0x80;
  const blobs: Hex[] = [];
  for (let at = 0; at < data.length; at += BLOB_BYTES) {
    const blob = new Uint8Array(32 * FIELD_ELEMENTS);
    for (let fe = 0; fe < FIELD_ELEMENTS && at + 31 * fe < data.length; fe++) {
      blob.set(data.subarray(at + 31 * fe, Math.min(at + 31 * fe + 31, data.length)), 32 * fe + 1);
    }
    blobs.push(bytesToHex(blob));
  }
  return { blobs, versioned: blobs.map((b) => versionedHash(kzg.commitment(b))) };
}

/** The payload blobs carry, or nothing if they are not as blobsOf makes them. */
export function payloadOf(blobs: readonly Hex[]): Uint8Array | undefined {
  const data = new Uint8Array(BLOB_BYTES * blobs.length);
  for (let i = 0; i < blobs.length; i++) {
    const b = hexToBytes(blobs[i]);
    if (b.length !== 32 * FIELD_ELEMENTS) return undefined;
    for (let fe = 0; fe < FIELD_ELEMENTS; fe++) {
      if (b[32 * fe] !== 0) return undefined;
      data.set(b.subarray(32 * fe + 1, 32 * fe + 32), BLOB_BYTES * i + 31 * fe);
    }
  }
  let end = data.length - 1;
  while (end >= 0 && data[end] === 0) end--;
  if (end < 0 || data[end] !== 0x80 || data.length - end > BLOB_BYTES) return undefined;
  return data.slice(0, end);
}

/**
 * Posts a payload's blobs through BlobPosting, at most BLOBS_PER_TX to a
 * transaction, the last closing the posting. Each transaction is sent in the
 * network form Fusaka requires: the signed transaction, then wrapper version
 * 1, the blobs, their commitments and every blob's 128 cell proofs. A node
 * from before Fusaka cannot decode that form, and is sent the one it takes:
 * the signed transaction, the blobs, their commitments and one proof a blob.
 * Returns the blobs' chained hash and each transaction's hash.
 */
export async function postBlobs(
  l1: PublicClient,
  wallet: WalletClient<Transport, Chain, Account>,
  blobPosting: Address,
  id: bigint,
  root: Hex,
  payload: Uint8Array,
  kzg: Kzg,
): Promise<{ blobsHash: Hex; txs: Hex[] }> {
  const { blobs, versioned } = blobsOf(payload, kzg);
  const txs: Hex[] = [];
  let cells = true;
  for (let at = 0; at < blobs.length; at += BLOBS_PER_TX) {
    const part = blobs.slice(at, at + BLOBS_PER_TX);
    const hashes = versioned.slice(at, at + BLOBS_PER_TX);
    const last = at + BLOBS_PER_TX >= blobs.length;
    const data = encodeFunctionData({ abi: blobPostingAbi, functionName: "post", args: [id, root, BigInt(part.length), last] });
    const fees = await l1.estimateFeesPerGas();
    const blobFee = await l1.getBlobBaseFee();
    const nonce = await l1.getTransactionCount({ address: wallet.account.address, blockTag: "pending" });
    const signed = await wallet.account.signTransaction?.({
      type: "eip4844", chainId: wallet.chain.id, nonce, to: blobPosting, data, gas: POST_GAS, value: 0n,
      maxFeePerGas: fees.maxFeePerGas, maxPriorityFeePerGas: fees.maxPriorityFeePerGas, maxFeePerBlobGas: 2n * blobFee + 1n,
      blobVersionedHashes: hashes,
    });
    if (!signed) throw new Error("the posting account cannot sign locally");
    const body = fromRlp(`0x${signed.slice(4)}` as Hex);
    const commitments = part.map((b) => kzg.commitment(b));
    const send = (raw: Hex) => l1.request({ method: "eth_sendRawTransaction", params: [raw] }) as Promise<Hex>;
    const legacy = () => send(`0x03${toRlp([body, part, commitments, part.map((b, i) => kzg.blobProof(b, commitments[i]))]).slice(2)}` as Hex);
    let hash: Hex;
    if (cells) {
      try {
        hash = await send(`0x03${toRlp([body, "0x01", part, commitments, part.flatMap((b) => kzg.cellProofs(b))]).slice(2)}` as Hex);
      } catch (e) {
        if (!/decode/i.test(String(e))) throw e;
        cells = false;
        hash = await legacy();
      }
    } else {
      hash = await legacy();
    }
    const r = await l1.waitForTransactionReceipt({ hash });
    if (r.status !== "success") throw new Error(`blob posting ${hash} reverted`);
    txs.push(hash);
  }
  return { blobsHash: blobsHash(versioned), txs };
}

/** Where a reader gets a blob by its versioned hash: an Ethereum node or a beacon node. */
export type BlobFetch = (versioned: Hex, block: { number: bigint; timestamp: bigint }) => Promise<Hex | undefined>;

/** A local node's blob store, as anvil keeps it. */
export const anvilBlobs = (l1: PublicClient): BlobFetch => async (v) =>
  ((await l1.request({ method: "anvil_getBlobByHash" as never, params: [v] as never })) as Hex | null) ?? undefined;

/**
 * A beacon node's blob store: the blobs of the slot the block was proposed
 * in, asked for by versioned hash, as the beacon API serves them since
 * Fusaka. Ethereum's nodes keep blobs for 4,096 epochs, about 18 days.
 */
export const beaconBlobs = (beacon: string): BlobFetch => {
  let genesis: bigint | undefined;
  return async (v, block) => {
    if (genesis === undefined) {
      const g = (await (await fetch(`${beacon}/eth/v1/beacon/genesis`)).json()) as { data: { genesis_time: string } };
      genesis = BigInt(g.data.genesis_time);
    }
    const slot = (block.timestamp - genesis) / 12n;
    const res = await fetch(`${beacon}/eth/v1/beacon/blobs/${slot}?versioned_hashes=${v}`);
    if (!res.ok) return undefined;
    const j = (await res.json()) as { data: Hex[] };
    return j.data[0];
  };
};

/** Reads postings of blobs back from Ethereum. */
export interface BlobSource {
  /**
   * The payload a poster's blobs for a batch carry, if the blobs whose
   * chained hash is `hash` can be read and every one matches the versioned
   * hash its transaction carried.
   */
  payload(poster: Address, id: bigint, root: Hex, hash: Hex): Promise<Uint8Array | undefined>;
}

/**
 * The postings BlobPosting recorded on Ethereum. A posting is the poster's
 * run of calls for a batch that a closing call ends; each run is tried, and
 * the one whose blobs chain to the hash is read.
 */
export function ethereumBlobs(l1: PublicClient, blobPosting: Address, fetchBlob: BlobFetch, kzg: () => Promise<Kzg> = loadKzg): BlobSource {
  return {
    async payload(poster, id, root, hash) {
      const args = { poster, id, root };
      const carried = await l1.getContractEvents({ address: blobPosting, abi: blobPostingAbi, eventName: "Carried", args, fromBlock: 0n });
      const closed = await l1.getContractEvents({ address: blobPosting, abi: blobPostingAbi, eventName: "Posted", args, fromBlock: 0n });
      const order = (l: { blockNumber: bigint | null; logIndex: number | null }) => [l.blockNumber ?? 0n, BigInt(l.logIndex ?? 0)] as const;
      const before = (a: { blockNumber: bigint | null; logIndex: number | null }, b: { blockNumber: bigint | null; logIndex: number | null }) => {
        const [x, y] = [order(a), order(b)];
        return x[0] < y[0] || (x[0] === y[0] && x[1] < y[1]);
      };
      let prev: (typeof closed)[number] | undefined;
      for (const end of closed) {
        const run = carried.filter((c) => (!prev || before(prev, c)) && !before(end, c));
        prev = end;
        if ((end.args.blobsHash as Hex).toLowerCase() !== hash.toLowerCase()) continue;
        const versioned: Hex[] = [];
        const blocks: { number: bigint; timestamp: bigint }[] = [];
        for (const c of run) {
          const tx = await l1.getTransaction({ hash: c.transactionHash as Hex });
          const b = await l1.getBlock({ blockNumber: tx.blockNumber as bigint });
          for (const v of tx.blobVersionedHashes ?? []) {
            versioned.push(v);
            blocks.push({ number: b.number as bigint, timestamp: b.timestamp });
          }
        }
        if (blobsHash(versioned).toLowerCase() !== hash.toLowerCase()) return undefined;
        const k = await kzg();
        const blobs: Hex[] = [];
        for (let i = 0; i < versioned.length; i++) {
          const blob = await fetchBlob(versioned[i], blocks[i]);
          if (!blob || versionedHash(k.commitment(blob)).toLowerCase() !== versioned[i].toLowerCase()) return undefined;
          blobs.push(blob);
        }
        return payloadOf(blobs);
      }
      return undefined;
    },
  };
}
