import { decodeAbiParameters, encodeAbiParameters, getAddress, keccak256, type Address, type Hex } from "viem";

/**
 * A payment's fields in the clear, as the agent opens them to its principal:
 * the payload the circuit's digest is taken over (amount, merchant, category,
 * signed time, payee, domain, nonce), the first unit of the run it consumes,
 * and a 32-byte salt so that the commitment the reserve records hides them.
 */
export interface Opening {
  salt: Hex;
  amount: bigint;
  merchant: bigint;
  category: bigint;
  time: bigint;
  payee: Address;
  domain: bigint;
  nonce: bigint;
  runStart: bigint;
}

const LAYOUT = [
  { type: "bytes32" }, { type: "uint64" }, { type: "uint64" }, { type: "uint64" }, { type: "uint64" },
  { type: "address" }, { type: "uint64" }, { type: "uint64" }, { type: "uint64" },
] as const;

/** The opening's fields in the order the commitment takes them. */
export function encodeOpening(o: Opening): Hex {
  return encodeAbiParameters(LAYOUT, [
    o.salt, o.amount, o.merchant, o.category, o.time, getAddress(o.payee), o.domain, o.nonce, o.runStart,
  ]);
}

export function decodeOpening(b: Hex): Opening {
  const [salt, amount, merchant, category, time, payee, domain, nonce, runStart] = decodeAbiParameters(LAYOUT, b);
  return { salt, amount, merchant, category, time, payee: getAddress(payee), domain, nonce, runStart };
}

/** The commitment the agent signs and the reserve emits with the settlement. */
export function commitOpening(o: Opening): Hex {
  return keccak256(encodeOpening(o));
}

/** The units a payment of this amount consumes at this unit size. */
export const unitsOf = (amount: bigint, unit: bigint): bigint => (amount + unit - 1n) / unit;
