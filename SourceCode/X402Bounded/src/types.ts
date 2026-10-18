/** The scheme's name on the wire. */
export const SCHEME = "bounded";

/**
 * What the agent sends in place of a transfer authorisation: one settlement of
 * its delegation on the reserve, signed by the agent. Integers travel as
 * decimal strings.
 */
export interface BoundedPayload {
  [key: string]: unknown;
  reserve: `0x${string}`;
  delegation: string;
  payee: `0x${string}`;
  amount: string;
  digest: string;
  time: string;
  elems: string[];
  signature: `0x${string}`;
}

/** What `extra` carries in the payment requirements. */
export interface BoundedExtra {
  [key: string]: unknown;
  reserve: `0x${string}`;
}

/** The shares and nullifiers of one payment, from the agent's prover. */
export interface FormedPayment {
  digest: bigint;
  elems: bigint[];
}

/**
 * The agent's payment engine: reserves units for a payment and returns its
 * payload digest and the values it publishes. The scheme only carries them.
 */
export interface PaymentSource {
  form(args: { reserve: `0x${string}`; delegation: bigint; payee: `0x${string}`; amount: bigint }): Promise<FormedPayment>;
}

export function isBoundedPayload(p: Record<string, unknown>): p is BoundedPayload {
  const s = (k: string) => typeof p[k] === "string";
  return (
    s("reserve") && s("delegation") && s("payee") && s("amount") && s("digest") && s("time") && s("signature") &&
    Array.isArray(p.elems) && (p.elems as unknown[]).every((e) => typeof e === "string")
  );
}
