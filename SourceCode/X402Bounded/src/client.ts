import type { PaymentPayloadResult, PaymentRequirements, SchemeNetworkClient } from "@x402/core/types";
import { keccak256, encodePacked, getAddress, type PrivateKeyAccount, type PublicClient } from "viem";
import { reserveAbi } from "./abi.js";
import { SCHEME, type BoundedExtra, type BoundedPayload, type PaymentSource } from "./types.js";

/**
 * The agent's side. It pays only through reserves it holds a delegation on,
 * and signs exactly what the reserve checks: the reserve's own signed digest
 * over the domain, the delegation, the payee, the amount, the payload digest,
 * the time, the published values and the commitment to the opening.
 */
export class BoundedEvmClient implements SchemeNetworkClient {
  readonly scheme = SCHEME;
  private readonly delegations: ReadonlyMap<string, bigint>;

  constructor(
    private readonly account: PrivateKeyAccount,
    private readonly chain: PublicClient,
    delegations: ReadonlyMap<string, bigint>,
    private readonly source: PaymentSource,
  ) {
    this.delegations = new Map([...delegations].map(([r, id]) => [getAddress(r), id]));
  }

  async createPaymentPayload(x402Version: number, req: PaymentRequirements): Promise<PaymentPayloadResult> {
    const reserve = getAddress((req.extra as BoundedExtra).reserve);
    const delegation = this.delegations.get(reserve);
    if (delegation === undefined) throw new Error(`no delegation on reserve ${reserve}`);
    const payee = getAddress(req.payTo);
    const amount = BigInt(req.amount);
    const time = (await this.chain.getBlock({ blockTag: "latest" })).timestamp;
    const { digest, elems, opening } = await this.source.form({ reserve, delegation, payee, amount, time });
    const elemsHash = keccak256(encodePacked(["uint64[]"], [elems]));
    const hash = await this.chain.readContract({
      address: reserve,
      abi: reserveAbi,
      functionName: "signedDigest",
      args: [delegation, payee, amount, digest, time, elemsHash, opening],
    });
    const signature = await this.account.sign({ hash });
    const payload: BoundedPayload = {
      reserve,
      delegation: delegation.toString(),
      payee,
      amount: amount.toString(),
      digest: digest.toString(),
      time: time.toString(),
      elems: elems.map((e) => e.toString()),
      opening,
      signature,
    };
    return { x402Version, payload };
  }
}
