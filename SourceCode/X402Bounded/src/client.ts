import type { PaymentPayloadResult, PaymentRequirements, SchemeNetworkClient } from "@x402/core/types";
import { keccak256, encodePacked, getAddress, type Account, type Chain, type PrivateKeyAccount, type PublicClient, type Transport, type WalletClient } from "viem";
import { reserveAbi } from "./abi.js";
import { SCHEME, type BoundedExtra, type BoundedPayload, type PaymentSource } from "./types.js";

/**
 * The agent's side. It pays only through reserves it holds a delegation on,
 * and signs exactly what the reserve checks: the reserve's own signed digest
 * over the domain, the delegation, the payee, the amount, the payload digest,
 * the time, the published values and the commitment to the opening.
 *
 * It also keeps every payment it signed until the payment is on the
 * finalized chain. A payment that reached the chain and then left it, the
 * sequencer having replaced its block, it sends again itself, unchanged, so
 * the units it consumed are spent by that one payment and never by a second
 * formed in its place; the payee is paid what the agent signed for. A
 * payment that never reaches the chain within the reserve's clock tolerance
 * can no longer settle, and its units stay unspent, as any run reserved and
 * never settled does.
 */
export class BoundedEvmClient implements SchemeNetworkClient {
  readonly scheme = SCHEME;
  private readonly delegations: ReadonlyMap<string, bigint>;
  private readonly kept = new Map<string, { payload: BoundedPayload; seen: boolean }>();
  private readonly tolerance = new Map<string, bigint>();

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
    this.kept.set(`${reserve}|${delegation}|${digest}`, { payload, seen: false });
    return { x402Version, payload };
  }

  /**
   * Checks every kept payment once: forgets one the finalized chain holds or
   * one past the tolerance that never landed, and sends again, through
   * `wallet`, one that landed and is no longer on the chain. Returns the
   * digests sent again.
   */
  async keep(wallet: WalletClient<Transport, Chain, Account>): Promise<bigint[]> {
    const sent: bigint[] = [];
    const now = (await this.chain.getBlock({ blockTag: "latest" })).timestamp;
    for (const [key, k] of this.kept) {
      const p = k.payload;
      const args = [BigInt(p.delegation), BigInt(p.digest)] as const;
      // The reserve may not exist yet at the finalized head; then nothing is final there.
      const at = async (blockTag: "latest" | "finalized") => {
        if (!(await this.chain.getCode({ address: p.reserve, blockTag }))) return false;
        return BigInt((await this.chain.readContract({ address: p.reserve, abi: reserveAbi, functionName: "settled", args, blockTag })) as `0x${string}`) !== 0n;
      };
      if (await at("finalized")) {
        this.kept.delete(key);
        continue;
      }
      if (await at("latest")) {
        k.seen = true;
        continue;
      }
      if (BigInt(p.time) + (await this.maxAge(p.reserve)) < now) {
        this.kept.delete(key);
        continue;
      }
      if (!k.seen) continue;
      const hash = await wallet.writeContract({
        address: p.reserve,
        abi: reserveAbi,
        functionName: "settleLogged",
        args: [BigInt(p.delegation), p.payee, BigInt(p.amount), BigInt(p.digest), BigInt(p.time), p.elems.map((e) => BigInt(e)), p.opening, p.signature],
      });
      await this.chain.waitForTransactionReceipt({ hash });
      sent.push(BigInt(p.digest));
    }
    return sent;
  }

  private async maxAge(reserve: `0x${string}`): Promise<bigint> {
    let t = this.tolerance.get(reserve);
    if (t === undefined) {
      t = (await this.chain.readContract({ address: reserve, abi: reserveAbi, functionName: "maxAge" })) as bigint;
      this.tolerance.set(reserve, t);
    }
    return t;
  }
}
