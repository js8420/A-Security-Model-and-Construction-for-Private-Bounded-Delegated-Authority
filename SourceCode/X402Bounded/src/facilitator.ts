import type {
  Network,
  PaymentPayload,
  PaymentRequirements,
  SchemeNetworkFacilitator,
  SettleResponse,
  VerifyResponse,
} from "@x402/core/types";
import {
  BaseError,
  ContractFunctionRevertedError,
  getAddress,
  parseEventLogs,
  type Account,
  type Chain,
  type PublicClient,
  type Transport,
  type WalletClient,
} from "viem";
import { reserveAbi } from "./abi.js";
import { sameBuild, type GenuineReserve } from "./reserveCode.js";
import { SCHEME, isBoundedPayload, type BoundedExtra, type BoundedPayload } from "./types.js";

type Wallet = WalletClient<Transport, Chain, Account>;

/**
 * The facilitator's side. It settles through reserves it is configured to
 * trust, after checking that the payload pays what the requirements ask and
 * that the reserve would admit it. The reserve itself refuses anything it
 * would not admit, so verification is a simulation of the very call that
 * settles. A reserve is taken as genuine only if the code deployed at its
 * address is the published build of Reserve.sol, immutables aside, and it
 * pulls Permit2 payments through the canonical Permit2: a contract at a
 * configured address that only looks like a reserve, answering the same
 * calls, could report a settlement it never paid. The check runs once for
 * each address, since deployed code does not change.
 */
export class BoundedEvmFacilitator implements SchemeNetworkFacilitator {
  readonly scheme = SCHEME;
  readonly caipFamily = "eip155:*";
  private readonly reserves: Set<string>;
  /** Each configured reserve's verdict, once its code has been read: empty if genuine, the reason if not. */
  private readonly verdicts = new Map<string, string>();
  /** Sends from the one signer go out in order, so concurrent settlements do not share a nonce. */
  private sending: Promise<unknown> = Promise.resolve();

  /**
   * The head a settlement must reach before the payee is told it is paid.
   * "latest" answers as soon as the settlement is in a block, which the
   * domain's sequencer can still replace until its data is on Ethereum; the
   * payee then bears that. "safe" waits until it is, and sends the same
   * signed settlement again if it left the chain on the way, so the agent's
   * unit is spent by that payment alone.
   */
  constructor(
    private readonly wallet: Wallet,
    private readonly chain: PublicClient,
    reserves: readonly `0x${string}`[],
    private readonly genuine: GenuineReserve,
    private readonly settled: { head: "latest" | "safe" | "finalized"; pollMs: number; tries: number } = { head: "latest", pollMs: 2000, tries: 3 },
  ) {
    this.reserves = new Set(reserves.map((r) => getAddress(r)));
  }

  /** Why the reserve at this address is not the published build under the canonical Permit2, or "" if it is. */
  async refusal(reserve: `0x${string}`): Promise<string> {
    const at = getAddress(reserve);
    const have = this.verdicts.get(at);
    if (have !== undefined) return have;
    const code = await this.chain.getCode({ address: at });
    let why = "";
    if (!code || !sameBuild(code, this.genuine.build)) why = "the code at the reserve's address is not the published build of Reserve.sol";
    else {
      const permit2 = await this.chain.readContract({ address: at, abi: reserveAbi, functionName: "permit2" });
      if (getAddress(permit2) !== getAddress(this.genuine.permit2)) why = `the reserve pulls Permit2 payments through ${permit2}, not ${this.genuine.permit2}`;
    }
    this.verdicts.set(at, why);
    return why;
  }

  getExtra(network: Network): Record<string, unknown> | undefined {
    void network;
    return { reserves: [...this.reserves] };
  }

  getSigners(network: string): string[] {
    void network;
    return [this.wallet.account.address];
  }

  async verify(payment: PaymentPayload, req: PaymentRequirements): Promise<VerifyResponse> {
    const checked = await this.check(payment, req);
    if ("invalidReason" in checked) return { isValid: false, ...checked };
    return { isValid: true, payer: checked.payer };
  }

  async settle(payment: PaymentPayload, req: PaymentRequirements): Promise<SettleResponse> {
    const checked = await this.check(payment, req);
    if ("invalidReason" in checked) {
      return { success: false, errorReason: checked.invalidReason, errorMessage: checked.invalidMessage, transaction: "", network: req.network };
    }
    const p = checked.p;
    for (let tries = 0; ; tries++) {
      const sent = this.sending.then(() =>
        this.wallet.writeContract({ address: p.reserve, abi: reserveAbi, functionName: "settleLogged", args: this.args(p) }),
      );
      this.sending = sent.catch(() => undefined);
      let hash: `0x${string}`;
      try {
        hash = await sent;
      } catch (e) {
        return { success: false, errorReason: "reserve_refused", errorMessage: revertName(e), transaction: "", network: req.network, payer: checked.payer };
      }
      const out = await this.recorded(hash, p, req, checked.payer);
      if (!out.success || this.settled.head === "latest") return out;
      const at = (await this.chain.getTransactionReceipt({ hash })).blockNumber;
      if (await this.reachesHead(hash)) return out;
      // The sequencer may have put the same settlement back in another block.
      const back = await this.chain.getContractEvents({
        address: p.reserve, abi: reserveAbi, eventName: "Settled", args: { id: BigInt(p.delegation) }, fromBlock: at > 64n ? at - 64n : 0n,
      });
      const same = back.find((l) => l.args.digest === BigInt(p.digest));
      if (same && (await this.reachesHead(same.transactionHash))) return { ...out, transaction: same.transactionHash };
      if (tries + 1 >= this.settled.tries) return { ...out, success: false, errorReason: "settlement_undone" };
      const again = await this.check(payment, req);
      if ("invalidReason" in again) return { success: false, errorReason: "settlement_undone", errorMessage: again.invalidMessage, transaction: hash, network: req.network, payer: checked.payer };
    }
  }

  /** Waits until the transaction's block is at or below the settled head; false if the transaction left the chain first. */
  private async reachesHead(hash: `0x${string}`): Promise<boolean> {
    for (;;) {
      const r = await this.chain.getTransactionReceipt({ hash }).catch(() => undefined);
      if (!r || r.status !== "success") return false;
      const head = (await this.chain.getBlock({ blockTag: this.settled.head })).number as bigint;
      if (r.blockNumber <= head) {
        const b = await this.chain.getBlock({ blockNumber: r.blockNumber });
        return b.hash === r.blockHash;
      }
      await new Promise((ok) => setTimeout(ok, this.settled.pollMs));
    }
  }

  private async recorded(hash: `0x${string}`, p: BoundedPayload, req: PaymentRequirements, payer: string): Promise<SettleResponse> {
    const receipt = await this.chain.waitForTransactionReceipt({ hash });
    const settled = parseEventLogs({ abi: reserveAbi, eventName: "Settled", logs: receipt.logs }).some(
      (l) =>
        getAddress(l.address) === p.reserve &&
        l.args.id === BigInt(p.delegation) &&
        l.args.digest === BigInt(p.digest) &&
        l.args.amount === BigInt(p.amount) &&
        getAddress(l.args.payee) === p.payee,
    );
    if (receipt.status !== "success" || !settled) {
      return { success: false, errorReason: "settlement_not_recorded", transaction: hash, network: req.network, payer };
    }
    return { success: true, transaction: hash, network: req.network, payer, amount: p.amount };
  }

  private args(p: BoundedPayload) {
    return [
      BigInt(p.delegation),
      p.payee,
      BigInt(p.amount),
      BigInt(p.digest),
      BigInt(p.time),
      p.elems.map((e) => BigInt(e)),
      p.opening,
      p.signature,
    ] as const;
  }

  private async check(
    payment: PaymentPayload,
    req: PaymentRequirements,
  ): Promise<{ p: BoundedPayload; payer: string } | { invalidReason: string; invalidMessage: string }> {
    const bad = (invalidReason: string, invalidMessage: string) => ({ invalidReason, invalidMessage });
    if (req.scheme !== SCHEME || payment.accepted.scheme !== SCHEME) return bad("unsupported_scheme", "not the bounded scheme");
    if (payment.accepted.network !== req.network) return bad("network_mismatch", "payload is for another network");
    const chainId = await this.chain.getChainId();
    if (req.network !== `eip155:${chainId}`) return bad("network_mismatch", `facilitator is on eip155:${chainId}`);
    if (!isBoundedPayload(payment.payload)) return bad("invalid_payload", "payload is not a bounded settlement");
    const p: BoundedPayload = {
      ...payment.payload,
      reserve: getAddress(payment.payload.reserve),
      payee: getAddress(payment.payload.payee),
    };
    const reserve = getAddress((req.extra as BoundedExtra).reserve);
    if (p.reserve !== reserve) return bad("reserve_mismatch", "payload settles on another reserve");
    if (!this.reserves.has(reserve)) return bad("untrusted_reserve", `reserve ${reserve} is not one this facilitator settles through`);
    const why = await this.refusal(reserve);
    if (why) return bad("unverified_reserve", why);
    if (p.payee !== getAddress(req.payTo)) return bad("payee_mismatch", "payload pays another address");
    if (BigInt(p.amount) !== BigInt(req.amount)) return bad("amount_mismatch", "payload pays another amount");
    const token = await this.chain.readContract({ address: reserve, abi: reserveAbi, functionName: "token" });
    if (getAddress(token) !== getAddress(req.asset)) return bad("asset_mismatch", "the reserve pays in another token");
    const payer = await this.chain.readContract({ address: reserve, abi: reserveAbi, functionName: "agentOf", args: [BigInt(p.delegation)] });
    try {
      await this.chain.simulateContract({
        account: this.wallet.account,
        address: reserve,
        abi: reserveAbi,
        functionName: "settleLogged",
        args: this.args(p),
      });
    } catch (e) {
      return bad("reserve_refused", revertName(e));
    }
    return { p, payer };
  }
}

function revertName(e: unknown): string {
  if (e instanceof BaseError) {
    const r = e.walk((x) => x instanceof ContractFunctionRevertedError);
    if (r instanceof ContractFunctionRevertedError) return r.data?.errorName ?? r.shortMessage;
    return e.shortMessage;
  }
  return String(e);
}
