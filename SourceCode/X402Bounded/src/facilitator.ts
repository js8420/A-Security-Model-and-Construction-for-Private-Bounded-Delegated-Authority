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
import { SCHEME, isBoundedPayload, type BoundedExtra, type BoundedPayload } from "./types.js";

type Wallet = WalletClient<Transport, Chain, Account>;

/**
 * The facilitator's side. It settles through reserves it is configured to
 * trust, after checking that the payload pays what the requirements ask and
 * that the reserve would admit it. The reserve itself refuses anything it
 * would not admit, so verification is a simulation of the very call that
 * settles.
 */
export class BoundedEvmFacilitator implements SchemeNetworkFacilitator {
  readonly scheme = SCHEME;
  readonly caipFamily = "eip155:*";
  private readonly reserves: Set<string>;
  /** Sends from the one signer go out in order, so concurrent settlements do not share a nonce. */
  private sending: Promise<unknown> = Promise.resolve();

  constructor(
    private readonly wallet: Wallet,
    private readonly chain: PublicClient,
    reserves: readonly `0x${string}`[],
  ) {
    this.reserves = new Set(reserves.map((r) => getAddress(r)));
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
      return { success: false, errorReason: "settlement_not_recorded", transaction: hash, network: req.network, payer: checked.payer };
    }
    return { success: true, transaction: hash, network: req.network, payer: checked.payer, amount: p.amount };
  }

  private args(p: BoundedPayload) {
    return [
      BigInt(p.delegation),
      p.payee,
      BigInt(p.amount),
      BigInt(p.digest),
      BigInt(p.time),
      p.elems.map((e) => BigInt(e)),
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
