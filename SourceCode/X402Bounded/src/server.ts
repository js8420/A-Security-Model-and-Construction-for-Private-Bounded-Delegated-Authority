import type {
  AssetAmount,
  Network,
  PaymentFlowConfig,
  PaymentRequirements,
  Price,
  SchemeNetworkServer,
  SupportedKind,
} from "@x402/core/types";
import { SDK_DEFAULT_ASSET_TRANSFER_METHOD } from "@x402/core/server";
import { convertToTokenAmount, parseMoney } from "@x402/core/utils";
import { SCHEME } from "./types.js";

/**
 * The resource server's side. It advertises the reserve it accepts payment
 * through and the token the reserve pays in. Prices are in that token.
 */
export class BoundedEvmServer implements SchemeNetworkServer {
  readonly scheme = SCHEME;
  readonly defaultAssetTransferMethod = SDK_DEFAULT_ASSET_TRANSFER_METHOD;
  readonly paymentFlows: Readonly<Record<string, PaymentFlowConfig>> = {
    [SDK_DEFAULT_ASSET_TRANSFER_METHOD]: { supported: ["authorization", "upfront"], default: "authorization" },
  };

  constructor(private readonly config: { reserve: `0x${string}`; asset: `0x${string}`; decimals: number }) {}

  getAssetDecimals(asset: string): number | undefined {
    return asset.toLowerCase() === this.config.asset.toLowerCase() ? this.config.decimals : undefined;
  }

  async parsePrice(price: Price, network: Network): Promise<AssetAmount> {
    if (typeof price === "object" && price !== null && "amount" in price) {
      if (price.asset && price.asset.toLowerCase() !== this.config.asset.toLowerCase()) {
        throw new Error(`the reserve on ${network} pays in ${this.config.asset}, not ${price.asset}`);
      }
      return { amount: price.amount, asset: this.config.asset, extra: { reserve: this.config.reserve } };
    }
    const { amount } = parseMoney(price);
    return {
      amount: convertToTokenAmount(String(amount), this.config.decimals),
      asset: this.config.asset,
      extra: { reserve: this.config.reserve },
    };
  }

  async enhancePaymentRequirements(req: PaymentRequirements, kind: SupportedKind, extensions: string[]): Promise<PaymentRequirements> {
    void kind;
    void extensions;
    return { ...req, extra: { ...req.extra, reserve: this.config.reserve } };
  }
}
