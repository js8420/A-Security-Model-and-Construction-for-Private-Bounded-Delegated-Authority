import { parseAbi, type Account, type Chain, type PublicClient, type Transport, type WalletClient } from "viem";
import { reserveAbi } from "./abi.js";

const freezeAbi = parseAbi(["function freeze(uint256 id)"]);

/** One domain the delegation spends on: its chain, its reserve and the delegation's id there. */
export interface Domain {
  name: string;
  chain: PublicClient;
  wallet: WalletClient<Transport, Chain, Account>;
  reserve: `0x${string}`;
  delegation: bigint;
}

/**
 * The principal's budget tripwire. The principal chose B, and every amount a
 * reserve pays is public, so the monitor adds them up across all domains and
 * freezes the delegation everywhere once the total passes B. It reads no
 * proof, so no bug in a proof verifier can blind it.
 */
export class BudgetMonitor {
  private readonly from = new Map<string, bigint>();
  private readonly spent = new Map<string, bigint>();
  private frozen = false;

  constructor(
    private readonly domains: readonly Domain[],
    private readonly budget: bigint,
  ) {}

  /** The total settled so far across all domains, as of the last poll. */
  total(): bigint {
    let t = 0n;
    for (const v of this.spent.values()) t += v;
    return t;
  }

  /** Reads new settlements on every domain and freezes if the total exceeds the budget. */
  async poll(): Promise<{ total: bigint; froze: boolean }> {
    for (const d of this.domains) {
      const head = await d.chain.getBlockNumber({ cacheTime: 0 });
      const fromBlock = this.from.get(d.name) ?? 0n;
      if (fromBlock > head) continue;
      const logs = await d.chain.getContractEvents({
        address: d.reserve,
        abi: reserveAbi,
        eventName: "Settled",
        args: { id: d.delegation },
        fromBlock,
        toBlock: head,
      });
      let sum = this.spent.get(d.name) ?? 0n;
      for (const l of logs) sum += l.args.amount ?? 0n;
      this.spent.set(d.name, sum);
      this.from.set(d.name, head + 1n);
    }
    const total = this.total();
    if (total <= this.budget || this.frozen) return { total, froze: false };
    await Promise.all(
      this.domains.map(async (d) => {
        const hash = await d.wallet.writeContract({ address: d.reserve, abi: freezeAbi, functionName: "freeze", args: [d.delegation] });
        await d.chain.waitForTransactionReceipt({ hash });
      }),
    );
    this.frozen = true;
    return { total, froze: true };
  }
}
