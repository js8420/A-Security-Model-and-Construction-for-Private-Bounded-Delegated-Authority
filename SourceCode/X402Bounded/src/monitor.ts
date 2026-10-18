import { encodePacked, getAddress, keccak256, type Account, type Address, type Chain, type Hex, type PublicClient, type Transport, type WalletClient } from "viem";
import { disputeAbi, reserveAbi } from "./abi.js";
import { commitOpening, unitsOf, type Opening } from "./opening.js";
import type { ProofGate, Statement, Terms } from "./stark/gate.js";

/** One domain the delegation spends on: its chain, its reserve, the delegation's id there, and the dispute contract if it has one. */
export interface Domain {
  name: string;
  chain: PublicClient;
  wallet: WalletClient<Transport, Chain, Account>;
  reserve: Address;
  delegation: bigint;
  dispute?: Address;
}

/** What the principal chose. The monitor checks every opening against it directly. */
export interface Policy {
  budget: bigint;
  cap: bigint;
  tStart: bigint;
  tExpiry: bigint;
  /** Each allowed merchant and the address it is paid at. */
  merchants: ReadonlyMap<bigint, Address>;
  categories: ReadonlySet<bigint>;
  unitSize: bigint;
  rangeBase: bigint;
  rangeLen: bigint;
  revoked: readonly { start: bigint; length: bigint }[];
}

/** A settlement as the reserve recorded it. */
export interface Record {
  domain: string;
  digest: bigint;
  amount: bigint;
  payee: Address;
  time: bigint;
  opening: Hex;
  elems: bigint[];
  epoch: bigint;
}

interface Chained {
  domain: bigint;
  terms: Terms;
  roots: Map<bigint, Hex>;
  onRequest: boolean;
}

const key = (r: { domain: string; digest: bigint }) => `${r.domain}/${r.digest}`;

/**
 * The principal's monitor. It reads every domain's settlement records, holds
 * the openings and proofs the agent delivers, and acts on four rules.
 * The total settled past the budget freezes the delegation everywhere. An
 * opening that breaks the policy, or that disagrees with its own record,
 * freezes it everywhere too; neither rule reads a proof. A settlement that
 * nothing delivered backs is challenged on its domain. And a challenge
 * answered without anything backing the settlement arriving within the
 * delivery wait freezes the delegation everywhere.
 *
 * What backs a settlement depends on the mode the principal chose at
 * issuance. Opening every payment, it is the opening and a proof every
 * verifier accepts. Opening on request, it is the proof alone until the
 * monitor asks for the opening, and the opening as well once the delivery
 * wait after the request has passed.
 */
export class Monitor {
  private readonly from = new Map<string, bigint>();
  private readonly records = new Map<string, Record>();
  private readonly openings = new Map<Hex, Opening>();
  private readonly backing = new Map<bigint, { terms: Terms; s: Statement }[]>();
  private readonly chained = new Map<string, Chained>();
  private readonly challenged = new Set<string>();
  private readonly answered = new Map<string, bigint>();
  private readonly requested = new Map<string, bigint>();
  private frozen = false;
  readonly reasons: string[] = [];

  constructor(
    private readonly domains: readonly Domain[],
    private readonly policy: Policy,
    private readonly gate: ProofGate | null,
    private readonly deliveryWait: bigint,
  ) {}

  deliverOpening(o: Opening): void {
    this.openings.set(commitOpening(o), o);
  }

  /** Returns whether every verifier accepted the batch. */
  async deliverProof(bytes: Uint8Array): Promise<boolean> {
    if (!this.gate) return false;
    const r = await this.gate.deliver(bytes);
    if (!r.accepted || !r.terms) return false;
    for (const s of r.payments) {
      const list = this.backing.get(s.digest) ?? [];
      list.push({ terms: r.terms, s });
      this.backing.set(s.digest, list);
    }
    return true;
  }

  total(): bigint {
    let t = 0n;
    for (const r of this.records.values()) t += r.amount;
    return t;
  }

  all(): Record[] {
    return [...this.records.values()];
  }

  isFrozen(): boolean {
    return this.frozen;
  }

  private async context(d: Domain): Promise<Chained> {
    const have = this.chained.get(d.name);
    if (have) return have;
    const read = <T>(functionName: string, args: unknown[] = []) =>
      d.chain.readContract({ address: d.reserve, abi: reserveAbi, functionName, args } as never) as Promise<T>;
    const domain = await read<bigint>("domain");
    const commitment = await read<Hex>("commitmentOf", [d.delegation]);
    const [unitSize, rangeBase, rangeLen, secretHash] = await read<[bigint, bigint, bigint, Hex]>("termsOf", [d.delegation]);
    const onRequest = await read<boolean>("openOnRequestOf", [d.delegation]);
    const c = { domain, terms: { commitment, unitSize, rangeBase, rangeLen, secretHash }, roots: new Map<bigint, Hex>(), onRequest };
    this.chained.set(d.name, c);
    return c;
  }

  private async root(d: Domain, epoch: bigint): Promise<Hex> {
    const c = await this.context(d);
    const have = c.roots.get(epoch);
    if (have) return have;
    const r = (await d.chain.readContract({ address: d.reserve, abi: reserveAbi, functionName: "rootAt", args: [d.delegation, epoch] })) as Hex;
    c.roots.set(epoch, r);
    return r;
  }

  /** Whether what the agent delivered backs this record, under the delegation's opening mode. */
  async backed(r: Record): Promise<boolean> {
    const d = this.domains.find((x) => x.name === r.domain);
    if (!d) return false;
    const c = await this.context(d);
    if (!this.openings.has(r.opening)) {
      if (!c.onRequest) return false;
      const asked = this.requested.get(key(r));
      if (asked !== undefined) {
        const now = (await d.chain.getBlock({ blockTag: "latest" })).timestamp;
        if (now >= asked + this.deliveryWait) return false;
      }
    }
    if (!this.gate) return true;
    const root = await this.root(d, r.epoch);
    const elemsHash = keccak256(encodePacked(["uint64[]"], [r.elems]));
    return (this.backing.get(r.digest) ?? []).some(({ terms: t, s }) =>
      t.commitment.toLowerCase() === c.terms.commitment.toLowerCase() &&
      t.secretHash.toLowerCase() === c.terms.secretHash.toLowerCase() &&
      t.unitSize === c.terms.unitSize && t.rangeBase === c.terms.rangeBase && t.rangeLen === c.terms.rangeLen &&
      s.root.toLowerCase() === root.toLowerCase() && s.domain === c.domain &&
      s.amount === r.amount && getAddress(s.payee) === getAddress(r.payee) && s.time === r.time &&
      keccak256(encodePacked(["uint64[]"], [s.elems])) === elemsHash,
    );
  }

  /** Every way the delivered openings break the policy or their own records. */
  async breaches(): Promise<string[]> {
    const p = this.policy;
    const out: string[] = [];
    const runs: { start: bigint; end: bigint; at: string }[] = [];
    for (const r of this.records.values()) {
      const o = this.openings.get(r.opening);
      if (!o) continue;
      const d = this.domains.find((x) => x.name === r.domain);
      if (!d) continue;
      const c = await this.context(d);
      const at = `${r.domain} digest ${r.digest}`;
      if (o.amount !== r.amount || getAddress(o.payee) !== getAddress(r.payee) || o.time !== r.time || o.domain !== c.domain) {
        out.push(`${at}: the opening disagrees with the record`);
        continue;
      }
      if (o.amount > p.cap) out.push(`${at}: amount above the cap`);
      const paid = p.merchants.get(o.merchant);
      if (!paid || getAddress(paid) !== getAddress(o.payee)) out.push(`${at}: merchant not allowed for this payee`);
      if (!p.categories.has(o.category)) out.push(`${at}: category not allowed`);
      if (o.time < p.tStart || o.time > p.tExpiry) out.push(`${at}: outside the validity window`);
      const end = o.runStart + unitsOf(o.amount, p.unitSize);
      if (o.runStart < p.rangeBase || end > p.rangeBase + p.rangeLen) out.push(`${at}: units outside the delegation's range`);
      if (p.revoked.some((v) => o.runStart < v.start + v.length && v.start < end)) out.push(`${at}: units revoked`);
      for (const q of runs) if (o.runStart < q.end && q.start < end) out.push(`${at}: units already consumed by ${q.at}`);
      runs.push({ start: o.runStart, end, at });
    }
    return out;
  }

  /** Reads new records and answers on every domain, then applies the freezing rules. */
  async poll(): Promise<{ total: bigint; froze: boolean; reasons: string[] }> {
    for (const d of this.domains) {
      const head = await d.chain.getBlockNumber({ cacheTime: 0 });
      const fromBlock = this.from.get(d.name) ?? 0n;
      if (fromBlock > head) continue;
      const range = { fromBlock, toBlock: head };
      const settled = await d.chain.getContractEvents({ address: d.reserve, abi: reserveAbi, eventName: "Settled", args: { id: d.delegation }, ...range });
      const transcripts = await d.chain.getContractEvents({ address: d.reserve, abi: reserveAbi, eventName: "Transcript", args: { id: d.delegation }, ...range });
      for (const l of settled) {
        const a = l.args as { digest: bigint; amount: bigint; payee: Address; time: bigint; opening: Hex };
        const t = transcripts.find((x) => x.transactionHash === l.transactionHash && (x.args as { digest: bigint }).digest === a.digest);
        const epoch = (await d.chain.readContract({ address: d.reserve, abi: reserveAbi, functionName: "epochOf", args: [d.delegation], blockNumber: l.blockNumber })) as bigint;
        const r: Record = {
          domain: d.name, digest: a.digest, amount: a.amount, payee: getAddress(a.payee), time: a.time, opening: a.opening,
          elems: t ? [...((t.args as { elems: readonly bigint[] }).elems)] : [], epoch,
        };
        this.records.set(key(r), r);
      }
      if (d.dispute) {
        const answers = await d.chain.getContractEvents({ address: d.dispute, abi: disputeAbi, eventName: "Answered", args: { id: d.delegation }, ...range });
        for (const l of answers) {
          const b = await d.chain.getBlock({ blockNumber: l.blockNumber });
          this.answered.set(key({ domain: d.name, digest: (l.args as { digest: bigint }).digest }), b.timestamp);
        }
      }
      this.from.set(d.name, head + 1n);
    }
    const reasons: string[] = [];
    const total = this.total();
    if (total > this.policy.budget) reasons.push(`total ${total} past the budget ${this.policy.budget}`);
    reasons.push(...(await this.breaches()));
    for (const [k, at] of this.answered) {
      const r = this.records.get(k);
      if (!r || (await this.backed(r))) continue;
      const d = this.domains.find((x) => x.name === r.domain) as Domain;
      const now = (await d.chain.getBlock({ blockTag: "latest" })).timestamp;
      if (now >= at + this.deliveryWait) reasons.push(`${k}: answered, and no backing opening and proof arrived`);
    }
    if (reasons.length === 0 || this.frozen) return { total, froze: false, reasons };
    await Promise.all(
      this.domains.map(async (d) => {
        const hash = await d.wallet.writeContract({ address: d.reserve, abi: reserveAbi, functionName: "freeze", args: [d.delegation] });
        await d.chain.waitForTransactionReceipt({ hash });
      }),
    );
    this.frozen = true;
    this.reasons.push(...reasons);
    return { total, froze: true, reasons };
  }

  /**
   * Asks the agent for the openings of every record it has not opened, as a
   * principal does on hearing of a bug in the proof system. The agent must
   * deliver them within the delivery wait. Returns the records asked for.
   */
  async requestOpenings(): Promise<Record[]> {
    const asked: Record[] = [];
    for (const r of this.records.values()) {
      if (this.openings.has(r.opening) || this.requested.has(key(r))) continue;
      const d = this.domains.find((x) => x.name === r.domain) as Domain;
      this.requested.set(key(r), (await d.chain.getBlock({ blockTag: "latest" })).timestamp);
      asked.push(r);
    }
    return asked;
  }

  /** How many payments' fields the principal holds in the clear. */
  openedCount(): number {
    let n = 0;
    for (const r of this.records.values()) if (this.openings.has(r.opening)) n += 1;
    return n;
  }

  /** Challenges, on its own domain, every record that nothing delivered backs. Returns the records challenged. */
  async challengeUnbacked(): Promise<Record[]> {
    const done: Record[] = [];
    for (const r of this.records.values()) {
      if (this.challenged.has(key(r)) || (await this.backed(r))) continue;
      const d = this.domains.find((x) => x.name === r.domain);
      if (!d?.dispute) continue;
      const bond = (await d.chain.readContract({ address: d.dispute, abi: disputeAbi, functionName: "challengerBond" })) as bigint;
      const s = { elems: keccak256(encodePacked(["uint64[]"], [r.elems])), amount: r.amount, payee: r.payee, time: r.time, epoch: r.epoch };
      const hash = await d.wallet.writeContract({ address: d.dispute, abi: disputeAbi, functionName: "open", args: [d.delegation, r.digest, s], value: bond });
      const receipt = await d.chain.waitForTransactionReceipt({ hash });
      if (receipt.status !== "success") throw new Error(`challenge of ${key(r)} reverted`);
      this.challenged.add(key(r));
      done.push(r);
    }
    return done;
  }
}
