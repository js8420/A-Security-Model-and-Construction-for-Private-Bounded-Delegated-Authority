import { decodeFunctionData, encodePacked, getAddress, hexToBytes, keccak256, parseEventLogs, type Account, type Address, type Chain, type Hex, type PublicClient, type Transport, type WalletClient } from "viem";
import { ANSWERED, disputeAbi, reserveAbi } from "./abi.js";
import { commitOpening, unitsOf, type Opening } from "./opening.js";
import { unseal } from "./seal.js";
import { proofHash } from "./answerer.js";
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

/** How the monitor runs. */
export interface Settings {
  /** Checks delivered proofs; null reads no proof, and then an opening alone backs a settlement. */
  gate: ProofGate | null;
  /**
   * How long the agent or its answerer has to deliver off chain what was
   * asked for, w_d. The dispute contract gives a staked answerer a longer
   * posting wait to put the same on chain, long enough to force it in
   * through Ethereum; the monitor does not wait for that.
   */
  deliveryWait: bigint;
  /**
   * How long after a settlement's signed time the monitor decides on it.
   * It must leave the margin a challenge needs for inclusion before the
   * dispute contract's acceptance window closes.
   */
  decideAfter: bigint;
  /** The key openings are sealed to, when the agent hands them to an answerer. */
  sealKey?: Hex;
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

/** Shares live in F_p[X]/(X^2 - 7), the extension the circuit forms them in. */
const P = 0xffffffff00000001n;
type F2 = readonly [bigint, bigint];
const md = (x: bigint) => ((x % P) + P) % P;
const sub2 = (a: F2, b: F2): F2 => [md(a[0] - b[0]), md(a[1] - b[1])];
const mul2 = (a: F2, b: F2): F2 => [md(a[0] * b[0] + 7n * a[1] * b[1]), md(a[0] * b[1] + a[1] * b[0])];
const pow = (b: bigint, e: bigint): bigint => {
  let r = 1n;
  for (b = md(b); e > 0n; e >>= 1n, b = md(b * b)) if (e & 1n) r = md(r * b);
  return r;
};
const inv2 = (a: F2): F2 => {
  const n = pow(md(a[0] * a[0] - 7n * a[1] * a[1]), P - 2n);
  return [md(a[0] * n), md(-a[1] * n)];
};

/**
 * Algorithm Extract on the settlements read so far, across every domain: a
 * nullifier published twice is a unit consumed twice, and two shares under
 * one key at different indices give the line and so the secret. Each slot
 * publishes its two share lanes and its nullifier, in that order.
 */
export function extractSecret(settled: readonly { digest: bigint; domain: bigint; elems: readonly bigint[] }[]): F2[] {
  const seen = new Map<bigint, { t: F2; i: F2 }>();
  const found: F2[] = [];
  for (const r of settled) {
    const i: F2 = [r.digest, r.domain];
    for (let k = 0; k + 2 < r.elems.length; k += 3) {
      const t: F2 = [r.elems[k], r.elems[k + 1]];
      const nf = r.elems[k + 2];
      const other = seen.get(nf);
      if (!other) {
        seen.set(nf, { t, i });
        continue;
      }
      const di = sub2(other.i, i);
      if (di[0] === 0n && di[1] === 0n) continue;
      const kv = mul2(sub2(other.t, t), inv2(di));
      found.push(sub2(t, mul2(kv, i)));
    }
  }
  return found;
}

/**
 * The principal's monitor. It reads every domain's settlement records and
 * holds what the agent, or its answerer, delivers: openings and proofs.
 *
 * A settlement is in order when what was delivered backs it, its opening (if
 * held) keeps to the policy and to its own record, and it does not take the
 * total settled on all domains past the budget. The monitor acts on a
 * settlement only at its decision time, a fixed delay after its signed time,
 * and in one way whatever the cause: a settlement not in order by then is
 * challenged on its domain. The delegation is frozen on every domain when a
 * challenge goes unanswered, or when it is answered and the settlement is
 * still not in order the delivery wait later.
 *
 * So what the chain shows depends only on whether backing was delivered in
 * time, never on which rule a settlement broke. A party who signs with the
 * agent's key but cannot prove sees every settlement it makes challenged at
 * the same moment, below the budget or past it, inside the allowlist or not.
 *
 * What backs a settlement depends on the mode the principal chose at
 * issuance. Opening every payment, it is the opening and a proof every
 * verifier accepts. Opening on request, it is the proof alone until the
 * monitor asks for the opening, and the opening as well once the delivery
 * wait after the request has passed. An answer to the monitor's own
 * challenge is such a request, dated when the answer landed.
 */
export class Monitor {
  private readonly from = new Map<string, bigint>();
  private readonly records = new Map<string, Record>();
  private readonly openings = new Map<Hex, Opening>();
  private readonly backing = new Map<bigint, { terms: Terms; s: Statement }[]>();
  private readonly chained = new Map<string, Chained>();
  private readonly challenged = new Map<string, bigint>();
  private readonly answered = new Map<string, bigint>();
  private readonly expired = new Set<string>();
  /** Challenges another party opened and someone answered before the monitor joined them. */
  private readonly joinedAnswered = new Set<string>();
  private readonly requested = new Map<string, bigint>();
  /** Batches bound for posting and not yet posted, by domain and root: the proof hash and when the binding landed. */
  private readonly bound = new Map<string, { domain: string; proofHash: Hex; at: bigint }>();
  private claimed = false;
  private frozen = false;
  readonly reasons: string[] = [];

  constructor(
    private readonly domains: readonly Domain[],
    private readonly policy: Policy,
    private readonly settings: Settings,
  ) {}

  deliverOpening(o: Opening): void {
    this.openings.set(commitOpening(o), o);
  }

  /**
   * An opening sealed to the monitor for the settlement of `digest` on the
   * domain whose id is `domain`, as an answerer holds it and posts it.
   * Returns whether it opened.
   */
  async deliverSealed(blob: Hex, domain: bigint, digest: bigint): Promise<boolean> {
    if (!this.settings.sealKey) return false;
    for (const d of this.domains) {
      const c = await this.context(d);
      if (c.domain !== domain) continue;
      try {
        this.deliverOpening(unseal(blob, this.settings.sealKey, { commitment: c.terms.commitment, domain, digest }));
        return true;
      } catch {
        return false;
      }
    }
    return false;
  }

  /** Returns whether every verifier accepted the batch. */
  async deliverProof(bytes: Uint8Array): Promise<boolean> {
    const gate = this.settings.gate;
    if (!gate) return false;
    const r = await gate.deliver(bytes);
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

  /** The records challenged so far. */
  challenges(): string[] {
    return [...this.challenged.keys()];
  }

  private domainOf(r: Record): Domain {
    const d = this.domains.find((x) => x.name === r.domain);
    if (!d) throw new Error(`no domain ${r.domain}`);
    return d;
  }

  private async now(d: Domain): Promise<bigint> {
    return (await d.chain.getBlock({ blockTag: "latest" })).timestamp;
  }

  private async context(d: Domain): Promise<Chained> {
    const have = this.chained.get(d.name);
    if (have) return have;
    const read = <T>(functionName: string, args: unknown[] = []) =>
      d.chain.readContract({ address: d.reserve, abi: reserveAbi, functionName, args } as never) as Promise<T>;
    if (d.dispute) {
      const window = await this.acceptWindow(d);
      if (this.settings.decideAfter >= window) throw new Error(`${d.name}: the decision time must fall inside the acceptance window of ${window} s`);
    }
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

  /** Whether what was delivered backs this record, under the delegation's opening mode. */
  async backed(r: Record): Promise<boolean> {
    const d = this.domainOf(r);
    const c = await this.context(d);
    if (!this.openings.has(r.opening)) {
      if (!c.onRequest || !this.settings.gate) return false;
      const asked = this.requested.get(key(r));
      if (asked !== undefined && (await this.now(d)) >= asked + this.settings.deliveryWait) return false;
    }
    if (!this.settings.gate) return true;
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

  /** Which records what was delivered backs. */
  private async backedSet(): Promise<Set<string>> {
    const out = new Set<string>();
    for (const r of this.records.values()) if (await this.backed(r)) out.add(key(r));
    return out;
  }

  /**
   * Every way the openings of backed records break the policy or their own
   * records. A record nothing backs is out of order already; leaving it out
   * here keeps what the monitor does about it the same whatever its opening
   * says.
   */
  async breaches(backed?: Set<string>): Promise<Map<string, string[]>> {
    const only = backed ?? (await this.backedSet());
    const p = this.policy;
    const out = new Map<string, string[]>();
    const add = (k: string, why: string) => out.set(k, [...(out.get(k) ?? []), why]);
    const runs: { start: bigint; end: bigint; at: string }[] = [];
    for (const r of this.ordered()) {
      const o = this.openings.get(r.opening);
      if (!o || !only.has(key(r))) continue;
      const c = await this.context(this.domainOf(r));
      const k = key(r);
      if (o.amount !== r.amount || getAddress(o.payee) !== getAddress(r.payee) || o.time !== r.time || o.domain !== c.domain) {
        add(k, "the opening disagrees with the record");
        continue;
      }
      if (o.amount > p.cap) add(k, "amount above the cap");
      const paid = p.merchants.get(o.merchant);
      if (!paid || getAddress(paid) !== getAddress(o.payee)) add(k, "merchant not allowed for this payee");
      if (!p.categories.has(o.category)) add(k, "category not allowed");
      if (o.time < p.tStart || o.time > p.tExpiry) add(k, "outside the validity window");
      const end = o.runStart + unitsOf(o.amount, p.unitSize);
      if (o.runStart < p.rangeBase || end > p.rangeBase + p.rangeLen) add(k, "units outside the delegation's range");
      if (p.revoked.some((v) => o.runStart < v.start + v.length && v.start < end)) add(k, "units revoked");
      for (const q of runs) if (o.runStart < q.end && q.start < end) add(k, `units already consumed by ${q.at}`);
      runs.push({ start: o.runStart, end, at: k });
    }
    return out;
  }

  /** Records in the order they were signed. */
  private ordered(): Record[] {
    return [...this.records.values()].sort((a, b) => (a.time !== b.time ? (a.time < b.time ? -1 : 1) : key(a) < key(b) ? -1 : 1));
  }

  /**
   * The backed records at which the running total of backed records, in
   * signed order, is past the budget. When every verifier is sound only the
   * agent's own payments are backed, and they never pass it, so this rule
   * acts only on a proof that should not have been accepted.
   */
  private overBudget(backed: Set<string>): Set<string> {
    const out = new Set<string>();
    let t = 0n;
    for (const r of this.ordered()) {
      if (!backed.has(key(r))) continue;
      t += r.amount;
      if (t > this.policy.budget) out.add(key(r));
    }
    return out;
  }

  /** Why a record is not in order, or nothing if it is. */
  async faults(r: Record): Promise<string[]> {
    const backed = await this.backedSet();
    return this.faultsWith(r, backed, await this.breaches(backed), this.overBudget(backed));
  }

  private faultsWith(r: Record, backed: Set<string>, breaches: Map<string, string[]>, over: Set<string>): string[] {
    const k = key(r);
    if (!backed.has(k)) return ["nothing delivered backs it"];
    const why = [...(breaches.get(k) ?? [])];
    if (over.has(k)) why.push(`the total backed is past the budget ${this.policy.budget}`);
    return why;
  }

  private async read(): Promise<void> {
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
          const k = key({ domain: d.name, digest: (l.args as { digest: bigint }).digest });
          if (this.joinedAnswered.has(k)) continue;
          this.answered.set(k, b.timestamp);
          if (this.challenged.has(k) && !this.requested.has(k)) this.requested.set(k, b.timestamp);
        }
        const expiries = await d.chain.getContractEvents({ address: d.dispute, abi: disputeAbi, eventName: "Expired", args: { id: d.delegation }, ...range });
        for (const l of expiries) this.expired.add(key({ domain: d.name, digest: (l.args as { digest: bigint }).digest }));
        const posted = await d.chain.getContractEvents({ address: d.dispute, abi: disputeAbi, eventName: "SealedDelivered", args: { id: d.delegation }, ...range });
        const c = await this.context(d);
        for (const l of posted) {
          const a = l.args as { digest: bigint; opening: Hex };
          await this.deliverSealed(a.opening, c.domain, a.digest);
        }
        const bindings = await d.chain.getContractEvents({ address: d.dispute, abi: disputeAbi, eventName: "PostingBound", args: { id: d.delegation }, ...range });
        for (const l of bindings) {
          const a = l.args as { root: Hex; proofHash: Hex };
          const b = await d.chain.getBlock({ blockNumber: l.blockNumber });
          this.bound.set(`${d.name}/${a.root}`, { domain: d.name, proofHash: a.proofHash, at: b.timestamp });
        }
        const proofs = await d.chain.getContractEvents({ address: d.dispute, abi: disputeAbi, eventName: "ProofPosted", args: { id: d.delegation }, ...range });
        for (const l of proofs) {
          const posted = (l.args as { proofHash: Hex }).proofHash.toLowerCase();
          for (const [k, v] of this.bound) if (v.domain === d.name && v.proofHash.toLowerCase() === posted) this.bound.delete(k);
          const a = l.args as { proofHash: Hex; poster: Address };
          const bytes = await this.postedProof(d, a.proofHash, a.poster);
          if (bytes) await this.deliverProof(bytes);
        }
      }
      this.from.set(d.name, head + 1n);
    }
  }

  /**
   * A proof posted in chunks: each chunk is read back from the call data of
   * the transaction that posted it, and the whole is kept only if its chained
   * hash is the one posted under.
   */
  private async postedProof(d: Domain, hash: Hex, poster: Address): Promise<Uint8Array | undefined> {
    const logs = await d.chain.getContractEvents({ address: d.dispute as Address, abi: disputeAbi, eventName: "ProofChunk", args: { id: d.delegation, proofHash: hash, poster }, fromBlock: 0n });
    const chunks = new Map<bigint, Uint8Array>();
    for (const l of logs) {
      const tx = await d.chain.getTransaction({ hash: l.transactionHash as Hex });
      const call = decodeFunctionData({ abi: disputeAbi, data: tx.input });
      if (call.functionName !== "postProof") continue;
      const [, , index, chunk] = call.args as readonly [bigint, Hex, bigint, Hex, boolean];
      chunks.set(index, hexToBytes(chunk));
    }
    const parts = [...chunks.entries()].sort((a, b) => (a[0] < b[0] ? -1 : 1)).map(([, c]) => c);
    const total = parts.reduce((n, c) => n + c.length, 0);
    const bytes = new Uint8Array(total);
    let at = 0;
    for (const c of parts) {
      bytes.set(c, at);
      at += c.length;
    }
    return proofHash(bytes).toLowerCase() === hash.toLowerCase() ? bytes : undefined;
  }

  private readonly windows = new Map<string, bigint>();

  private async acceptWindow(d: Domain): Promise<bigint> {
    const have = this.windows.get(d.name);
    if (have !== undefined) return have;
    const w = (await d.chain.readContract({ address: d.dispute as Address, abi: disputeAbi, functionName: "acceptWindow" })) as bigint;
    this.windows.set(d.name, w);
    return w;
  }

  /**
   * Step 1's challenge, topping the posting pool up to one deposit. A settlement someone else
   * challenged first is joined instead: an open challenge then holds it as
   * the monitor's own would, and an answered one carries the monitor's
   * request from the join, so step 3 counts the delivery wait from there.
   * One already expired froze the delegation on its domain, and step 2
   * freezes it on the others.
   */
  private async challenge(d: Domain, r: Record): Promise<void> {
    const dispute = d.dispute as Address;
    const bond = (await d.chain.readContract({ address: dispute, abi: disputeAbi, functionName: "challengerBond" })) as bigint;
    const topUp = (await d.chain.readContract({ address: dispute, abi: disputeAbi, functionName: "postingTopUp", args: [d.delegation] })) as bigint;
    const s = { elems: keccak256(encodePacked(["uint64[]"], [r.elems])), amount: r.amount, payee: r.payee, time: r.time, epoch: r.epoch };
    let hash: Hex;
    let joined = false;
    try {
      hash = await d.wallet.writeContract({ address: dispute, abi: disputeAbi, functionName: "open", args: [d.delegation, r.digest, s], value: bond + topUp });
    } catch (e) {
      if (!String(e).includes("AlreadyChallenged")) throw e;
      try {
        hash = await d.wallet.writeContract({ address: dispute, abi: disputeAbi, functionName: "join", args: [d.delegation, r.digest, s], value: topUp });
        joined = true;
      } catch (f) {
        if (String(f).includes("NotOpen")) {
          this.challenged.set(key(r), 0n);
          return;
        }
        throw f;
      }
    }
    const receipt = await d.chain.waitForTransactionReceipt({ hash });
    if (receipt.status !== "success") throw new Error(`challenge of ${key(r)} reverted`);
    const deadline = joined
      ? parseEventLogs({ abi: disputeAbi, logs: receipt.logs, eventName: "Joined" }).find((e) => e.args.digest === r.digest)?.args.deadline
      : parseEventLogs({ abi: disputeAbi, logs: receipt.logs, eventName: "Challenged" }).find((e) => e.args.digest === r.digest)?.args.deadline;
    if (deadline === undefined) throw new Error(`challenge of ${key(r)} left no event`);
    this.challenged.set(key(r), deadline);
    if (joined) {
      const c = await d.chain.readContract({ address: dispute, abi: disputeAbi, functionName: "challengeOf", args: [d.delegation, r.digest], blockNumber: receipt.blockNumber });
      if (c.status === ANSWERED) {
        const t = (await d.chain.getBlock({ blockNumber: receipt.blockNumber })).timestamp;
        this.answered.set(key(r), t);
        this.requested.set(key(r), t);
        this.joinedAnswered.add(key(r));
      }
    }
  }

  /**
   * Keeps one posting deposit in each domain's pool for every batch bound for
   * posting whose proof is not yet posted and whose posting wait is still
   * running, so batches due at once do not share one deposit.
   */
  private async fundPostings(): Promise<void> {
    for (const d of this.domains) {
      if (!d.dispute) continue;
      const dispute = d.dispute as Address;
      const now = await this.now(d);
      const wait = (await d.chain.readContract({ address: dispute, abi: disputeAbi, functionName: "deliveryWait" })) as bigint;
      let due = 0n;
      for (const v of this.bound.values()) if (v.domain === d.name && now <= v.at + wait) due += 1n;
      if (due === 0n) continue;
      const deposit = (await d.chain.readContract({ address: dispute, abi: disputeAbi, functionName: "postingDeposit" })) as bigint;
      const pool = (await d.chain.readContract({ address: dispute, abi: disputeAbi, functionName: "postingPool", args: [d.delegation] })) as bigint;
      if (pool >= due * deposit) continue;
      const hash = await d.wallet.writeContract({ address: dispute, abi: disputeAbi, functionName: "fundPosting", args: [d.delegation], value: due * deposit - pool });
      await d.chain.waitForTransactionReceipt({ hash });
    }
  }

  /**
   * Step 4: as soon as the transcript gives up a secret that opens the
   * delegation's H(s), claim the bond on every domain, which also freezes
   * the delegation there. A candidate that opens nothing is dropped, and a
   * domain whose bond is already paid is skipped. Returns whether a claim
   * went through.
   */
  private async claim(): Promise<boolean> {
    const settled = [];
    for (const r of this.records.values()) {
      const c = await this.context(this.domainOf(r));
      settled.push({ digest: r.digest, domain: c.domain, elems: r.elems });
    }
    for (const secret of extractSecret(settled)) {
      let any = false;
      for (const d of this.domains) {
        try {
          const { request } = await d.chain.simulateContract({
            account: d.wallet.account, address: d.reserve, abi: reserveAbi, functionName: "claim", args: [d.delegation, [secret[0], secret[1]]],
          });
          const hash = await d.wallet.writeContract(request);
          await d.chain.waitForTransactionReceipt({ hash });
          any = true;
        } catch {
          continue;
        }
      }
      if (any) {
        this.claimed = true;
        return true;
      }
    }
    return false;
  }

  private async freezeAll(): Promise<void> {
    await Promise.all(
      this.domains.map(async (d) => {
        const hash = await d.wallet.writeContract({ address: d.reserve, abi: reserveAbi, functionName: "freeze", args: [d.delegation] });
        await d.chain.waitForTransactionReceipt({ hash });
      }),
    );
    this.frozen = true;
  }

  /**
   * Reads new records, answers and expiries on every domain, then acts. Every
   * record past its decision time and not in order is challenged; on a
   * domain with no dispute contract, if the monitor itself comes too late
   * to challenge, the delegation is frozen instead; a record another party
   * challenged first is joined. A challenge past its deadline unanswered is expired, and one
   * answered whose record is still not in order the delivery wait later
   * freezes the delegation on every domain.
   */
  async poll(): Promise<{ total: bigint; challenged: Record[]; froze: boolean; reasons: string[] }> {
    await this.read();
    await this.fundPostings();
    const total = this.total();
    const challenged: Record[] = [];
    const reasons: string[] = [];
    if (!this.claimed && (await this.claim())) {
      reasons.push("a unit consumed twice gave up the secret: the bond is claimed on every domain");
      this.reasons.push(...reasons);
      const was = this.frozen;
      this.frozen = true;
      return { total, challenged, froze: !was, reasons };
    }
    if (this.frozen) return { total, challenged, froze: false, reasons };
    const backed = await this.backedSet();
    const breaches = await this.breaches(backed);
    const over = this.overBudget(backed);
    let freeze = false;
    for (const r of this.ordered()) {
      const k = key(r);
      const d = this.domainOf(r);
      const now = await this.now(d);
      if (!this.challenged.has(k)) {
        if (now < r.time + this.settings.decideAfter) continue;
        const why = this.faultsWith(r, backed, breaches, over);
        if (why.length === 0) continue;
        reasons.push(`${k}: ${why.join("; ")}`);
        if (d.dispute && now < r.time + (await this.acceptWindow(d))) {
          await this.challenge(d, r);
          challenged.push(r);
        } else freeze = true;
        continue;
      }
      if (this.expired.has(k)) {
        reasons.push(`${k}: challenged and not answered`);
        freeze = true;
        continue;
      }
      const at = this.answered.get(k);
      if (at === undefined) {
        const deadline = this.challenged.get(k) as bigint;
        if (deadline !== 0n && now > deadline) {
          const hash = await d.wallet.writeContract({ address: d.dispute as Address, abi: disputeAbi, functionName: "expire", args: [d.delegation, r.digest] });
          await d.chain.waitForTransactionReceipt({ hash });
          this.expired.add(k);
          reasons.push(`${k}: challenged and not answered`);
          freeze = true;
        }
        continue;
      }
      if (now < at + this.settings.deliveryWait) continue;
      const why = this.faultsWith(r, backed, breaches, over);
      if (why.length > 0) {
        reasons.push(`${k}: answered, and still ${why.join("; ")}`);
        freeze = true;
      }
    }
    if (!freeze) return { total, challenged, froze: false, reasons };
    await this.freezeAll();
    this.reasons.push(...reasons);
    return { total, challenged, froze: true, reasons };
  }

  /**
   * Asks for the openings of every record not yet opened, as a principal
   * does on hearing of a bug in the proof system. The agent, or its answerer
   * holding them sealed, must deliver them within the delivery wait. Returns
   * the records asked for.
   */
  async requestOpenings(): Promise<Record[]> {
    const asked: Record[] = [];
    for (const r of this.records.values()) {
      if (this.openings.has(r.opening) || this.requested.has(key(r))) continue;
      this.requested.set(key(r), await this.now(this.domainOf(r)));
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
}
