import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import {
  createPublicClient,
  createWalletClient,
  defineChain,
  encodePacked,
  http,
  keccak256,
  parseEther,
  type Abi,
  type Address,
  type Hex,
  type PublicClient,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import {
  Monitor, ProofGate, commitOpening, disputeAbi, independentVerifier, loadConstraints, reserveAbi, statements, unitsOf,
  type Check, type Domain, type Opening, type Policy, type Statement, deployedVerifier,
} from "../src/index.js";
import { parse } from "../src/stark/proof.js";

const OUT = fileURLToPath(new URL("../../Reserve/out/", import.meta.url));
const KEYS = {
  principal: "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
  agent: "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
  sender: "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a",
  payee: "0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6",
} as const;
const P = 0xffffffff00000001n;
const ZERO: Address = "0x0000000000000000000000000000000000000000";
const env = (k: string) => {
  const v = process.env[k];
  if (!v) throw new Error(`${k} not set`);
  return v;
};

function artifact(file: string, name: string): { abi: Abi; bytecode: Hex } {
  const j = JSON.parse(readFileSync(`${OUT}${file}/${name}.json`, "utf8"));
  return { abi: j.abi, bytecode: j.bytecode.object };
}

const agent = privateKeyToAccount(KEYS.agent);
const payee = privateKeyToAccount(KEYS.payee).address;
const reserveFull = artifact("Reserve.sol", "Reserve").abi;

interface Terms {
  cap: bigint;
  unitSize: bigint;
  rangeBase: bigint;
  rangeLen: bigint;
  commitment: Hex;
  revocationRoot: Hex;
  secretHash: Hex;
  openOnRequest?: boolean;
}

/** A reserve on one local chain, with a dispute contract whose answer system accepts anything when `dispute` is set. */
async function chain(name: string, rpc: string, chainId: number, domainId: bigint, dispute: boolean) {
  const chainDef = defineChain({ id: chainId, name, nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 }, rpcUrls: { default: { http: [rpc] } } });
  const pub = createPublicClient({ chain: chainDef, transport: http(rpc) }) as PublicClient;
  const principal = createWalletClient({ account: privateKeyToAccount(KEYS.principal), chain: chainDef, transport: http(rpc) });
  const sender = createWalletClient({ account: privateKeyToAccount(KEYS.sender), chain: chainDef, transport: http(rpc) });
  const done = async (h: Hex) => {
    const r = await pub.waitForTransactionReceipt({ hash: h });
    if (r.status !== "success") throw new Error(`transaction ${h} reverted`);
    return r;
  };
  const deploy = async (file: string, cname: string, args: unknown[] = []) => {
    const a = artifact(file, cname);
    const r = await done(await principal.deployContract({ abi: a.abi, bytecode: a.bytecode, args }));
    if (!r.contractAddress) throw new Error(`deploy ${cname}`);
    return r.contractAddress;
  };
  const token = await deploy("MockToken.sol", "MockToken");
  const poseidon = await deploy("Poseidon2Goldilocks.sol", "Poseidon2Goldilocks");
  const reserve = await deploy("Reserve.sol", "Reserve", [domainId, token, ZERO, poseidon, 3600n, 2n * 86400n]);
  let vd: Address | undefined;
  if (dispute) {
    const vkey = keccak256("0x01");
    const echo = await deploy("ValidityDisputeScale.t.sol", "EchoVerifier", [vkey]);
    vd = await deploy("ValidityDispute.sol", "ValidityDispute", [reserve, echo, vkey, 86400n, 3600n, 60n, parseEther("0.01")]);
    await done(await principal.writeContract({ address: reserve, abi: reserveFull, functionName: "setDispute", args: [vd] }));
  }
  const tokenAbi = artifact("MockToken.sol", "MockToken").abi;
  await done(await principal.writeContract({ address: token, abi: tokenAbi, functionName: "mint", args: [principal.account.address, 10n ** 15n] }));
  await done(await principal.writeContract({ address: token, abi: tokenAbi, functionName: "approve", args: [reserve, 2n ** 256n - 1n] }));

  /** A delegation under these terms, and this domain as the monitor sees it. */
  const delegate = async (t: Terms): Promise<Domain> => {
    const id = (await pub.readContract({ address: reserve, abi: reserveFull, functionName: "nextId" })) as bigint;
    const now = (await pub.getBlock()).timestamp;
    const terms = {
      agent: agent.address, cap: t.cap, velocityN: 20n, windowW: 86_400n, secretHash: t.secretHash, funding: 0,
      deposit: 10n ** 12n, commitment: t.commitment, revocationRoot: t.revocationRoot, expiry: now + 30n * 86_400n,
      unitSize: t.unitSize, rangeBase: t.rangeBase, rangeLen: t.rangeLen, monitor: ZERO, answerer: ZERO,
      openOnRequest: t.openOnRequest ?? false,
    };
    await done(await principal.writeContract({ address: reserve, abi: reserveFull, functionName: "register", args: [terms], value: parseEther("0.1") }));
    return { name, chain: pub, wallet: principal, reserve, delegation: id, dispute: vd };
  };

  /** One settlement, signed by the agent and sent by a third party. Returns "settled" or the reserve's reason. */
  const settle = async (d: Domain, s: { digest: bigint; amount: bigint; payee: Address; time: bigint; elems: bigint[]; opening: Hex }) => {
    const hash = await pub.readContract({
      address: reserve, abi: reserveAbi, functionName: "signedDigest",
      args: [d.delegation, s.payee, s.amount, s.digest, s.time, keccak256(encodePacked(["uint64[]"], [s.elems])), s.opening],
    });
    const signature = await agent.sign({ hash });
    try {
      const { request } = await pub.simulateContract({
        account: sender.account, address: reserve, abi: reserveAbi, functionName: "settleLogged",
        args: [d.delegation, s.payee, s.amount, s.digest, s.time, s.elems, s.opening, signature],
      });
      await done(await sender.writeContract(request));
      return "settled";
    } catch (e) {
      const m = String(e).match(/reverted with the following reason:\s*\n\s*(\w+)|Error: (\w+)\(\)/);
      return m ? (m[1] ?? m[2]) : "refused";
    }
  };

  /** An answer through the answer system that accepts anything: what an unsound one does. */
  const forgeAnswer = async (d: Domain, r: { digest: bigint; amount: bigint; payee: Address; time: bigint; elems: bigint[]; epoch: bigint }) => {
    const s = { elems: keccak256(encodePacked(["uint64[]"], [r.elems])), amount: r.amount, payee: r.payee, time: r.time, epoch: r.epoch };
    const root = (await pub.readContract({ address: vd as Address, abi: disputeAbi, functionName: "rootOf", args: [d.delegation, r.digest, s, 0n, []] })) as Hex;
    await done(await sender.writeContract({ address: vd as Address, abi: disputeAbi, functionName: "answer", args: [d.delegation, r.digest, s, 0n, [], root] }));
  };

  const state = async (d: Domain) => {
    const [frozen, holds] = (await pub.readContract({ address: reserve, abi: reserveAbi, functionName: "frozenOf", args: [d.delegation] })) as [boolean, number];
    return { frozen, holds };
  };
  const now = async () => (await pub.getBlock({ blockTag: "latest" })).timestamp;
  /** Moves the chain's clock forward and mines a block. */
  const advance = async (seconds: number) => {
    await (pub.request as (a: { method: string; params: unknown[] }) => Promise<unknown>)({ method: "evm_increaseTime", params: [seconds] });
    await (pub.request as (a: { method: string; params: unknown[] }) => Promise<unknown>)({ method: "evm_mine", params: [] });
  };
  return { delegate, settle, forgeAnswer, state, now, advance };
}

const lines: string[] = [];
let failures = 0;
const check = (name: string, ok: boolean, detail = "") => {
  lines.push(`  ${ok ? "PASS" : "FAIL"}  ${name}${detail ? `: ${detail}` : ""}`);
  if (!ok) failures += 1;
};
const section = (title: string) => lines.push(`  ${title}`);

/** The agent's engine for payments that no proof stands behind: fresh digests, 3 values a unit, and the opening. */
function engine(domainIds: Map<string, bigint>, unit: bigint) {
  let next = 1_000n;
  let run = 0n;
  return (d: Domain, time: bigint, amount: bigint, o: Partial<Opening> = {}) => {
    const digest = next++;
    const units = unitsOf(amount, unit);
    const elems = Array.from({ length: Number(3n * units) }, (_, i) => BigInt(keccak256(encodePacked(["uint64", "uint64"], [digest, BigInt(i)]))) % P);
    const opening: Opening = {
      salt: keccak256(encodePacked(["string", "uint64"], ["salt", digest])), amount, merchant: 1n, category: 1n, time, payee,
      domain: domainIds.get(d.name) as bigint, nonce: digest, runStart: run, ...o,
    };
    if (o.runStart === undefined) run += units;
    return { s: { digest, amount, payee, time, elems, opening: commitOpening(opening) }, opening };
  };
}

async function main() {
  const A = await chain("domain A", process.env.RPC_A ?? "http://127.0.0.1:8545", 31337, 8453n, true);
  const B = await chain("domain B", process.env.RPC_B ?? "http://127.0.0.1:8546", 31338, 10n, false);
  const ids = new Map([["domain A", 8453n], ["domain B", 10n]]);
  const UNIT = 10_000n;
  const plain: Terms = { cap: 50_000n, unitSize: UNIT, rangeBase: 0n, rangeLen: 1024n, commitment: keccak256("0x02"), revocationRoot: keccak256("0x03"), secretHash: keccak256("0x01") };
  const policy = (budget: bigint): Policy => ({
    budget, cap: 50_000n, tStart: 0n, tExpiry: 2n ** 63n, merchants: new Map([[1n, payee]]), categories: new Set([1n, 2n]),
    unitSize: UNIT, rangeBase: 0n, rangeLen: 1024n, revoked: [],
  });

  section("budget tripwire, no proof read");
  {
    const dA = await A.delegate(plain);
    const dB = await B.delegate(plain);
    const m = new Monitor([dA, dB], policy(50_000n), null, 0n);
    const pay = engine(ids, UNIT);
    let froze = false;
    for (const [d, x] of [[dA, A], [dB, B], [dA, A], [dB, B], [dA, A]] as const) {
      const p = pay(d, await x.now(), UNIT);
      m.deliverOpening(p.opening);
      await x.settle(d, p.s);
      froze ||= (await m.poll()).froze;
    }
    check("five payments of 10,000 across two domains, total 50,000 = B, no freeze", !froze && m.total() === 50_000n);
    const p6 = pay(dB, await B.now(), UNIT);
    m.deliverOpening(p6.opening);
    const sixth = await B.settle(dB, p6.s);
    const after = await m.poll();
    check("the sixth, on domain B, takes the total past B and the monitor freezes both domains", sixth === "settled" && after.froze && after.total === 60_000n);
    const onA = await A.settle(dA, pay(dA, await A.now(), UNIT).s);
    const onB = await B.settle(dB, pay(dB, await B.now(), UNIT).s);
    check("a further payment refused on both domains", onA !== "settled" && onB !== "settled", `${onA}, ${onB}`);
  }

  section("openings checked in the clear, no proof read");
  {
    const dA = await A.delegate(plain);
    const dB = await B.delegate(plain);
    const m = new Monitor([dA, dB], policy(1_000_000n), null, 0n);
    const pay = engine(ids, UNIT);
    const ok = pay(dA, await A.now(), UNIT, { category: 2n });
    m.deliverOpening(ok.opening);
    await A.settle(dA, ok.s);
    const r1 = await m.poll();
    check("a payment in an allowed category: no freeze", !r1.froze && r1.reasons.length === 0, r1.reasons.join("; "));
    const bad = pay(dB, await B.now(), UNIT, { category: 9n });
    m.deliverOpening(bad.opening);
    const sent = await B.settle(dB, bad.s);
    const r2 = await m.poll();
    check("a payment whose opening names a category the policy does not allow settles, and the monitor freezes both domains", sent === "settled" && r2.froze && r2.reasons.some((x) => x.includes("category")), r2.reasons.join("; "));
    const later = await A.settle(dA, pay(dA, await A.now(), UNIT).s);
    check("a further payment on the other domain refused", later !== "settled", later);
  }
  {
    const dA = await A.delegate(plain);
    const dB = await B.delegate(plain);
    const m = new Monitor([dA, dB], policy(1_000_000n), null, 0n);
    const pay = engine(ids, UNIT);
    const first = pay(dA, await A.now(), UNIT, { runStart: 7n });
    const again = pay(dB, await B.now(), UNIT, { runStart: 7n });
    m.deliverOpening(first.opening);
    m.deliverOpening(again.opening);
    await A.settle(dA, first.s);
    await B.settle(dB, again.s);
    const r = await m.poll();
    check("the same unit consumed on two domains: the monitor sees it in the openings and freezes both", r.froze && r.reasons.some((x) => x.includes("already consumed")), r.reasons.join("; "));
  }
  {
    const dA = await A.delegate(plain);
    const m = new Monitor([dA], policy(1_000_000n), null, 0n);
    const pay = engine(ids, UNIT);
    const p = pay(dA, await A.now(), UNIT, { amount: 1n });
    m.deliverOpening(p.opening);
    await A.settle(dA, p.s);
    const r = await m.poll();
    check("an opening that disagrees with its own record freezes the delegation", r.froze && r.reasons.some((x) => x.includes("disagrees")), r.reasons.join("; "));
  }

  section("proofs, the gate and challenges on domain A");
  const air = loadConstraints(readFileSync(env("CONSTRAINTS")));
  const honest = new Uint8Array(readFileSync(env("PROOF_SMALL")));
  const { offsets } = parse(honest);
  const forged = honest.slice();
  {
    let v = 0n;
    for (let i = 7; i >= 0; i--) v = (v << 8n) | BigInt(forged[offsets.foldSibling + i]);
    v = (v + 1n) % P;
    for (let i = 0; i < 8; i++) forged[offsets.foldSibling + i] = Number((v >> BigInt(8 * i)) & 0xffn);
  }
  const { terms: pt, payments } = statements(parse(honest).pv, air.globals, air.rowWidth);
  const proven: Terms = {
    cap: 1_000_000n, unitSize: pt.unitSize, rangeBase: pt.rangeBase, rangeLen: pt.rangeLen,
    commitment: pt.commitment, secretHash: pt.secretHash, revocationRoot: payments[0].root,
  };
  const provenPolicy: Policy = {
    budget: 1_000_000n, cap: 1_000_000n, tStart: 0n, tExpiry: 2n ** 63n,
    merchants: new Map([[1n, payments[0].payee]]), categories: new Set([1n]),
    unitSize: pt.unitSize, rangeBase: pt.rangeBase, rangeLen: pt.rangeLen, revoked: [],
  };
  const openingsOf = (ps: Statement[]) => {
    let run = pt.rangeBase;
    return ps.map((s) => {
      const o: Opening = {
        salt: keccak256(encodePacked(["string", "uint64"], ["proven", s.digest])), amount: s.amount, merchant: 1n, category: 1n,
        time: s.time, payee: s.payee, domain: s.domain, nonce: s.digest, runStart: run,
      };
      run += unitsOf(s.amount, pt.unitSize);
      return o;
    });
  };
  const settleProven = async (d: Domain) => {
    const os = openingsOf(payments);
    const results: string[] = [];
    for (let i = 0; i < payments.length; i++) {
      const s = payments[i];
      results.push(await A.settle(d, { digest: s.digest, amount: s.amount, payee: s.payee, time: s.time, elems: s.elems, opening: commitOpening(os[i]) }));
    }
    return { os, results };
  };
  const deployed = deployedVerifier(env("CIRCUIT_BIN"));
  const independent = independentVerifier(air);
  const buggy: Check = async () => ({ ok: true });

  const dX = await A.delegate(proven);
  const mX = new Monitor([dX], provenPolicy, new ProofGate([{ name: "deployed", check: deployed }, { name: "independent", check: independent }], air.globals, air.rowWidth), 0n);
  const x = await settleProven(dX);
  check(`the ${payments.length} payments the honest proof states settle on domain A`, x.results.length === payments.length && x.results.every((r) => r === "settled"), x.results.join(", "));
  for (const o of x.os) mX.deliverOpening(o);
  const acceptedX = await mX.deliverProof(honest);
  const rX = await mX.poll();
  const cX = await mX.challengeUnbacked();
  check("their openings and the honest proof are delivered: both verifiers accept, nothing is challenged, nothing frozen", mX.all().length === payments.length && acceptedX && !rX.froze && cX.length === 0, rX.reasons.join("; "));

  const dZ = await A.delegate(proven);
  const mZ = new Monitor([dZ], provenPolicy, new ProofGate([{ name: "deployed", check: deployed }, { name: "independent", check: independent }], air.globals, air.rowWidth), 0n);
  const s0 = payments[0];
  const oZ: Opening = { ...openingsOf(payments)[0], amount: s0.amount + 1n };
  const zSent = await A.settle(dZ, { digest: s0.digest, amount: s0.amount + 1n, payee: s0.payee, time: s0.time, elems: s0.elems, opening: commitOpening(oZ) });
  mZ.deliverOpening(oZ);
  await mZ.deliverProof(honest);
  await mZ.poll();
  const cZ = await mZ.challengeUnbacked();
  check("an honest proof does not back a settlement of one more unit of value than it states: the monitor challenges it", zSent === "settled" && cZ.length === 1, zSent);

  const dY = await A.delegate(proven);
  const mY = new Monitor([dY], provenPolicy, new ProofGate([{ name: "deployed, with a bug that accepts", check: buggy }, { name: "independent", check: independent }], air.globals, air.rowWidth), 0n);
  const y = await settleProven(dY);
  check("the same payments settle under a second delegation", y.results.every((r) => r === "settled"), y.results.join(", "));
  for (const o of y.os) mY.deliverOpening(o);
  const acceptedY = await mY.deliverProof(forged);
  await mY.poll();
  const cY = await mY.challengeUnbacked();
  const heldY = await A.state(dY);
  check("the same payments under a second delegation, delivered with a forged proof: the gate refuses it beside a deployed verifier that accepts anything", !acceptedY);
  check(`the monitor challenges all ${payments.length} on chain and the delegation is held`, cY.length === payments.length && heldY.holds === payments.length && !heldY.frozen, `holds ${heldY.holds}`);
  const more = engine(ids, pt.unitSize);
  const extra = more(dY, await A.now(), 1n);
  const blocked = await A.settle(dY, extra.s);
  check("a further payment on the held delegation is refused", blocked === "Held", blocked);
  for (const r of cY) await A.forgeAnswer(dY, r);
  const lifted = await A.state(dY);
  check("forged answers through an answer system that accepts anything lift the hold", lifted.holds === 0 && !lifted.frozen, `holds ${lifted.holds}`);
  const rY = await mY.poll();
  const endY = await A.state(dY);
  check("no backing proof arrives, so the monitor freezes the delegation", rY.froze && endY.frozen && rY.reasons.some((r) => r.includes("answered")), rY.reasons[0] ?? "");
  const endX = await A.state(dX);
  check("the honest delegation is neither held nor frozen", !endX.frozen && endX.holds === 0);

  section("opening on request, on domain A");
  const WAIT = 600n;
  const asked: Terms = { ...proven, openOnRequest: true };
  const gateBoth = () => new ProofGate([{ name: "deployed", check: deployed }, { name: "independent", check: independent }], air.globals, air.rowWidth);
  {
    const dW = await A.delegate(asked);
    const mW = new Monitor([dW], provenPolicy, gateBoth(), WAIT);
    const w = await settleProven(dW);
    await mW.deliverProof(honest);
    const r0 = await mW.poll();
    const c0 = await mW.challengeUnbacked();
    check("payments under a delegation that opens on request, delivered with the honest proof alone: nothing challenged, and the principal holds no payment's fields", w.results.every((r) => r === "settled") && !r0.froze && c0.length === 0 && mW.openedCount() === 0, w.results.join(", "));
    const req = await mW.requestOpenings();
    for (const o of w.os.slice(0, w.os.length - 1)) mW.deliverOpening(o);
    const c1 = await mW.challengeUnbacked();
    check(`the principal asks for all ${payments.length} openings; within the delivery wait nothing is challenged`, req.length === payments.length && c1.length === 0);
    await A.advance(Number(WAIT) + 1);
    const r2 = await mW.poll();
    const c2 = await mW.challengeUnbacked();
    const held = await A.state(dW);
    check("the agent opens all but one; after the wait the one it withheld is challenged on chain and the delegation held", !r2.froze && c2.length === 1 && c2[0].digest === payments[payments.length - 1].digest && held.holds === 1, `challenged ${c2.length}, holds ${held.holds}`);
  }
  {
    const dV = await A.delegate(asked);
    const mV = new Monitor([dV], provenPolicy, gateBoth(), WAIT);
    const os = openingsOf(payments).map((o, i) => (i === 0 ? { ...o, category: 9n } : o));
    const sent: string[] = [];
    for (let i = 0; i < payments.length; i++) {
      const s = payments[i];
      sent.push(await A.settle(dV, { digest: s.digest, amount: s.amount, payee: s.payee, time: s.time, elems: s.elems, opening: commitOpening(os[i]) }));
    }
    await mV.deliverProof(honest);
    const quiet = await mV.poll();
    await mV.requestOpenings();
    for (const o of os) mV.deliverOpening(o);
    const r = await mV.poll();
    check("a delegation that opens on request, with the honest proof delivered: one payment, opened on request, names a category the policy does not allow, and the monitor freezes the delegation", sent.every((x) => x === "settled") && !quiet.froze && r.froze && r.reasons.some((x) => x.includes("category")), r.reasons.join("; "));
  }

  console.log("THE MONITOR ON TWO LOCAL CHAINS: BUDGET, OPENINGS, PROOFS AND CHALLENGES");
  console.log("=".repeat(78));
  for (const l of lines) console.log(l);
  console.log(`  ${failures === 0 ? "all checks pass" : `${failures} checks fail`}`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
