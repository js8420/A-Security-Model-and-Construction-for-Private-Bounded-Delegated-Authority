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
  Answerer, Monitor, ProofGate, commitOpening, deployedVerifier, disputeAbi, encodeOpening, independentVerifier, loadConstraints,
  proofChunks, proofHash, reserveAbi, seal, sealedTree, sealingKeyOf, statements, unitsOf, unseal,
  type Check, type Domain, type Opening, type Policy, type Record, type Sealed, type Statement,
} from "../src/index.js";
import { parse } from "../src/stark/proof.js";
import { offsets } from "./stark_kit.js";

const OUT = fileURLToPath(new URL("../../Reserve/out/", import.meta.url));
const KEYS = {
  principal: "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
  agent: "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
  sender: "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a",
  payee: "0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6",
  seal: "0x47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a",
  answerer: "0x8b3a350cf5c34c9194ca85829a2df0ec3153be0318b5e2d3348e872092edffba",
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
const answererKey = privateKeyToAccount(KEYS.answerer);
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
  answerer?: boolean;
}

const ACCEPT_WINDOW = 86_400n;
const ANSWER_WINDOW = 3_600n;
const SLOT = 60n;
const WAIT = 600n;

/**
 * A reserve on one local chain, with a dispute contract whose answer system
 * is a stand-in that accepts any proof. An honest answer passes it as the
 * deployed answer system would; a forged one passes it as an unsound one
 * would.
 */
async function chain(name: string, rpc: string, chainId: number, domainId: bigint) {
  const chainDef = defineChain({ id: chainId, name, nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 }, rpcUrls: { default: { http: [rpc] } } });
  const pub = createPublicClient({ chain: chainDef, transport: http(rpc) }) as PublicClient;
  const principal = createWalletClient({ account: privateKeyToAccount(KEYS.principal), chain: chainDef, transport: http(rpc) });
  const sender = createWalletClient({ account: privateKeyToAccount(KEYS.sender), chain: chainDef, transport: http(rpc) });
  const answering = createWalletClient({ account: answererKey, chain: chainDef, transport: http(rpc) });
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
  const vkey = keccak256("0x01");
  const echo = await deploy("ValidityDisputeScale.t.sol", "EchoVerifier", [vkey]);
  const vd = await deploy("ValidityDispute.sol", "ValidityDispute", [reserve, echo, vkey, ACCEPT_WINDOW, ANSWER_WINDOW, SLOT, parseEther("0.01"), WAIT]);
  await done(await principal.writeContract({ address: reserve, abi: reserveFull, functionName: "setDispute", args: [vd] }));
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
      unitSize: t.unitSize, rangeBase: t.rangeBase, rangeLen: t.rangeLen, monitor: ZERO, answerer: t.answerer ? answererKey.address : ZERO,
      openOnRequest: t.openOnRequest ?? false,
    };
    await done(await principal.writeContract({ address: reserve, abi: reserveFull, functionName: "register", args: [terms], value: parseEther("0.1") }));
    if (t.answerer) await done(await answering.writeContract({ address: reserve, abi: reserveFull, functionName: "stakeAnswerer", args: [id], value: parseEther("0.2") }));
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

  /** An answer through the stand-in answer system. */
  const answer = async (d: Domain, r: { digest: bigint; amount: bigint; payee: Address; time: bigint; elems: bigint[]; epoch: bigint }) => {
    const s = { elems: keccak256(encodePacked(["uint64[]"], [r.elems])), amount: r.amount, payee: r.payee, time: r.time, epoch: r.epoch };
    const root = (await pub.readContract({ address: vd, abi: disputeAbi, functionName: "rootOf", args: [d.delegation, r.digest, s, 0n, []] })) as Hex;
    await done(await sender.writeContract({ address: vd, abi: disputeAbi, functionName: "answer", args: [d.delegation, r.digest, s, 0n, [], root] }));
  };

  /** The record a settlement's calls name. */
  const recordOf = (r: { amount: bigint; payee: Address; time: bigint; elems: bigint[]; epoch: bigint }) =>
    ({ elems: keccak256(encodePacked(["uint64[]"], [r.elems])), amount: r.amount, payee: r.payee, time: r.time, epoch: r.epoch });

  /**
   * The answerer's receipt for a settlement standing as a batch of one, as the
   * stand-in answer system takes it: the settlement's leaf is the batch's root.
   */
  const receipt = async (d: Domain, r: Record, sealedRoot: Hex, proof: Hex, receivedAt: bigint) => {
    const root = (await pub.readContract({ address: vd, abi: disputeAbi, functionName: "rootOf", args: [d.delegation, r.digest, recordOf(r), 0n, []] })) as Hex;
    const h = (await pub.readContract({ address: vd, abi: disputeAbi, functionName: "receiptDigest", args: [d.delegation, root, sealedRoot, proof, receivedAt] })) as Hex;
    return { sealedRoot, proofHash: proof, receivedAt, signature: await answererKey.sign({ hash: h }) };
  };

  /** The answerer posts a batch proof in chunks, one transaction each. */
  const postProof = async (d: Domain, proof: Uint8Array) => {
    const h = proofHash(proof);
    const chunks = proofChunks(proof);
    for (let i = 0; i < chunks.length; i++) {
      const data = `0x${Buffer.from(chunks[i]).toString("hex")}` as Hex;
      await done(await answering.writeContract({ address: vd, abi: disputeAbi, functionName: "postProof", args: [d.delegation, h, BigInt(i), data, i === chunks.length - 1], gas: 15_000_000n }));
    }
    return chunks.length;
  };

  /** The answerer posts a settlement's sealed opening on chain under its receipt. */
  const deliver = async (d: Domain, r: Record, rc: { sealedRoot: Hex; proofHash: Hex; receivedAt: bigint; signature: Hex }, opening: Hex, sealedPath: Hex[]) => {
    await done(await answering.writeContract({ address: vd, abi: disputeAbi, functionName: "deliver", args: [d.delegation, r.digest, recordOf(r), 0n, [], rc, opening, sealedPath] }));
  };

  /** Anyone holding the receipt slashes an answerer that withheld; returns whether it went through. */
  const slashWithholding = async (d: Domain, r: Record, rc: { sealedRoot: Hex; proofHash: Hex; receivedAt: bigint; signature: Hex }) => {
    try {
      await done(await sender.writeContract({ address: vd, abi: disputeAbi, functionName: "slashWithholding", args: [d.delegation, r.digest, recordOf(r), 0n, [], rc] }));
      return true;
    } catch {
      return false;
    }
  };

  const stakeOf = async (d: Domain) => ((await pub.readContract({ address: reserve, abi: reserveFull, functionName: "answererOf", args: [d.delegation] })) as [Address, bigint])[1];

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
  return { delegate, settle, answer, state, now, advance, receipt, deliver, postProof, slashWithholding, stakeOf };
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

const digests = (rs: readonly Record[]) => rs.map((r) => r.digest);

async function main() {
  const A = await chain("domain A", process.env.RPC_A ?? "http://127.0.0.1:8545", 31337, 8453n);
  const B = await chain("domain B", process.env.RPC_B ?? "http://127.0.0.1:8546", 31338, 10n);
  const advanceBoth = async (s: number) => {
    await A.advance(s);
    await B.advance(s);
  };
  /** Brings the two chains' clocks together and returns a signed time both accept, so that payments across them sign in the order they are made. */
  const later = async () => {
    const [a, b] = [await A.now(), await B.now()];
    if (a < b) await A.advance(Number(b - a));
    if (b < a) await B.advance(Number(a - b));
    return (a > b ? a : b) + 1n;
  };
  const ids = new Map([["domain A", 8453n], ["domain B", 10n]]);
  const UNIT = 10_000n;
  const DECIDE = ACCEPT_WINDOW - 600n;
  const PAST_DEADLINE = Number(ANSWER_WINDOW + 40n * SLOT);
  const plain: Terms = { cap: 50_000n, unitSize: UNIT, rangeBase: 0n, rangeLen: 1024n, commitment: keccak256("0x02"), revocationRoot: keccak256("0x03"), secretHash: keccak256("0x01") };
  const policy = (budget: bigint): Policy => ({
    budget, cap: 50_000n, tStart: 0n, tExpiry: 2n ** 63n, merchants: new Map([[1n, payee]]), categories: new Set([1n, 2n]),
    unitSize: UNIT, rangeBase: 0n, rangeLen: 1024n, revoked: [],
  });

  const air = loadConstraints(readFileSync(env("CONSTRAINTS")));
  const honest = new Uint8Array(readFileSync(env("PROOF_SMALL")));
  const at = offsets(honest);
  const forged = honest.slice();
  {
    let v = 0n;
    for (let i = 7; i >= 0; i--) v = (v << 8n) | BigInt(forged[at.foldSibling + i]);
    v = (v + 1n) % P;
    for (let i = 0; i < 8; i++) forged[at.foldSibling + i] = Number((v >> BigInt(8 * i)) & 0xffn);
  }
  const deployed = deployedVerifier(env("CIRCUIT_BIN"));
  const independent = independentVerifier(air);
  const buggy: Check = async () => ({ ok: true });
  const gateBoth = () => new ProofGate([{ name: "deployed", check: deployed }, { name: "independent", check: independent }], air.globals, air.rowWidth);
  const gateBuggy = () => new ProofGate([{ name: "deployed, with a bug that accepts", check: buggy }, { name: "independent", check: independent }], air.globals, air.rowWidth);
  const proving = (gate: ProofGate | null, sealKey?: Hex) => ({ gate, deliveryWait: WAIT, decideAfter: DECIDE, sealKey });

  const { terms: pt, payments } = statements(parse(honest).pv, air.globals, air.rowWidth);
  const proven: Terms = {
    cap: 1_000_000n, unitSize: pt.unitSize, rangeBase: pt.rangeBase, rangeLen: pt.rangeLen,
    commitment: pt.commitment, secretHash: pt.secretHash, revocationRoot: payments[0].root,
  };
  const asked: Terms = { ...proven, openOnRequest: true };
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
  const settleProven = async (d: Domain, os = openingsOf(payments)) => {
    const results: string[] = [];
    for (let i = 0; i < payments.length; i++) {
      const s = payments[i];
      results.push(await A.settle(d, { digest: s.digest, amount: s.amount, payee: s.payee, time: s.time, elems: s.elems, opening: commitOpening(os[i]) }));
    }
    return { os, results };
  };
  const n = payments.length;
  const last = payments[n - 1].digest;

  section(`proofs, the gate and challenges on domain A, with the ${n} payments the honest proof states`);
  const dX = await A.delegate(proven);
  const mX = new Monitor([dX], provenPolicy, proving(gateBoth()));
  const x = await settleProven(dX);
  check(`the ${n} payments settle on domain A`, x.results.every((r) => r === "settled"), x.results.join(", "));
  for (const o of x.os) mX.deliverOpening(o);
  const acceptedX = await mX.deliverProof(honest);

  const dZ = await A.delegate(proven);
  const mZ = new Monitor([dZ], provenPolicy, proving(gateBoth()));
  const s0 = payments[0];
  const oZ: Opening = { ...openingsOf(payments)[0], amount: s0.amount + 1n };
  const zSent = await A.settle(dZ, { digest: s0.digest, amount: s0.amount + 1n, payee: s0.payee, time: s0.time, elems: s0.elems, opening: commitOpening(oZ) });
  mZ.deliverOpening(oZ);
  await mZ.deliverProof(honest);

  const dY = await A.delegate(proven);
  const mY = new Monitor([dY], provenPolicy, proving(gateBuggy()));
  const y = await settleProven(dY);
  for (const o of y.os) mY.deliverOpening(o);
  const acceptedY = await mY.deliverProof(forged);

  const dW = await A.delegate(asked);
  const mW = new Monitor([dW], provenPolicy, proving(gateBoth()));
  const w = await settleProven(dW);
  await mW.deliverProof(honest);

  const dV = await A.delegate(asked);
  const mV = new Monitor([dV], provenPolicy, proving(gateBoth()));
  const v = await settleProven(dV, openingsOf(payments).map((o, i) => (i === 0 ? { ...o, category: 9n } : o)));
  await mV.deliverProof(honest);

  const to = sealingKeyOf(KEYS.seal);
  const sealAll = (os: Opening[]): Sealed[] => os.map((o) => ({ domain: o.domain, digest: o.nonce, blob: seal(o, to, { commitment: pt.commitment, domain: o.domain, digest: o.nonce }) }));
  const dU = await A.delegate(asked);
  const mU = new Monitor([dU], provenPolicy, proving(gateBoth(), KEYS.seal));
  const u = await settleProven(dU);
  const answererU = new Answerer();
  answererU.receive(honest, sealAll(u.os));
  const dU2 = await A.delegate(asked);
  const mU2 = new Monitor([dU2], provenPolicy, proving(gateBoth(), KEYS.seal));
  await settleProven(dU2);
  const answererU2 = new Answerer();
  answererU2.receive(honest, []);
  const dT = await A.delegate(proven);
  const mT = new Monitor([dT], provenPolicy, proving(gateBoth(), KEYS.seal));
  const t = await settleProven(dT);
  const answererT = new Answerer();
  answererT.receive(honest, sealAll(t.os));
  const dS = await A.delegate({ ...proven, answerer: true });
  const mS = new Monitor([dS], provenPolicy, proving(gateBoth(), KEYS.seal));
  const sS = await settleProven(dS);
  const answererS = new Answerer();
  const sealedS = sealAll(sS.os);
  const heldS = answererS.receive(honest, sealedS);
  const dR = await A.delegate({ ...proven, answerer: true });
  const mR = new Monitor([dR], provenPolicy, proving(gateBoth(), KEYS.seal));
  const sR = await settleProven(dR);
  const answererR = new Answerer();
  const sealedR = sealAll(sR.os);
  const heldR = answererR.receive(honest, sealedR);
  let twice = false;
  try {
    answererR.receive(honest, sealedS);
  } catch {
    twice = true;
  }
  const receivedAt = await A.now();

  const all = [mX, mZ, mY, mW, mV, mU, mU2, mT, mS, mR];
  const early = await Promise.all(all.map((m) => m.poll()));
  check("before the decision time the monitor acts on nothing: no challenge and no freeze under any delegation", early.every((r) => r.challenged.length === 0 && !r.froze));
  check("the honest batch passes both verifiers; the forged one is refused beside a deployed verifier that accepts anything", acceptedX && !acceptedY);

  const wReq = await mW.requestOpenings();
  for (const o of w.os.slice(0, n - 1)) mW.deliverOpening(o);
  await mV.requestOpenings();
  for (const o of v.os) mV.deliverOpening(o);
  await mU.requestOpenings();
  const servedU = await answererU.serve(mU);
  await mU2.requestOpenings();
  const servedU2 = await answererU2.serve(mU2);
  const servedT = await answererT.serve(mT);
  check(`on request, the principal asks for all ${n} openings of each delegation that opens on request`, wReq.length === n && mW.openedCount() === n - 1);
  check("the agent is offline; its answerer, holding the proof and the openings sealed to the monitor, delivers both and every opening opens", servedU.proofs === 1 && servedU.opened === n && mU.openedCount() === n);
  check("an answerer holding the proof alone delivers it, but no opening", servedU2.proofs === 1 && servedU2.opened === 0 && mU2.openedCount() === 0);
  check("in the mode that opens every payment, an answerer with sealed openings backs an offline agent's batch", servedT.proofs === 1 && servedT.opened === n);

  const held = answererU.held();
  const plainHex = u.os.map((o) => encodeOpening(o).slice(2));
  check("the answerer holds ciphertexts only: no opening's encoding appears in what it stores", held.sealed.every((b) => plainHex.every((p) => !b.includes(p))));
  check("every sealed opening has one length, so its size reveals no field", new Set(held.sealed.map((b) => b.length)).size === 1, `${(held.sealed[0].length - 2) / 2} bytes`);
  const b0 = { commitment: pt.commitment, domain: payments[0].domain, digest: payments[0].digest };
  let wrongKey = false;
  try {
    unseal(held.sealed[0], KEYS.agent, b0);
  } catch {
    wrongKey = true;
  }
  const flipped = `${held.sealed[0].slice(0, -2)}${held.sealed[0].endsWith("00") ? "01" : "00"}` as Hex;
  check("a key other than the monitor's does not open a sealed opening, and an altered one is refused", wrongKey && !(await mU.deliverSealed(flipped, b0.domain, b0.digest)));
  const otherDigest = payments[n - 1].digest;
  check("a sealed opening is bound to its settlement: offered for another settlement of the batch, it does not open", !(await mU.deliverSealed(held.sealed[0], b0.domain, otherDigest)) && (await mU.deliverSealed(held.sealed[0], b0.domain, b0.digest)));
  check("the answerer takes a batch once: a second set of openings for a proof it holds is refused", twice);

  await A.advance(Number(DECIDE));
  const rX = await mX.poll();
  check("at the decision time, the honest delegation with openings and proof delivered: nothing challenged", rX.challenged.length === 0 && !rX.froze, rX.reasons.join("; "));
  const rZ = await mZ.poll();
  check("a settlement of one more unit of value than the honest proof states is challenged at its decision time", zSent === "settled" && rZ.challenged.length === 1 && !rZ.froze, rZ.reasons.join("; "));
  const rY = await mY.poll();
  const heldY = await A.state(dY);
  check(`the batch with the forged proof: all ${n} challenged and the delegation held`, rY.challenged.length === n && heldY.holds === n && !heldY.frozen, `holds ${heldY.holds}`);
  const extra = engine(ids, pt.unitSize)(dY, await A.now(), 1n);
  const blocked = await A.settle(dY, extra.s);
  check("a further payment on the held delegation is refused", blocked === "Held", blocked);
  const rW = await mW.poll();
  check("on request, the one opening the agent withheld past the delivery wait: that settlement alone is challenged", rW.challenged.length === 1 && rW.challenged[0].digest === last, digests(rW.challenged).join(", "));
  const rV = await mV.poll();
  check("on request, the opening that names a category the policy does not allow: that settlement alone is challenged", rV.challenged.length === 1 && rV.challenged[0].digest === payments[0].digest, rV.reasons.join("; "));
  const rU = await mU.poll();
  check("the offline agent whose answerer delivered sealed openings: nothing challenged", rU.challenged.length === 0 && !rU.froze, rU.reasons.join("; "));
  const rU2 = await mU2.poll();
  check(`the offline agent whose answerer holds the proof alone: all ${n} challenged`, rU2.challenged.length === n, rU2.reasons[0] ?? "");
  const rT = await mT.poll();
  check("the offline agent opening every payment, with its answerer: nothing challenged", rT.challenged.length === 0 && !rT.froze, rT.reasons.join("; "));
  const rS = await mS.poll();
  const rR = await mR.poll();
  check(`two offline agents whose staked answerers have delivered nothing yet: all ${n} challenged under each`, rS.challenged.length === n && rR.challenged.length === n);

  for (const r of rY.challenged) await A.answer(dY, r);
  const lifted = await A.state(dY);
  check("forged answers through an unsound answer system lift the hold", lifted.holds === 0 && !lifted.frozen, `holds ${lifted.holds}`);
  for (const r of rW.challenged) await A.answer(dW, r);
  for (const r of rV.challenged) await A.answer(dV, r);
  for (const r of rU2.challenged) await A.answer(dU2, r);
  const tree = (s: Sealed[]) => sealedTree(s.map((x) => x.blob));
  for (const r of rS.challenged) {
    await A.answer(dS, r);
    const i = sealedS.findIndex((x) => x.digest === r.digest);
    const one = tree([sealedS[i]]);
    await A.deliver(dS, r, await A.receipt(dS, r, one.root, heldS.proofHash, receivedAt), sealedS[i].blob, one.path(0));
  }
  const chunksS = await A.postProof(dS, answererS.proofOf(sealedS[0].domain, sealedS[0].digest) as Uint8Array);
  for (const r of rR.challenged) await A.answer(dR, r);
  const servedR = await answererR.serve(mR, true);
  await A.advance(Number(WAIT) + 1);
  const fY = await mY.poll();
  check("no backing proof arrives within the delivery wait, so the monitor freezes the delegation", fY.froze && (await A.state(dY)).frozen, fY.reasons[0] ?? "");
  const fW = await mW.poll();
  check("the withheld opening, answered on chain and still not delivered: frozen", fW.froze && (await A.state(dW)).frozen, fW.reasons[0] ?? "");
  const fV = await mV.poll();
  check("the opening outside the policy, answered on chain: frozen, as no answer can change what the opening says", fV.froze && fV.reasons.some((r) => r.includes("category")), fV.reasons[0] ?? "");
  const fU2 = await mU2.poll();
  check("the answerer without openings answers every challenge, yet the honest delegation is frozen: the answerer needs the sealed openings", fU2.froze, fU2.reasons[0] ?? "");
  const fS = await mS.poll();
  check(`the staked answerer answers and posts on chain all ${n} sealed openings and the batch proof, in ${chunksS} chunks; the monitor reads both there and freezes nothing`, chunksS > 1 && mS.openedCount() === n && !fS.froze && !(await A.state(dS)).frozen, fS.reasons.join("; "));
  const fR = await mR.poll();
  const stakeBefore = await A.stakeOf(dR);
  const r0 = rR.challenged[0];
  const i0 = sealedR.findIndex((x) => x.digest === r0.digest);
  const slashed = await A.slashWithholding(dR, r0, await A.receipt(dR, r0, tree([sealedR[i0]]).root, heldR.proofHash, receivedAt));
  check("an answerer that answers, hands over the proof and withholds the openings: the delegation is frozen, and the agent's receipt burns its stake", servedR.proofs === 1 && fR.froze && slashed && stakeBefore > 0n && (await A.stakeOf(dR)) === 0n, fR.reasons[0] ?? "");
  const zBefore = await A.state(dZ);
  await A.advance(PAST_DEADLINE);
  const fZ = await mZ.poll();
  check("the extra unit's challenge goes unanswered, as no proof of it exists; past its deadline the monitor expires it and the delegation is frozen", !zBefore.frozen && fZ.froze && (await A.state(dZ)).frozen, fZ.reasons[0] ?? "");
  const ends = await Promise.all([dX, dU, dT, dS].map((d) => A.state(d)));
  check("the honest delegations, the offline ones with sealed openings among them, are neither held nor frozen", ends.every((e) => !e.frozen && e.holds === 0));

  section("budget tripwire, no proof read");
  await later();
  {
    const dA = await A.delegate(plain);
    const dB = await B.delegate(plain);
    const m = new Monitor([dA, dB], policy(50_000n), proving(null));
    const pay = engine(ids, UNIT);
    let acted = false;
    const order = [[dA, A], [dB, B], [dA, A], [dB, B], [dA, A], [dB, B]] as const;
    const start = await later();
    for (const [i, [d, c]] of order.entries()) {
      const p = pay(d, start + BigInt(i), UNIT);
      m.deliverOpening(p.opening);
      await c.settle(d, p.s);
      const r = await m.poll();
      acted ||= r.froze || r.challenged.length > 0;
    }
    const sixth = m.all().find((r) => r.domain === "domain B" && r.digest === 1_005n);
    check("six payments of 10,000 across two domains, the sixth taking the total to 60,000 past B: nothing happens at once", !acted && m.total() === 60_000n && sixth !== undefined);
    await advanceBoth(Number(DECIDE) + 10);
    const r = await m.poll();
    const [sa, sb] = [await A.state(dA), await B.state(dB)];
    check("at the sixth's decision time, it alone is challenged, on domain B, which is held", r.challenged.length === 1 && r.challenged[0].digest === 1_005n && sb.holds === 1 && sa.holds === 0, r.reasons.join("; "));
    const onB = await B.settle(dB, pay(dB, await B.now(), UNIT).s);
    check("a further payment on domain B is refused", onB === "Held", onB);
    await advanceBoth(PAST_DEADLINE);
    const f = await m.poll();
    const onA = await A.settle(dA, pay(dA, await A.now(), UNIT).s);
    check("its challenge goes unanswered, and the monitor freezes both domains", f.froze && (await A.state(dA)).frozen && (await B.state(dB)).frozen && onA !== "settled", onA);
  }

  section("openings checked in the clear, no proof read");
  {
    const dA = await A.delegate(plain);
    const dB = await B.delegate(plain);
    const m = new Monitor([dA, dB], policy(1_000_000n), proving(null));
    const pay = engine(ids, UNIT);
    const ok = pay(dA, await A.now(), UNIT, { category: 2n });
    const bad = pay(dB, await B.now(), UNIT, { category: 9n });
    m.deliverOpening(ok.opening);
    m.deliverOpening(bad.opening);
    const sent = [await A.settle(dA, ok.s), await B.settle(dB, bad.s)];
    const r0 = await m.poll();
    await advanceBoth(Number(DECIDE) + 10);
    const r1 = await m.poll();
    check("an opening naming a category the policy does not allow: nothing at once, and at its decision time that settlement alone is challenged", sent.every((x) => x === "settled") && r0.challenged.length === 0 && r1.challenged.length === 1 && r1.challenged[0].digest === bad.s.digest && r1.reasons.some((x) => x.includes("category")), r1.reasons.join("; "));
    for (const c of r1.challenged) await B.answer(dB, c);
    await advanceBoth(Number(WAIT) + 1);
    const r2 = await m.poll();
    const later = await A.settle(dA, pay(dA, await A.now(), UNIT).s);
    check("answered through an unsound answer system, it still breaks the policy, so both domains are frozen", r2.froze && later !== "settled", later);
  }
  {
    const dA = await A.delegate(plain);
    const dB = await B.delegate(plain);
    const m = new Monitor([dA, dB], policy(1_000_000n), proving(null));
    const pay = engine(ids, UNIT);
    const start = await later();
    const first = pay(dA, start, UNIT, { runStart: 7n });
    const again = pay(dB, start + 1n, UNIT, { runStart: 7n });
    const off = pay(dA, start + 2n, UNIT, { amount: 1n });
    for (const p of [first, again, off]) m.deliverOpening(p.opening);
    await A.settle(dA, first.s);
    await B.settle(dB, again.s);
    await A.settle(dA, off.s);
    await advanceBoth(Number(DECIDE) + 10);
    const r = await m.poll();
    const why = r.reasons.join("; ");
    check("the same unit consumed on two domains: the later settlement is challenged", r.challenged.some((c) => c.digest === again.s.digest) && why.includes("already consumed"), why);
    check("an opening that disagrees with its own record: that settlement is challenged", r.challenged.some((c) => c.digest === off.s.digest) && why.includes("disagrees") && r.challenged.length === 2, why);
  }

  section("the chain shows the same whatever the cause: an adversary with the agent's key and no proof");
  {
    const cases = [
      { name: "budget 50,000, no openings", budget: 50_000n, open: null as bigint | null },
      { name: "budget 1,000,000, no openings", budget: 1_000_000n, open: null },
      { name: "budget 1,000,000, openings naming an allowed merchant", budget: 1_000_000n, open: 1n },
      { name: "budget 1,000,000, openings naming a merchant outside the allowlist", budget: 1_000_000n, open: 2n },
    ];
    const runs: { c: typeof cases[number]; dA: Domain; dB: Domain; m: Monitor; pay: ReturnType<typeof engine>; trace: string[] }[] = [];
    for (const c of cases) {
      const dA = await A.delegate(plain);
      const dB = await B.delegate(plain);
      runs.push({ c, dA, dB, m: new Monitor([dA, dB], policy(c.budget), proving(gateBoth())), pay: engine(ids, UNIT), trace: [] as string[] });
    }
    const observe = async (k: typeof runs[number]) => {
      const r = await k.m.poll();
      const [sa, sb] = [await A.state(k.dA), await B.state(k.dB)];
      const at = r.challenged.map((x) => `${x.domain === "domain A" ? "A" : "B"}${x.digest - 1_000n}`).sort().join(",");
      k.trace.push(`[${at}] A ${sa.frozen ? "frozen" : `holds ${sa.holds}`}, B ${sb.frozen ? "frozen" : `holds ${sb.holds}`}`);
    };
    const start = await later();
    for (let i = 0; i < 6; i++) {
      for (const k of runs) {
        const [d, c] = i % 2 === 0 ? [k.dA, A] : [k.dB, B];
        const p = k.pay(d, start + BigInt(i), UNIT, k.c.open === null ? {} : { merchant: k.c.open });
        if (k.c.open !== null) k.m.deliverOpening(p.opening);
        await c.settle(d, p.s);
      }
      for (const k of runs) await observe(k);
    }
    await advanceBoth(Number(DECIDE) + 10);
    for (const k of runs) await observe(k);
    await advanceBoth(PAST_DEADLINE);
    for (const k of runs) await observe(k);
    const ref = runs[0].trace.join(" | ");
    for (const k of runs.slice(1)) check(`${k.c.name}: the same actions at the same steps as ${runs[0].c.name}`, k.trace.join(" | ") === ref);
    const t0 = runs[0].trace;
    check("in every case, nothing before the decision time, then all six challenged at once, then both domains frozen", t0.slice(0, 6).every((s) => s.startsWith("[]") && !s.includes("frozen")) && t0[6].startsWith("[A0,A2,A4,B1,B3,B5]") && t0[7].endsWith("A frozen, B frozen"), t0.slice(5).join(" | "));
  }

  console.log("THE MONITOR ON TWO LOCAL CHAINS: BUDGET, OPENINGS, PROOFS, CHALLENGES AND THE ANSWERER");
  console.log("=".repeat(78));
  for (const l of lines) console.log(l);
  console.log(`  ${failures === 0 ? "all checks pass" : `${failures} checks fail`}`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
