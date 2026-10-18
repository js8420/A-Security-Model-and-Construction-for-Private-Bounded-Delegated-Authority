import { readFileSync } from "node:fs";
import type { Server } from "node:http";
import { fileURLToPath } from "node:url";
import express from "express";
import { x402Facilitator } from "@x402/core/facilitator";
import { x402Client } from "@x402/core/client";
import { HTTPFacilitatorClient } from "@x402/core/server";
import { decodePaymentRequiredHeader, decodePaymentResponseHeader, encodePaymentSignatureHeader } from "@x402/core/http";
import type { Network, PaymentPayload, PaymentRequirements, VerifyResponse } from "@x402/core/types";
import { paymentMiddleware, x402ResourceServer } from "@x402/express";
import { wrapFetchWithPayment } from "@x402/fetch";
import {
  createPublicClient,
  createWalletClient,
  encodePacked,
  http,
  keccak256,
  parseEther,
  type Abi,
  type Hex,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { foundry } from "viem/chains";
import { BoundedEvmClient, BoundedEvmFacilitator, BoundedEvmServer, commitOpening, unitsOf, type Opening, type PaymentSource } from "../src/index.js";

const RPC = process.env.RPC_URL ?? "http://127.0.0.1:8545";
const OUT = fileURLToPath(new URL("../../Reserve/out/", import.meta.url));
const NETWORK = `eip155:${foundry.id}` as Network;
const KEYS = {
  principal: "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
  agent: "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
  facilitator: "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a",
  payee: "0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6",
  stranger: "0x47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a",
} as const;
const UNIT = 10_000n;
const CAP = 50_000n;
const RATE = 5n;
const P = 0xffffffff00000001n;

function artifact(file: string, name: string): { abi: Abi; bytecode: Hex } {
  const j = JSON.parse(readFileSync(`${OUT}${file}/${name}.json`, "utf8"));
  return { abi: j.abi, bytecode: j.bytecode.object };
}

const chain = createPublicClient({ chain: foundry, transport: http(RPC) });
const wallet = (k: Hex) => createWalletClient({ account: privateKeyToAccount(k), chain: foundry, transport: http(RPC) });
const principal = wallet(KEYS.principal);
const facWallet = wallet(KEYS.facilitator);
const agent = privateKeyToAccount(KEYS.agent);
const payee = privateKeyToAccount(KEYS.payee).address;

async function deploy(file: string, name: string, args: unknown[] = []): Promise<Hex> {
  const a = artifact(file, name);
  const hash = await principal.deployContract({ abi: a.abi, bytecode: a.bytecode, args });
  const r = await chain.waitForTransactionReceipt({ hash });
  if (!r.contractAddress) throw new Error(`deploy ${name}`);
  return r.contractAddress;
}

async function send(hash: Hex) {
  const r = await chain.waitForTransactionReceipt({ hash });
  if (r.status !== "success") throw new Error(`transaction ${hash} reverted`);
  return r;
}

const DOMAIN = 8453n;

/**
 * Stands in for the agent's payment engine: one fresh digest, 3 values a unit,
 * and the opening of the payment's fields, kept for the principal.
 */
class DemoSource implements PaymentSource {
  private next = 1_000n;
  private run = 0n;
  readonly openings: Opening[] = [];
  async form(a: { payee: `0x${string}`; amount: bigint; time: bigint }) {
    const digest = this.next++;
    const units = unitsOf(a.amount, UNIT);
    const elems = Array.from({ length: Number(3n * units) }, (_, i) =>
      BigInt(keccak256(encodePacked(["uint64", "uint64"], [digest, BigInt(i)]))) % P,
    );
    const o: Opening = {
      salt: keccak256(encodePacked(["string", "uint64"], ["salt", digest])),
      amount: a.amount, merchant: 1n, category: 1n, time: a.time, payee: a.payee,
      domain: DOMAIN, nonce: digest, runStart: this.run,
    };
    this.run += units;
    this.openings.push(o);
    return { digest, elems, opening: commitOpening(o) };
  }
}

const lines: string[] = [];
let failures = 0;
function check(name: string, ok: boolean, detail = "") {
  lines.push(`  ${ok ? "PASS" : "FAIL"}  ${name}${detail ? `: ${detail}` : ""}`);
  if (!ok) failures += 1;
}

function listen(app: express.Express, port: number): Promise<Server> {
  return new Promise((resolve) => {
    const s = app.listen(port, () => resolve(s));
  });
}

async function main() {
  const token = await deploy("MockToken.sol", "MockToken");
  const poseidon = await deploy("Poseidon2Goldilocks.sol", "Poseidon2Goldilocks");
  const reserve = await deploy("Reserve.sol", "Reserve", [DOMAIN, token, "0x0000000000000000000000000000000000000000", poseidon, 3600n, 2n * 86400n]);
  const tokenAbi = artifact("MockToken.sol", "MockToken").abi;
  const reserveFull = artifact("Reserve.sol", "Reserve").abi;
  await send(await principal.writeContract({ address: token, abi: tokenAbi, functionName: "mint", args: [principal.account.address, 10_000_000n] }));
  await send(await principal.writeContract({ address: token, abi: tokenAbi, functionName: "approve", args: [reserve, 2n ** 256n - 1n] }));
  const now = (await chain.getBlock()).timestamp;
  const terms = {
    agent: agent.address, cap: CAP, velocityN: RATE, windowW: 86_400n,
    secretHash: keccak256("0x01"), funding: 0, deposit: 1_000_000n,
    commitment: keccak256("0x02"), revocationRoot: keccak256("0x03"), expiry: now + 30n * 86_400n,
    unitSize: UNIT, rangeBase: 0n, rangeLen: 1024n,
    monitor: "0x0000000000000000000000000000000000000000", answerer: "0x0000000000000000000000000000000000000000",
    openOnRequest: false,
  };
  const id = 0n;
  await send(await principal.writeContract({ address: reserve, abi: reserveFull, functionName: "register", args: [terms], value: parseEther("0.1") }));

  const verdicts: VerifyResponse[] = [];
  const facScheme = new BoundedEvmFacilitator(facWallet, chain, [reserve]);
  const verify = facScheme.verify.bind(facScheme);
  facScheme.verify = async (p: PaymentPayload, r: PaymentRequirements) => {
    const v = await verify(p, r);
    verdicts.push(v);
    return v;
  };
  const facilitator = new x402Facilitator().register(NETWORK, facScheme);
  const fapp = express();
  fapp.use(express.json());
  fapp.get("/supported", (_q, s) => {
    s.json(facilitator.getSupported());
  });
  fapp.post("/verify", async (q, s) => {
    s.json(await facilitator.verify(q.body.paymentPayload, q.body.paymentRequirements));
  });
  fapp.post("/settle", async (q, s) => {
    s.json(await facilitator.settle(q.body.paymentPayload, q.body.paymentRequirements));
  });
  const fsrv = await listen(fapp, 4022);

  const option = (amount: bigint) => ({ scheme: "bounded", network: NETWORK, payTo: payee, price: { amount: amount.toString(), asset: token } });
  const rs = new x402ResourceServer(new HTTPFacilitatorClient({ url: "http://127.0.0.1:4022" })).register(
    NETWORK,
    new BoundedEvmServer({ reserve, asset: token, decimals: 6 }),
  );
  const app = express();
  app.use(
    paymentMiddleware(
      {
        "GET /data": { accepts: option(10_000n), description: "one record", mimeType: "application/json" },
        "GET /dear": { accepts: option(60_000n), description: "priced above the cap", mimeType: "application/json" },
      },
      rs,
    ),
  );
  app.get("/data", (_q, s) => {
    s.json({ record: 42 });
  });
  app.get("/dear", (_q, s) => {
    s.json({ record: 43 });
  });
  const srv = await listen(app, 4021);

  const delegations = new Map([[reserve, id]]);
  const source = new DemoSource();
  const controls = { allowedAssets: [{ network: NETWORK, asset: token, maxAmountPerPayment: "100000" }] };
  const client = new x402Client()
    .register("eip155:*", new BoundedEvmClient(agent, chain, delegations, source))
    .setSpendControls(controls);
  const pay = wrapFetchWithPayment(fetch, client);
  const balance = (who: Hex) => chain.readContract({ address: token, abi: tokenAbi, functionName: "balanceOf", args: [who] }) as Promise<bigint>;
  const gas: bigint[] = [];

  async function paid(path: string) {
    const r = await pay(`http://127.0.0.1:4021${path}`);
    const header = r.headers.get("PAYMENT-RESPONSE");
    const settle = header ? decodePaymentResponseHeader(header) : undefined;
    if (settle?.success) gas.push((await chain.getTransactionReceipt({ hash: settle.transaction as Hex })).gasUsed);
    await r.text();
    return { status: r.status, settle };
  }
  const lastReason = () => verdicts.at(-1)?.invalidMessage ?? verdicts.at(-1)?.invalidReason ?? "";

  const b0 = await balance(payee);
  const r0 = await balance(reserve);
  const first = await Promise.all([0, 1, 2].map(() => paid("/data")));
  check("three paid requests through the facilitator, each served", first.every((x) => x.status === 200 && x.settle?.success === true));
  check("payee paid 3 x 10,000 from the reserve's deposit", (await balance(payee)) - b0 === 30_000n && r0 - (await balance(reserve)) === 30_000n);

  const before = await balance(payee);
  const dear = await paid("/dear");
  check("a price above the public cap refused before any transaction", dear.status === 402 && (await balance(payee)) === before, lastReason());

  const url = "http://127.0.0.1:4021/data";
  const req402 = await fetch(url);
  const required = decodePaymentRequiredHeader(req402.headers.get("PAYMENT-REQUIRED") ?? "");
  await req402.text();
  const payment = await client.createPaymentPayload(required);
  const header = encodePaymentSignatureHeader(payment);
  const once = await fetch(url, { headers: { "PAYMENT-SIGNATURE": header } });
  await once.text();
  const b1 = await balance(payee);
  const twice = await fetch(url, { headers: { "PAYMENT-SIGNATURE": header } });
  await twice.text();
  check("the same signed payment, sent twice, settles once", once.status === 200 && twice.status === 402 && (await balance(payee)) === b1, lastReason());

  const forged = new x402Client()
    .register("eip155:*", new BoundedEvmClient(privateKeyToAccount(KEYS.stranger), chain, delegations, source))
    .setSpendControls(controls);
  const f = await wrapFetchWithPayment(fetch, forged)(url);
  await f.text();
  check("a payment signed by anyone but the agent refused", f.status === 402 && (await balance(payee)) === b1, lastReason());

  const fifth = await paid("/data");
  check("the fifth payment of the window settles", fifth.status === 200);
  const sixth = await paid("/data");
  check("the sixth, past the public rate limit, refused", sixth.status === 402, lastReason());

  await chain.request({ method: "evm_increaseTime" as never, params: [86_401] as never });
  await chain.request({ method: "evm_mine" as never, params: [] as never });
  const next = await paid("/data");
  check("a new rate window settles again", next.status === 200);
  await send(await principal.writeContract({ address: reserve, abi: reserveFull, functionName: "freeze", args: [id] }));
  const frozen = await paid("/data");
  check("after the principal's freeze, refused", frozen.status === 402, lastReason());

  srv.close();
  fsrv.close();
  const settled = gas.length;
  console.log("x402 BOUNDED SCHEME, END TO END ON A LOCAL CHAIN");
  console.log("=".repeat(78));
  console.log(`  @x402/core, @x402/express, @x402/fetch 2.28.0; network ${NETWORK}`);
  console.log(`  reserve ${reserve}, delegation ${id}, cap ${CAP}, ${RATE} payments a day, unit ${UNIT}`);
  for (const l of lines) console.log(l);
  console.log(`  settlements ${settled}, gas each: ${gas.map((g) => g.toLocaleString("en-US")).join(", ")}`);
  console.log(`  ${failures === 0 ? "all checks pass" : `${failures} checks fail`}`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
