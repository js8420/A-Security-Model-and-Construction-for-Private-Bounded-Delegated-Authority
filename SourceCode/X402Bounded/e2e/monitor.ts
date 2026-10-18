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
  type Hex,
  type PublicClient,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { BudgetMonitor, reserveAbi, type Domain } from "../src/index.js";

const OUT = fileURLToPath(new URL("../../Reserve/out/", import.meta.url));
const KEYS = {
  principal: "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
  agent: "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
  sender: "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a",
  payee: "0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6",
} as const;
const UNIT = 10_000n;
const BUDGET = 50_000n;
const P = 0xffffffff00000001n;

function artifact(file: string, name: string): { abi: Abi; bytecode: Hex } {
  const j = JSON.parse(readFileSync(`${OUT}${file}/${name}.json`, "utf8"));
  return { abi: j.abi, bytecode: j.bytecode.object };
}

const agent = privateKeyToAccount(KEYS.agent);
const payee = privateKeyToAccount(KEYS.payee).address;

async function domain(name: string, rpc: string, chainId: number, domainId: bigint) {
  const chainDef = defineChain({ id: chainId, name, nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 }, rpcUrls: { default: { http: [rpc] } } });
  const chain = createPublicClient({ chain: chainDef, transport: http(rpc) }) as PublicClient;
  const principal = createWalletClient({ account: privateKeyToAccount(KEYS.principal), chain: chainDef, transport: http(rpc) });
  const sender = createWalletClient({ account: privateKeyToAccount(KEYS.sender), chain: chainDef, transport: http(rpc) });
  const deploy = async (file: string, cname: string, args: unknown[] = []) => {
    const a = artifact(file, cname);
    const r = await chain.waitForTransactionReceipt({ hash: await principal.deployContract({ abi: a.abi, bytecode: a.bytecode, args }) });
    if (!r.contractAddress) throw new Error(`deploy ${cname}`);
    return r.contractAddress;
  };
  const token = await deploy("MockToken.sol", "MockToken");
  const poseidon = await deploy("Poseidon2Goldilocks.sol", "Poseidon2Goldilocks");
  const reserve = await deploy("Reserve.sol", "Reserve", [domainId, token, "0x0000000000000000000000000000000000000000", poseidon, 3600n, 2n * 86400n]);
  const tokenAbi = artifact("MockToken.sol", "MockToken").abi;
  const done = async (h: Hex) => chain.waitForTransactionReceipt({ hash: h });
  await done(await principal.writeContract({ address: token, abi: tokenAbi, functionName: "mint", args: [principal.account.address, 10_000_000n] }));
  await done(await principal.writeContract({ address: token, abi: tokenAbi, functionName: "approve", args: [reserve, 2n ** 256n - 1n] }));
  const now = (await chain.getBlock()).timestamp;
  const terms = {
    agent: agent.address, cap: 50_000n, velocityN: 10n, windowW: 86_400n,
    secretHash: keccak256("0x01"), funding: 0, deposit: 1_000_000n,
    commitment: keccak256("0x02"), revocationRoot: keccak256("0x03"), expiry: now + 30n * 86_400n,
    unitSize: UNIT, rangeBase: 0n, rangeLen: 1024n,
    monitor: "0x0000000000000000000000000000000000000000", answerer: "0x0000000000000000000000000000000000000000",
  };
  await done(await principal.writeContract({ address: reserve, abi: artifact("Reserve.sol", "Reserve").abi, functionName: "register", args: [terms], value: parseEther("0.1") }));
  const d: Domain = { name, chain, wallet: principal, reserve, delegation: 0n };
  let next = 1_000n;
  /** One unit to the payee, signed by the agent and sent by a third party. */
  const settle = async (): Promise<string> => {
    const digest = next++;
    const elems = [0n, 1n, 2n].map((i) => BigInt(keccak256(encodePacked(["uint64", "uint64"], [digest, i]))) % P);
    const time = (await chain.getBlock()).timestamp;
    const hash = await chain.readContract({
      address: reserve, abi: reserveAbi, functionName: "signedDigest",
      args: [0n, payee, UNIT, digest, time, keccak256(encodePacked(["uint64[]"], [elems]))],
    });
    const signature = await agent.sign({ hash });
    try {
      const { request } = await chain.simulateContract({
        account: sender.account, address: reserve, abi: reserveAbi, functionName: "settleLogged",
        args: [0n, payee, UNIT, digest, time, elems, signature],
      });
      await done(await sender.writeContract(request));
      return "settled";
    } catch (e) {
      const m = String(e).match(/reverted with the following reason:\s*\n\s*(\w+)|Error: (\w+)\(\)/);
      return m ? (m[1] ?? m[2]) : "refused";
    }
  };
  return { d, settle };
}

async function main() {
  const a = await domain("domain A", process.env.RPC_A ?? "http://127.0.0.1:8545", 31337, 8453n);
  const b = await domain("domain B", process.env.RPC_B ?? "http://127.0.0.1:8546", 31338, 10n);
  const monitor = new BudgetMonitor([a.d, b.d], BUDGET);
  const lines: string[] = [];
  let failures = 0;
  const check = (name: string, ok: boolean, detail = "") => {
    lines.push(`  ${ok ? "PASS" : "FAIL"}  ${name}${detail ? `: ${detail}` : ""}`);
    if (!ok) failures += 1;
  };

  const plan = [a, b, a, b, a];
  let froze = false;
  for (const x of plan) {
    await x.settle();
    froze ||= (await monitor.poll()).froze;
  }
  check("five payments of 10,000 across two domains, total 50,000 = B, no freeze", !froze && monitor.total() === BUDGET);
  const sixth = await b.settle();
  const after = await monitor.poll();
  check("the sixth, on domain B, takes the total past B", sixth === "settled" && after.total === 60_000n);
  check("the monitor freezes the delegation on both domains", after.froze);
  const onA = await a.settle();
  const onB = await b.settle();
  check("a further payment on domain A refused", onA !== "settled", onA);
  check("a further payment on domain B refused", onB !== "settled", onB);

  console.log("BUDGET TRIPWIRE, TWO DOMAINS ON TWO LOCAL CHAINS");
  console.log("=".repeat(78));
  console.log(`  budget ${BUDGET}, unit ${UNIT}; no proof is read at any step`);
  for (const l of lines) console.log(l);
  console.log(`  spent past the budget before the freeze: ${after.total - BUDGET}`);
  console.log(`  ${failures === 0 ? "all checks pass" : `${failures} checks fail`}`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
