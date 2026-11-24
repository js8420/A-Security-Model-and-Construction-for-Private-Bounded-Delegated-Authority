// How far Base's safe and finalized heads trail its newest block, sampled
// from mainnet: the wait of a payee whose facilitator waits for either head.
// Usage: tsx e2e/safe_lag.ts RPC_URL MINUTES SECONDS_BETWEEN_SAMPLES
import { createPublicClient, http } from "viem";
import { base } from "viem/chains";

const [url, minutes, every] = [process.argv[2], Number(process.argv[3] ?? 60), Number(process.argv[4] ?? 30)];
if (!url) throw new Error("usage: tsx e2e/safe_lag.ts RPC_URL MINUTES SECONDS_BETWEEN_SAMPLES");
const chain = createPublicClient({ chain: base, transport: http(url, { retryCount: 5 }) });
const safe: number[] = [];
const final: number[] = [];
const end = Date.now() + minutes * 60_000;
let first = 0n;
let last = 0n;
while (Date.now() < end) {
  try {
    const [l, s, f] = await Promise.all([
      chain.getBlock({ blockTag: "latest" }),
      chain.getBlock({ blockTag: "safe" }),
      chain.getBlock({ blockTag: "finalized" }),
    ]);
    safe.push(Number(l.timestamp - s.timestamp));
    final.push(Number(l.timestamp - f.timestamp));
    if (first === 0n) first = l.number;
    last = l.number;
  } catch {
    // A sample the endpoint did not answer is skipped, not guessed.
  }
  await new Promise((ok) => setTimeout(ok, every * 1000));
}
const q = (xs: number[], p: number) => {
  const s = [...xs].sort((a, b) => a - b);
  return s[Math.min(s.length - 1, Math.floor(p * s.length))];
};
console.log("HOW FAR BASE'S SAFE AND FINALIZED HEADS TRAIL ITS NEWEST BLOCK, SECONDS");
console.log("=".repeat(78));
console.log(`  ${safe.length} samples every ${every} s over ${minutes} min, blocks ${first} to ${last}`);
for (const [name, xs] of [["safe", safe], ["finalized", final]] as const) {
  if (xs.length === 0) throw new Error("no sample answered");
  console.log(`  ${name.padEnd(10)} least ${Math.min(...xs)}, median ${q(xs, 0.5)}, 90th percentile ${q(xs, 0.9)}, 99th ${q(xs, 0.99)}, most ${Math.max(...xs)}`);
}
