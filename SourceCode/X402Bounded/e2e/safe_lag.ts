// How far Base's safe and finalized heads trail its newest block, sampled
// from mainnet: the wait of a payee whose facilitator waits for either head.
// Each sample is appended to FILE as it is taken, so a run cut short by a
// restart is continued by running it again, and the summary covers every
// sample the file holds.
// Usage: tsx e2e/safe_lag.ts RPC_URL MINUTES SECONDS_BETWEEN_SAMPLES FILE
import { appendFileSync, existsSync, readFileSync } from "node:fs";
import { createPublicClient, http } from "viem";
import { base } from "viem/chains";

const [url, minutes, every, file] = [process.argv[2], Number(process.argv[3] ?? 60), Number(process.argv[4] ?? 30), process.argv[5]];
if (!url || !file) throw new Error("usage: tsx e2e/safe_lag.ts RPC_URL MINUTES SECONDS_BETWEEN_SAMPLES FILE");
const chain = createPublicClient({ chain: base, transport: http(url, { retryCount: 5 }) });
const end = Date.now() + minutes * 60_000;
while (Date.now() < end) {
  try {
    const [l, s, f] = await Promise.all([
      chain.getBlock({ blockTag: "latest" }),
      chain.getBlock({ blockTag: "safe" }),
      chain.getBlock({ blockTag: "finalized" }),
    ]);
    appendFileSync(file, `${l.timestamp},${l.number},${l.timestamp - s.timestamp},${l.timestamp - f.timestamp}\n`);
  } catch {
    // A sample the endpoint did not answer is skipped, not guessed.
  }
  await new Promise((ok) => setTimeout(ok, every * 1000));
}
if (!existsSync(file)) throw new Error("no sample answered");
const rows = readFileSync(file, "utf8").trim().split("\n").map((x) => x.split(",").map(Number));
const safe = rows.map((r) => r[2]);
const final = rows.map((r) => r[3]);
const q = (xs: number[], p: number) => {
  const s = [...xs].sort((a, b) => a - b);
  return s[Math.min(s.length - 1, Math.floor(p * s.length))];
};
const hours = (rows[rows.length - 1][0] - rows[0][0]) / 3600;
console.log("HOW FAR BASE'S SAFE AND FINALIZED HEADS TRAIL ITS NEWEST BLOCK, SECONDS");
console.log("=".repeat(78));
console.log(`  ${rows.length} samples over ${hours.toFixed(1)} h, blocks ${rows[0][1]} to ${rows[rows.length - 1][1]}`);
for (const [name, xs] of [["safe", safe], ["finalized", final]] as const) {
  console.log(`  ${name.padEnd(10)} least ${Math.min(...xs)}, median ${q(xs, 0.5)}, 90th ${q(xs, 0.9)}, 99th ${q(xs, 0.99)}, 99.9th ${q(xs, 0.999)}, most ${Math.max(...xs)}`);
}
