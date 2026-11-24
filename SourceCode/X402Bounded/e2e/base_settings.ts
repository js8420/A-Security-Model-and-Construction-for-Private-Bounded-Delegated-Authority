// Base's fee settings as its newest block header carries them, read from
// mainnet, and the monitor's verdict on them at the deployed factor and floor.
// Usage: tsx e2e/base_settings.ts RPC_URL
import { createPublicClient, http } from "viem";
import { base } from "viem/chains";
import { feeSettingsRefusal, headerFeeSettings, type HeaderReader } from "../src/monitor.js";

const TESTED_RISE = 0.0202;
const L2_FACTOR = 4n;
const L2_FEE_FLOOR = 10_000_000n;

const url = process.argv[2];
if (!url) throw new Error("usage: tsx e2e/base_settings.ts RPC_URL");
const chain = createPublicClient({ chain: base, transport: http(url) });
const top = await chain.getBlock();
const s = await headerFeeSettings(chain as unknown as HeaderReader);
if (!s) throw new Error(`block ${top.number} carries no fee settings: extra data ${top.extraData}`);
const rise = Math.pow(1 + (s.elasticity - 1) / s.denominator, s.blocksPerSecond) - 1;
const why = feeSettingsRefusal(s, TESTED_RISE, L2_FACTOR, L2_FEE_FLOOR);
console.log("BASE FEE SETTINGS FROM THE NEWEST HEADER");
console.log("=".repeat(78));
console.log(`  block ${top.number}, extra data ${top.extraData}`);
console.log(`  denominator ${s.denominator}, elasticity ${s.elasticity}, minimum base fee ${s.minBaseFee} wei`);
console.log(`  blocks a second over the last 300 blocks ${s.blocksPerSecond.toFixed(3)}`);
console.log(`  fastest rise a second ${(100 * rise).toFixed(3)}%, tested ${(100 * TESTED_RISE).toFixed(2)}%`);
console.log(`  verdict: ${why === "" ? "within what the factors were tested on" : why}`);
