// Base's fee settings as its newest block carries them, read from mainnet:
// the EIP-1559 settings and minimum base fee in the header's extra data, the
// block gas limit, and the data-fee scalars, operator fee and DA footprint
// scalar in the L1Block predeploy; and the monitor's verdict at the deployed
// factor, floor and largest dispute transaction. The predeploy's values are
// the ones the deployment records as measured under.
// Usage: tsx e2e/base_settings.ts RPC_URL
import { createPublicClient, http, type PublicClient } from "viem";
import { base } from "viem/chains";
import { feeSettingsRefusal, headerFeeSettings, l1BlockCosts, maxRise, type HeaderReader } from "../src/monitor.js";

const TESTED_RISE = 0.0202;
const L2_FACTOR = 4n;
const L2_FEE_FLOOR = 10_000_000n;
/** The batch answer of a whole batch, the largest transaction a dispute was measured to need. */
const MIN_GAS_LIMIT = 14_485_897n;

const url = process.argv[2];
if (!url) throw new Error("usage: tsx e2e/base_settings.ts RPC_URL");
const chain = createPublicClient({ chain: base, transport: http(url) }) as PublicClient;
const top = await chain.getBlock();
const s = await headerFeeSettings(chain as unknown as HeaderReader);
if (!s) throw new Error(`block ${top.number} carries no fee settings: extra data ${top.extraData}`);
const costs = await l1BlockCosts(chain);
if (costs.baseFeeScalar === 0n || costs.blobBaseFeeScalar === 0n) throw new Error("the L1Block predeploy returned no data-fee scalars");
const why = feeSettingsRefusal({ ...s, costs }, TESTED_RISE, L2_FACTOR, L2_FEE_FLOOR, { minGasLimit: MIN_GAS_LIMIT, measuredCosts: costs });
console.log("BASE FEE SETTINGS FROM THE NEWEST BLOCK");
console.log("=".repeat(78));
console.log(`  block ${top.number}, extra data ${top.extraData}`);
console.log(`  denominator ${s.denominator}, elasticity ${s.elasticity}, minimum base fee ${s.minBaseFee} wei`);
console.log(`  blocks a second over the last 300 blocks ${s.blocksPerSecond.toFixed(3)}`);
console.log(`  fastest rise a second ${(100 * maxRise(s)).toFixed(3)}%, tested ${(100 * TESTED_RISE).toFixed(2)}%`);
console.log(`  block gas limit ${s.gasLimit}, largest dispute transaction ${MIN_GAS_LIMIT}`);
console.log(`  L1Block: base fee scalar ${costs.baseFeeScalar}, blob base fee scalar ${costs.blobBaseFeeScalar},`);
console.log(`           operator fee scalar ${costs.operatorFeeScalar}, operator fee constant ${costs.operatorFeeConstant}, DA footprint gas scalar ${costs.daFootprintGasScalar}`);
console.log(`  verdict: ${why === "" ? "within what the factors were tested on" : why}`);
