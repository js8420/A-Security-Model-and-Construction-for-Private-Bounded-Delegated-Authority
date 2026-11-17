import type { Address, Hex } from "viem";

/**
 * The published build of Reserve.sol, as its compiler output gives it: the
 * runtime code, and where in it the deployment's own values sit. Those
 * immutables (the domain, the token, the Permit2 contract, the Poseidon2
 * contract, the deployer, the age bound and the close delay) differ from one
 * deployment to the next; everything else is the same code byte for byte,
 * the compiler's metadata hash at its end included.
 */
export interface PublishedBuild {
  object: Hex;
  immutableReferences: Record<string, readonly { start: number; length: number }[]>;
}

/** What a facilitator accepts a reserve as: the published build, under the canonical Permit2. */
export interface GenuineReserve {
  build: PublishedBuild;
  permit2: Address;
}

/** The build as forge writes it, from the artifact's JSON. */
export function publishedBuild(artifact: { deployedBytecode: { object: string; immutableReferences?: PublishedBuild["immutableReferences"] } }): PublishedBuild {
  const object = (artifact.deployedBytecode.object.startsWith("0x") ? artifact.deployedBytecode.object : `0x${artifact.deployedBytecode.object}`) as Hex;
  return { object: object.toLowerCase() as Hex, immutableReferences: artifact.deployedBytecode.immutableReferences ?? {} };
}

/** The code with every immutable's bytes set to zero. */
function masked(code: Hex, refs: PublishedBuild["immutableReferences"]): string {
  const hex = code.toLowerCase().slice(2).split("");
  for (const list of Object.values(refs)) {
    for (const { start, length } of list) {
      for (let i = 2 * start; i < 2 * (start + length) && i < hex.length; i++) hex[i] = "0";
    }
  }
  return hex.join("");
}

/** Whether deployed runtime code is the published build, its immutables aside. */
export function sameBuild(deployed: Hex, build: PublishedBuild): boolean {
  if (deployed.length !== build.object.length) return false;
  return masked(deployed, build.immutableReferences) === masked(build.object, build.immutableReferences);
}

/**
 * What a principal checks before it opens a delegation: that the reserve,
 * its dispute contract, the posting contract and the Poseidon2 contract are
 * the published builds, wired to each other, and that every value the
 * deployment fixed is the one it publishes: for the reserve the domain, the
 * token, the Permit2 contract, the age bound and the close delay; for the
 * dispute contract the verifier, the program key, the windows, the slot, the
 * proving bond and cost, the forcing gas and the fee factors and floors; for
 * the posting contract the posting gas and bytes, its factor and floor, the
 * messenger, the inclusion wait and the BlobPosting address. A facilitator
 * needs less, because a payee is protected by the money moving: the build,
 * the token and the Permit2 contract.
 */
export interface Deployment {
  builds: { reserve: PublishedBuild; dispute: PublishedBuild; postings: PublishedBuild; poseidon: PublishedBuild };
  reserve: Record<string, bigint | Hex>;
  dispute: Record<string, bigint | Hex>;
  postings: Record<string, bigint | Hex>;
}

interface Reader {
  getCode(a: { address: Address }): Promise<Hex | undefined>;
  readContract(a: { address: Address; abi: readonly unknown[]; functionName: string }): Promise<unknown>;
}

const word = (name: string) => [{ type: "function", name, stateMutability: "view", inputs: [], outputs: [{ type: "uint256" }] }] as const;

/** Why the deployment behind a reserve is not the one published, or "" if it is. */
export async function deploymentRefusal(chain: Reader, reserve: Address, d: Deployment): Promise<string> {
  const read = async (address: Address, name: string) => (await chain.readContract({ address, abi: word(name), functionName: name })) as bigint;
  const addr = (v: bigint) => `0x${v.toString(16).padStart(40, "0")}` as Address;
  const check = async (what: string, at: Address, build: PublishedBuild, values: Record<string, bigint | Hex>): Promise<string> => {
    const code = await chain.getCode({ address: at });
    if (!code || !sameBuild(code, build)) return `the ${what} at ${at} is not the published build`;
    for (const [name, want] of Object.entries(values)) {
      const have = await read(at, name);
      if (have !== BigInt(want)) return `the ${what}'s ${name} is ${have}, not ${BigInt(want)}`;
    }
    return "";
  };
  let why = await check("reserve", reserve, d.builds.reserve, d.reserve);
  if (why) return why;
  const dispute = addr(await read(reserve, "dispute"));
  why = await check("dispute contract", dispute, d.builds.dispute, d.dispute);
  if (why) return why;
  if ((await read(dispute, "reserve")) !== BigInt(reserve)) return "the dispute contract answers for another reserve";
  const postings = addr(await read(dispute, "postings"));
  why = await check("posting contract", postings, d.builds.postings, d.postings);
  if (why) return why;
  if ((await read(postings, "dispute")) !== BigInt(dispute) || (await read(postings, "reserve")) !== BigInt(reserve)) return "the posting contract is wired to other contracts";
  return check("Poseidon2 contract", addr(await read(reserve, "poseidon")), d.builds.poseidon, {});
}
