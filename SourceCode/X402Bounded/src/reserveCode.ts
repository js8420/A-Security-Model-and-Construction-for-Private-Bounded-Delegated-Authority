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
