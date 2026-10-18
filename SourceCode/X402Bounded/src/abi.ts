import { parseAbi } from "viem";

/** The calls of Reserve.sol the scheme makes, and the errors it can revert with. */
export const reserveAbi = parseAbi([
  "function settleLogged(uint256 id, address payee, uint64 amount, uint64 digest, uint64 time, uint64[] elems, bytes signature)",
  "function signedDigest(uint256 id, address payee, uint64 amount, uint64 digest, uint64 time, bytes32 elemsHash) view returns (bytes32)",
  "function agentOf(uint256 id) view returns (address)",
  "function token() view returns (address)",
  "function frozenOf(uint256 id) view returns (bool frozen, uint32 holds)",
  "event Settled(uint256 indexed id, uint64 digest, uint64 amount, address payee)",
  "error IndexAlreadySettled()",
  "error AmountAboveCap()",
  "error BadSignature()",
  "error VelocityExceeded()",
  "error DepositExhausted()",
  "error StaleTime()",
  "error Expired()",
  "error Frozen()",
  "error Held()",
  "error WrongSlotCount()",
]);
