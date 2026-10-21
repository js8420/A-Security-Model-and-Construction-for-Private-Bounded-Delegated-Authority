"""What posting a batch proof on chain costs on Base, in ether and dollars.

The gas and the call data are those of the postProof transactions in a
receipts file of ValidityDisputeOnChain. Base charges each transaction its
execution gas at the base fee plus an L1 data fee, which its gas price oracle
quotes from the transaction's size; a proof is incompressible, so the oracle's
upper bound for that size is the fee. The base fee is the median over the last
1,024 blocks, and the dollar price is Chainlink's ETH / USD feed on Base. The
same is printed for one answer, so the two can be set against the bounty.

Run: python3 posting_cost.py RECEIPTS_JSON
Env: L2_RPC (one endpoint, tried first).
"""
import json
import os
import statistics
import subprocess
import sys
import time

RPCS = ["https://base-rpc.publicnode.com", "https://mainnet.base.org", "https://base.drpc.org", "https://1rpc.io/base"]
ORACLE = "0x420000000000000000000000000000000000000F"
ETH_USD = "0x71041dddad3595F9CEd3DcCFBe3D1F4b0a16Bb70"
# An EIP-1559 transaction's envelope beyond its call data: chain id, nonce,
# fees, gas, recipient, value, an empty access list and the signature.
ENVELOPE = 110


class Refused(Exception):
    pass


def cast(*args):
    r = subprocess.run(["cast", *args], capture_output=True, text=True, timeout=120)
    if r.returncode != 0:
        raise Refused(r.stderr.strip().splitlines()[-1] if r.stderr.strip() else f"exit {r.returncode}")
    return r.stdout.strip()


def endpoint():
    tried = []
    for url in ([os.environ["L2_RPC"]] if os.environ.get("L2_RPC") else []) + RPCS:
        try:
            if "ETH / USD" not in cast("call", "--rpc-url", url, ETH_USD, "description()(string)"):
                raise Refused("not the ETH / USD feed")
            json.loads(cast("rpc", "--rpc-url", url, "eth_feeHistory", "0x400", "latest", "[]"))
            return url
        except Refused as e:
            tried.append(f"{url}: {e}")
    raise SystemExit("no Base endpoint served every call:\n  " + "\n  ".join(tried))


def first(out):
    return int(out.split()[0])


def main():
    receipts = json.load(open(sys.argv[1]))
    posted, answer = [], None
    for t, r in zip(receipts["transactions"], receipts["receipts"]):
        name = (t["function"] or "").split("(")[0]
        data = t["transaction"].get("input") or t["transaction"].get("data")
        size = (len(data) - 2) // 2
        if name == "postProof":
            posted.append((int(r["gasUsed"], 16), size))
        elif name == "answer" and answer is None:
            answer = (int(r["gasUsed"], 16), size)
    url = endpoint()
    history = json.loads(cast("rpc", "--rpc-url", url, "eth_feeHistory", "0x400", "latest", "[]"))
    fees = [int(x, 16) for x in history["baseFeePerGas"]]
    base = statistics.median(fees)
    block = int(history["oldestBlock"], 16) + len(fees) - 1
    price = first(cast("call", "--rpc-url", url, ETH_USD, "latestAnswer()(int256)")) / 1e8

    def cost(txs):
        execution = sum(g for g, _ in txs) * base
        data = sum(first(cast("call", "--rpc-url", url, ORACLE, "getL1FeeUpperBound(uint256)(uint256)",
                              str(s + ENVELOPE))) for _, s in txs)
        return execution / 1e18, data / 1e18

    print("POSTING A BATCH PROOF ON BASE")
    print("=" * 78)
    print(f"  {time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime())}, Base block {block}, endpoint {url}")
    print(f"  base fee, median of the last {len(fees)} blocks  {base / 1e9:>14.6f} gwei")
    print(f"  base fee, least and greatest            {min(fees) / 1e9:>10.6f} {max(fees) / 1e9:>10.6f} gwei")
    print(f"  ETH / USD, Chainlink on Base            {price:>14.2f}")
    print()
    for label, txs in (("proof, all chunks", posted), ("one answer", [answer])):
        e, d = cost(txs)
        print(f"  {label:<20} {len(txs):>3} tx  {sum(g for g, _ in txs):>12,} gas  {sum(s for _, s in txs):>10,} bytes")
        print(f"  {'':<20} execution {e:.8f} ETH, L1 data {d:.8f} ETH, total {e + d:.8f} ETH = {(e + d) * price:.2f} USD")


if __name__ == "__main__":
    main()
