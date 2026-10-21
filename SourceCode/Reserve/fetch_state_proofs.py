"""Real proofs for the cross-domain read of test/StateRead.sol: an Ethereum
block header, an account and storage proof on Ethereum under it, and on Base
the state root, the message passer's storage root, the block hash, and an
account and storage proof under that state root. Each storage slot is the
first non-zero one among the account's first 64.

The Ethereum account is Base's dispute game factory, read from its portal,
which stands for the contract that holds Base's output roots; the Base
account is USDC, the token x402 settles. Both can be overridden.

Public endpoints differ in which calls they serve, eth_getProof above all,
so each chain's endpoints are tried in turn until one serves every call.

Run: python3 fetch_state_proofs.py OUT_DIR
Env: L1_RPC, L2_RPC (one endpoint each, tried first), L1_ACCOUNT, L2_ACCOUNT.
"""
import json
import os
import subprocess
import sys

L1_RPCS = ["https://ethereum-rpc.publicnode.com", "https://eth.drpc.org", "https://eth.llamarpc.com", "https://1rpc.io/eth"]
L2_RPCS = ["https://base-rpc.publicnode.com", "https://mainnet.base.org", "https://base.drpc.org", "https://base.llamarpc.com", "https://1rpc.io/base"]
PORTAL = "0x49048044D57e1C92A77f79988d21Fa8fAF74E97e"
USDC = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
MESSAGE_PASSER = "0x4200000000000000000000000000000000000016"
HEADER = ["parentHash", "sha3Uncles", "miner", "stateRoot", "transactionsRoot", "receiptsRoot", "logsBloom",
          "difficulty", "number", "gasLimit", "gasUsed", "timestamp", "extraData", "mixHash", "nonce",
          "baseFeePerGas", "withdrawalsRoot", "blobGasUsed", "excessBlobGas", "parentBeaconBlockRoot", "requestsHash"]
QUANTITIES = {"difficulty", "number", "gasLimit", "gasUsed", "timestamp", "baseFeePerGas", "blobGasUsed", "excessBlobGas"}


class Refused(Exception):
    pass


def cast(*args):
    r = subprocess.run(["cast", *args], capture_output=True, text=True, timeout=120)
    if r.returncode != 0:
        raise Refused(r.stderr.strip().splitlines()[-1] if r.stderr.strip() else f"exit {r.returncode}")
    return r.stdout.strip()


def rpc(url, method, *params):
    return json.loads(cast("rpc", "--rpc-url", url, method, *[json.dumps(p) if not isinstance(p, str) else p for p in params]))


def rlp(x):
    if isinstance(x, list):
        body = b"".join(rlp(i) for i in x)
        return length(len(body), 0xC0) + body
    if len(x) == 1 and x[0] < 0x80:
        return x
    return length(len(x), 0x80) + x


def length(n, offset):
    if n < 56:
        return bytes([offset + n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([offset + 55 + len(b)]) + b


def field(k, v):
    if k in QUANTITIES:
        n = int(v, 16)
        return n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    return bytes.fromhex(v[2:])


def slot_of(url, account, block):
    for i in range(64):
        k = "0x" + i.to_bytes(32, "big").hex()
        v = rpc(url, "eth_getStorageAt", account, k, block)
        if int(v, 16) != 0:
            return k, "0x" + int(v, 16).to_bytes(32, "big").hex()
    raise SystemExit(f"no non-zero slot among the first 64 of {account}")


def proof(url, account, block):
    k, v = slot_of(url, account, block)
    p = rpc(url, "eth_getProof", account, [k], block)
    return {"address": account, "accountProof": p["accountProof"], "slot": k,
            "storageProof": p["storageProof"][0]["proof"], "value": v}, p


def ethereum(url, account):
    n = int(cast("block-number", "--rpc-url", url)) - 2
    b = rpc(url, "eth_getBlockByNumber", hex(n), False)
    header = rlp([field(k, b[k]) for k in HEADER if k in b])
    d, _ = proof(url, account, hex(n))
    d.update({"block": n, "blockHash": b["hash"], "header": "0x" + header.hex()})
    return d


def base(url, account):
    n = int(cast("block-number", "--rpc-url", url)) - 2
    b = rpc(url, "eth_getBlockByNumber", hex(n), False)
    d, _ = proof(url, account, hex(n))
    mp = rpc(url, "eth_getProof", MESSAGE_PASSER, [], hex(n))
    d.update({"block": n, "blockHash": b["hash"], "stateRoot": b["stateRoot"], "messagePasserRoot": mp["storageHash"]})
    return d


def first(name, urls, fetch):
    for url in urls:
        try:
            d = fetch(url)
            d["rpc"] = url
            return d
        except (Refused, subprocess.TimeoutExpired, KeyError, ValueError) as e:
            print(f"  {name}: {url} refused: {e}")
    raise SystemExit(f"no {name} endpoint served every call")


def main(out):
    os.makedirs(out, exist_ok=True)
    l1_urls = [u for u in [os.environ.get("L1_RPC")] if u] + L1_RPCS
    l2_urls = [u for u in [os.environ.get("L2_RPC")] if u] + L2_RPCS
    l1_account = os.environ.get("L1_ACCOUNT")
    if not l1_account:
        l1_account = first("Ethereum", l1_urls, lambda u: {"a": cast("call", "--rpc-url", u, PORTAL, "disputeGameFactory()(address)")})["a"]
    l2_account = os.environ.get("L2_ACCOUNT", USDC)
    l1 = first("Ethereum", l1_urls, lambda u: ethereum(u, l1_account))
    l2 = first("Base", l2_urls, lambda u: base(u, l2_account))
    for name, d in (("l1", l1), ("l2", l2)):
        json.dump(d, open(f"{out}/{name}.json", "w"), indent=1)
    print(f"Ethereum block {l1['block']} from {l1['rpc']}, account {l1_account}, slot {l1['slot']}: {len(l1['accountProof'])} account and {len(l1['storageProof'])} storage nodes")
    print(f"Base block {l2['block']} from {l2['rpc']}, account {l2_account}, slot {l2['slot']}: {len(l2['accountProof'])} account and {len(l2['storageProof'])} storage nodes")


if __name__ == "__main__":
    main(sys.argv[1])
