"""How far the base fee rises after a challenge: for every block since the
Dencun upgrade, the largest base fee in the window that follows it divided by
the base fee at its start, on Ethereum and on Base, and the largest Ethereum
blob base fee in the posting window. The fee factor F is chosen from these.

  python3 fee_ratio.py fetch DATA_DIR      download, resumable; run again to continue
  python3 fee_ratio.py analyze DATA_DIR    print the distributions

Only block headers are read, through eth_feeHistory with no reward percentiles,
so a full node serves every block. The data are fixed once fetched, so one
analysis is the result. The first fetch fixes the last block and records it.
"""
import json
import math
import os
import sys
import time
import urllib.request
from array import array
from collections import deque
from concurrent.futures import ThreadPoolExecutor

START_TIME = 1710374400  # 2024-03-14 00:00 UTC, after Dencun on both chains
CHUNK = 1024
CHAINS = {
    "ethereum": {
        "rpcs": ["https://ethereum-rpc.publicnode.com", "https://eth.drpc.org", "https://eth.llamarpc.com", "https://1rpc.io/eth"],
        "block_seconds": 12,
        "blob": True,
    },
    "base": {
        "rpcs": ["https://base-rpc.publicnode.com", "https://mainnet.base.org", "https://base.drpc.org", "https://1rpc.io/base"],
        "block_seconds": 2,
        "blob": False,
    },
}
# Windows from the deployment: the answer window w_a for the bond, and the
# answer window plus the posting wait w_p for the deposit and the blobs.
W_A_HOURS = 32
W_POST_HOURS = 32 + 30
# One batch's postings as blobs: the proof file and 256 sealed openings, at
# 31 usable bytes in each of a blob's 4,096 field elements.
PROOF_FILE_BYTES = 10_365_547
OPENING_BYTES = 1_604
BATCH = 256
BLOB_USABLE = 31 * 4096
BLOB_GAS = 131_072


def rpc(urls, method, params, start=0):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    last = None
    for attempt in range(12):
        url = urls[(start + attempt) % len(urls)]
        try:
            req = urllib.request.Request(url, body, {"content-type": "application/json", "user-agent": "fee-ratio/1"})
            with urllib.request.urlopen(req, timeout=60) as r:
                out = json.loads(r.read())
            if "result" in out and out["result"] is not None:
                return out["result"]
            last = out.get("error")
        except Exception as e:
            last = e
        time.sleep(min(30, 2 ** attempt * 0.5))
    raise RuntimeError(f"{method} {params} failed on every endpoint: {last}")


def block_at(urls, t):
    """The first block whose timestamp is at least t."""
    hi = int(rpc(urls, "eth_blockNumber", []), 16)
    lo = 0
    while lo < hi:
        mid = (lo + hi) // 2
        ts = int(rpc(urls, "eth_getBlockByNumber", [hex(mid), False])["timestamp"], 16)
        if ts < t:
            lo = mid + 1
        else:
            hi = mid
    return lo


def paths(data, chain):
    d = os.path.join(data, chain)
    os.makedirs(d, exist_ok=True)
    return d, os.path.join(d, "meta.json")


def fetch(data):
    for chain, c in CHAINS.items():
        d, meta_path = paths(data, chain)
        if os.path.exists(meta_path):
            meta = json.load(open(meta_path))
        else:
            first = block_at(c["rpcs"], START_TIME)
            last = int(rpc(c["rpcs"], "eth_blockNumber", []), 16)
            meta = {"first": first, "last": last, "fixed_at": int(time.time())}
            json.dump(meta, open(meta_path, "w"))
        first, last = meta["first"], meta["last"]
        starts = list(range(first, last + 1, CHUNK))
        todo = [s for s in starts if not os.path.exists(os.path.join(d, f"{s}.json"))]
        print(f"{chain}: blocks {first:,} to {last:,}, {len(starts):,} chunks, {len(todo):,} left", flush=True)

        cap = [CHUNK]

        def one(job):
            i, s = job
            want = min(CHUNK, last - s + 1)
            got_fee, got_blob = [], []
            at = s
            while at < s + want:
                n = min(s + want - at, cap[0])
                r = rpc(c["rpcs"], "eth_feeHistory", [hex(n), hex(at + n - 1), []], start=i)
                oldest = int(r["oldestBlock"], 16)
                fees = [int(x, 16) for x in r["baseFeePerGas"]]
                count = len(fees) - 1
                if count < 1:
                    raise RuntimeError(f"{chain}: feeHistory at {at} returned no blocks")
                if oldest > at:
                    # The node serves fewer blocks a call than asked; ask for that many.
                    cap[0] = min(cap[0], count)
                    continue
                skip = at - oldest
                got_fee += fees[skip:count]
                if c["blob"]:
                    got_blob += [int(x, 16) for x in r.get("baseFeePerBlobGas", ["0x0"] * (count + 1))][skip:count]
                at = oldest + count
            if len(got_fee) != want or (c["blob"] and len(got_blob) != want):
                raise RuntimeError(f"{chain}: chunk {s} has {len(got_fee)} fees for {want} blocks")
            tmp = os.path.join(d, f"{s}.tmp")
            json.dump({"fee": got_fee, "blob": got_blob}, open(tmp, "w"))
            os.replace(tmp, os.path.join(d, f"{s}.json"))
            return s

        done = 0
        with ThreadPoolExecutor(max_workers=4) as pool:
            for _ in pool.map(one, enumerate(todo)):
                done += 1
                if done % 200 == 0 or done == len(todo):
                    print(f"  {chain}: {done:,} of {len(todo):,} chunks", flush=True)


def load(data, chain):
    d, meta_path = paths(data, chain)
    meta = json.load(open(meta_path))
    fee, blob = array("Q"), array("Q")
    for s in range(meta["first"], meta["last"] + 1, CHUNK):
        p = os.path.join(d, f"{s}.json")
        if not os.path.exists(p):
            raise SystemExit(f"{chain}: chunk {s} missing; run fetch again")
        j = json.load(open(p))
        fee.extend(j["fee"])
        blob.extend(j["blob"])
    if len(fee) != meta["last"] - meta["first"] + 1:
        raise SystemExit(f"{chain}: {len(fee)} fees for {meta['last'] - meta['first'] + 1} blocks")
    return meta, fee, blob


def window_max(x, w):
    """m[i] = max(x[i], ..., x[i + w]) for every i with i + w inside x."""
    out = array("Q", bytes(8 * max(0, len(x) - w)))
    q = deque()
    for j in range(len(x) - 1, -1, -1):
        v = x[j]
        while q and x[q[-1]] <= v:
            q.pop()
        q.append(j)
        if q[0] > j + w:
            q.popleft()
        if j + w < len(x):
            out[j] = x[q[0]]
    return out


BINS = 20000  # log10 of the ratio from 0 to 4 in steps of 0.0002, 0.05% wide


def ratio_stats(fee, w):
    m = window_max(fee, w)
    hist = [0] * (BINS + 1)
    n = 0
    top, top_at = 1.0, 0
    over = {2: 0, 3: 0, 5: 0, 10: 0}
    for i in range(len(m)):
        f = fee[i]
        if f == 0:
            continue
        r = m[i] / f
        n += 1
        if r > top:
            top, top_at = r, i
        for k in over:
            if r > k:
                over[k] += 1
        b = min(BINS, int(math.log10(r) / 4 * BINS))
        hist[b] += 1
    def pct(p):
        target, run = p / 100 * n, 0
        for b, h in enumerate(hist):
            run += h
            if run >= target:
                return min(top, 10 ** ((b + 1) * 4 / BINS))
        return top
    return n, top, top_at, over, {p: pct(p) for p in (50, 90, 99, 99.9, 99.99)}, hist


def smallest_factor(hist, n, share):
    """The smallest F, to bin precision, with at most this share of windows above it."""
    run = 0
    for b, h in enumerate(hist):
        run += h
        if n - run <= share * n:
            return 10 ** ((b + 1) * 4 / BINS)
    return float("inf")


def analyze(data):
    print("HOW FAR THE BASE FEE RISES AFTER A CHALLENGE, SINCE DENCUN")
    print("=" * 78)
    for chain, c in CHAINS.items():
        meta, fee, blob = load(data, chain)
        print(f"  {chain}: blocks {meta['first']:,} to {meta['last']:,}, {len(fee):,} blocks, fixed at {time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime(meta['fixed_at']))}")
        windows = [("answer window w_a", W_A_HOURS), ("answer window plus posting wait", W_POST_HOURS)]
        for label, hours in windows:
            w = math.ceil(hours * 3600 / c["block_seconds"])
            n, top, top_at, over, pcts, hist = ratio_stats(fee, w)
            print(f"  {chain}, {label}, {hours} h = {w:,} blocks; {n:,} windows")
            print("    largest fee in the window over the fee at its start:")
            print("    " + "  ".join(f"p{p:g} {v:.3f}" for p, v in pcts.items()) + f"  max {top:.3f} at block {meta['first'] + top_at:,}")
            print("    share of windows above F:  " + "  ".join(f"{k}x {over[k] / n:.6f}" for k in over))
            print("    smallest F exceeded by at most 1e-2, 1e-3, 1e-4 of windows:  " + "  ".join(f"{smallest_factor(hist, n, s):.3f}" for s in (1e-2, 1e-3, 1e-4)))
        if c["blob"]:
            w = math.ceil(W_POST_HOURS * 3600 / c["block_seconds"])
            m = window_max(blob, w)
            blobs = math.ceil(PROOF_FILE_BYTES / BLOB_USABLE) + math.ceil(BATCH * OPENING_BYTES / BLOB_USABLE)
            vals = sorted(m)
            def q(p):
                return vals[min(len(vals) - 1, int(p / 100 * len(vals)))]
            print(f"  ethereum blob base fee, highest within {W_POST_HOURS} h of each block, wei; {len(vals):,} windows")
            print("    " + "  ".join(f"p{p:g} {q(p):,}" for p in (50, 90, 99, 99.9)) + f"  max {vals[-1]:,}")
            print(f"  one batch as blobs: {blobs} blobs ({PROOF_FILE_BYTES:,} proof bytes and {BATCH} openings of {OPENING_BYTES:,}), blob gas {blobs * BLOB_GAS:,}")
            print("    blob fee for the batch at those quantiles, ETH: " + "  ".join(f"p{p:g} {q(p) * blobs * BLOB_GAS / 1e18:.3g}" for p in (50, 90, 99, 99.9)) + f"  max {vals[-1] * blobs * BLOB_GAS / 1e18:.3g}")
        print()


if __name__ == "__main__":
    if len(sys.argv) != 3 or sys.argv[1] not in ("fetch", "analyze"):
        raise SystemExit(__doc__)
    (fetch if sys.argv[1] == "fetch" else analyze)(sys.argv[2])
