"""How far the base fee rises after a challenge: for every block since the
Dencun upgrade, the largest base fee in the window that follows it divided by
the base fee at its start, on Ethereum and on Base, and the largest Ethereum
blob base fee in the posting window. The fee factors are chosen from these.

  python3 fee_ratio.py fetch DATA_DIR      download, resumable; run again to continue
  python3 fee_ratio.py analyze DATA_DIR    print the distributions
  python3 fee_ratio.py floors DATA_DIR     the same with the fee at the challenge read
                                           no lower than a floor, to choose floors and factors
  python3 fee_ratio.py oos DATA_DIR        the deployed factors tested out of sample: fitted
                                           on the windows that start before July 2025 and
                                           tested on those after, in windows that do not overlap
  python3 fee_ratio.py blobs DATA_DIR [ETH_USD STAKE_USD BOUNTY_USD]
                                           how often, and by how much, posting a batch as blobs
                                           on Ethereum costs more than posting it on Base, and
                                           how often the excess is above the stake less the bounty
  python3 fee_ratio.py london DATA_DIR     the bond's factor on Ethereum from London to Dencun,
                                           August 2021 to March 2024, which fetch also downloads

Only block headers are read, through eth_feeHistory with no reward percentiles,
so a full node serves every block. The data are fixed once fetched, so one
analysis is the result. The first fetch fixes the last block and records it.
The oos and blobs modes also look up, once, the block at the split time and
the time of one Ethereum block in every 900, and record them in DATA_DIR.
"""
import heapq
import json
import math
import os
import re
import sys
import threading
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
    # Ethereum from the London upgrade, the first block with a base fee, to
    # the block before the Dencun-era data above begins.
    "ethereum_london": {
        "rpcs": ["https://ethereum-rpc.publicnode.com", "https://eth.drpc.org", "https://eth.llamarpc.com", "https://1rpc.io/eth"],
        "block_seconds": 12,
        "blob": False,
        "first": 12_965_000,
        "until": "ethereum",
    },
}
# Windows from the deployment: the answer window w_a for the bond, and the
# answer window plus the posting wait w_p for the deposit and the blobs.
W_A_HOURS = 32
W_POST_HOURS = 32 + 30
# What an answerer that sends when it can actually pays. It is ready t_ans
# after the challenge (the slowest Groth16 run with its setup, s9_batch_low_a,
# 9,697.7 s) and may send in any block until its deadline. Through Ethereum the
# transaction must land there 12 h (the sequencing window) plus the clock bound
# chi = 12.5 h before the deadline on Base. Postings follow an answer by at
# most w_p = 30 h.
T_ANS_HOURS = 9697.7 / 3600
SEQ_HOURS = 12
CHI_HOURS = 12.5
W_P_HOURS = 30
# One batch's postings as blobs, as blobPayload lays them out: the proof
# file's length and the file, the count of sealed openings and each 349-byte
# opening after its 8-byte digest, then the end byte, at 31 usable bytes in
# each of a blob's 4,096 field elements.
PROOF_FILE_BYTES = 10_365_547
OPENING_BYTES = 349
BATCH = 256
BLOB_USABLE = 31 * 4096
BLOB_GAS = 131_072
PAYLOAD_BYTES = 4 + PROOF_FILE_BYTES + 4 + BATCH * (8 + OPENING_BYTES) + 1
# The proof's postings on Base: one transaction for each 96 KiB chunk.
CHUNKS = math.ceil(PROOF_FILE_BYTES / 98304)
# Blobs travel six to a transaction since Fusaka.
BLOBS_PER_TX = 6
# The domain records the Ethereum base fee of its L1 origin, which may lag
# the domain's clock by up to max_sequencer_drift, 1,800 s: 150 Ethereum
# blocks. The fee a bond is sized at may be that stale.
LAG_ETH = 1800 // 12
# Fit before this time, test after: 2025-07-01 00:00 UTC.
SPLIT_TIME = 1751328000
# One Ethereum block in this many has its time looked up, to place Ethereum
# blocks against Base's, whose blocks come every 2 s.
TIME_STEP = 7200


# A node that fails sits out for a while, so the threads keep to the nodes
# that answer instead of waiting on the ones that refuse.
_bench = {}
_bench_lock = threading.Lock()


def rpc(urls, method, params, start=0):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    last = None
    order = [urls[(start + k) % len(urls)] for k in range(len(urls))]
    for round_ in range(12):
        now = time.time()
        with _bench_lock:
            ready = [u for u in order if _bench.get(u, (0, 0))[0] <= now]
        for url in ready or order:
            try:
                req = urllib.request.Request(url, body, {"content-type": "application/json", "user-agent": "fee-ratio/1"})
                with urllib.request.urlopen(req, timeout=60) as r:
                    out = json.loads(r.read())
                if "result" in out and out["result"] is not None:
                    with _bench_lock:
                        _bench.pop(url, None)
                    return out["result"]
                last = f"{url}: {out.get('error')}"
            except Exception as e:
                last = f"{url}: {e}"
            with _bench_lock:
                strikes = _bench.get(url, (0, 0))[1] + 1
                _bench[url] = (time.time() + min(600, 15 * 2 ** strikes), strikes)
        time.sleep(min(30, 2 ** round_ * 0.5))
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
            if "first" in c:
                first = c["first"]
                last = json.load(open(paths(data, c["until"])[1]))["first"] - 1
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


def window_min_ahead(x, a, b):
    """m[i] = min(x[i + a], ..., x[i + b]) for every i with i + b inside x."""
    w = b - a
    out = array("Q", bytes(8 * max(0, len(x) - b)))
    q = deque()
    for j in range(len(x) - 1, -1, -1):
        v = x[j]
        while q and x[q[-1]] >= v:
            q.pop()
        q.append(j)
        if q[0] > j + w:
            q.popleft()
        i = j - a
        if 0 <= i < len(out):
            out[i] = x[q[0]]
    return out


# log10 of the ratio from -8 to 8 in steps of 0.0002, 0.05% wide
LO, HI = -8.0, 8.0
BINS = int((HI - LO) / 0.0002)


def edge(b):
    return 10 ** (LO + (b + 1) * (HI - LO) / BINS)


def lagged(fee, lag):
    """out[i] = min(fee[i - lag], ..., fee[i]): the lowest fee a record up to
    lag blocks stale can show at block i."""
    if lag == 0:
        return fee
    m = window_min_ahead(fee, 0, lag)
    out = array("Q", fee[:lag])
    for i in range(1, lag):
        out[i] = min(out[i - 1], out[i])
    out.extend(m)
    return out


def ratio_stats(fee, w, m=None, floor=0, ref=None):
    if m is None:
        m = window_max(fee, w)
    if ref is None:
        ref = fee
    hist = [0] * (BINS + 1)
    n = 0
    top, top_at = 0.0, 0
    over = {2: 0, 3: 0, 5: 0, 10: 0}
    for i in range(len(m)):
        f = ref[i] if ref[i] > floor else floor
        if f == 0:
            continue
        r = m[i] / f
        n += 1
        if r > top:
            top, top_at = r, i
        for k in over:
            if r > k:
                over[k] += 1
        if r == 0:
            b = 0
        else:
            b = max(0, min(BINS, int((math.log10(r) - LO) / (HI - LO) * BINS)))
        hist[b] += 1
    def pct(p):
        target, run = p / 100 * n, 0
        for b, h in enumerate(hist):
            run += h
            if run >= target:
                return min(top, edge(b))
        return top
    return n, top, top_at, over, {p: pct(p) for p in (50, 90, 99, 99.9, 99.99)}, hist


def smallest_factor(hist, n, share, top=float("inf")):
    """The smallest F, to bin precision, with at most this share of windows above it."""
    run = 0
    for b, h in enumerate(hist):
        run += h
        if n - run <= share * n:
            return min(top, edge(b))
    return top


def analyze(data):
    print("HOW FAR THE BASE FEE RISES AFTER A CHALLENGE, SINCE DENCUN")
    print("=" * 78)
    for chain in ("ethereum", "base"):
        c = CHAINS[chain]
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
            print("    smallest F exceeded by at most 1e-2, 1e-3, 1e-4 of windows:  " + "  ".join(f"{smallest_factor(hist, n, s, top):.3f}" for s in (1e-2, 1e-3, 1e-4)))
        bs = c["block_seconds"]
        def blocks(h):
            return math.ceil(h * 3600 / bs)
        ready = blocks(T_ANS_HOURS)
        if chain == "ethereum":
            patient = [("an answer forced in, landing on Ethereum by", W_A_HOURS - SEQ_HOURS - CHI_HOURS),
                       ("postings forced in, landing on Ethereum by", T_ANS_HOURS + W_P_HOURS - SEQ_HOURS - CHI_HOURS)]
        else:
            patient = [("an answer sent on Base by", W_A_HOURS),
                       ("postings sent on Base by", T_ANS_HOURS + W_P_HOURS)]
        for label, until in patient:
            m = window_min_ahead(fee, ready, blocks(until))
            n, top, top_at, over, pcts, hist = ratio_stats(fee, 0, m)
            print(f"  {chain}, sending when ready: {label} {until:.2f} h after the challenge, ready at {T_ANS_HOURS:.2f} h; {n:,} windows")
            print("    lowest fee from ready to the last block that can still land, over the fee at the challenge:")
            print("    " + "  ".join(f"p{p:g} {v:.3f}" for p, v in pcts.items()) + f"  max {top:.3f} at block {meta['first'] + top_at:,}")
            print("    share of windows above F:  " + "  ".join(f"{k}x {over[k] / n:.6f}" for k in over))
            print("    smallest F exceeded by at most 1e-2, 1e-3, 1e-4 of windows:  " + "  ".join(f"{smallest_factor(hist, n, s, top):.3f}" for s in (1e-2, 1e-3, 1e-4)))
        if c["blob"]:
            w = math.ceil(W_POST_HOURS * 3600 / c["block_seconds"])
            m = window_max(blob, w)
            blobs = math.ceil(PAYLOAD_BYTES / BLOB_USABLE)
            vals = sorted(m)
            def q(p):
                return vals[min(len(vals) - 1, int(p / 100 * len(vals)))]
            print(f"  ethereum blob base fee, highest within {W_POST_HOURS} h of each block, wei; {len(vals):,} windows")
            print("    " + "  ".join(f"p{p:g} {q(p):,}" for p in (50, 90, 99, 99.9)) + f"  max {vals[-1]:,}")
            print(f"  one batch as blobs: {blobs} blobs ({PROOF_FILE_BYTES:,} proof bytes and {BATCH} openings of {OPENING_BYTES:,}), blob gas {blobs * BLOB_GAS:,}")
            print("    blob fee for the batch at those quantiles, ETH: " + "  ".join(f"p{p:g} {q(p) * blobs * BLOB_GAS / 1e18:.3g}" for p in (50, 90, 99, 99.9)) + f"  max {vals[-1] * blobs * BLOB_GAS / 1e18:.3g}")
            until = T_ANS_HOURS + W_P_HOURS - SEQ_HOURS - CHI_HOURS
            m = window_min_ahead(blob, ready, blocks(until))
            vals = sorted(m)
            print(f"  ethereum blob base fee, lowest from ready, {T_ANS_HOURS:.2f} h, to {until:.2f} h after the challenge, wei; {len(vals):,} windows")
            print("    " + "  ".join(f"p{p:g} {q(p):,}" for p in (50, 90, 99, 99.9)) + f"  max {vals[-1]:,}")
            print("    blob fee for the batch at those quantiles, ETH: " + "  ".join(f"p{p:g} {q(p) * blobs * BLOB_GAS / 1e18:.3g}" for p in (50, 90, 99, 99.9)) + f"  max {vals[-1] * blobs * BLOB_GAS / 1e18:.3g}")
        print()


# Floors to try for the fee read at the challenge, in wei: Ethereum's base
# fee, Base's base fee, and Ethereum's blob base fee.
FLOORS = {
    "ethereum": [0, 10**8, 2 * 10**8, 5 * 10**8, 10**9, 2 * 10**9],
    "base": [0, 10**6, 2 * 10**6, 5 * 10**6, 10**7],
    "blob": [0, 10**6, 10**7, 10**8, 10**9],
}


def share_at_or_below(fee, floor):
    return sum(1 for f in fee if f <= floor) / len(fee)


def floors(data):
    """For each payment sized at a challenge, the lowest fee the answerer can
    still land at over the fee at the challenge read no lower than a floor:
    the factor that covers all but a share of challenges, and how often the
    floor decides. The bond is sized at the Ethereum fee the domain records,
    which may be up to LAG_ETH blocks stale, so it is shown both ways."""
    print("FEE FLOORS AND FACTORS: THE LOWEST FEE AN ANSWERER CAN LAND AT OVER max(FEE AT THE CHALLENGE, FLOOR)")
    print("=" * 78)
    eth_meta, eth_fee, blob = load(data, "ethereum")
    base_meta, base_fee, _ = load(data, "base")
    ready_h = T_ANS_HOURS
    cases = [
        ("bond: the answer forced in through Ethereum, landing by", "ethereum", eth_fee, 12, W_A_HOURS - SEQ_HOURS - CHI_HOURS, 0),
        (f"bond, the recorded fee up to {LAG_ETH} blocks stale: the answer forced in, landing by", "ethereum", eth_fee, 12, W_A_HOURS - SEQ_HOURS - CHI_HOURS, LAG_ETH),
        ("gas pool: the answer sent on Base by", "base", base_fee, 2, W_A_HOURS, 0),
    ]
    for label, kind, fee, bs, until, lag in cases:
        a = math.ceil(ready_h * 3600 / bs)
        b = math.ceil(until * 3600 / bs)
        m = window_min_ahead(fee, a, b)
        ref = lagged(fee, lag)
        print(f"  {label} {until:.2f} h, ready at {ready_h:.2f} h; {len(m):,} windows")
        print("    floor wei      at or below   >2x        >3x        >5x        >10x       F at 1e-3  F at 1e-4  F at 1e-5  max")
        for fl in FLOORS[kind]:
            n, top, top_at, over, pcts, hist = ratio_stats(fee, 0, m, fl, ref)
            below = share_at_or_below(fee, fl)
            fs = "  ".join(f"{smallest_factor(hist, n, s, top):9.3f}" for s in (1e-3, 1e-4, 1e-5))
            print(f"    {fl:>13,}  {below:10.6f}  " + "  ".join(f"{over[k] / n:.7f}" for k in (2, 3, 5, 10)) + f"  {fs}  {top:.3f}")
        print()


def deployed(name):
    """A constant of the deployment library, in wei for ether and gwei amounts,
    so the analysis tests what is deployed."""
    here = os.path.dirname(os.path.abspath(__file__))
    src = open(os.path.join(here, "..", "Reserve", "script", "Deployment.sol"), encoding="utf8").read()
    m = re.search(rf"\b{name}\s*=\s*([\d_.]+)\s*(ether|gwei)?\s*;", src)
    if not m:
        raise SystemExit(f"no {name} in Deployment.sol")
    v = float(m.group(1).replace("_", ""))
    return int(round(v * {"ether": 1e18, "gwei": 1e9, None: 1}[m.group(2)]))


def recorded(data, name, compute):
    """A value looked up once and kept in DATA_DIR, so later runs read the same."""
    p = os.path.join(data, name)
    if os.path.exists(p):
        return json.load(open(p))
    v = compute()
    json.dump(v, open(p, "w"))
    return v


def split_index(data, chain, meta):
    """The place in the chain's fee array of the first block at SPLIT_TIME."""
    urls = CHAINS[chain]["rpcs"]
    v = recorded(data, f"split_{chain}.json", lambda: {"time": SPLIT_TIME, "block": block_at(urls, SPLIT_TIME)})
    if v["time"] != SPLIT_TIME:
        raise SystemExit(f"{data}/split_{chain}.json is for another split time")
    return v["block"] - meta["first"]


def block_time(urls, n):
    return int(rpc(urls, "eth_getBlockByNumber", [hex(n), False])["timestamp"], 16)


def eth_times(data, meta):
    """The time of every TIME_STEP-th Ethereum block from the first, and of the last."""
    urls = CHAINS["ethereum"]["rpcs"]
    blocks = list(range(meta["first"], meta["last"], TIME_STEP)) + [meta["last"]]

    def look():
        with ThreadPoolExecutor(max_workers=4) as pool:
            ts = list(pool.map(lambda n: block_time(urls, n), blocks))
        return {"step": TIME_STEP, "blocks": blocks, "times": ts}

    v = recorded(data, "times_ethereum.json", look)
    if v["step"] != TIME_STEP or v["blocks"][0] != meta["first"] or v["blocks"][-1] != meta["last"]:
        raise SystemExit(f"{data}/times_ethereum.json does not match the fetched blocks")
    return v


def eth_index(times, t):
    """The place of the Ethereum block at time t, between the looked-up times."""
    ts, bs = times["times"], times["blocks"]
    if t <= ts[0]:
        return 0
    if t >= ts[-1]:
        return bs[-1] - bs[0]
    lo, hi = 0, len(ts) - 1
    while hi - lo > 1:
        mid = (lo + hi) // 2
        if ts[mid] <= t:
            lo = mid
        else:
            hi = mid
    return bs[lo] - bs[0] + round((t - ts[lo]) / (ts[hi] - ts[lo]) * (bs[hi] - bs[lo]))


def binom_cdf(k, n, p):
    if k < 0:
        return 0.0
    if k >= n or p <= 0:
        return 1.0
    if p >= 1:
        return 0.0
    lp, lq = math.log(p), math.log1p(-p)
    c = math.lgamma(n + 1)
    return min(1.0, sum(math.exp(c - math.lgamma(j + 1) - math.lgamma(n - j + 1) + j * lp + (n - j) * lq) for j in range(k + 1)))


def clopper_pearson(k, n, conf=0.95):
    """The exact two-sided interval for a share of k in n."""
    a = (1 - conf) / 2

    def bisect(f):
        lo, hi = 0.0, 1.0
        for _ in range(80):
            mid = (lo + hi) / 2
            if f(mid):
                lo = mid
            else:
                hi = mid
        return (lo + hi) / 2

    low = 0.0 if k == 0 else bisect(lambda p: binom_cdf(k - 1, n, p) > 1 - a)
    high = 1.0 if k == n else bisect(lambda p: binom_cdf(k, n, p) > a)
    return low, high


def share(k, n):
    lo, hi = clopper_pearson(k, n)
    return f"{k} of {n:,}, {k / n:.5f} (95% CI {lo:.5f} to {hi:.5f})"


WEEK = 7 * 86400


def disjoint(fee, bs, a, b, lag, k, floor):
    """Windows that do not overlap, each b + 1 blocks from its start i: the
    cost the payer can land at from block i + a on, over the fee at i, read
    as the lowest of the lag blocks before and no lower than the floor.
    Returns (i, ratio, floored) for each."""
    out = []
    for i in range(lag, len(fee) - b, b + 1):
        ref = min(fee[i - lag:i + 1])
        seg = fee[i + a:i + b + 1]
        cost = min(seg) if k == 1 else sum(heapq.nsmallest(k, seg)) / k
        out.append((i, cost / max(ref, floor), ref <= floor))
    return out


def every(fee, a, b, lag, floor):
    """Every window, overlapping: (ratio, start) of the lowest fee from a to b
    blocks after each block over the fee there, read as above."""
    m = window_min_ahead(fee, a, b)
    ref = lagged(fee, lag)
    for i in range(lag, len(m)):
        f = ref[i] if ref[i] > floor else floor
        yield m[i] / f, i


def weeks(rows, bs, factor):
    """The windows grouped by the week they start in: how many weeks, and in
    how many some window exceeded the factor. Fees move in regimes that last
    days, so a week of windows is nearer one independent trial than a window."""
    seen = {}
    for i, r, _ in rows:
        w = i * bs // WEEK
        seen[w] = seen.get(w, False) or r > factor
    return sum(seen.values()), len(seen)


def oos(data):
    """Each payment sized at one moment and spent later, in windows that do
    not overlap: the cost the payer can land at, over the fee at the moment
    read no lower than the deployed floor. The factor the windows before the
    split need is fitted on them alone; the windows after the split test it
    and the deployed factor. A window that spans the split is in neither. The
    bound on how often the factor is exceeded is given over windows and over
    weeks of windows; and, for the payments priced at one block, the largest
    ratio of every window, overlapping, before and after the split."""
    l1_floor, l1_factor = deployed("L1_FEE_FLOOR"), deployed("L1_FACTOR")
    l2_floor, l2_factor = deployed("L2_FEE_FLOOR"), deployed("L2_FACTOR")
    land = W_A_HOURS - SEQ_HOURS - CHI_HOURS
    cases = [
        ("bond: the answer forced in through Ethereum, landing by", "ethereum", T_ANS_HOURS, land, 0, 1, l1_floor, l1_factor),
        (f"bond, the recorded fee up to {LAG_ETH} blocks stale, landing by", "ethereum", T_ANS_HOURS, land, LAG_ETH, 1, l1_floor, l1_factor),
        ("gas pool: the answer sent on Base by", "base", T_ANS_HOURS, W_A_HOURS, 0, 1, l2_floor, l2_factor),
        (f"posting deposit: from the payment, its {CHUNKS} chunks in the {CHUNKS} cheapest Base blocks by", "base", 0, W_P_HOURS, 0, CHUNKS, l2_floor, l2_factor),
    ]
    print("THE DEPLOYED FEE FACTORS OUT OF SAMPLE: FITTED BEFORE 1 JULY 2025, TESTED AFTER, WINDOWS THAT DO NOT OVERLAP")
    print("=" * 78)
    loaded = {}
    for label, chain, start_h, until_h, lag, k, floor, factor in cases:
        if chain not in loaded:
            meta, fee, _ = load(data, chain)
            loaded[chain] = (meta, fee, split_index(data, chain, meta))
        meta, fee, s = loaded[chain]
        bs = CHAINS[chain]["block_seconds"]
        a = math.ceil(start_h * 3600 / bs)
        b = math.ceil(until_h * 3600 / bs)
        rows = disjoint(fee, bs, a, b, lag, k, floor)
        fit = [x for x in rows if x[0] + b < s]
        test = [x for x in rows if x[0] >= s]
        f_fit = max(r for _, r, _ in fit)
        below = sum(f for _, _, f in rows)
        print(f"  {label} {until_h:.2f} h, from {start_h:.2f} h; floor {floor / 1e9:g} gwei, deployed factor {factor}")
        print(f"    windows of {b + 1:,} blocks: {len(fit):,} before the split, {len(test):,} after; fee at or below the floor in {below / (len(rows) or 1):.4f} of all")
        print(f"    fit, before: largest ratio {f_fit:.3f}, the factor the fit needs")
        print(f"    test, after: largest ratio {max(r for _, r, _ in test):.3f}; above the fitted factor: {share(sum(r > f_fit for _, r, _ in test), len(test))}")
        print(f"                 above the deployed factor: {share(sum(r > factor for _, r, _ in test), len(test))}")
        kw, nw = weeks(test, bs, factor)
        print(f"                 weeks with a window above the deployed factor: {share(kw, nw)}")
        print(f"    all windows: largest ratio {max(r for _, r, _ in rows):.3f}; above the deployed factor: {share(sum(r > factor for _, r, _ in rows), len(rows))}")
        kw, nw = weeks(rows, bs, factor)
        print(f"                 weeks with a window above the deployed factor: {share(kw, nw)}")
        if k == 1:
            top = {"before": (0.0, 0), "after": (0.0, 0)}
            for r, i in every(fee, a, b, lag, floor):
                key = "before" if i + b < s else "after" if i >= s else None
                if key and r > top[key][0]:
                    top[key] = (r, i)
            for key, (r, i) in top.items():
                print(f"    every window, overlapping, {key} the split: largest ratio {r:.3f}, from block {meta['first'] + i:,}")
        print()


def london(data):
    """The bond's factor on Ethereum before the Dencun-era data: every block
    from London, which introduced the base fee, to the block before it. The
    same measure as floors and oos, at the deployed floor and without it."""
    floor, factor = deployed("L1_FEE_FLOOR"), deployed("L1_FACTOR")
    meta, fee, _ = load(data, "ethereum_london")
    bs = CHAINS["ethereum_london"]["block_seconds"]
    land = W_A_HOURS - SEQ_HOURS - CHI_HOURS
    a = math.ceil(T_ANS_HOURS * 3600 / bs)
    b = math.ceil(land * 3600 / bs)
    print("THE BOND'S FACTOR FROM LONDON TO DENCUN: ETHEREUM, AUGUST 2021 TO MARCH 2024")
    print("=" * 78)
    print(f"  blocks {meta['first']:,} to {meta['last']:,}; the answer forced in, landing by {land:.2f} h, ready at {T_ANS_HOURS:.2f} h; deployed factor {factor}")
    print(f"  fee at or below {floor / 1e9:g} gwei in {share_at_or_below(fee, floor):.6f} of blocks")
    for lag in (0, LAG_ETH):
        name = "the fee at the challenge" if lag == 0 else f"the fee read as the lowest of the {LAG_ETH} blocks before"
        print(f"  {name}:")
        for fl in (0, floor):
            n, top, top_i, over = 0, 0.0, 0, []
            ratios = array("d")
            for r, i in every(fee, a, b, lag, fl):
                n += 1
                ratios.append(r)
                if r > factor:
                    over.append(i)
                if r > top:
                    top, top_i = r, i
            print(f"    floor {fl / 1e9:g} gwei, every window: {n:,} windows, above the factor {len(over):,} ({len(over) / n:.7f}), largest {top:.3f} from block {meta['first'] + top_i:,}")
            if over:
                ref = lagged(fee, lag)
                rest = max(r for j, r in enumerate(ratios) if not over[0] - lag <= j <= over[-1] - lag)
                print(f"      those start from block {meta['first'] + over[0]:,} to {meta['first'] + over[-1]:,}, fee read there {ref[over[0]] / 1e9:.3f} to {ref[over[-1]] / 1e9:.3f} gwei; every window starting outside that span at most {rest:.3f}")
            rows = disjoint(fee, bs, a, b, lag, 1, fl)
            kw, nw = weeks(rows, bs, factor)
            print(f"      windows that do not overlap: above the factor {share(sum(r > factor for _, r, _ in rows), len(rows))}")
            for i, r, _ in rows:
                if r > factor:
                    print(f"        from block {meta['first'] + i:,}, ratio {r:.3f}")
            print(f"      weeks with a window above the factor: {share(kw, nw)}")
    print()


def blobs(data, eth_usd=None, stake_usd=None, bounty_usd=None):
    """Under censorship of its domain postings, the answerer posts a batch as
    blobs, and is refunded no more than posting it on the domain costs when
    the report arrives. In posting waits that do not overlap, the cheapest the
    blob way can be, its transactions in the cheapest Ethereum blocks of the
    wait, against the domain way at Base's lowest base fee in the wait and
    without the data fee: a domain way that cheap only overstates the excess
    the answerer bears."""
    eth_meta, eth_fee, blob = load(data, "ethereum")
    base_meta, base_fee, _ = load(data, "base")
    times = eth_times(data, eth_meta)
    base_t0 = recorded(data, "time_base_first.json", lambda: block_time(CHAINS["base"]["rpcs"], base_meta["first"]))
    n_blobs, call_gas, posting_gas = deployed("BLOBS"), deployed("BLOB_GAS"), deployed("POSTING_GAS")
    l2_floor, l2_factor = deployed("L2_FEE_FLOOR"), deployed("L2_FACTOR")
    txs = math.ceil(n_blobs / BLOBS_PER_TX)
    deposit = l2_factor * posting_gas * l2_floor
    L = math.ceil(W_P_HOURS * 3600 / 2)
    rows = []
    for j in range(0, len(base_fee) - L, L + 1):
        t0 = base_t0 + 2 * j
        e0, e1 = eth_index(times, t0), eth_index(times, t0 + 2 * L)
        if e1 >= len(eth_fee):
            break
        units = [n_blobs * BLOB_GAS * blob[e] + call_gas * eth_fee[e] for e in range(e0, e1 + 1)]
        blob_way = sum(heapq.nsmallest(txs, units)) / txs
        domain_way = posting_gas * min(base_fee[j:j + L + 1])
        rows.append((blob_way, domain_way))
    n = len(rows)
    excess = sorted(max(0, bw - dw) for bw, dw in rows)
    over = [x for x in excess if x > 0]

    def q(v, p):
        return v[min(len(v) - 1, int(p / 100 * len(v)))]

    print(f"BLOBS ON ETHEREUM AGAINST POSTINGS ON BASE: ONE BATCH, IN POSTING WAITS OF {W_P_HOURS} H THAT DO NOT OVERLAP")
    print("=" * 78)
    print(f"  {n_blobs} blobs in {txs} transactions and {call_gas:,} Ethereum gas, against {posting_gas:,} Base gas; {n:,} waits")
    bws = sorted(bw for bw, _ in rows)
    dws = sorted(dw for _, dw in rows)
    print("  blob way, ETH:   " + "  ".join(f"p{p:g} {q(bws, p) / 1e18:.3g}" for p in (50, 90, 99)) + f"  max {bws[-1] / 1e18:.3g}")
    print("  domain way, ETH: " + "  ".join(f"p{p:g} {q(dws, p) / 1e18:.3g}" for p in (50, 90, 99)) + f"  max {dws[-1] / 1e18:.3g}")
    print(f"  waits in which the blob way costs more: {share(len(over), n)}")
    if over:
        print("  the excess when it does, ETH: " + "  ".join(f"p{p:g} {q(over, p) / 1e18:.3g}" for p in (50, 90)) + f"  max {over[-1] / 1e18:.3g}")
        print(f"  the largest excess is {over[-1] / deposit:.3f} posting deposits at the floor ({deposit / 1e18:.6f} ETH, without the data fee)")
    if eth_usd is not None:
        price, stake, bounty = float(eth_usd), float(stake_usd), float(bounty_usd)
        # A censored answerer that does not post loses its stake and, bringing
        # its own receipt, recovers the bounty: posting is rational while the
        # excess is below the stake less the bounty.
        for name, usd in (("the stake less the bounty", stake - bounty), ("the stake", stake)):
            wei = usd / price * 1e18
            print(f"  waits whose excess is above {name}, {usd:.2f} USD = {wei / 1e18:.6f} ETH at {price:.2f} USD: {share(sum(x > wei for x in excess), n)}")
    print()


if __name__ == "__main__":
    modes = {"fetch": fetch, "analyze": analyze, "floors": floors, "oos": oos, "blobs": blobs, "london": london}
    if len(sys.argv) < 3 or sys.argv[1] not in modes or (len(sys.argv) != 3 and sys.argv[1] != "blobs") or len(sys.argv) not in (3, 6):
        raise SystemExit(__doc__)
    modes[sys.argv[1]](*sys.argv[2:])
