"""
Covering-set selection for the partitioned budget tree: how many nodes a
payment actually consumes, and what the count gives away.
"""

import math
import random
import statistics
from collections import defaultdict

SEED = 20260830


def cover(lo, hi):
    """Decompose [lo, hi) into maximal aligned blocks."""
    out = []
    while lo < hi:
        # lo & -lo is the alignment of lo; shrink it until it fits
        size = lo & -lo if lo else 1 << 62
        while size > hi - lo:
            size >>= 1
        out.append((lo, size))
        lo += size
    return out


def worst_case(depth):
    m = 1 << depth
    worst, arg = 0, None
    for lo in range(m):
        for hi in range(lo + 1, m + 1):
            c = len(cover(lo, hi))
            if c > worst:
                worst, arg = c, (lo, hi)
    return worst, arg


def payment_units(rng, mean_units, sigma):
    mu = math.log(mean_units) - (sigma ** 2) / 2.0
    return max(1, int(math.ceil(rng.lognormvariate(mu, sigma))))


def simulate(depth, k, mean_units, sigma, trials):
    m = 1 << depth
    per_part = m // k
    sizes = []
    rng = random.Random(SEED)

    for _ in range(trials):
        spent = [0] * k
        while True:
            n = payment_units(rng, mean_units, sigma)
            j = rng.randrange(k)
            if spent[j] + n > per_part:
                if all(spent[i] + n > per_part for i in range(k)):
                    break
                continue
            lo = j * per_part + spent[j]
            sizes.append(len(cover(lo, lo + n)))
            spent[j] += n
    return sizes


def leakage(depth, k, max_n):
    per_part = 1 << (depth - int(math.log2(k)))
    buckets = defaultdict(list)
    # sampling the counter rather than sweeping it; the pattern repeats
    for s in range(0, per_part, max(1, per_part // 512)):
        for n in range(1, min(max_n, per_part - s) + 1):
            buckets[len(cover(s, s + n))].append(n)
    return buckets


def report(depth, k, mean_units, sigma, trials):
    m = 1 << depth
    sizes = simulate(depth, k, mean_units, sigma, trials)
    hist = defaultdict(int)
    for s in sizes:
        hist[s] += 1

    print()
    print(f"DEPTH {depth}   m = {m:,} units   k = {k}   "
          f"mean {mean_units} units   sigma {sigma}")
    print("=" * 78)
    print(f"  payments measured        {len(sizes):,}")
    print(f"  mean nodes per payment   {statistics.mean(sizes):.2f}")
    print(f"  median                   {statistics.median(sizes):.0f}")
    print(f"  95th percentile          "
          f"{sorted(sizes)[int(0.95 * len(sizes))]}")
    print(f"  max observed             {max(sizes)}")
    print(f"  quantisation analysis assumed {depth}")
    print()
    print(f"  {'nodes':>6} {'payments':>10} {'share':>8}")
    print(f"  {'-'*6} {'-'*10} {'-'*8}")
    for c in sorted(hist):
        print(f"  {c:>6} {hist[c]:>10,} {hist[c]/len(sizes):>7.1%}")
    return sizes


if __name__ == "__main__":
    print()
    print("WORST-CASE COVER SIZE BY TREE DEPTH")
    print("=" * 78)
    print(f"  {'depth':>6} {'units':>10} {'worst cover':>13} {'2(d-1)':>8}")
    print(f"  {'-'*6} {'-'*10} {'-'*13} {'-'*8}")
    for d in range(2, 11):
        w, _ = worst_case(d)
        print(f"  {d:>6} {1 << d:>10,} {w:>13} {2 * (d - 1):>8}")
    print()
    print("  Worst case tracks 2(d-1), so depth 16 gives 30 and depth 19")
    print("  gives 36. Both are roughly double what Section 6.1 assumed.")

    report(16, 8, 50, 1.0, 3)
    report(19, 8, 5, 1.8, 3)

    print()
    print("WHAT THE NODE COUNT ALONE REVEALS, DEPTH 16, k = 8")
    print("=" * 78)
    b = leakage(16, 8, 256)
    print(f"  {'nodes':>6} {'possible amounts':>18} {'min':>7} {'max':>7}")
    print(f"  {'-'*6} {'-'*18} {'-'*7} {'-'*7}")
    for c in sorted(b):
        v = b[c]
        print(f"  {c:>6} {len(set(v)):>18,} {min(v):>7} {max(v):>7}")
    print()
