"""What the base fee did around one block: hourly lowest, median and highest
base fee, in gwei, from some hours before the block to some hours after it,
read from the data fee_ratio.py fetched. Used to explain the tail of
fee_ratio.py's distributions.

  python3 fee_spot.py DATA_DIR CHAIN BLOCK HOURS_BEFORE HOURS_AFTER
"""
import math
import sys
import time

import fee_ratio

# Base produces a block every 2 s from its genesis, so a block's time is exact.
BASE_GENESIS = 1686789347


def main():
    if len(sys.argv) != 6:
        raise SystemExit(__doc__)
    data, chain, block, before, after = sys.argv[1], sys.argv[2], int(sys.argv[3]), float(sys.argv[4]), float(sys.argv[5])
    meta, fee, _ = fee_ratio.load(data, chain)
    bs = fee_ratio.CHAINS[chain]["block_seconds"]
    per_hour = 3600 // bs
    at = block - meta["first"]
    lo = max(0, at - math.ceil(before * per_hour))
    hi = min(len(fee), at + math.ceil(after * per_hour))
    print(f"{chain} block {block:,}: base fee {fee[at] / 1e9:.9f} gwei")
    if chain == "base":
        print(f"  time {time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime(BASE_GENESIS + 2 * block))}")
    print("  hour   lowest gwei     median gwei    highest gwei")
    for s in range(lo, hi, per_hour):
        h = sorted(fee[s:min(hi, s + per_hour)])
        print(f"  {(s - at) / per_hour:+6.1f}  {h[0] / 1e9:13.9f}  {h[len(h) // 2] / 1e9:13.9f}  {h[-1] / 1e9:13.9f}")


if __name__ == "__main__":
    main()
