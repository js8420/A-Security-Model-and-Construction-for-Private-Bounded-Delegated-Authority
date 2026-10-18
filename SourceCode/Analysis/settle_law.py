"""Settlement gas against units consumed, from a forge log of the reserve's
tests: the least-squares line through the logged settlements of
testStoredAgainstLogged, its worst relative error, and the stored slope.
Usage: python3 settle_law.py WorkingHistory/run_TAG_forge.txt"""
import re
import sys


def sweep(path):
    rows, units, inside = [], None, False
    for line in open(path, encoding="utf8"):
        if "testStoredAgainstLogged" in line:
            inside = True
            continue
        if inside and line.startswith("[PASS]"):
            break
        if not inside:
            continue
        m = re.match(r"\s+units (\d+)", line)
        if m:
            units = int(m.group(1))
            rows.append({"n": units})
        m = re.match(r"\s+(stored|logged) (\d+)", line)
        if m and rows:
            rows[-1][m.group(1)] = int(m.group(2))
    return rows


def fit(xs, ys):
    k = len(xs)
    mx, my = sum(xs) / k, sum(ys) / k
    slope = sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / sum((x - mx) ** 2 for x in xs)
    return slope, my - slope * mx


rows = sweep(sys.argv[1])
n = [r["n"] for r in rows]
logged = [r["logged"] for r in rows]
stored = [r["stored"] for r in rows]
s, c = fit(n, logged)
worst = max(abs(c + s * x - y) / y for x, y in zip(n, logged))
print("SETTLEMENT GAS AGAINST UNITS")
print("=" * 78)
for r in rows:
    print(f"  {r['n']:>3} units   stored {r['stored']:>9,}   logged {r['logged']:>7,}   ratio {r['stored'] / r['logged']:.1f}")
print(f"  logged: {c:,.0f} + {s:,.0f} n, worst relative error {100 * worst:.2f}%")
print(f"  stored, first to last unit: {(stored[-1] - stored[0]) / (n[-1] - n[0]):,.0f} a unit")
