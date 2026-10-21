"""Where each verifier refused the randomly altered proofs and the faulty
proofs the prover made, check by check.

Run: python3 fault_summary.py FUZZ_DIR DEEP_RESULTS
FUZZ_DIR holds one fuzz_*.json per seed; DEEP_RESULTS is the JSON-lines file
e2e/stark_deep.ts appends to.
"""
import glob
import json
import sys
from collections import Counter, defaultdict

CHECKS = ["accepted", "parsing", "shape", "out-of-domain point", "grinding",
          "input opening", "fold opening", "final polynomial", "constraints"]


def table(title, rows):
    """rows: name -> (deployed Counter, independent Counter)."""
    print(title)
    print("=" * 78)
    names = list(rows)
    print(f"  {'check':<20}" + "".join(f"{n:>14}" for n in names))
    for c in CHECKS:
        cells = []
        for n in names:
            d, i = rows[n]
            cells.append(f"{d[c]:>6} /{i[c]:>6}")
        if any(rows[n][0][c] or rows[n][1][c] for n in names):
            print(f"  {c:<20}" + "".join(f"{x:>14}" for x in cells))
    print("  each cell: deployed / independent")
    print()


def fuzz(directory):
    d, i = Counter(), Counter()
    total = other = disagree = 0
    for f in sorted(glob.glob(f"{directory}/fuzz_*.json")):
        j = json.load(open(f))
        d.update(j["checks"]["deployed"])
        i.update(j["checks"]["independent"])
        other += j["checks"]["otherCheck"]
        disagree += j["deployedOnly"] + j["independentOnly"]
        total += j["count"] - j["unchanged"]
    table(f"RANDOM ALTERATIONS OF THE HONEST PROOF: {total} CHANGED", {"all": (d, i)})
    print(f"  accepted by one verifier and refused by the other: {disagree}")
    print(f"  refused by both at different checks: {other}")
    print()


def deep(path):
    rows = [json.loads(l) for l in open(path) if l.strip()]
    fams = defaultdict(list)
    for r in rows:
        fams[r["family"]].append(r)
    print("FAULTS THE PROVER MADE, ONE PER PROOF, EVERYTHING ELSE HONEST")
    print("=" * 78)
    for fam, rs in fams.items():
        made = [r for r in rs if r["made"]]
        refused = len(rs) - len(made)
        d = Counter(r["deployed"] for r in made)
        i = Counter(r["independent"] for r in made)
        other = sum(1 for r in made if r["deployed"] != r["independent"])
        split = sum(1 for r in made if (r["deployed"] == "accepted") != (r["independent"] == "accepted"))
        print(f"  {fam}: {len(made)} proofs" + (f", {refused} the prover refused to make" if refused else ""))
        for c in CHECKS:
            if d[c] or i[c]:
                print(f"    {c:<20} deployed {d[c]:>5}   independent {i[c]:>5}")
        print(f"    accepted by one and refused by the other {split}; refused at different checks {other - split}")
        if fam in ("draw", "codeword"):
            by = defaultdict(Counter)
            for r in made:
                w = r["where"]
                key = w if fam == "draw" else w.split(":")[0]
                by[key][r["independent"]] += 1
            for k in sorted(by, key=lambda x: (len(x), x)):
                print(f"      {k:<44} " + ", ".join(f"{c} {n}" for c, n in by[k].most_common()))
    print()


if __name__ == "__main__":
    fuzz(sys.argv[1])
    deep(sys.argv[2])
