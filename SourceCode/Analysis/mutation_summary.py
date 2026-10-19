"""The mutation score of the independent verifier from Stryker's JSON report.

Usage: python3 mutation_summary.py mutation.json

Prints, per file and in all: mutants made, killed (by a failing check or a
timeout), survived, and the score killed / (killed + survived), then every
surviving mutant with its line and replacement. Mutants the TypeScript checker
refused, which do not compile, and mutants that crashed Stryker itself are
listed as errors and not counted.
"""
import json
import sys
from collections import Counter


def main(path):
    report = json.load(open(path))
    rows = []
    survivors = []
    total = Counter()
    for name, f in sorted(report["files"].items()):
        c = Counter(m["status"] for m in f["mutants"])
        killed = c["Killed"] + c["Timeout"]
        survived = c["Survived"] + c["NoCoverage"]
        errors = c["CompileError"] + c["RuntimeError"]
        rows.append((name, killed + survived, killed, survived, errors))
        total.update(c)
        lines = f["source"].split("\n")
        for m in f["mutants"]:
            if m["status"] in ("Survived", "NoCoverage"):
                s = m["location"]["start"]
                survivors.append((name, s["line"], m["mutatorName"], lines[s["line"] - 1].strip(), m.get("replacement", "")))
    print(f"{'file':<28}{'mutants':>9}{'killed':>8}{'survived':>10}{'score':>8}{'errors':>12}")
    for name, n, k, s, ce in rows:
        print(f"{name:<28}{n:>9}{k:>8}{s:>10}{100 * k / max(k + s, 1):>7.1f}%{ce:>12}")
    k = total["Killed"] + total["Timeout"]
    s = total["Survived"] + total["NoCoverage"]
    print(f"{'all':<28}{k + s:>9}{k:>8}{s:>10}{100 * k / max(k + s, 1):>7.1f}%{total['CompileError'] + total['RuntimeError']:>12}")
    print(f"timeouts counted as killed: {total['Timeout']}")
    print("surviving mutants:")
    for name, line, kind, src, rep in survivors:
        print(f"  {name}:{line} {kind}: {src}  ->  {rep}")


if __name__ == "__main__":
    main(sys.argv[1])
