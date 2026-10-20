"""Why each mutant of the independent verifier that the full test set does not
kill survives, from Stryker's JSON report. Every survivor is put in one of
five classes by its file and line, and the script fails if one is left over.

  no effect     the change alters no value the verifier computes: an array
                created without its length, a loop that runs once more over
                nothing, a sort of a list that never holds two entries
  same value    another path computes the same value: an operation on base
                field values done in the extension, a shortcut whose general
                formula gives the same result, a count that the stated degree
                leaves unchanged
  one height    every matrix the deployed proofs open has one height, so the
                code that combines openings of different heights never runs
  redundant     a shape check whose every violation in the test set is refused
                by a later check, so removing it changes no verdict there
  1 in 2^64     a sample equal to p exactly, which a 64-bit draw hits with
                probability 2^-64

Usage: python3 mutant_classes.py mutation.json
"""
import json
import sys
from collections import Counter

CLASSES = {
    "no effect": {
        "src/stark/constraints.ts": {80, 90, 116, 117, 119},
        "src/stark/field.ts": {86, 93},
        "src/stark/proof.ts": {83},
        "src/stark/verify.ts": {146, 382},
    },
    "same value": {
        "src/stark/constraints.ts": {65, 137, 141},
        "src/stark/verify.ts": {79, 140},
    },
    "one height": {
        "src/stark/verify.ts": {247, 296, 298, 302, 360, 362, 365, 381},
    },
    "redundant": {
        "src/stark/merkle.ts": {51, 52, 69},
        "src/stark/proof.ts": {48, 49, 67, 73, 91, 142},
        "src/stark/verify.ts": {99, 101, 138, 149, 150, 152, 153, 157, 191, 198, 240, 241, 242, 243, 245, 248, 256,
                                266, 272, 273, 301, 354, 358, 372},
    },
    "1 in 2^64": {
        "src/stark/transcript.ts": {67},
    },
}


def main(path):
    report = json.load(open(path))
    counts = Counter()
    left = []
    for name, f in sorted(report["files"].items()):
        for m in f["mutants"]:
            if m["status"] not in ("Survived", "NoCoverage"):
                continue
            line = m["location"]["start"]["line"]
            hit = [c for c, files in CLASSES.items() if line in files.get(name, set())]
            if len(hit) == 1:
                counts[hit[0]] += 1
            else:
                left.append(f"{name}:{line} {m['mutatorName']}")
    total = sum(counts.values()) + len(left)
    print(f"surviving mutants: {total}")
    for c in CLASSES:
        print(f"  {c:<12} {counts[c]:>4}")
    if left:
        print("not classified:")
        for l in left:
            print("  " + l)
        sys.exit(1)
    print("every survivor classified")


if __name__ == "__main__":
    main(sys.argv[1])
