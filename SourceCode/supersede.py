#!/usr/bin/env python3
"""
WHAT DOES THIS INSERTION SUPERSEDE, AND WAS IT REMOVED?

Every finding of the last several rounds has been text that was correct until
an adjacent change made it wrong, and in each case the new text was written as
an ADDITION beside the old rather than in place of it. A new subsubsection, a
new paragraph, a new clause. The old passage keeps its tense and its claim and
sits a page away contradicting the repair.

Given two versions, this reports each paragraph the new file adds, together with
the paragraphs of the old file it most resembles that SURVIVE unchanged. A high
overlap between an inserted paragraph and a surviving one is the signature: the
author wrote the correction next to the thing it corrects.

Usage:
    python supersede.py new.tex old.tex
"""

import re
import sys


def paras(path):
    """Paragraphs with their offset, so proximity can be tested."""
    t = open(path, encoding="utf-8").read()
    t = re.sub(r"%.*", "", t)
    out, pos = [], 0
    for p in t.split("\n\n"):
        if len(p.strip()) > 200:
            out.append((pos, re.sub(r"\s+", " ", p).strip()))
        pos += len(p) + 2
    return out


def words(p):
    """Prose only. Two definitions share \\begin, \\label, \\emph and \\cref
    whatever they are about, and counting those makes every neighbouring pair
    of environments look like a supersession."""
    p = re.sub(r"\\[A-Za-z]+", " ", p)
    p = re.sub(r"\$[^$]*\$", " ", p)
    return set(w.lower() for w in re.findall(r"[A-Za-z]{4,}", p))


def overlap(a, b):
    wa, wb = words(a), words(b)
    if not wa or not wb:
        return 0.0
    return len(wa & wb) / min(len(wa), len(wb))


def main():
    if len(sys.argv) != 3:
        print(__doc__)
        return 2
    new, old = paras(sys.argv[1]), paras(sys.argv[2])
    olds = {p for _, p in old}
    survivors = [(o, p) for o, p in new if p in olds]
    inserted = [(o, p) for o, p in new if p not in olds]

    print("SUPERSESSION CHECK")
    print("%d paragraphs inserted, %d carried through unchanged"
          % (len(inserted), len(survivors)))
    print()

    hits = 0
    # Only survivors near the insertion: the failure is writing the correction
    # beside the thing it corrects, not anywhere in the paper.
    NEAR = 9000
    for off, ins in inserted:
        near = [(o, p) for o, p in survivors if abs(o - off) <= NEAR]
        best = max(((overlap(ins, p), p) for _, p in near), default=(0, ""))
        if best[0] >= 0.55:
            hits += 1
            print("INSERTED: %s..." % ins[:150])
            print("  resembles a surviving paragraph at %.0f%%:" % (best[0] * 100))
            print("  SURVIVING: %s..." % best[1][:150])
            print("  Does the insertion supersede it? If so it should be gone.")
            print()

    if not hits:
        print("No insertion closely resembles a paragraph left in place.")
    return 1 if hits else 0


if __name__ == "__main__":
    sys.exit(main())
