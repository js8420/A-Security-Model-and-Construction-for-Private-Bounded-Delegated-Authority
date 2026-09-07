#!/usr/bin/env python3
"""
DOES THE PAPER AGREE WITH ITSELF?

Three checkers in this project compare a version against an earlier one. None
can see a defect in text nobody touched, and that is where the worst finding of
the last ten rounds came from: a definition and a game that had contradicted
each other for twenty-four rounds while every diff came back clean.

This one reads one file and looks for internal disagreement.

  REFERENCES   Every \\cref target must exist, and every label should be reached.
               A dangling reference is a silent "??" in the PDF.

  COUNTS       The paper states counts in prose -- five channels, seven
               operations, four range checks, eight comparisons. Each is a claim
               that some enumeration elsewhere must match. Every counted noun is
               collected with every count asserted of it, so a noun carrying two
               different numbers is visible in one line.

  THRESHOLDS   Quantities that appear in more than one role -- what the circuit
               bounds, what the agent declines at, what the reserve compares
               against -- are collected with their surrounding clause, so a
               passage naming the wrong one can be read directly.

Nothing here decides anything. It gathers what has to be read together and
would otherwise be four hundred lines apart.

Usage:
    python consistency.py PaperIEEE.tex
"""

import re
import sys
from collections import defaultdict

WORDNUM = {
    "one": 1, "two": 2, "three": 3, "four": 4, "five": 5, "six": 6,
    "seven": 7, "eight": 8, "nine": 9, "ten": 10, "eleven": 11,
    "twelve": 12, "thirteen": 13, "fourteen": 14, "fifteen": 15,
    "sixteen": 16, "seventeen": 17, "eighteen": 18, "nineteen": 19,
    "twenty": 20, "thirty": 30, "forty": 40, "fifty": 50,
}

# Nouns whose count is a claim about an enumeration somewhere else.
COUNTED = (
    r"channels?|operations?|oracles?|restrictions?|range checks?|comparisons?|"
    r"controls?|permutations?|conditions?|clauses?|disclosures?|checks?|"
    r"algorithms?|gaps?|arguments?|inclusions?|openings?|refusals?"
)

# Quantities that mean different things in different roles.
THRESHOLDS = r"\$g\$|\$g = G/u\$|G/u|\$m\$|\$m_b\$|B/u|\\min\(|committed\(D\)"


def sentences(text):
    body = re.sub(r"%.*", "", text)
    for m in re.finditer(r"[^.!?]{20,600}[.!?]", body):
        yield m.start(), re.sub(r"\s+", " ", m.group(0)).strip()


def references(text):
    labels = set(re.findall(r"\\label\{([^}]+)\}", text))
    refs = set()
    for m in re.finditer(r"\\[Cc]refs?\{([^}]+)\}", text):
        refs |= {r.strip() for r in m.group(1).split(",")}
    return labels, refs


def counts(text):
    """Every counted noun, with the counts asserted of it and where."""
    found = defaultdict(list)
    pat = re.compile(
        r"\b(" + "|".join(WORDNUM) + r"|\d{1,3})\b[^.]{0,30}?\b(" + COUNTED + r")\b",
        re.I)
    for off, s in sentences(text):
        for m in pat.finditer(s):
            raw, noun = m.group(1).lower(), m.group(2).lower().rstrip("s")
            n = WORDNUM.get(raw, None)
            if n is None:
                try:
                    n = int(raw)
                except ValueError:
                    continue
            if n > 200:
                continue
            found[noun].append((n, off, s))
    return found


def thresholds(text):
    out = []
    pat = re.compile(THRESHOLDS)
    for off, s in sentences(text):
        if pat.search(s) and re.search(
                r"declin|refus|bound|threshold|compare|check", s, re.I):
            out.append((off, s))
    return out


def main():
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    text = open(sys.argv[1], encoding="utf-8").read()

    print("INTERNAL CONSISTENCY")
    print()

    labels, refs = references(text)
    dangling = sorted(refs - labels)
    unused = sorted(labels - refs)
    print("REFERENCES: %d labels, %d referenced" % (len(labels), len(refs)))
    if dangling:
        print("  DANGLING (these render as ?? in the PDF):")
        for r in dangling:
            print("    %s" % r)
    else:
        print("  no dangling reference")
    if unused:
        print("  never referenced: %s" % ", ".join(unused))
    print()

    print("COUNTS: a noun carrying two different numbers needs reading")
    conflicts = 0
    for noun, hits in sorted(counts(text).items()):
        distinct = sorted({n for n, _, _ in hits})
        if len(distinct) > 1:
            conflicts += 1
            print("  %-12s %s" % (noun, distinct))
            for n, off, s in sorted(hits):
                print("      %2d  ...%s" % (n, s[:120]))
    if not conflicts:
        print("  every counted noun carries one number")
    print()

    th = thresholds(text)
    print("THRESHOLDS: %d clauses name a bound or a decline point" % len(th))
    print("  (read together; the failure mode is one of them naming m where")
    print("   the construction bounds at g)")
    for off, s in th:
        print("    %s" % s[:150])
    return 1 if (dangling or conflicts) else 0


if __name__ == "__main__":
    sys.exit(main())
