#!/usr/bin/env python3
"""
AN ALGORITHM AND THE PROSE BESIDE IT ARE ONE OBJECT

A game is written twice: once as an algorithm and once as the paragraphs that
say what the algorithm does. Only one of the two gets read carefully, and a
revision that rewrites the prose and leaves the algorithm produces a definition
whose statement and whose formalisation disagree. The proposition proved against
the algorithm is then not the proposition the prose claims.

Two checks, and the second is the one that does not need a previous version.

  COUPLING   Given an earlier file, report every algorithm whose prose changed
             while its body did not, or the reverse. Either is a revision that
             touched one half of an object.

  VOCABULARY Without an earlier file, report tokens that carry a restriction in
             one half and appear nowhere in the other: a guard in the algorithm
             the prose never mentions, or a quantity the prose calls a
             restriction that the algorithm never tests.

Neither check decides anything. Both narrow forty pages to a handful of places
where the two halves may have drifted, which is where this class of defect has
landed nine rounds out of ten.

Usage:
    python paircheck.py PaperIEEE.tex
    python paircheck.py PaperIEEE.tex --against previous.tex
"""

import re
import sys

# Words that carry a condition in either half. A guard is interesting when it
# names one of these and its partner does not.
CARRIERS = re.compile(
    r"\\lceil|\\log_2|well[- ]formed|differ|bracket|declare[ds]?|"
    r"identical|equal|restrict\w*|abort\w*|refus\w*|exclude[sd]?|"
    r"\\min|\\le\b|\\ge\b|\\neq"
)

MATH = re.compile(r"\\?[A-Za-z]{2,}|\\[a-zA-Z]+")


def algorithms(text):
    """Every algorithm environment, with its label, caption and body."""
    out = []
    for m in re.finditer(r"\\begin\{algorithm\*?\}(.*?)\\end\{algorithm\*?\}", text, re.S):
        body = m.group(1)
        label = re.search(r"\\label\{([^}]*)\}", body)
        caption = re.search(r"\\caption\{(.*?)\}\s*\n", body, re.S)
        out.append({
            "label": label.group(1) if label else "(unlabelled)",
            "caption": (caption.group(1)[:60] if caption else ""),
            "body": body,
            "start": m.start(),
            "end": m.end(),
        })
    return out


def prose_around(text, alg, span=2600):
    """The paragraphs on either side of an algorithm. Deliberately generous:
    a restriction is often stated a paragraph before the game and discussed
    two after it."""
    lo = max(0, alg["start"] - span)
    hi = min(len(text), alg["end"] + span)
    before = text[lo:alg["start"]]
    after = text[alg["end"]:hi]
    return before + "\n" + after


def guards(body):
    """The lines of an algorithm that decide something."""
    return [ln.strip() for ln in body.split("\n")
            if re.search(r"\\lIf|\\If|\\Return\s+\\bad|\\bad", ln)]


# Abstract nouns every game's prose carries and no algorithm ever spells.
# Left out rather than flagged, since a line that always fires is a line
# nobody reads.
NOISE = {"restrict", "restriction", "refusal", "abort", "exclude", "condition"}


def stem(t):
    for suf in ("ations", "ation", "ences", "ence", "ings", "ing", "eds",
                "ed", "es", "s"):
        if t.endswith(suf) and len(t) - len(suf) > 3:
            return t[: -len(suf)]
    return t


def tokens(s):
    out = set()
    for t in MATH.findall(s):
        if len(t) > 3:
            r = stem(t.lower())
            if r not in NOISE:
                out.add(r)
    return out


def coupling(new, old):
    """Algorithms where one half moved and the other did not."""
    an = {a["label"]: a for a in algorithms(new)}
    ao = {a["label"]: a for a in algorithms(old)}
    rows = []
    for label, a in an.items():
        if label not in ao:
            rows.append((label, "new algorithm", ""))
            continue
        b = ao[label]
        body_moved = norm(a["body"]) != norm(b["body"])
        prose_moved = norm(prose_around(new, a)) != norm(prose_around(old, b))
        if prose_moved and not body_moved:
            rows.append((label, "PROSE CHANGED, ALGORITHM DID NOT",
                         "the game may no longer be what the text says it is"))
        elif body_moved and not prose_moved:
            rows.append((label, "ALGORITHM CHANGED, PROSE DID NOT",
                         "the text may no longer describe the game"))
    return rows


def norm(s):
    return re.sub(r"\s+", " ", s).strip()


def vocabulary(text):
    """Condition-carrying tokens present in one half and absent from the other."""
    rows = []
    for a in algorithms(text):
        prose = prose_around(text, a)
        pt, gt = tokens(prose), set()
        for g in guards(a["body"]):
            gt |= tokens(g)
        only_alg = sorted(t for t in gt - pt if CARRIERS.search(t))
        # a restriction the prose names and the algorithm never tests
        claimed = set()
        for sent in re.split(r"(?<=\.)\s", prose):
            if re.search(r"restrict|well[- ]formed|may differ only|must be", sent):
                claimed |= {t for t in tokens(sent) if CARRIERS.search(t)}
        only_prose = sorted(claimed - gt)
        if only_alg or only_prose:
            rows.append((a["label"], a["caption"], only_alg, only_prose))
    return rows


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    against = None
    if "--against" in sys.argv:
        against = sys.argv[sys.argv.index("--against") + 1]
        args = [a for a in args if a != against]
    if not args:
        print(__doc__)
        return 2

    new = open(args[0], encoding="utf-8").read()
    algs = algorithms(new)
    print("ALGORITHM AND PROSE PAIRING")
    print("%d algorithms in %s" % (len(algs), args[0]))
    print()

    bad = 0
    if against:
        old = open(against, encoding="utf-8").read()
        rows = coupling(new, old)
        print("COUPLING against %s" % against)
        if not rows:
            print("  every algorithm moved with its prose, or neither moved")
        for label, verdict, note in rows:
            print("  %-22s %s" % (label, verdict))
            if note:
                print("  %-22s   %s" % ("", note))
            bad += 1
        print()

    rows = vocabulary(new)
    print("VOCABULARY")
    if not rows:
        print("  no condition-carrying token sits in one half only")
    for label, caption, only_alg, only_prose in rows:
        print("  %s  --  %s" % (label, caption))
        if only_alg:
            print("    tested but not described: %s" % ", ".join(only_alg))
        if only_prose:
            print("    described but not tested: %s" % ", ".join(only_prose))
        bad += 1

    print()
    print("Nothing here is a defect on its own. Each line is a place where the")
    print("two halves of one object may have drifted, and each needs reading.")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
