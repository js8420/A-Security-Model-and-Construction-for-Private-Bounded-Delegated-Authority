#!/usr/bin/env python3
"""
SURVIVING SENTENCES

A paragraph is rewritten and one sentence of the previous version is left
standing inside it. Both are individually plausible, so a careful read passes
over them. Three checks address this and the first two each miss a case:

  near-duplicate paragraphs   catches a whole paragraph left beside its
                              replacement, missed the sentence-level case
  doubled sentences           catches two sentences repeating each other,
                              missed the case where the survivor CONTRADICTS
                              its replacement rather than repeating it
  this one                    catches any sentence that survived a rewrite,
                              whatever its relation to what replaced it

The remedy is to diff rather than to read, which is what this does. Given the previous version of the manuscript, it reports, for
every paragraph that changed, the sentences carried over verbatim. Most are
fine --- a rewrite usually keeps some of what it edits. The ones to look at are
the sentences at the END of a rewritten paragraph, because a survivor stranded
there is what every one of the twelve instances looked like.

This is a review aid rather than a pass/fail gate: it cannot know which
survivors are intended. It exits non-zero only when a paragraph was rewritten by
more than half and still ends with an unchanged sentence, which is the exact
shape of the defect.

Usage:
    python survivors.py OLD.tex [NEW.tex]

OLD is any earlier copy; the backups kept per delivery are the natural input.
"""

import os
import re
import sys

TEX = r"E:\ZK_Delegated_Authority_for_Agentic_Payments\ResearchPaper04\Manuscript\PaperIEEE.tex"


def paragraphs(text):
    out = []
    for p in text.split("\n\n"):
        q = " ".join(p.split())
        if len(q) > 120 and not q.startswith("\\"):
            out.append(q)
    return out


def sentences(p):
    return [x.strip() for x in re.split(r"(?<=[.!?]) +", p) if len(x.strip()) > 40]


def words(s):
    return set(re.findall(r"[a-z]{4,}", s.lower()))


def citation_clusters(text):
    """
    Every place a result is invoked, listed together.

    The thirteenth instance of the residue defeated all three duplicate checks,
    and the reason is worth recording. A corollary was widened to contain an
    extension that a nearby paragraph had been added to supply; the paragraph
    was then redundant. But it had not changed, so the diff was silent; it
    shared almost no vocabulary with the corollary, so containment read 0.26;
    and the repetition was across paragraphs, so the sentence check could not
    see it. The two passages shared exactly one thing: they cited the same
    result for the same claim.

    That cannot be decided mechanically --- whether two invocations of a lemma
    say the same thing is a question about meaning. So this reports rather than
    judges: for every result cited more than once, it prints the citing
    sentences together, so that reading them side by side is a minute's work
    instead of a search. It is a pre-submission aid, not a gate, and it always
    exits zero.
    """
    sents = []
    for para in text.split("\n\n"):
        q = " ".join(para.split())
        if len(q) < 60 or q.startswith("\\begin"):
            continue
        for x in re.split(r"(?<=[.!?]) +", q):
            if len(x.strip()) > 50:
                sents.append(x.strip())

    by_label = {}
    for s in sents:
        for lab in set(re.findall(r"\\[cC]ref\{([^}]+)\}", s)):
            for one in lab.split(","):
                by_label.setdefault(one.strip(), []).append(s)
    return {k: v for k, v in by_label.items() if len(v) > 1}


def main():
    if len(sys.argv) < 2:
        print(__doc__.strip().splitlines()[-3])
        return 2
    old_path = sys.argv[1]
    new_path = sys.argv[2] if len(sys.argv) > 2 else TEX
    for p in (old_path, new_path):
        if not os.path.isfile(p):
            print("not found: %s" % p)
            return 2

    old = paragraphs(open(old_path, encoding="utf-8").read())
    new = paragraphs(open(new_path, encoding="utf-8").read())
    old_set = set(old)

    # Pair each changed paragraph with the old one it most resembles.
    old_bags = [(p, words(p)) for p in old]

    print("SURVIVING SENTENCES")
    print("  old  %s" % old_path)
    print("  new  %s" % new_path)
    print("")

    findings = []
    for p in new:
        if p in old_set:
            continue
        bag = words(p)
        if len(bag) < 20:
            continue
        best, score = None, 0.0
        for q, qb in old_bags:
            if not qb:
                continue
            j = len(bag & qb) / len(bag | qb)
            if j > score:
                best, score = q, j
        if best is None or score < 0.25:
            continue          # a new paragraph, not a rewrite
        old_sents = set(sentences(best))
        new_sents = sentences(p)
        carried = [s for s in new_sents if s in old_sents]
        if not carried:
            continue
        changed = 1.0 - len(carried) / max(1, len(new_sents))
        trailing = new_sents and new_sents[-1] in old_sents
        findings.append((changed, trailing, p, carried))

    # At least half the paragraph rewritten and it still ends on a carried
    # sentence. The bound is inclusive: the instance this was built for sits at
    # exactly one half, and a strict inequality reported the file clean.
    hard = [f for f in findings if f[0] >= 0.5 and f[1]]

    print("=== rewritten paragraphs ending with an unchanged sentence ===")
    if hard:
        for changed, _, p, carried in hard:
            print("  %.0f%% of the paragraph is new; %d sentence(s) survived:"
                  % (changed * 100, len(carried)))
            for c in carried:
                print("    - %s" % c[:170])
    else:
        print("  none")

    print("")
    print("=== other sentences carried through a rewrite (for review) ===")
    soft = [f for f in findings if f not in hard]
    if soft:
        for changed, trailing, p, carried in soft[:12]:
            print("  %.0f%% new; %d sentence(s) carried" % (changed * 100, len(carried)))
            print("    %s" % carried[0][:150])
    else:
        print("  none")

    print("")
    clusters = citation_clusters(open(new_path, encoding="utf-8").read())
    interesting = {k: v for k, v in clusters.items()
                   if k.startswith(("prop:", "cor:", "lem:", "def:")) and len(v) >= 3}
    print("")
    print("=== results invoked from three or more places (read side by side) ===")
    for k in sorted(interesting, key=lambda k: -len(interesting[k]))[:8]:
        print("  %s, cited %d times" % (k, len(interesting[k])))
        for s in interesting[k][:4]:
            print("     - %s" % s[:140])
        print("")

    print("STRANDED TRAILING SENTENCES: %d" % len(hard))
    print("")
    print("A survivor is not automatically wrong; a rewrite keeps what it means")
    print("to keep. What this reports is the shape the defect has taken twelve")
    print("takes: a paragraph rebuilt around a correction, ending on the line")
    print("the correction replaced.")
    return 1 if hard else 0


if __name__ == "__main__":
    sys.exit(main())
