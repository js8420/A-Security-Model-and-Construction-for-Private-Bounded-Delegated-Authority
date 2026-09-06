#!/usr/bin/env python3
"""
RETIRED VOCABULARY

The most persistent defect in a manuscript under revision is not an error of
fact. It is a correct fix landing beside the text it
supersedes: a dead key-derivation subsection, a retracted argument left inside a
proof, a refuse-design range check beside the section rejecting it, six stale
cross-references, and an entire partitioned construction left standing in the
section that replaced it.

No other check in this project can see that. Prose termination reads one
paragraph, environment nesting reads one bracket pair, numeric traceability
reads one figure, model consistency reads the definitions against the games.
None of them notices a paragraph that is well formed, correctly punctuated,
arithmetically sound, and about a mechanism that no longer exists.

This script keeps a list of terms the construction has retired and reports every
occurrence whose paragraph does not mark itself as history. It is deliberately
noisy in one direction: it would rather ask about a legitimate mention of the
abandoned design than miss a live one, because the cost of the two is not
symmetric.

Two ways an occurrence is permitted:

  1. Its paragraph contains a marker of retrospect --- "an earlier revision",
     "the divided design", "we built it first" --- so the reader is told the
     mechanism is being described rather than used.
  2. It falls inside a section listed in ALLOWED, which is for material whose
     subject genuinely is the abandoned alternative. Section V prices what
     partitioning costs and cannot be written without the word.

Everything else is reported, with its line and a window of context, for a human
to judge. A clean result does not mean the prose is current; it means no
retired term appears outside a passage that announces itself as history.
"""

import os
import re
import sys

TEX = r"E:\ZK_Delegated_Authority_for_Agentic_Payments\ResearchPaper04\Manuscript\PaperIEEE.tex"

# The manuscript is not the only place retired vocabulary survives. The
# reference implementation kept describing a superseded design after the
# construction stopped having it, because this check read only the .tex.
# Sources are scanned with the same term list and the same markers, since a
# comment saying "an earlier revision" is the same signal as a paragraph.
SOURCES = [
    r"E:\ZK_Delegated_Authority_for_Agentic_Payments\ResearchPaper04\SourceCode\reference.py",
]

# The crate's own sources. reference.py described a superseded design for four
# because this check read only the .tex, and the Rust sources did the same
# because it then read only reference.py. Comments describing a removed design
# are worse in the crate than in the paper, since the crate is what a reader
# consults to see what is actually constrained. The directory is globbed rather
# than listed so a new module is scanned the day it is written.
CRATE = r"E:\ZK_Delegated_Authority_for_Agentic_Payments\ResearchPaper04\Circuits\src"

# Terms the construction has retired, with what replaced each. The note is
# printed with the finding so a reader knows what the passage should say now.
RETIRED = {
    "partition":         "the budget is not divided; payments reserve runs from one counter",
    "sub-budget":        "the budget is not divided; the only threshold is B itself",
    "modular reduction": "removed with the divisions; runs are contiguous",
    "one-hot":           "the selector over division sizes is gone; the width law has no depth term",
    # "s_j" is deliberately absent. It named a per-division counter, which is
    # gone, but it also names the secret of the j-th delegation in a chain
    # (Section VI-F), which is current. A term that means two things cannot be
    # checked this way, and a check that cries wolf on live prose gets ignored.
    "wraps":             "runs do not wrap; a run that would leave the range is refused at B",
    "wrapped":           "runs do not wrap",
}

# Phrases that mark a paragraph as describing the abandoned design rather than
# using it.
MARKERS = (
    "earlier revision", "earlier revisions", "an earlier version",
    "the divided design", "the divided construction", "divided the budget",
    "we built it first", "alternative", "used to", "no longer",
    "is gone", "are gone", "went with the divisions", "replaced",
    "abandoned", "supersed", "previous design", "this section prices",
    "removes the", "removed with", "stopped entering", "would satisfy",
)

# Sections whose subject is the alternative itself.
ALLOWED = ("sec:conc", "sec:frag")


def sections(text):
    """Map each character offset to the label of the section containing it."""
    marks = [(m.start(), m.group(1))
             for m in re.finditer(r"\\label\{(sec:[^}]+)\}", text)]
    def label_at(pos):
        cur = None
        for at, lab in marks:
            if at <= pos:
                cur = lab
            else:
                break
        return cur
    return label_at


def main():
    if not os.path.isfile(TEX):
        print("manuscript not found: %s" % TEX)
        return 2
    text = open(TEX, encoding="utf-8").read()
    label_at = sections(text)
    extra = []
    if os.path.isdir(CRATE):
        for name in sorted(os.listdir(CRATE)):
            if name.endswith(".rs"):
                SOURCES.append(os.path.join(CRATE, name))
    else:
        print("crate directory not found, not scanned: %s" % CRATE)
    for src in SOURCES:
        if os.path.isfile(src):
            extra.append((src, open(src, encoding="utf-8").read()))
        else:
            print("source not found, not scanned: %s" % src)

    # Paragraph boundaries, so an occurrence can be judged in context.
    paras = []
    at = 0
    for chunk in text.split("\n\n"):
        paras.append((at, at + len(chunk), chunk))
        at += len(chunk) + 2

    def paragraph_of(pos):
        for a, b, chunk in paras:
            if a <= pos < b:
                return chunk
        return ""

    print("RETIRED VOCABULARY")
    print(TEX)
    for src, _ in extra:
        print(src)
    print("")
    print("  scanning %d file(s) for %d retired terms"
          % (1 + len(extra), len(RETIRED)))
    print("")

    findings = []
    for term, note in RETIRED.items():
        for m in re.finditer(re.escape(term), text):
            para = paragraph_of(m.start()).lower()
            if any(k in para for k in MARKERS):
                continue
            lab = label_at(m.start())
            if lab and any(lab.startswith(a) for a in ALLOWED):
                continue
            line = text.count("\n", 0, m.start()) + 1
            window = " ".join(text[max(0, m.start() - 60):m.start() + 70].split())
            findings.append((line, term, lab or "(front matter)", note, window))

    for src, body in extra:
        blocks = body.split("\n\n")
        at = 0
        spans = []
        for chunk in blocks:
            spans.append((at, at + len(chunk), chunk))
            at += len(chunk) + 2
        for term, note in RETIRED.items():
            for m in re.finditer(re.escape(term), body):
                block = ""
                for a, b, chunk in spans:
                    if a <= m.start() < b:
                        block = chunk.lower()
                        break
                if any(k in block for k in MARKERS):
                    continue
                line = body.count("\n", 0, m.start()) + 1
                window = " ".join(
                    body[max(0, m.start() - 60):m.start() + 70].split())
                findings.append((line, term, os.path.basename(src), note, window))

    findings.sort()
    print("=== retired terms outside a passage that marks itself as history ===")
    if findings:
        seen_terms = []
        for line, term, lab, note, window in findings:
            print("  line %-5d %-18s in %s" % (line, term, lab))
            print("        ... %s ..." % window)
            if term not in seen_terms:
                seen_terms.append(term)
        print("")
        for term in seen_terms:
            print("  %-18s %s" % (term, RETIRED[term]))
    else:
        print("  none")

    print("")
    print("RETIRED TERMS IN LIVE PROSE: %d" % len(findings))
    print("")
    print("A clean result does not mean the prose is current. It means no retired")
    print("term appears outside a passage that announces itself as history, which")
    print("is the failure this check exists for.")
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
