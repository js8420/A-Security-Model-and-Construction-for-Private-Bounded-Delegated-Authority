"""
Flag prose paragraphs in the manuscript that end without terminal punctuation.

Four sentences in this paper have broken off mid-clause, each beside an edit of
mine, and each survived a structural check and a reading pass. Cross-reference
and environment checks cannot see them: the LaTeX is valid, the references
resolve, and the paragraph simply stops. A reader notices only if they happen to
read that line.

The rule is mechanical. A paragraph of prose ends with '.', '?', '!', or a
closing delimiter after one of those. Anything else is either a truncation or a
construct this script does not know about, and both are worth a look.

Run it before every build.
"""

import os
import re
import sys

TEX = r"E:\ZK_Delegated_Authority_for_Agentic_Payments\ResearchPaper04\Manuscript\PaperIEEE.tex"

# Lines that are structure rather than prose, and paragraphs that legitimately
# end without a full stop.
SKIP_PREFIX = (
    "\\begin", "\\end", "\\label", "\\caption", "\\item", "\\bibliography",
    "\\section", "\\subsection", "\\subsubsection", "\\newcommand", "\\usepackage",
    "\\documentclass", "\\theoremstyle", "\\newtheorem", "\\title", "\\author", "\\maketitle", "\\appendices",
    "\\IEEE", "\\toprule", "\\midrule", "\\bottomrule", "\\cmidrule", "\\centering",
    "\\small", "\\[", "\\]", "%",
)
OK_ENDINGS = (".", "?", "!", ".}", ".$", "$.", ".\\", ":", ".'", '."')


def paragraphs(text):
    """Yield (line number of last line, text) for each blank-line-separated block."""
    lines = text.split("\n")
    start = None
    buf = []
    for i, line in enumerate(lines, start=1):
        if line.strip() == "":
            if buf:
                yield start, i - 1, "\n".join(buf)
            buf, start = [], None
        else:
            if start is None:
                start = i
            buf.append(line)
    if buf:
        yield start, len(lines), "\n".join(buf)


def is_prose(block):
    first = block.lstrip()
    if first.startswith(SKIP_PREFIX):
        return False
    # inside a table row, an algorithm, or a display
    if "&" in block and "\\\\" in block:
        return False
    if block.rstrip().endswith("\\\\"):
        return False
    if re.match(r"^\s*\$\$", first):
        return False
    return True


def nesting(text):
    """
    Theorem environments that contain other theorem environments.

    A proposition inside a remark compiles, resolves every reference, passes a
    prose check and numbers itself correctly. It is still wrong, and it has been
    introduced into this manuscript twice --- once during drafting and once
    while converting a remark into a proved result. No other check in this
    project can see it.
    """
    envs = ("definition", "proposition", "lemma", "corollary", "remark",
            "assumption", "theorem")
    opens = "|".join(envs)
    bad, stack = [], []
    for m in re.finditer(r"\\(begin|end)\{(" + opens + r")\}", text):
        kind, env = m.group(1), m.group(2)
        line = text.count("\n", 0, m.start()) + 1
        if kind == "begin":
            if stack:
                bad.append((line, env, stack[-1][1], stack[-1][0]))
            stack.append((line, env))
        elif stack and stack[-1][1] == env:
            stack.pop()
        else:
            bad.append((line, env, "unmatched end", 0))
    for line, env in stack:
        bad.append((line, env, "never closed", 0))
    return bad


def near_duplicates(text):
    """
    Paragraphs that say the same thing twice.

    This is how a repair lands beside the text it replaces: both paragraphs read
    correctly on their own, so proofreading passes over them, and the reader is
    left to guess which governs. It arises whenever a paragraph is
    rebuilt around a correction and the sentence being corrected is left in
    place, and it survives audits of counts, cross-references, macros, tables
    and citations, none of which look for repetition.

    The measure is CONTAINMENT, not similarity: the fraction of the shorter
    paragraph's content words that appear in the longer one. A replacement is
    usually longer than what it replaces, since it adds the clause that motivated
    the rewrite, so the two overlap asymmetrically and a symmetric measure reads
    low. On the case this was built for, containment is 0.76 and Jaccard is
    0.35; keying on the latter reports a clean file.
    """
    stop = set("""the a an and or of to in is are was were be been being that this
    those these it its as at by for from on with which what when where how not no
    but if then than so such we our their there here one two three""".split())

    paras = [p.strip() for p in text.split("\n\n")]
    keep = []
    for i, p in enumerate(paras):
        if len(p) < 300 or p.lstrip().startswith("\\"):
            continue
        words = re.findall(r"[a-z]{4,}", p.lower())
        bag = set(w for w in words if w not in stop)
        if len(bag) >= 25:
            keep.append((i, p, bag))

    found = []
    for a in range(len(keep)):
        for b in range(a + 1, len(keep)):
            ia, pa, ba = keep[a]
            ib, pb, bb = keep[b]
            j = len(ba & bb) / min(len(ba), len(bb))
            if j >= 0.65:
                found.append((j, pa, pb))
    return sorted(found, reverse=True)


def doubled_sentences(text):
    """
    Two sentences in one paragraph saying the same thing.

    The paragraph detector cannot see this: the paragraph is unique, the
    repetition is inside it. A correct sentence superseded by a
    better one, both left standing, neither wrong on its own.

    The tell is worth encoding directly: two sentences of one paragraph citing
    the SAME cross-reference for the same fact. That is cheap
    to test and it is where the duplicates have been. Content overlap catches
    the rest.
    """
    stop = set("""the a an and or of to in is are was were be been being that this
    those these it its as at by for from on with which what when where how not no
    but if then than so such we our their there here one two three""".split())

    out = []
    for para in text.split("\n\n"):
        p = " ".join(para.split())
        if len(p) < 200 or p.startswith("\\"):
            continue
        parts = [x.strip() for x in re.split(r"(?<=[.!?]) +", p) if len(x.strip()) > 60]
        for i in range(len(parts)):
            for j in range(i + 1, len(parts)):
                a, b = parts[i], parts[j]
                ra = set(re.findall(r"\\[cC]ref\{([^}]+)\}", a))
                rb = set(re.findall(r"\\[cC]ref\{([^}]+)\}", b))
                wa = set(w for w in re.findall(r"[a-z]{4,}", a.lower()) if w not in stop)
                wb = set(w for w in re.findall(r"[a-z]{4,}", b.lower()) if w not in stop)
                if not wa or not wb:
                    continue
                ov = len(wa & wb) / min(len(wa), len(wb))
                shared_ref = bool(ra & rb)
                # The shared cross-reference is the discriminating signal: two
                # sentences citing the same result for the same fact is what a
                # superseded sentence looks like. Content overlap alone needs a
                # much higher bar, because adjacent sentences in a definition
                # legitimately share most of their vocabulary.
                if ov >= 0.80 or (shared_ref and ov >= 0.50):
                    out.append((ov, shared_ref, a, b))
    return sorted(out, reverse=True)


# The abstract's claims, each with the phrase that must also appear in the body.
# A correction can reach the body and not the headline, or the reverse: a
# measured 23.6% becomes "about a quarter" in the evaluation and stays "a
# fifth" in the abstract. A figure can be traced to a log; a fraction in prose
# cannot, so the pairing is listed and checked.
ABSTRACT_CLAIMS = [
    ("proving penalty",        "about a tenth more proving"),
    ("verification penalty",   "about a quarter more"),
    ("composed width",         "25{,}720"),
    ("per-payment proving",    "49.39"),
    ("per-payment verifying",  "10.41"),
    ("proof size",             "285"),
    ("the bracket concession", "power-of-two bracket"),
    ("the capacity concession", "committed capacity"),
]


def abstract_against_body(text):
    """Claims the abstract makes that the body does not repeat."""
    try:
        i = text.index("\\begin{abstract}")
        j = text.index("\\end{abstract}")
    except ValueError:
        return [("the abstract could not be located", "")]
    ab, body = text[i:j], text[j:]
    out = []
    for name, phrase in ABSTRACT_CLAIMS:
        in_ab = phrase in ab
        in_body = phrase in body
        if in_ab and not in_body:
            out.append((name, "in the abstract, not in the body: " + phrase))
        elif not in_ab:
            out.append((name, "no longer in the abstract: " + phrase))
    return out


def main():
    if not os.path.isfile(TEX):
        print("FATAL: manuscript not found: " + TEX)
        return 1
    with open(TEX, "r", encoding="utf-8", errors="replace") as f:
        text = f.read()

    print("PROSE TERMINATION CHECK")
    print(TEX)
    print("")

    bad = []
    for first, last, block in paragraphs(text):
        if not is_prose(block):
            continue
        tail = block.rstrip()
        # A paragraph whose last lines are environment enders is judged on the
        # prose above them: \end{proof} is not a sentence and never terminates one.
        while True:
            stripped = re.sub(r"(?:\s*\\end\{[a-zA-Z*]+\})+\s*$", "", tail)
            if stripped == tail:
                break
            tail = stripped.rstrip()
        if not tail:
            continue
        if tail.endswith(OK_ENDINGS):
            continue
        # a paragraph ending in a closing brace after a sentence is fine
        if re.search(r"[.?!]\s*[}\)\]]*\s*$", tail):
            continue
        bad.append((first, last, " ".join(tail.split())[-100:]))

    print("=== paragraphs not ending in terminal punctuation ===")
    if bad:
        for first, last, tail in bad:
            print("  line %-5d ... %s" % (last, tail))
    else:
        print("  none")
    print("")
    print("TRUNCATED OR UNRECOGNISED: %d" % len(bad))
    print("")

    nest = nesting(text)
    print("=== theorem environments inside other theorem environments ===")
    if nest:
        for line, env, outer, oline in nest:
            if oline:
                print("  line %-5d %s inside %s opened at line %d" % (line, env, outer, oline))
            else:
                print("  line %-5d %s: %s" % (line, env, outer))
    else:
        print("  none")
    print("")
    print("NESTED OR UNMATCHED ENVIRONMENTS: %d" % len(nest))

    dups = near_duplicates(text)
    print("")
    print("=== paragraphs that say the same thing twice ===")
    if dups:
        for j, pa, pb in dups:
            print("  containment %.2f" % j)
            print("    A: %s ..." % " ".join(pa.split())[:150])
            print("    B: %s ..." % " ".join(pb.split())[:150])
    else:
        print("  none")
    print("")
    print("NEAR-DUPLICATE PARAGRAPHS: %d" % len(dups))

    doubles = doubled_sentences(text)
    print("")
    print("=== sentences repeating another in the same paragraph ===")
    if doubles:
        for ov, shared, a, b in doubles:
            print("  overlap %.2f%s" % (ov, ", same cross-reference" if shared else ""))
            print("    A: %s" % a[:150])
            print("    B: %s" % b[:150])
    else:
        print("  none")
    print("")
    print("DOUBLED SENTENCES: %d" % len(doubles))

    drift = abstract_against_body(text)
    print("")
    print("=== abstract claims the body does not carry ===")
    if drift:
        for name, why in drift:
            print("  %-26s %s" % (name, why))
    else:
        print("  none")
    print("")
    print("ABSTRACT DRIFT: %d" % len(drift))
    print("Each is either a sentence that stops mid-clause or a construct this")
    print("script does not model. Both want a human look; neither is visible to")
    print("a cross-reference or environment check.")
    return 1 if (bad or nest) else 0


if __name__ == "__main__":
    sys.exit(main())
