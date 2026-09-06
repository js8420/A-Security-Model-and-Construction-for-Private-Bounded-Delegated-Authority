#!/usr/bin/env python3
"""
MODEL CONSISTENCY

The other three checkers in this project are local. Prose termination looks at
one paragraph, environment nesting at one bracket pair, numeric traceability at
one figure. None of them can see that the policy definition on page 3 declares a
field the security game on page 8 contradicts, because neither text is wrong on
its own.

That is the defect this script exists for. In one version the
construction gained two committed policy fields, the definition was updated, and
the bound-privacy game forty pages away was not: its abort condition excluded
any pair of challenge policies differing outside B, while the new fields were
determined by B, so every admissible pair aborted and the property became
unsatisfiable by any scheme whatsoever. A build, a prose check, an environment
check and a numeric check all passed.

What it does:

  A  every field of the policy tuple is classified public or committed, exactly
     once;
  B  the fields a challenge pair may differ in are committed --- a public field
     differing is distinguishable by inspection;
  C  the differ-set is closed under the relations the paper states: if B is in
     it and the paper says B = u k p, then every committed field among u, k, p
     is in it too, or the game aborts on every admissible pair;
  D  the two games agree about which quantities carry a bound, since a property
     the construction enforces per sub-budget and a game that excuses only the
     total describe different schemes.

What it cannot do: read the propositions. It checks that the definitions and the
games are mutually consistent, not that either is right.
"""

import os
import re
import sys

ROOT = r"E:\ZK_Delegated_Authority_for_Agentic_Payments\ResearchPaper04"
TEX = os.path.join(ROOT, "Manuscript", "PaperIEEE.tex")

# Symbols that are deployment constants rather than policy fields, so a game may
# name them without the policy declaring them.
CONSTANTS = {"u", "w"}


def symbols(blob):
    """Field names out of a LaTeX tuple, normalised."""
    out = []
    for raw in blob.split(","):
        t = raw.strip().strip("$").strip()
        t = t.replace("\\;", "").strip()
        m = re.match(r"\\mathsf\{(\w+)\}", t)
        if m:
            out.append(m.group(1))
            continue
        m = re.match(r"([A-Za-z])_\{?\\mathrm\{(\w+)\}\}?", t)
        if m:
            out.append("%s_%s" % (m.group(1), m.group(2)))
            continue
        m = re.match(r"^([A-Za-z])$", t)
        if m:
            out.append(m.group(1))
            continue
        if t:
            out.append(t)
    return out


def main():
    if not os.path.isfile(TEX):
        print("manuscript not found: %s" % TEX)
        return 2
    text = open(TEX, encoding="utf-8").read()

    print("MODEL CONSISTENCY")
    print(TEX)
    print("")
    problems = []

    m = re.search(r"\\pol = \(([^)]*)\)", text)
    if not m:
        print("  policy tuple not found; nothing can be checked")
        return 2
    declared = symbols(m.group(1))

    m_pub = re.search(r"\\emph\{public\} part \$\(([^)]*)\)\$", text)
    m_com = re.search(r"\\emph\{committed\} part \$\(([^)]*)\)\$", text)
    if not (m_pub and m_com):
        print("  the public/committed split was not found next to the tuple")
        return 2
    public = symbols(m_pub.group(1))
    committed = symbols(m_com.group(1))

    print("  tuple      %s" % ", ".join(declared))
    print("  public     %s" % ", ".join(public))
    print("  committed  %s" % ", ".join(committed))
    print("")

    # A. the split covers the tuple exactly once
    for f in declared:
        n = (f in public) + (f in committed)
        if n == 0:
            problems.append("field %s is in the tuple and in neither part" % f)
        elif n == 2:
            problems.append("field %s is declared both public and committed" % f)
    for f in set(public) | set(committed):
        if f not in declared:
            problems.append("field %s is classified but not in the tuple" % f)

    # B and C. the challenge pair's differ-set
    # Same discipline as numcheck's REQUIRED list: if the differ-set cannot be
    # located the check has stopped checking, and that is a finding rather than
    # a silence.
    m_diff = re.search(r"differ outside \$\\\{([^\\]*)\\\}\$", text)
    if not m_diff:
        m_diff = re.search(r"differ outside \$([A-Za-z])\$", text)
        if not m_diff:
            problems.append(
                "the challenge differ-set could not be located; this check has "
                "stopped checking rather than passed")
        differ = symbols(m_diff.group(1)) if m_diff else []
    else:
        differ = symbols(m_diff.group(1))

    if not differ:
        problems.append("the bound-privacy abort's differ-set was not found")
    else:
        print("  challenge policies may differ in: %s" % ", ".join(differ))
        for f in differ:
            if f in public:
                problems.append(
                    "challenge policies may differ in %s, which the definition "
                    "calls public; a public field differing is distinguishable "
                    "by inspection" % f)
            elif f not in committed:
                problems.append(
                    "challenge policies may differ in %s, which the policy does "
                    "not declare" % f)

        # C. closure under a stated determination
        for rel in re.finditer(r"\$?([A-Za-z]) = ((?:[a-zA-Z] ?\\cdot ?)+[a-zA-Z])\$?", text):
            lhs = rel.group(1)
            rhs = [t.strip() for t in rel.group(2).split("\\cdot")]
            if lhs not in differ:
                continue
            for v in rhs:
                if v in CONSTANTS:
                    continue
                if v in committed and v not in differ:
                    problems.append(
                        "the paper states %s = %s and lets the challenge pair "
                        "differ in %s, but %s is committed and outside the "
                        "differ-set, so every admissible pair aborts and the "
                        "property is unsatisfiable"
                        % (lhs, " . ".join(rhs), lhs, v))
                if v in public and v in differ:
                    problems.append(
                        "%s is public yet inside the differ-set" % v)

    # D. the two games must bound the same quantities.
    #
    # Located by brace matching rather than by a regex over the abort's wording.
    # A regex here is a check that stops checking the moment the sentence is
    # rewritten, and it did: the bound-privacy abort was reworded to quantify
    # over the query sequence and this comparison silently lapsed, reporting a
    # missing condition rather than an inconsistency.
    def lif_containing(needle):
        at = 0
        while True:
            at = text.find("\\lIf{", at)
            if at < 0:
                return None
            i, depth = at + 5, 1
            while i < len(text) and depth:
                if text[i] == "{":
                    depth += 1
                elif text[i] == "}":
                    depth -= 1
                i += 1
            body = text[at:i]
            if needle in body:
                return body
            at = i

    bp = lif_containing("either} policy")
    ex = lif_containing("\\polof(D).B")
    if bp and ex:
        bp_sub = "sub-budget" in bp
        ex_sub = "sub-budget" in ex
        if bp_sub != ex_sub:
            problems.append(
                "one game bounds sub-budgets and the other only the total; "
                "bound privacy %s, exculpability %s"
                % ("does" if bp_sub else "does not",
                   "does" if ex_sub else "does not"))
        # The bound-privacy abort must be a predicate on the queries. One that
        # tests what was settled is correlated with the challenge bit whenever
        # the agent's willingness to serve depends on the hidden parameter.
        if "queries" not in bp and "settled(D) >" in bp:
            problems.append(
                "the bound-privacy abort tests what was settled rather than "
                "what was queried, so it is correlated with the challenge bit")
    else:
        problems.append(
            "abort condition not found: bound privacy %s, exculpability %s"
            % ("found" if bp else "MISSING", "found" if ex else "MISSING"))

    # E. The challenge delegation must be out of reach of the corruption oracle.
    #
    # The agent witness carries the policy opening, so an adversary permitted to
    # corrupt the challenge reads the hidden field in one query and every
    # property quantified over it is false. This was true of this manuscript for
    # some versions: nothing said which delegations an oracle applied to, and
    # under the permissive reading bound privacy was trivially broken.
    if "\\Ocor" in text:
        if "\\setminus \\{\\Ocor(D)\\}" not in text:
            problems.append(
                "the bound-privacy game does not exclude corruption of the "
                "challenge delegation, and the agent witness carries the policy "
                "opening")
        if "may not be invoked on it" not in text:
            problems.append(
                "the oracle table does not say which delegations an oracle may "
                "be called on")

    # F. The game's abort and the construction's refusal must be in the same
    # units.
    #
    # This is a defect that survives redesigns. The counter
    # advances on reservation; settled spend advances on settlement; the
    # construction refuses on the counter. An abort stated over settled value
    # therefore leaves a window in which one branch declines and the other does
    # not, and the property is false --- with advantage one half, from queries
    # that are never settled at all. Three sections carried the mismatch and
    # each was fixed in a different round, because reading for sense does not
    # notice that two correct sentences are counting different things.
    bp = lif_containing("either} policy")
    if bp:
        counter_words = ("counter", "reserv", "units", "committed")
        value_words = ("settle more than", "settled spend", "settled value")
        on_counter = any(w in bp for w in counter_words)
        on_value = any(w in bp for w in value_words)
        if on_value and not on_counter:
            problems.append(
                "the bound-privacy abort is stated over settled value while the "
                "construction refuses on the reservation counter; the two differ "
                "by the stranded fraction")
        if not on_counter and not on_value:
            problems.append(
                "the bound-privacy abort names no quantity this check "
                "recognises; it cannot be compared with the refusal threshold")

    print("")
    print("=== inconsistencies between the definitions and the games ===")
    # A relation stated in three places is one inconsistency, not three.
    seen, unique = set(), []
    for p in problems:
        if p not in seen:
            seen.add(p)
            unique.append(p)
    problems = unique
    if problems:
        for p in problems:
            print("  %s" % p)
    else:
        print("  none")
    print("")
    print("INCONSISTENCIES: %d" % len(problems))
    print("")
    print("These are contradictions between two texts that are each correct on")
    print("their own, which is the class no local check can see. A clean result")
    print("means the model agrees with itself, not that the model is right.")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
