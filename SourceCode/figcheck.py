#!/usr/bin/env python3
r"""
Every number in the manuscript that looks measured must appear in the run log
that produced it.

The failure this exists to catch: a figure is updated where it is tabulated and
left stale where it is quoted, or a law fitted to one circuit survives into the
text describing another. Neither a LaTeX build nor a brace check nor a
reference check can see it.

A figure counts as measured if it is written in the manuscript's thousands form
($12{,}345$) or as a timing ($12.34$\,ms). Anything matching that shape and
absent from the log is reported. Some will be legitimate -- arithmetic the text
derives, or a figure from a different experiment -- so the report is a list to
answer, not a list of errors. Answer every line or the check is worthless.

    python figcheck.py <manuscript.tex> <run log> [more logs...]
"""

import re
import sys
from collections import Counter


def numbers_in_log(paths):
    """Every integer and decimal the harness printed, as plain strings."""
    seen = set()
    for p in paths:
        text = open(p, encoding="utf-8-sig", errors="replace").read()
        for m in re.finditer(r"\d[\d,]*\.?\d*", text):
            raw = m.group(0).replace(",", "")
            seen.add(raw)
            if "." in raw:
                # the manuscript rounds; keep two and one decimal places too
                try:
                    v = float(raw)
                    seen.add("%.2f" % v)
                    seen.add("%.1f" % v)
                    seen.add("%.0f" % v)
                except ValueError:
                    pass
    return seen


def figures_in_tex(path):
    """(figure, line, context) for everything written as a measurement."""
    out = []
    lines = open(path, encoding="utf-8").read().split("\n")
    for n, line in enumerate(lines, 1):
        if line.lstrip().startswith("%"):
            continue
        for m in re.finditer(r"\$?(\d{1,3}(?:\{,\}\d{3})+)\$?", line):
            out.append((m.group(1).replace("{,}", ""), n, line.strip()[:90]))
        for m in re.finditer(r"\$(\d+\.\d+)\$\\,ms", line):
            out.append((m.group(1), n, line.strip()[:90]))
    return out


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        return 2
    tex, logs = sys.argv[1], sys.argv[2:]
    have = numbers_in_log(logs)
    figs = figures_in_tex(tex)

    missing = [(f, n, c) for f, n, c in figs if f not in have]
    counts = Counter(f for f, _, _ in figs)

    print("manuscript: %s" % tex)
    print("logs:       %s" % ", ".join(logs))
    print("measured-looking figures: %d, distinct %d" % (len(figs), len(counts)))
    print()

    if missing:
        print("NOT FOUND IN ANY LOG -- answer each of these:")
        for f, n, c in missing:
            print("  L%-5d %-14s %s" % (n, f, c))
    else:
        print("every measured-looking figure appears in a log.")

    print()
    print("REPEATED FIGURES -- check they still mean the same thing:")
    for f, k in counts.most_common():
        if k > 1:
            where = [str(n) for g, n, _ in figs if g == f]
            print("  %-14s x%-3d lines %s" % (f, k, ", ".join(where)))

    return 1 if missing else 0


if __name__ == "__main__":
    sys.exit(main())
