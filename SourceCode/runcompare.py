#!/usr/bin/env python3
"""
TWO RUNS OF THE HARNESS, COMPARED, AND THE TABLE BODIES THAT FOLLOW

Section 13.1 splits the figures in two. A width, a constraint count, a proof
size and a control verdict are deterministic: one run is the measurement, and
if a second run disagrees the cause is a bug rather than noise. A wall-clock
figure is not: a single sample is not a measurement however many iterations
sit behind it, so the whole experiment is repeated and the manuscript quotes
one named run of the two.

This does both jobs. Any deterministic figure that moves between the runs is
reported as an ERROR, since nothing in the circuit changed between them. Every
timing is reported with its agreement, and the LaTeX bodies are printed from
whichever run is named, so no figure is retyped on its way into the paper.

Usage:
    python runcompare.py run_partition_20260906.txt run_partition_second.txt
    python runcompare.py run_one.txt run_two.txt --quote 2
"""

import re
import sys


def load(path):
    """PowerShell's Tee-Object writes UTF-16LE, cargo writes UTF-8, and a log
    that decodes to mostly NUL bytes parses as an empty run rather than as an
    error. Decide the encoding from the bytes."""
    raw = open(path, "rb").read()
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
        text = raw.decode("utf-16")
    elif raw[:3] == b"\xef\xbb\xbf":
        text = raw[3:].decode("utf-8", errors="replace")
    elif b"\x00" in raw[:400]:
        text = raw.decode("utf-16-le", errors="replace")
    else:
        text = raw.decode("utf-8", errors="replace")
    return text.replace("\r\n", "\n").replace("\r", "\n").split("\n")


def section(lines, header, after=0):
    """Line index just past a banner, searching from `after`."""
    for i in range(after, len(lines)):
        if header in lines[i]:
            return i
    return None


def numbers(text):
    return [float(x) for x in re.findall(r"-?\d+\.?\d*", text.replace(",", ""))]


def height_table(lines, start):
    """The min/q1/median/q3/per-payment table that follows a header line."""
    out = {}
    for line in lines[start:start + 12]:
        s = line.strip()
        if not s or s.startswith("-") or s.startswith("rows"):
            continue
        n = numbers(s)
        if len(n) == 6 and n[0] in (8, 16, 32):
            out[int(n[0])] = n[1:]
        elif out:
            break
    return out


def proving_and_verification(lines):
    """Both height tables. The first is proving, the second verification."""
    found = []
    for i, line in enumerate(lines):
        if "per payment" in line and "median" in line:
            t = height_table(lines, i + 1)
            if t:
                found.append(t)
    return (found + [{}, {}])[:2]


def cost_structure(lines):
    i = section(lines, "COST STRUCTURE:")
    if i is None:
        return {}
    out = {}
    for line in lines[i:i + 30]:
        s = line.strip()
        if not s or s.startswith("-") or s.startswith("variant"):
            continue
        m = re.match(r"^(.*?)\s{2,}(\d+)\s+([\d.]+)ms\s+(\d+)\s+([\d.]+)ms$", s)
        if m:
            out[m.group(1).strip()] = (int(m.group(2)), float(m.group(3)),
                                       int(m.group(4)), float(m.group(5)))
        elif out and "Medians" in s:
            break
    return out


def one_payment(lines):
    i = section(lines, "WHAT ONE PAYMENT COSTS")
    if i is None:
        return {}
    out = {}
    for line in lines[i:i + 14]:
        s = line.strip()
        if not s or s.startswith("-") or s.startswith("min"):
            continue
        m = re.match(r"^([a-z][a-z, ]+?)\s{2,}([\d.]+)\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)", s)
        if m:
            out[m.group(1).strip()] = [float(m.group(k)) for k in (2, 3, 4, 5)]
    return out


def verdicts(lines):
    out = {}
    for line in lines:
        m = re.match(r"^\s{2,}(.*?)\s{2,}(true|false)\s*$", line)
        if m:
            out[m.group(1).strip()] = m.group(2)
    return out


def pct(a, b):
    return 0.0 if a == b else abs(a - b) / ((a + b) / 2) * 100


def compare(name, one, two, deterministic, errors, drifts):
    keys = sorted(set(one) | set(two), key=str)
    for k in keys:
        if k not in one or k not in two:
            errors.append("%s: %r present in only one run" % (name, k))
            continue
        a, b = one[k], two[k]
        a = a if isinstance(a, (list, tuple)) else [a]
        b = b if isinstance(b, (list, tuple)) else [b]
        for j, (x, y) in enumerate(zip(a, b)):
            if j in deterministic:
                if x != y:
                    errors.append("%s / %s field %d: %s vs %s -- deterministic, "
                                  "must not move" % (name, k, j, x, y))
            else:
                drifts.append((pct(x, y), "%s / %s field %d" % (name, k, j)))


def tex_heights(t, label):
    print("%% %s" % label)
    for r in (8, 16, 32):
        if r in t:
            v = t[r]
            print("%-2d & $%.1f$ & $%.1f$ & $%.1f$ & $%.1f$ & $%.2f$ \\\\"
                  % (r, v[0], v[1], v[2], v[3], v[4]))
    print()


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    quote = 2 if "--quote" in sys.argv and sys.argv[-1] == "2" else 1
    if len(args) != 2:
        print(__doc__)
        return 2

    runs = [load(p) for p in args]
    prov = [proving_and_verification(r)[0] for r in runs]
    verf = [proving_and_verification(r)[1] for r in runs]
    cost = [cost_structure(r) for r in runs]
    pay = [one_payment(r) for r in runs]
    vs = [verdicts(r) for r in runs]

    # A table that parsed as empty is a parse failure, not an agreement. Report
    # it as an error rather than letting the run compare nothing and pass.
    fatal = []
    for label, got in (("proving by height", prov), ("verification by height", verf),
                       ("cost structure", cost), ("one payment", pay),
                       ("control verdicts", vs)):
        for n, g in enumerate(got, start=1):
            if not g:
                fatal.append("%s: parsed nothing from run %d (%s)" % (label, n, args[n - 1]))
    if fatal:
        print("PARSE FAILURE -- nothing was compared, so nothing is confirmed")
        for f in fatal:
            print("  %s" % f)
        return 2

    errors, drifts = [], []
    compare("proving by height", prov[0], prov[1], set(), errors, drifts)
    compare("verification by height", verf[0], verf[1], set(), errors, drifts)
    compare("one payment", pay[0], pay[1], set(), errors, drifts)
    # columns and proof bytes are deterministic; the two timings are not
    compare("cost structure", cost[0], cost[1], {0, 2}, errors, drifts)

    for k in sorted(set(vs[0]) | set(vs[1])):
        if vs[0].get(k) != vs[1].get(k):
            errors.append("verdict %r: %s vs %s" % (k, vs[0].get(k), vs[1].get(k)))

    print("RUN 1: %s" % args[0])
    print("RUN 2: %s" % args[1])
    print()
    print("verdicts compared: %d" % len(set(vs[0]) | set(vs[1])))
    print("timing figures compared: %d" % len(drifts))
    print()

    if errors:
        print("ERRORS -- these must be understood before either run is quoted")
        for e in errors:
            print("  %s" % e)
        print()
    else:
        print("Every deterministic figure and every control verdict is identical "
              "across the two runs.")
        print()

    if drifts:
        drifts.sort(reverse=True)
        worst = drifts[0]
        print("Timing agreement: worst %.2f%% (%s), median %.2f%%"
              % (worst[0], worst[1], sorted(d[0] for d in drifts)[len(drifts) // 2]))
        over = [d for d in drifts if d[0] > 2.0]
        if over:
            print("  Above two percent, which the protocol paragraph claims as its bound:")
            for d in over:
                print("    %.2f%%  %s" % d)
        else:
            print("  Nothing exceeds two percent, so the protocol paragraph's claim holds.")
        print()

    q = quote - 1
    print("=" * 78)
    print("TABLE BODIES FROM RUN %d -- PASTE BETWEEN THE MIDRULES" % quote)
    print("=" * 78)
    print()
    tex_heights(prov[q], "tab:proving")
    tex_heights(verf[q], "tab:verify:time")

    print("% tab:composed")
    order = [("composed, proving", "Composed, proving"),
             ("composed, verification", "Composed, verification"),
             ("two halves, proving", "Two halves, proving"),
             ("two halves, verification", "Two halves, verification")]
    for key, label in order:
        if key in pay[q]:
            v = pay[q][key]
            print("%-26s & $%.2f$ & $%.2f$ & $%.2f$ & $%.2f$ \\\\"
                  % (label, v[0], v[1], v[2], v[3]))
    print()

    print("% tab:structure -- columns and bytes are run-independent")
    for k, v in cost[q].items():
        print("%-34s & %d & $%.2f$\\,ms & %d & $%.2f$\\,ms \\\\"
              % (k, v[0], v[1], v[2], v[3]))
    print()

    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
