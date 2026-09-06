"""
Cross-check the manuscript's measured figures against the harness output.

A number in a paper whose contribution is measurement must be traceable to a
run. This checks that mechanically: every large integer and every millisecond
figure in the .tex is looked up in the run logs, and anything that is not found
is reported. It does not decide whether a number is *right* -- only whether it
came from somewhere.

Run it after every measurement and before every submission.
"""

import os
import re
import sys

TEX = r"E:\ZK_Delegated_Authority_for_Agentic_Payments\ResearchPaper04\Manuscript\PaperIEEE.tex"
LOGS = r"E:\ZK_Delegated_Authority_for_Agentic_Payments\ResearchPaper04\WorkingHistory"

# Numbers below this are parameters, depths, section numbers and the like, not
# measurements, and checking them produces noise rather than signal.
MIN_INT = 1000

# Figures that are definitional or cited from other work rather than measured
# here, so they will not appear in any run log.
EXEMPT = {
    "2014", "2019", "2020", "2021", "2022", "2023", "2024", "2025", "2026",
    "1993", "1996", "2017", "4337", "8383",
    # Constants of the affine proof-size law. They are not measured and never
    # appear in a log; derived_checks below refits them against the measured
    # rows on every run, which is a stronger test than finding them in a file.
    "81093", "43600",
}


def tex_numbers(text):
    """Large integers written with the LaTeX thousands separator, and ms figures."""
    ints = set()
    for m in re.finditer(r"\$?(\d{1,3}(?:\{,\}\d{3})+)\$?", text):
        ints.add(m.group(1).replace("{,}", ""))
    for m in re.finditer(r"\$(\d{4,})\$", text):
        ints.add(m.group(1))
    times = set()
    for m in re.finditer(r"\$(\d+(?:\.\d+)?)\$\\,ms", text):
        times.add(m.group(1))
    return ints, times


def read_log(path):
    """
    PowerShell writes redirected output as UTF-16LE, so a log read as UTF-8 has a
    null byte between every character and no number in it will ever match. Detect
    that rather than assume an encoding.
    """
    with open(path, "rb") as f:
        raw = f.read()
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff") or raw.count(b"\x00") > len(raw) // 4:
        for enc in ("utf-16", "utf-16-le", "utf-16-be"):
            try:
                return raw.decode(enc)
            except UnicodeDecodeError:
                continue
    return raw.decode("utf-8", errors="replace")


def log_numbers(paths):
    ints, times = set(), set()
    for path in paths:
        body = read_log(path)
        for m in re.finditer(r"(?<![\d.])(\d{4,})", body):
            ints.add(m.group(1))
        for m in re.finditer(r"(?<![\d.])(\d+\.\d+)", body):
            times.add(m.group(1))
        for m in re.finditer(r"(?<![\d.])(\d+)", body):
            ints.add(m.group(1))
    return ints, times


def cost_rows(body):
    """
    (width, proof bytes) for every single-proof row of the cost-structure table.

    Selecting a log by looking for the table's HEADING was wrong: a log can
    carry the rows without the heading, and the heading is prose that may be
    reworded. Selecting it by whether these rows parse cannot drift away from
    what the checks below actually need. The paired row is excluded because it
    is two proofs and carries the affine intercept twice.
    """
    rows = []
    for line in body.splitlines():
        if "two halves" in line:
            continue
        m = re.match(r"\s+\S.*?(\d{3,6})\s+[\d.]+ms\s+(\d{6,})\s+[\d.]+ms\s*$", line)
        if m:
            rows.append((int(m.group(1)), int(m.group(2))))
    return rows


def near(value, pool, tol=0.005):
    """A figure rounded for presentation still counts as traced."""
    try:
        v = float(value)
    except ValueError:
        return False
    for q in pool:
        try:
            w = float(q)
        except ValueError:
            continue
        if w == 0:
            continue
        if abs(v - w) / max(abs(w), 1e-9) <= tol:
            return True
    return False



# Every claim this file recomputes, with the pattern that locates it. A check
# whose subject has been reworded finds nothing and reports nothing, which is
# indistinguishable from a pass, and a double-escaped pattern that matches no
# text at all reports success. So the subjects are listed once and their
# absence is itself a finding.
REQUIRED = [
    ("the permutation accounting",
     r"spends \$([\d{},]+)\$ of its \$([\d{},]+)\$ columns on \$(\d+)\$ Poseidon2"),
    ("the verification model's two constants",
     r"under \$([\d.]+)\$\\,ms of fixed cost plus \$([\d.]+)\$ microseconds per column"),
    ("the packing economy",
     r"halving that count and removing \$([\d{},]+)\$ columns"),
    ("the allowlist marginal",
     r"Merkle inclusions cost \$([\d{},]+)\$ between them"),
    ("the permutation share",
     r"spends \$[\d{},]+\$ of its \$[\d{},]+\$ columns[^.]*\. That is \$[\d.]+\\%\$"),
    ("the composition proof saving", r"saves \$[\d.]+\\%\$ of proof size"),
]


def subjects_present(text):
    """Report any claim this file expects to recompute and cannot locate."""
    return [name for name, pat in REQUIRED if not re.search(pat, text)]


def derived_checks(text, logs, verified):
    """
    Figures the paper computes rather than reads. These have no provenance in any
    log by construction, so flagging them as untraced is useless; what is useful
    is recomputing them. A total that no longer equals the sum of its rows is the
    defect that put two different totals for one construction forty pages apart,
    and it is invisible to a reading pass.

    Every figure this function successfully recomputes is added to `verified`, so
    the untraced list above shrinks as this one grows. Without that the derived
    figures are reported as untraced forever, the count never reaches zero, and a
    check nobody can clear is a check nobody reads.
    """
    problems = []

    def num(tok):
        return int(tok.replace("{,}", "").replace(",", ""))

    # tab:cost: the halves and their bindings must sum to the stated total, in
    # both columns. The row labels are part of this check: renaming a row in the
    # manuscript silently disables it, which is how this check went unrun once,
    # so a missing row is reported rather than skipped.
    rows = {}
    for name, key in (("Compliance half", "comp"), ("Accountability half", "acct"),
                      ("Bindings between the halves", "bind"), ("Total", "total")):
        m = re.search(re.escape(name) + r"\s*&\s*([\d{},]+)\s*&\s*([\d{},]+)", text)
        if m:
            rows[key] = (num(m.group(1)), num(m.group(2)))
    if len(rows) == 4:
        for i, what in ((0, "columns"), (1, "constraints")):
            got = rows["total"][i]
            want = rows["comp"][i] + rows["acct"][i] + rows["bind"][i]
            if got != want:
                problems.append(
                    "tab:cost %s total is %d, rows sum to %d" % (what, got, want))
    else:
        problems.append(
            "tab:cost rows not found (%d of 4); the total is unchecked" % len(rows))

    # The marginal costs quoted in prose must equal differences of measured rows
    # FROM ONE RUN. Reading them across every log would compare a row from one
    # version of the circuit against a row from another, which is precisely the
    # error this script exists to catch, and an earlier version of it made that
    # error itself: it matched a compliance row from a log predating a change
    # that added a column, and reported an off-by-one in the paper that was not
    # there. Recomputation uses the most recent log alone.
    # The newest log is not always a complete one: a run that fails to compile,
    # or is cut short, still leaves a file. Recomputing against it silently
    # unchecks everything, and every figure the derived checks would have
    # verified falls back into the untraced list above, which reads as six new
    # problems in the paper when the paper has not changed. Take the newest log
    # that actually contains the cost-structure table, and say which one it was.
    newest, body = None, ""
    for path in sorted(logs, key=os.path.getmtime, reverse=True):
        candidate = read_log(path)
        if len(cost_rows(candidate)) >= 3:
            newest, body = path, candidate
            break
    if newest is None:
        problems.append("no log under %s contains a cost-structure table; "
                        "every derived figure is unchecked" % LOGS)
        return problems
    problems_prefix = "in %s: " % os.path.basename(newest)
    print("  recomputing against %s" % os.path.basename(newest))
    def logrow(label):
        m = re.search(re.escape(label) + r"\s+(\d+)\s+([\d.]+)ms\s+(\d+)", body)
        return (int(m.group(1)), float(m.group(2)), int(m.group(3))) if m else None

    full = logrow("+ allowlists + revocation d32")
    pub = logrow("allowlists outside the proof")
    if full and pub:
        want = full[0] - pub[0]
        m = re.search(r"costs \$([\d{},]+)\$ columns, \$[\d.]+\$\\,ms of proving", text)
        if m and num(m.group(1)) != want:
            problems.append(
                problems_prefix
                + "allowlist marginal in prose is %d columns, measured rows differ by %d"
                % (num(m.group(1)), want))
    else:
        problems.append(
            problems_prefix + "cost-structure rows not found; marginals unchecked")

    # The affine proof-size law. Refit against the measured (width, bytes) pairs
    # in the newest log rather than trusted from the manuscript, then used to
    # check the proof sizes the paper quotes. The paired row is excluded because
    # it is two proofs and carries the intercept twice.
    pairs = cost_rows(body)

    if len(pairs) < 3:
        problems.append(problems_prefix + "cost-structure rows not parsed; the law is unchecked")
    else:
        # The slope is recovered rather than assumed: it is the one that leaves
        # the fewest distinct intercepts across every measured row. Taking it
        # from consecutive pairs instead was wrong, because the table interleaves
        # hiding and non-hiding rows and a pair straddling the two families lies
        # on neither line.
        slope, intercepts = min(
            ((s, {b - s * w for w, b in pairs}) for s in range(300, 400)),
            key=lambda t: len(t[1]),
        )
        if slope != 352 or intercepts != {81093, 37493}:
            problems.append(
                problems_prefix
                + "proof size fits slope %d with intercepts %s, not 352 with 81093 and 37493"
                % (slope, sorted(intercepts)))

        verified.add("81093")
        verified.add("37493")

        m_total = re.search(r"trace is \$([\d{},]+)\$ bytes in a compact", text)
        m_each = re.search(r"which is \$([\d{},]+)\$ bytes per payment", text)
        if m_total and m_each:
            total, each = num(m_total.group(1)), num(m_each.group(1))
            if each != total // 32:
                problems.append("per-payment proof size is %d, total over 32 rows is %d"
                                % (each, total // 32))
            else:
                verified.add(str(each))
        else:
            problems.append("proof-size sentence not found; bytes per payment unchecked")

        # The cell counts in the zero-knowledge paragraph are a measured width
        # times the row count, so they are checked against the widths in the log.
        widths = {w for w, _ in pairs}
        for phrase in (r"proves \$([\d{},]+)\$ cells", r"non-hiding one \$([\d{},]+)\$ cells"):
            m = re.search(phrase, text)
            if not m:
                continue
            cells = num(m.group(1))
            if cells % 32 or cells // 32 not in widths:
                problems.append("cell count %s is not a measured width times 32 rows"
                                % m.group(1))
            else:
                verified.add(str(cells))

        # The permutation accounting: the columns attributed to Poseidon2 are the
        # permutation count times the measured width of one, and the remainder
        # is the stated total less that. Both are derived, so they are checked
        # rather than looked for.
        m = re.search(
            r"spends \$([\d{},]+)\$ of its \$([\d{},]+)\$ columns on \$(\d+)\$ Poseidon2",
            text)
        m_w = re.search(r"^\s+1\s+(\d+)\s+\d+\s+3\s*$", body, re.M)
        if m and m_w:
            attributed, total, perms = num(m.group(1)), num(m.group(2)), int(m.group(3))
            width = int(m_w.group(1))
            if attributed != perms * width:
                problems.append(
                    "permutation columns quoted at %d; %d permutations of %d is %d"
                    % (attributed, perms, width, perms * width))
            else:
                verified.add(str(attributed))
                # Anchored after the sentence it belongs to. Searching the whole
                # manuscript found an unrelated "is $N$ columns" earlier in the
                # same section and reported the paper wrong about its own
                # arithmetic.
                rest = re.search(r"is \$([\d{},]+)\$ columns", text[m.end():])
                if rest and num(rest.group(1)) == total - attributed:
                    verified.add(rest.group(1).replace("{,}", ""))
                elif rest:
                    problems.append(
                        "the remainder is quoted at %s; %d less %d is %d"
                        % (rest.group(1), total, attributed, total - attributed))

        # The linear model of verification cost. Its two constants are fitted
        # to the narrowest and widest single-proof rows, so they are derived and
        # appear in no log; refitting them here is what keeps the superlinearity
        # argument honest, since the whole point of that paragraph is that the
        # model reproduces one arrangement and fails on the other.
        # The intercept is quoted as a bound, not a value: it refits to 1.39
        # and 1.47 ms across two runs of the same circuit, so two decimals would
        # be precision the measurement does not have. The slope is stable and is
        # checked as a value.
        m = re.search(
            r"under \$([\d.]+)\$\\,ms of fixed cost plus \$([\d.]+)\$ microseconds per column",
            text)
        if m and len(pairs) >= 2:
            ver = {}
            for line in body.splitlines():
                mm = re.match(r"\s+\S.*?(\d{3,6})\s+[\d.]+ms\s+\d{6,}\s+([\d.]+)ms\s*$", line)
                if mm and "two halves" not in line:
                    ver[int(mm.group(1))] = float(mm.group(2)) * 32.0
            if len(ver) >= 2:
                lo, hi = min(ver), max(k for k in ver if k <= 14000) if any(
                    k <= 14000 for k in ver) else max(ver)
                slope = (ver[hi] - ver[lo]) / (hi - lo)
                fixed = ver[lo] - slope * lo
                if fixed > float(m.group(1)):
                    problems.append(
                        "the fitted fixed cost is bounded by %s ms and refits to %.2f ms"
                        % (m.group(1), fixed))
                else:
                    verified.add(m.group(1))
                if abs(float(m.group(2)) - slope * 1000) > 0.1:
                    problems.append(
                        "the fitted per-column cost is quoted at %s us and refits to %.2f us"
                        % (m.group(2), slope * 1000))
            else:
                problems.append("the verification model could not be refitted")

        # The packing economy: halving the slot permutations. Both terms are
        # measured --- the slot count from the composed configuration and the
        # width of one permutation from the Poseidon2 table --- so the product
        # is recomputed here rather than trusted, like every other figure this
        # section derives.
        m = re.search(
            r"halving that count and removing \$([\d{},]+)\$ columns", text)
        if m:
            perm = None
            for line in body.splitlines():
                mm = re.match(r"\s+1\s+(\d{3})\s+\d+\s+3\s*$", line)
                if mm:
                    perm = int(mm.group(1))
                    break
            slots = None
            ms = re.search(r"one for each of the \$(\d+)\$ padded slots", text)
            if ms:
                slots = int(ms.group(1))
            if perm and slots:
                want = (slots // 2) * perm
                if num(m.group(1)) != want:
                    problems.append(
                        "the packing economy is quoted at %s columns and "
                        "recomputes to %d (%d slots halved, %d columns each)"
                        % (m.group(1), want, slots, perm))
                else:
                    verified.add(m.group(1).replace(",", "").replace("{", "").replace("}", ""))
            else:
                problems.append(
                    "the packing economy could not be recomputed: no measured "
                    "permutation width or slot count found")

        # The two allowlists quoted as one figure are two measured components.
        m = re.search(r"Merkle inclusions cost \$([\d{},]+)\$ between them", text)
        m_one = re.search(r"^\s+16 / 1\s+(\d+)\s", body, re.M)
        if m and m_one:
            claimed, one = num(m.group(1)), int(m_one.group(1))
            if claimed != 2 * one:
                problems.append("the two inclusions are quoted at %d, twice the measured %d is %d"
                                % (claimed, one, 2 * one))
            else:
                verified.add(str(claimed))

    # Percentages. Every checker in this project was blind to them: a figure
    # below a thousand with a per-cent sign after it is invisible to the integer
    # sweep and to the millisecond sweep alike. Four were stale when this was
    # written, including a claim that composing saves 0.6 per cent of proof size
    # when the measured saving had halved to 0.3.
    #
    # Each entry names the percentage as it appears, and the two measured
    # quantities it relates. The tolerance is half a unit in the last digit
    # quoted, so a figure written to one decimal is held to one decimal.
    def pct(claimed, num_val, den_val, what):
        if num_val is None or den_val is None:
            problems.append("%s: a measured quantity for this was not found" % what)
            return
        want = 100.0 * num_val / den_val
        digits = len(claimed.split(".")[1]) if "." in claimed else 0
        if abs(float(claimed) - want) > 0.5 * 10 ** (-digits):
            problems.append("%s is quoted at %s%% and computes to %.2f%%"
                            % (what, claimed, want))

    widths = dict(pairs)
    by_width = {w: b for w, b in pairs}
    composed = max(widths) if widths else None

    m = re.search(r"spends \$([\d{},]+)\$ of its \$([\d{},]+)\$ columns[^.]*\. That is \$([\d.]+)\\%\$", text)
    if m:
        pct(m.group(3), num(m.group(1)), num(m.group(2)), "the permutation share")

    m = re.search(r"saves \$([\d.]+)\\%\$ of proof size", text)
    m_two = re.search(r"two separate proofs, same payments\s+(\d+)", body)
    if m and m_two and composed:
        two = int(m_two.group(1))
        pct(m.group(1), two - by_width[composed], two, "the composition proof saving")
    elif m:
        problems.append("the composition proof saving could not be recomputed")

    return problems


def main():
    if not os.path.isfile(TEX):
        print("FATAL: manuscript not found: " + TEX)
        return 1
    logs = []
    if os.path.isdir(LOGS):
        for name in sorted(os.listdir(LOGS)):
            if name.startswith("run_") and name.endswith(".txt"):
                logs.append(os.path.join(LOGS, name))
    if not logs:
        print("FATAL: no run_*.txt logs under " + LOGS)
        return 1

    with open(TEX, "r", encoding="utf-8", errors="replace") as f:
        text = f.read()

    t_ints, t_times = tex_numbers(text)
    l_ints, l_times = log_numbers(logs)

    print("NUMERIC TRACEABILITY")
    print("manuscript " + TEX)
    print("logs       %d file(s) under %s" % (len(logs), LOGS))
    print("")

    verified = set()
    absent = subjects_present(text)
    derived_early = derived_checks(text, logs, verified)
    if absent:
        derived_early = ["this check's subject is not in the manuscript: " + a
                         for a in absent] + derived_early
    missing_i = sorted(
        (v for v in t_ints if v not in EXEMPT and v not in l_ints and v not in verified),
        key=lambda x: int(x),
    )
    print("=== large integers in the paper with no match in any run log ===")
    if missing_i:
        for v in missing_i:
            ctx = ""
            m = re.search(r".{0,70}" + re.escape(v[:2]) + r"[\d{},]*" + re.escape(v[-2:]) + r".{0,50}", text)
            if m:
                ctx = " ".join(m.group(0).split())
            print("  %-12s %s" % (v, ctx[:110]))
    else:
        print("  none")
    print("")

    # Integer millisecond figures live in the log's integer pool, not its float
    # pool. Checking them against floats alone reported every whole-number
    # timing as untraced, which is how a figure that was in the log came back
    # flagged.
    missing_t = sorted(
        (v for v in t_times
         if not near(v, l_times) and v not in l_times and v not in l_ints
         and v not in verified),
        key=float,
    )
    print("=== millisecond figures with no match in any run log ===")
    if missing_t:
        for v in missing_t:
            print("  %s ms" % v)
    else:
        print("  none")
    print("")

    print("=== figures the paper derives, recomputed ===")
    derived = derived_early
    if derived:
        for d in derived:
            print("  " + d)
    else:
        print("  totals and marginals agree with the measured rows")
    print("")

    bad = len(missing_i) + len(missing_t) + len(derived)
    print("UNTRACED FIGURES: %d" % bad)
    print("")
    print("A figure listed above is not necessarily wrong. It is a figure this")
    print("script could not find in a run log, which is the condition under which")
    print("a stale number survives. Trace each one to a table or remove it.")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
