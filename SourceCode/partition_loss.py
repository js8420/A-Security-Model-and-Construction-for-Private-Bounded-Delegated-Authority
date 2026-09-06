"""
Capital-efficiency cost of static budget partitioning.

A budget B split into k partitions of B/k each buys concurrency k: k proofs
can be generated in parallel because each touches a different piece of state,
so no sequencer is needed to order them.

The cost is fragmentation. A payment assigned to partition j is blocked when
that partition's remaining balance is below the amount, even though the
aggregate remaining balance across all partitions is sufficient. This file
measures that cost as a function of k.

Four properties of the measurement, each of which materially affects the
result and none of which is optional:

  EXHAUSTION   Each run continues until the delegation is spent out, not for
               a fixed number of payments. A run that stops with budget left
               over measures the payment-size tail, not fragmentation.

  RETRY        A real agent whose payment is refused on one partition tries
               another. Dropping the payment on first refusal overstates the
               blocked rate. Both regimes are reported: retries=0 is the
               worst case, retries=k-1 is the realistic one.

  PAIRING      Every value of k is driven by the identical sequence of
               payment amounts and the identical sequence of partition
               choices (common random numbers). Without this the comparison
               across k is confounded with sampling noise.

  INVARIANCE   The claim that admissible k is governed by payment-size
               variance and not by budget or payment count is tested by
               sweeping B and n, not asserted.

Pure standard library. No dependencies. Deterministic under a fixed seed.
"""

import math
import random
import statistics

SEED = 20260827

DECIMALS = 6
UNIT = 10 ** DECIMALS


def draw_amounts(rng, n, mean_tokens, sigma, family="lognormal"):
    """
    Payment sizes in canonical units, all families scaled to the same
    arithmetic mean so the comparison is about shape rather than scale.

    lognormal   many small, thin tail; sigma sets dispersion
    exponential memoryless, fixed shape, no dispersion parameter
    pareto      heavy tail; sigma reused as the tail index alpha
    """
    out = []
    for _ in range(n):
        if family == "lognormal":
            mu = math.log(mean_tokens) - (sigma ** 2) / 2.0
            v = rng.lognormvariate(mu, sigma)
        elif family == "exponential":
            v = rng.expovariate(1.0 / mean_tokens)
        elif family == "pareto":
            alpha = max(1.1, sigma)
            xm = mean_tokens * (alpha - 1.0) / alpha
            v = xm * rng.paretovariate(alpha)
        else:
            raise ValueError(family)
        out.append(max(1, int(round(v * UNIT))))
    return out


def draw_choices(rng, n, max_k):
    """
    Partition preference orders, drawn once and reused across every k so that
    all values of k face identical decisions. Each entry is a permutation of
    range(max_k); for a given k the order is the subsequence of entries below
    k, which preserves relative ordering across k.
    """
    out = []
    for _ in range(n):
        perm = list(range(max_k))
        rng.shuffle(perm)
        out.append(perm)
    return out


def run_once(budget_units, k, amounts, choices, retries, policy="random"):
    """
    One simulated delegation lifetime.

    The run ends when the delegation is spent out, defined as no partition
    being able to fund the smallest amount remaining in the stream, or when
    the amount stream is exhausted.

    A payment is counted as blocked only when it could have been funded from
    the aggregate remaining balance but was refused because no partition it
    was willing to try held enough. That is the fragmentation loss; a payment
    exceeding the aggregate is the delegation ending, not a partition defect.

    policy is how the agent picks among partitions. random is the order it was
    handed, which assumes nothing; best_fit takes the tightest partition that
    still covers the amount, worst_fit the loosest. The first two are the
    standard bin-packing heuristics and the third keeps balances level.
    """
    part = [budget_units // k] * k
    part[0] += budget_units - sum(part)

    attempted = 0
    blocked = 0
    spent = 0

    for idx, a in enumerate(amounts):
        aggregate = sum(part)
        if aggregate < a:
            break

        order = [j for j in choices[idx] if j < k][:retries + 1]
        if policy == "best_fit":
            order = sorted(order, key=lambda j: (part[j] < a, part[j]))
        elif policy == "worst_fit":
            order = sorted(order, key=lambda j: (part[j] < a, -part[j]))
        attempted += 1
        placed = False
        for j in order:
            if part[j] >= a:
                part[j] -= a
                spent += a
                placed = True
                break
        if not placed:
            blocked += 1

    return {"attempted": attempted, "blocked": blocked,
            "spent": spent, "budget": budget_units}


def quartiles(v):
    """
    min, Q1, median, Q3 by nearest rank, matching how the proving-time
    measurements elsewhere in this work are summarised. A bare mean hides
    whether a figure is a property of the process or of one unlucky draw, and
    reporting one statistic here and four there would be two standards in one
    paper.
    """
    w = sorted(v)
    pick = lambda f: w[round((len(w) - 1) * f)]
    return w[0], pick(0.25), pick(0.5), pick(0.75)


def measure(budget_tokens, mean_tokens, sigma, ks, trials, stream_len,
            retries, max_k, family="lognormal", policy="random"):
    """
    Returns [(k, blocked_rates, utilisations)] with one entry per trial rather
    than a mean, so callers may summarise across trials and seeds together.
    Trial t uses the same amount stream and the same choice stream for every k.
    """
    budget_units = int(budget_tokens * UNIT)
    per_k = {k: {"br": [], "ut": []} for k in ks}

    for t in range(trials):
        rng = random.Random(SEED + t)
        amounts = draw_amounts(rng, stream_len, mean_tokens, sigma, family)
        choices = draw_choices(rng, stream_len, max_k)
        for k in ks:
            r = run_once(budget_units, k, amounts, choices, retries, policy)
            att = r["attempted"] if r["attempted"] else 1
            per_k[k]["br"].append(r["blocked"] / att)
            per_k[k]["ut"].append(r["spent"] / r["budget"])

    return [(k, per_k[k]["br"], per_k[k]["ut"]) for k in ks]


def admissible_k(rows, tolerance):
    """
    Largest k whose MEDIAN blocked rate meets the tolerance. The median rather
    than the mean, because a single trial in which the delegation happens to
    exhaust early can move a mean across a rung.
    """
    ok = [k for (k, br, _ut) in rows if statistics.median(br) <= tolerance]
    return max(ok) if ok else None


TOLERANCES = (0.001, 0.005, 0.01, 0.02, 0.05, 0.10)


def assignment_sweep(ks, trials, retries, max_k, stream_len, tolerance,
                     seeds=(0,)):
    """
    What partition selection is worth. The figures elsewhere assume the agent
    takes whatever partition it is handed, which is the conservative case; an
    agent that chose deliberately would do better, and this measures by how
    much.
    """
    global SEED
    base = SEED
    print()
    print("PARTITION SELECTION POLICY, FULL RETRY")
    print("=" * 78)
    print(f"  {'policy':<14} {'sigma':>6} {'adm. k':>10} "
          f"{'blocked at k=32':>28} {'blocked at k=64':>28}")
    print(f"  {'-'*14} {'-'*6} {'-'*10} {'-'*18} {'-'*18}")
    for policy in ("random", "best_fit", "worst_fit"):
        for sigma in (1.0, 1.8):
            adm, at32, at64 = set(), [], []
            for offset in seeds:
                SEED = base + offset * 1000
                rows = measure(1000, 1, sigma, ks, trials, stream_len,
                               retries, max_k, "lognormal", policy)
                adm.add(admissible_k(rows, tolerance) or 0)
                for (k, br, _ut) in rows:
                    if k == 32:
                        at32.extend(br)
                    if k == 64:
                        at64.extend(br)
            v = sorted(adm)
            shown = str(v[0]) if len(v) == 1 else f"{v[0]}-{v[-1]}"
            m32 = quartiles(at32)
            m64 = quartiles(at64)
            print(f"  {policy:<14} {sigma:>6} {shown:>10} "
                  f"{m32[2]:>10.2%} [{m32[0]:.2%}, {m32[3]:.2%}]"
                  f"{m64[2]:>10.2%} [{m64[0]:.2%}, {m64[3]:.2%}]")
    SEED = base
    print()
    print("  Blocked rates are medians with min and Q3 in brackets, pooled over")
    print("  seeds and trials. The k=32 and k=64 columns are where the policies")
    print("  separate; below that everything is near zero.")


def tolerance_sweep(ks, trials, retries, max_k, stream_len, seeds=(0,)):
    """
    Admissible k against the blocked-rate tolerance, over several seeds.

    A seed makes the run repeatable, not robust: every entry still rests on one
    random draw, and an admissible k sitting near a boundary can move to the
    next rung under a different draw. Where the seeds disagree the cell shows
    the range.
    """
    print()
    print("ADMISSIBLE k AGAINST TOLERANCE AND DISTRIBUTION FAMILY, FULL RETRY")
    print("=" * 78)
    head = "  {:<24}".format("family / parameter") + "".join(
        "{:>8.1%}".format(t) for t in TOLERANCES)
    print(head)
    print("  " + "-" * 24 + "".join("{:>8}".format("-" * 6) for _ in TOLERANCES))

    cases = [
        ("lognormal sigma 1.0", "lognormal", 1.0),
        ("lognormal sigma 1.4", "lognormal", 1.4),
        ("lognormal sigma 1.8", "lognormal", 1.8),
        ("exponential", "exponential", 1.0),
        ("pareto alpha 1.5", "pareto", 1.5),
        ("pareto alpha 2.5", "pareto", 2.5),
    ]
    global SEED
    base = SEED
    for label, fam, sig in cases:
        per_tol = {t: set() for t in TOLERANCES}
        for offset in seeds:
            SEED = base + offset * 1000
            rows = measure(1000, 1, sig, ks, trials, stream_len, retries, max_k, fam)
            for t in TOLERANCES:
                per_tol[t].add(admissible_k(rows, t) or 0)
        cells = ""
        for t in TOLERANCES:
            vals = sorted(per_tol[t])
            cells += "{:>8}".format(
                str(vals[0]) if len(vals) == 1 else f"{vals[0]}-{vals[-1]}")
        print("  {:<24}{}".format(label, cells))
    SEED = base
    print()
    print(f"  {len(seeds)} seeds per cell. A range means the seeds disagreed and")
    print("  the entry is not determined by the data. Zero means no k qualified.")


def sweep(label, budget_tokens, mean_tokens, sigma, ks, trials, stream_len,
          retries, max_k, tolerance, seeds=(0,)):
    """
    Blocked rate against k. Rates are means over seeds; the admissible k is
    given as a range when the seeds disagree, since a single draw can put a
    boundary case on either side.
    """
    global SEED
    base = SEED
    per_k = {k: [] for k in ks}
    per_ut = {k: [] for k in ks}
    adm = set()
    for offset in seeds:
        SEED = base + offset * 1000
        rows = measure(budget_tokens, mean_tokens, sigma, ks, trials,
                       stream_len, retries, max_k)
        for (k, br, ut) in rows:
            per_k[k].extend(br)
            per_ut[k].extend(ut)
        adm.add(admissible_k(rows, tolerance) or 0)
    SEED = base

    print()
    print(label)
    print("=" * 78)
    print(f"  budget {budget_tokens:,} tokens   mean payment {mean_tokens}"
          f"   sigma {sigma}   retries {retries}   trials {trials}"
          f"   seeds {len(seeds)}")
    print()
    print(f"  {'k':>4} {'min':>9} {'Q1':>9} {'median':>9} {'Q3':>9} "
          f"{'utilisation':>13}")
    print(f"  {'-'*4} {'-'*9} {'-'*9} {'-'*9} {'-'*9} {'-'*13}")
    for k in ks:
        lo, q1, med, q3 = quartiles(per_k[k])
        _, _, umed, _ = quartiles(per_ut[k])
        print(f"  {k:>4} {lo:>8.2%} {q1:>8.2%} {med:>8.2%} {q3:>8.2%} "
              f"{umed:>12.2%}")
    print()
    print(f"  {len(per_k[ks[0]])} runs per row, {len(seeds)} seeds by {trials} "
          f"trials. Quartiles, not means:")
    print("  the blocked rate is a property of a draw as much as of k, and a")
    print("  single figure cannot say which.")
    a = sorted(adm)
    shown = str(a[0]) if len(a) == 1 else f"{a[0]}-{a[-1]}"
    print()
    print(f"  tolerance {tolerance:.2%}   largest admissible k: {shown}")
    return a


def invariance(ks, trials, retries, max_k, tolerance, seeds=(0,)):
    """
    Admissible k against budget at fixed payment count. Budget and payment
    count cannot vary independently while the delegation still spends out,
    since n * mean = B at exhaustion, so n is held fixed and B is scaled by
    scaling the mean payment. Ranges mean the seeds disagreed.
    """
    global SEED
    base = SEED
    print()
    print("INVARIANCE OF ADMISSIBLE k IN BUDGET, AT FIXED PAYMENT COUNT")
    print("=" * 78)
    print(f"  {'sigma':>6} {'n':>7} {'B=100':>10} {'B=1,000':>10} {'B=10,000':>10}")
    print(f"  {'-'*6} {'-'*7} {'-'*10} {'-'*10} {'-'*10}")
    for sigma in (1.0, 1.4, 1.8):
        for n_target in (250, 1000):
            cells = []
            for budget_tokens in (100, 1000, 10000):
                got = set()
                for offset in seeds:
                    SEED = base + offset * 1000
                    rows = measure(budget_tokens, budget_tokens / float(n_target),
                                   sigma, ks, trials, 3 * n_target, retries, max_k)
                    got.add(admissible_k(rows, tolerance) or 0)
                v = sorted(got)
                cells.append(str(v[0]) if len(v) == 1 else f"{v[0]}-{v[-1]}")
            print(f"  {sigma:>6} {n_target:>7} {cells[0]:>10} {cells[1]:>10} {cells[2]:>10}")
        print()
    SEED = base
    print("  Invariance holds where a row reads the same across the three budgets.")


if __name__ == "__main__":
    KS = [1, 2, 4, 8, 16, 32, 64]
    MAX_K = 64
    TRIALS = 20
    STREAM = 4000
    TOL = 0.01

    SEEDS = range(8)

    a_lo_0 = sweep("NARROW DISTRIBUTION, NO RETRY (worst case)",
                   1000, 1, 1.0, KS, TRIALS, STREAM, 0, MAX_K, TOL, SEEDS)
    a_hi_0 = sweep("WIDE DISTRIBUTION, NO RETRY (worst case)",
                   1000, 1, 1.8, KS, TRIALS, STREAM, 0, MAX_K, TOL, SEEDS)
    a_lo_r = sweep("NARROW DISTRIBUTION, FULL RETRY",
                   1000, 1, 1.0, KS, TRIALS, STREAM, MAX_K - 1, MAX_K, TOL, SEEDS)
    a_hi_r = sweep("WIDE DISTRIBUTION, FULL RETRY",
                   1000, 1, 1.8, KS, TRIALS, STREAM, MAX_K - 1, MAX_K, TOL, SEEDS)

    invariance(KS, 10, MAX_K - 1, MAX_K, TOL, SEEDS)

    assignment_sweep(KS, TRIALS, MAX_K - 1, MAX_K, STREAM, TOL, seeds=range(8))

    tolerance_sweep(KS, TRIALS, MAX_K - 1, MAX_K, STREAM, seeds=range(8))

    print()
    print("SUMMARY")
    print("=" * 78)
    def rng(a):
        return str(a[0]) if len(a) == 1 else f"{a[0]}-{a[-1]}"
    print(f"  no retry     sigma 1.0 -> k = {rng(a_lo_0)}     sigma 1.8 -> k = {rng(a_hi_0)}")
    print(f"  full retry   sigma 1.0 -> k = {rng(a_lo_r)}     sigma 1.8 -> k = {rng(a_hi_r)}")
    print()
