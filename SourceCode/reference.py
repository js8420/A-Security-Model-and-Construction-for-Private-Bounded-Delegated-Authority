"""
Reference implementation of the bounded-delegation construction: budget tree,
deterministic covering-set selection, tag keys, share publication, and the
extractor. Produces the positive and negative test vectors the circuit is
checked against.
"""

import hashlib
import json
import sys

# Goldilocks. Chosen in the design notes for the circuit field.
P = (1 << 64) - (1 << 32) + 1

DECIMALS = 6
UNIT = 10 ** DECIMALS


def h(*parts):
    d = hashlib.sha256()
    for p in parts:
        d.update(p if isinstance(p, bytes) else str(p).encode())
    return int.from_bytes(d.digest(), "big") % P


def cover(lo, hi):
    """Canonical decomposition of [lo, hi) into maximal aligned blocks."""
    out = []
    while lo < hi:
        size = lo & -lo if lo else 1 << 62
        while size > hi - lo:
            size >>= 1
        out.append((lo, size))
        lo += size
    return out


class Tree:
    """A padded index space of m = 2^depth units. Only the first `spendable`
    of them can be charged; the rest are the padding that keeps revocation from
    publishing the budget."""

    def __init__(self, depth, k, root_key):
        assert k & (k - 1) == 0 and k <= (1 << depth)
        self.depth = depth
        self.m = 1 << depth
        # The padded index space. The spendable count is a property of the
        # delegation, not of the tree, and is not in general a power of two.
        self.k = k
        self.root_key = root_key

    def key(self, offset, size):
        """
        Tag key of the node spanning [offset, offset+size). Derived down the
        path from the root, so a node's key yields its descendants' keys and
        nothing else.
        """
        kk = self.root_key
        span = self.m
        lo = 0
        while span > size:
            span //= 2
            bit = 0 if offset < lo + span else 1
            if bit:
                lo += span
            kk = h(kk, bit, span)
        return kk


class Delegation:
    def __init__(self, policy, depth, k, secret, root_key):
        self.pol = policy
        self.tree = Tree(depth, k, root_key)
        self.secret = secret
        # Spendable units: three quarters of the padded range, so the padding
        # is exercised rather than degenerate.
        self.spendable = (self.tree.m * 3) // 4
        self.velocity = []
        self.transcript = []
        self.settled = 0
        # Indices already SETTLED under this delegation. Condition (I5): the
        # domain refuses a repeated index. A refusal is not terminal --- a
        # payment refused on the racy velocity bound may be resubmitted once
        # the window rolls, which is what keeps that race a delay rather than a
        # destroyed payment. The circuit cannot enforce this: freshness is a
        # predicate on a set of payments and a proof sees one.
        self.indices = set()
        # The single spend counter. A payment reserves [s, s+n) and advances it
        # before the proof is formed. Runs are contiguous and none is reused.
        self.counter = 0
        # What Pay reports as assigned, summed: the model's committed(D). The
        # syntax requires a scheme to report it because a challenger cannot read
        # assignment out of a state update, and three arguments need it. Here it
        # is the counter in value terms, so committed = u * counter always.
        self.committed = 0
        self.revoked_at = None
        self.seq = 0


def units(amount):
    """Amounts round up so accounted spend never falls below settled spend."""
    return -(-amount // UNIT)


def satisfies(pol, m, cum, vel_count):
    """
    C1-C6 as an explicit conjunction, one verdict per clause.

    This is the whole predicate, and no single mechanism enforces it. The paper
    splits it three ways and the split is its organising decision, so the code
    keeps the three apart rather than evaluating one dictionary and calling that
    compliance:

      stateless(pol, m)   C1, C3, C4, C5 --- what a payment proof establishes
                          about a payment on its own
      C2                  the cumulative budget, enforced by the TREE. It appears
                          here for completeness and `c2_clause_binds_nothing`
                          below shows why it cannot be enforced as a clause: the
                          cumulative total is supplied by the prover.
      C6                  the rate limit, enforced by the RESERVE, which counts
                          settlements. A proof cannot: the count is over the
                          settled set, which is the impossibility the paper
                          states as its freshness proposition.
    """
    return {
        **stateless(pol, m),
        "C2": cum + m["amount"] <= pol["budget"],
        "C6": vel_count + 1 <= pol["velocity_n"],
    }


def stateless(pol, m):
    """The clauses a payment proof establishes about one payment alone."""
    return {
        "C1": m["amount"] <= pol["cap"],
        "C3": m["merchant"] in pol["merchants"],
        "C4": m["category"] in pol["categories"],
        "C5": pol["t_start"] <= m["t"] <= pol["t_expiry"],
    }


def select(d, n):
    """Units consumed: a function of (counter, size) and nothing else."""
    return cover(d.counter, d.counter + n)


def index(m):
    """
    The share index is the payload digest, one field element. Distinct payments
    carry distinct indices only if the digest does not collide, which over one
    field element is about 2**32 work --- which is why the domain refuses on the
    index rather than on the payload.
    """
    return h(m["amount"], m["merchant"], m["category"], m["t"], m.get("nonce", 0))


def pay(d, m, force=False, fresh=True, release=False):
    """
    Returns (accepted, shares). force skips the compliance check, which is how
    an overdrawing agent is simulated. fresh is condition (I5): with it off, the
    domain admits a payment whose index it has already seen, which is the case
    the extractor cannot recover from. release models the rule of Section VI-B:
    a run returns to the counter only while no proof stands against it. Setting
    it True on a payment that was proved is the unsafe rule, kept here so the
    failure can be exhibited rather than described.
    """
    i = index(m)
    if fresh and i in d.indices:
        return False, []
    n = units(m["amount"])
    window = [t for t in d.velocity if t > m["t"] - d.pol["velocity_w"]]
    verdict = satisfies(d.pol, m, d.settled, len(window))

    # The run is reserved before the proof is formed, which is what the counter
    # advancing here rather than at settlement models.
    start = d.counter
    nodes = select(d, n)
    d.counter += n
    # The capacity this payment assigns, which Pay reports whatever becomes of
    # the payment afterwards. Well-formedness is c >= amount.
    c = n * UNIT
    assert c >= m["amount"], "a payment must assign at least what it settles"
    d.committed += c

    if start + n > d.spendable:
        if not force:
            # Refused at the budget. The run is stranded: the counter has
            # advanced, and this is the only threshold whose predicate depends
            # on a hidden field, which is why it opens no refusal channel.
            return False, []
        # Overdraw: reset the counter into the range already consumed, which is
        # the only way to consume a unit twice.
        d.counter = start + n - d.spendable
        nodes = select(d, n)

    d.seq += 1
    shares = []
    for (off, size) in nodes:
        kv = d.tree.key(off, size)
        shares.append({"node": [off, size], "index": i,
                       "share": (d.secret + kv * i) % P})

    if not force and not all(verdict.values()):
        # Proved, then refused by the reserve. The shares exist and are in a
        # payee's hands; the run may NOT be released. Setting release=True here
        # is the unsafe rule, and the counter rollback below is what
        # makes two payments share a key.
        if release:
            d.counter = start
        return False, shares

    d.indices.add(i)
    d.transcript.extend(shares)
    d.settled += m["amount"]
    d.velocity = window + [m["t"]]
    return True, shares


def extract(transcript):
    """
    Two shares under one key recover the secret. Nodes in an ancestor relation
    share a derivable key, but the reference only needs the equal-node case
    because selection never produces a partial overlap.
    """
    seen = {}
    for sh in transcript:
        nid = tuple(sh["node"])
        if nid in seen:
            a, b = seen[nid], sh
            if a["index"] == b["index"]:
                continue
            di = (a["index"] - b["index"]) % P
            kv = ((a["share"] - b["share"]) * pow(di, P - 2, P)) % P
            return (a["share"] - kv * a["index"]) % P
        seen[nid] = sh
    return None


BASE_POLICY = {
    "budget": 1000 * UNIT,
    "cap": 200 * UNIT,
    "merchants": ["m1", "m2", "m3"],
    "categories": ["c1", "c2"],
    "t_start": 1000,
    "t_expiry": 9000,
    "velocity_n": 5,
    "velocity_w": 100,
}

GOOD_PAYMENT = {"amount": 10 * UNIT, "merchant": "m1", "category": "c1", "t": 2000}


def fresh(depth=10, k=4):
    return Delegation(dict(BASE_POLICY), depth, k, secret=h("secret"),
                      root_key=h("root"))


def clause_vectors():
    """One negative vector per clause, plus the positive it was derived from."""
    out = []
    d = fresh()
    v = satisfies(d.pol, GOOD_PAYMENT, 0, 0)
    out.append({"name": "positive", "payment": GOOD_PAYMENT,
                "cum": 0, "vel": 0, "verdict": v, "accept": all(v.values())})

    cases = [
        ("C1", {**GOOD_PAYMENT, "amount": 500 * UNIT}, 0, 0),
        ("C2", GOOD_PAYMENT, 995 * UNIT, 0),
        ("C3", {**GOOD_PAYMENT, "merchant": "zz"}, 0, 0),
        ("C4", {**GOOD_PAYMENT, "category": "zz"}, 0, 0),
        ("C5", {**GOOD_PAYMENT, "t": 9500}, 0, 0),
        ("C6", GOOD_PAYMENT, 0, 5),
    ]
    for clause, m, cum, vel in cases:
        d = fresh()
        v = satisfies(d.pol, m, cum, vel)
        out.append({"name": f"negative_{clause}", "payment": m, "cum": cum,
                    "vel": vel, "verdict": v, "accept": all(v.values()),
                    "expected_failing_clause": clause})
    return out


def honest_run(depth=10, k=4, count=30):
    d = fresh(depth, k)
    accepted = 0
    for i in range(count):
        m = {**GOOD_PAYMENT, "amount": 5 * UNIT, "t": 2000 + i * 200}
        ok, _ = pay(d, m)
        accepted += ok
    return d, accepted


def overdraw_run(depth=10, k=4):
    """Push the counter past the spendable range by ignoring the check."""
    d = fresh(depth, k)
    amount = (d.spendable // 4) * UNIT
    for i in range(6):
        pay(d, {**GOOD_PAYMENT, "amount": amount, "t": 2000 + i * 200},
            force=True)
    return d


def selection_matches_model(depth=10, k=4, count=40):
    """Selection must depend only on (counter, size)."""
    a = fresh(depth, k)
    b = fresh(depth, k)
    for i in range(count):
        m = {**GOOD_PAYMENT, "amount": 3 * UNIT, "t": 2000 + i * 200}
        na = select(a, units(m["amount"]))
        pay(a, m)
        nb = select(b, units(m["amount"]))
        pay(b, m)
        if na != nb:
            return False
    return True


def no_honest_collision(depth=10, k=4, count=60):
    d = fresh(depth, k)
    seen = set()
    for i in range(count):
        m = {**GOOD_PAYMENT, "amount": 4 * UNIT, "t": 2000 + i * 200}
        ok, shares = pay(d, m)
        if not ok:
            continue
        for sh in shares:
            nid = tuple(sh["node"])
            if nid in seen:
                return False
            seen.add(nid)
    return True


def repeated_index_refused(depth=10, k=4):
    """(I5) holds: the same payload twice is admitted once."""
    d = fresh(depth, k)
    m = {**GOOD_PAYMENT, "amount": 5 * UNIT, "t": 3000}
    first, _ = pay(d, m)
    second, _ = pay(d, m)
    return first and not second


def overdraft_without_freshness(depth=10, k=4):
    """
    (I5) removed: an agent repeats one payload past what its budget allows. Every
    share it publishes carries the same index, so two shares under one key are
    the same share written twice, and the extractor recovers nothing.

    This is the case the self-revelation proposition excludes by assumption
    rather than by construction, and it is why freshness is a condition of the
    accountable interface rather than a remark beside it.
    """
    d = fresh(depth, k)
    amount = (d.spendable // 4) * UNIT
    m = {**GOOD_PAYMENT, "amount": amount, "t": 2000}
    for _ in range(6):
        pay(d, m, force=True, fresh=False)
    return extract(d.transcript) is None


def release_after_proving_breaks_correctness(depth=10, k=4):
    """
    Why release is permitted only before a proof exists, exhibited rather than
    described.

    An agent reserves a run, proves, and the reserve refuses on the velocity
    bound. With release=True the counter rolls back, a later payment consumes
    the same run, and the refused payment's shares --- which a payee holds ---
    stand under the same keys at a different index. Two shares, one key, and
    the secret falls out. Returns True when the failure occurs, which is why
    the construction permits release only before a proof exists.
    """
    d = fresh(depth, k)
    amount = 3 * UNIT
    for i in range(d.pol["velocity_n"]):
        pay(d, {**GOOD_PAYMENT, "amount": amount, "t": 5000 + i})
    # Proved, refused on the velocity bound, and released against the rule.
    refused, held = pay(d, {**GOOD_PAYMENT, "amount": amount, "t": 5000 + 90},
                        release=True)
    assert not refused and held, "the payment must be proved and then refused"
    # A later payment reserves the run the release returned.
    ok, _ = pay(d, {**GOOD_PAYMENT, "amount": amount, "t": 6000})
    assert ok, "the later payment must settle"
    return extract(d.transcript + held) is not None


def c2_clause_binds_nothing(depth=10, k=4):
    """
    Why C2 is enforced by the tree and not as a clause.

    The cumulative total is a value the prover supplies. An agent that under-
    states it satisfies C2 on every payment while spending past its budget, so
    a circuit checking C2 against a witnessed total would accept the whole
    sequence. What stops the overdraft is structural: the counter advances
    whatever the agent claims, and running past the range consumes a unit twice.

    Returns True when the clause accepts a sequence that overdraws --- which is
    the failure, and the reason the clause is not where the enforcement lives.
    """
    d = fresh(depth, k)
    amount = (d.spendable // 4) * UNIT
    lying_total = 0                       # the prover's claim, never advanced
    accepted_by_clause = 0
    for i in range(6):
        v = satisfies(d.pol, {**GOOD_PAYMENT, "amount": amount}, lying_total, 0)
        if v["C2"]:
            accepted_by_clause += 1
        pay(d, {**GOOD_PAYMENT, "amount": amount, "t": 2000 + i * 200},
            force=True)
    overdrawn = d.settled > d.pol["budget"]
    revealed = extract(d.transcript) is not None
    return accepted_by_clause == 6 and overdrawn and revealed


def committed_bounds_settled(depth=10, k=4):
    """
    settled(D) <= committed(D), and alpha is the gap.

    The model defines committed as the sum of the capacities Pay reports, and
    every property that mentions a budget is stated over one or the other. This
    exercises the inequality on a run where some payments settle and some do
    not, which is the only case where the two differ.
    """
    d = fresh(depth, k)
    for i in range(10):
        pay(d, {**GOOD_PAYMENT, "amount": 3 * UNIT, "t": 2000 + i * 200})
    # Three payments that are proved and refused: they assign and never settle.
    for i in range(3):
        pay(d, {**GOOD_PAYMENT, "amount": 3 * UNIT, "t": 20000 + i})
    if d.committed <= 0 or d.settled > d.committed:
        return False
    alpha = 1 - d.settled / d.committed
    return 0 < alpha < 1 and d.committed == d.counter * UNIT


def c8_check(lo, hi, exhibited, nxt):
    """
    C8's four comparisons, exactly as the circuit constrains them: the exhibited
    revoked range starts at or below the run, ends before it, the next revoked
    range begins after it, and the run's endpoints are ordered.
    """
    start, end = exhibited
    return (lo - start >= 0 and lo - end - 1 >= 0
            and nxt - hi - 1 >= 0 and hi - lo >= 0)


def c8_accepts(acc, lo, hi):
    """True if SOME entry the prover may exhibit passes. The prover chooses."""
    acc = sorted(acc)
    for i, (s, e) in enumerate(acc):
        nxt = acc[i + 1][0] if i + 1 < len(acc) else 1 << 40
        if c8_check(lo, hi, (s, e), nxt):
            return True
    return False


def nested_ranges_defeat_c8():
    """
    Why (I6) is load-bearing, exhibited rather than asserted.

    C8 exhibits ONE revoked range and shows the run falls outside it. That is
    sound only if a range covering the run would be the one exhibited, which
    holds when entries are disjoint and fails when they nest. Revoking a child
    before its parent produces nested entries, and nesting is the mechanism the
    whole design rests on --- a parent's range covers its descendants'.

    Returns True when the check accepts a payment under a revoked delegation,
    which is the failure, and False once the entries are kept disjoint.
    """
    parent, child = (0, 100), (10, 20)
    run_lo, run_hi = 30, 40

    nested = [parent, child]                       # child revoked, then parent
    disjoint = [(0, 9), child, (21, 100)]          # the parent published as the
                                                   # complement of what is
                                                   # already revoked within it
    broken = c8_accepts(nested, run_lo, run_hi)
    fixed = c8_accepts(disjoint, run_lo, run_hi)
    return broken and not fixed


def run_checks():
    results = []

    def check(name, cond, detail=""):
        results.append((name, bool(cond), detail))

    d, accepted = honest_run()
    check("honest run accepts every compliant payment", accepted == 30,
          f"{accepted}/30 accepted")
    check("honest transcript yields no evidence", extract(d.transcript) is None,
          f"{len(d.transcript)} shares published")
    check("selection is deterministic in (counter, size)",
          selection_matches_model())
    check("no node consumed twice under honest concurrency",
          no_honest_collision())

    o = overdraw_run()
    rec = extract(o.transcript)
    check("overdraft reconstructs the secret", rec == o.secret,
          "recovered" if rec == o.secret else "NOT recovered")

    check("a repeated index is refused when the domain enforces (I5)",
          repeated_index_refused())
    check("nested revoked ranges defeat C8; disjoint ones do not",
          nested_ranges_defeat_c8(),
          "(I6) is what makes the single-exhibit argument sound")
    check("settled never exceeds committed, and alpha is the gap",
          committed_bounds_settled(),
          "Pay reports the capacity it assigns; committed is the sum")
    check("C2 as a clause accepts an overdraft the tree catches",
          c2_clause_binds_nothing(),
          "the cumulative total is prover-supplied; the tree is what binds")
    check("releasing a proved run breaks correctness",
          release_after_proving_breaks_correctness(),
          "the rule of Section VI-B permits release only before a proof exists")
    check("without (I5), overdraft on one payload yields nothing",
          overdraft_without_freshness(),
          "the extractor recovers nothing, which is the point")

    vs = clause_vectors()
    pos = [v for v in vs if v["name"] == "positive"][0]
    check("positive vector accepts", pos["accept"])
    for v in vs:
        if v["name"] == "positive":
            continue
        c = v["expected_failing_clause"]
        failing = [kk for kk, ok in v["verdict"].items() if not ok]
        check(f"{v['name']} fails exactly {c}", failing == [c],
              f"failing: {failing}")

    single = o.transcript[0]["share"]
    check("a single share is not the secret", single != o.secret)

    return results, vs


if __name__ == "__main__":
    results, vectors = run_checks()

    print()
    print("REFERENCE IMPLEMENTATION CHECKS")
    print("=" * 78)
    width = max(len(n) for n, _, _ in results)
    passed = 0
    for name, ok, detail in results:
        passed += ok
        print(f"  {'PASS' if ok else 'FAIL'}  {name.ljust(width)}  {detail}")
    print()
    print(f"  {passed}/{len(results)} passed")

    out = "vectors.json"
    with open(out, "w") as f:
        json.dump({"field": P, "unit": UNIT, "policy": BASE_POLICY,
                   "clause_vectors": vectors}, f, indent=2)
    print(f"  wrote {out}")
    print()
    sys.exit(0 if passed == len(results) else 1)
