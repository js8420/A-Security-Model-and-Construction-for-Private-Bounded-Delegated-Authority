#!/usr/bin/env python3
"""
CHAIN CONTAINMENT: WHICH RULE BOUNDS TOTAL SPEND ACROSS A DELEGATION CHAIN

The question this settles is not whether a rule looks right. It is whether a
chain of delegations obeying the rule can settle more than the root's budget
while no single delegation reuses a unit of its own range.

That qualification is the whole of it. Extraction combines two shares under one
key at two indices. Two delegations hold different secrets, so a unit consumed
once by a parent and once by a child yields two equations in three unknowns and
the hash test fails: a cross-delegation collision is settled value with no
evidence behind it. Only a delegation colliding with itself is detectable.

So the rule has to make the chain's spendable sets disjoint, not merely nested.
Four candidates are enumerated over every small chain shape.

  padded      a child's range lies inside its parent's PADDED range
              (what Definition 22 says and what containment.rs checks)
  spendable   a child's range lies inside its parent's first m units
  disjoint    spendable, and sibling grants may not overlap
  partition   disjoint, and each delegation commits g <= m: it may spend
              [0, g) itself and may grant only from [g, m)
  block       partition, but the grantable part is a single published block
              [p, p + 2^j) with g <= p and p + 2^j <= m. The block is public,
              so the reserve checks a grant against it without reading g or m.

Every quantity here is combinatorial. One run is the measurement.

Usage:
    python chaincheck.py
"""

import itertools
import sys


def padded(m):
    """The power-of-two index range a budget of m units is allocated."""
    return 1 << (m - 1).bit_length() if m > 1 else 1


class Node:
    __slots__ = ("lo", "hi", "m", "g", "p", "blk", "children")

    def __init__(self, lo, hi, m, g, p=0, blk=0):
        self.lo = lo          # first index of the granted range
        self.hi = hi          # one past the last index of the granted range
        self.m = m            # committed spendable count
        self.g = g            # self-region size under the partition rule
        self.p = p            # offset of the published grant block
        self.blk = blk        # length of the published grant block
        self.children = []

    def own_region(self, rule):
        """The indices this delegation's own circuit will let it consume."""
        n = self.g if rule in ("partition", "block") else self.m
        return set(range(self.lo, self.lo + n))

    def grant_region(self, rule):
        """The indices it may grant away."""
        if rule == "padded":
            return set(range(self.lo, self.lo + padded(self.m)))
        if rule == "partition":
            return set(range(self.lo + self.g, self.lo + self.m))
        if rule == "block":
            return set(range(self.lo + self.p, self.lo + self.p + self.blk))
        return set(range(self.lo, self.lo + self.m))


def audit(root, rule):
    """Total settled, and whether any delegation collides with itself.

    Every delegation spends its full allowance on distinct units of its own
    region, which is the worst case and is available to an agent that simply
    does what its circuit permits. No delegation reuses a unit of its own, so
    no evidence is extractable anywhere in the chain.
    """
    total = 0
    stack = [root]
    while stack:
        node = stack.pop()
        total += len(node.own_region(rule))
        stack.extend(node.children)
    return total


def blocks(w):
    """Published grant blocks a delegation of w units could declare, as
    (g, p, blk): self-region g, block at p of power-of-two length blk, with
    g <= p and p + blk <= w. The empty block is (g, w, 0)."""
    out = []
    for g in range(0, w + 1):
        out.append((g, w, 0))
        j = 1
        while j <= w:
            for p in range(g, w - j + 1):
                out.append((g, p, j))
            j *= 2
    return out


def child_specs(node, rule, taken):
    """Every grant the rule would admit from this node, as (lo, hi, m, g, p, blk)."""
    region = sorted(node.grant_region(rule))
    if not region:
        return []
    lo0, hi0 = region[0], region[-1] + 1
    out = []
    for lo in range(lo0, hi0):
        for hi in range(lo + 1, hi0 + 1):
            rng = set(range(lo, hi))
            if not rng <= set(region):
                continue
            if rule in ("disjoint", "partition") and rng & taken:
                continue
            w = hi - lo
            if rule == "block":
                for (g, p, blk) in blocks(w):
                    out.append((lo, hi, w, g, p, blk))
            elif rule == "partition":
                for g in range(0, w + 1):
                    out.append((lo, hi, w, g, 0, 0))
            else:
                out.append((lo, hi, w, w, 0, 0))
    return out


def trees(node, rule, taken, depth, max_depth, max_children):
    """Every chain the rule admits below this node. Yields nothing but mutates
    and restores node.children, so callers clone what they keep."""
    yield None
    if depth >= max_depth:
        return
    specs = child_specs(node, rule, taken)
    for n_kids in range(1, max_children + 1):
        for combo in itertools.combinations(specs, n_kids):
            local = set(taken)
            kids, ok = [], True
            for (lo, hi, m, g, p, blk) in combo:
                rng = set(range(lo, hi))
                if rule in ("disjoint", "partition", "block") and rng & local:
                    ok = False
                    break
                local |= rng
                kids.append(Node(lo, hi, m, g, p, blk))
            if not ok:
                continue
            node.children = kids
            for _ in expand(kids, rule, local, depth + 1, max_depth,
                            1 if depth + 1 >= 1 else max_children):
                yield None
            node.children = []


def expand(kids, rule, taken, depth, max_depth, max_children):
    """Enumerate subtrees under a fixed list of siblings."""
    if not kids:
        yield None
        return
    head, rest = kids[0], kids[1:]
    for _ in trees(head, rule, taken, depth, max_depth, max_children):
        for _ in expand(rest, rule, taken, depth, max_depth, max_children):
            yield None


def shapes(m_root, rule, max_children, max_depth):
    out = []
    if rule == "block":
        root_specs = blocks(m_root)
    elif rule == "partition":
        root_specs = [(g, 0, 0) for g in range(0, m_root + 1)]
    else:
        root_specs = [(m_root, 0, 0)]
    for (g, p, blk) in root_specs:
        root = Node(0, padded(m_root), m_root, g, p, blk)
        for _ in trees(root, rule, set(), 0, max_depth, max_children):
            out.append(clone(root))
    return out


def clone(node):
    c = Node(node.lo, node.hi, node.m, node.g, node.p, node.blk)
    c.children = [clone(k) for k in node.children]
    return c


def describe(node, indent=0):
    pad = "  " * indent
    s = "%srange [%d,%d)  m=%d  g=%d  block [%d,%d)\n" % (
        pad, node.lo, node.hi, node.m, node.g, node.p, node.p + node.blk)
    for k in node.children:
        s += describe(k, indent + 1)
    return s


def main():
    rules = ["padded", "spendable", "disjoint", "partition", "block"]
    max_m = 5
    max_children = 2
    max_depth = 2

    print("CHAIN CONTAINMENT ENUMERATION")
    print("root budgets m = 1..%d, up to %d children per node, depth %d"
          % (max_m, max_children, max_depth))
    print("worst case: every delegation spends its full allowance on distinct units")
    print("breach: total settled exceeds the root budget with no delegation")
    print("        colliding with itself, so nothing is extractable")
    print()

    verdict = {}
    for rule in rules:
        worst = None
        checked = 0
        breaches = 0
        for m_root in range(1, max_m + 1):
            for shape in shapes(m_root, rule, max_children, max_depth):
                checked += 1
                total = audit(shape, rule)
                if total > m_root:
                    breaches += 1
                    ratio = total / m_root
                    if worst is None or ratio > worst[0]:
                        worst = (ratio, m_root, total, shape)
        verdict[rule] = (checked, breaches, worst)
        status = "BOUNDED" if breaches == 0 else "BREACHED"
        print("%-10s  %7d chains  %7d breaches   %s"
              % (rule, checked, breaches, status))

    print()
    for rule in rules:
        checked, breaches, worst = verdict[rule]
        if breaches == 0:
            continue
        ratio, m_root, total, shape = worst
        print("WORST CASE UNDER %s" % rule.upper())
        print("  root budget %d units, chain settles %d units, factor %.2f"
              % (m_root, total, ratio))
        print(describe(shape), end="")
        print()

    bad = [r for r in rules if verdict[r][1] > 0]
    if bad:
        print("RULES THAT DO NOT BOUND THE CHAIN: %s" % ", ".join(bad))
        return 1
    print("every rule bounds the chain")
    return 0


if __name__ == "__main__":
    sys.exit(main())
