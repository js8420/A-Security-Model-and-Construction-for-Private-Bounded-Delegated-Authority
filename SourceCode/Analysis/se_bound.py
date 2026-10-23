"""Knowledge-soundness error of the deployed payment proof, round by round.

The interactive protocol is the zero-knowledge DEEP-ALI of Haboeck and Kindi,
whose round-by-round knowledge soundness Atapoor, Delpech de Saint Guilhem and
Kindi prove (ePrint 2024/1553, Theorems 2 and 3). Plonky3 departs from that
protocol in five places, and each changes one term:

  constraints   combined by the powers of one challenge, not by independent
                ones: the combination is a polynomial of degree s - 1 in it.
  batching      the N opened columns are combined by the powers of one
                challenge: the proximity gap is that of a curve of degree N - 1
                (Ben-Sasson, Carmon, Ishai, Kopparty, Saraf 2020), N - 1 times
                the gap of a line.
  folding       arities 4, 4 and 2: a fold of arity a is a curve of degree a - 1.
  grinding      the query round is drawn only after a 20-bit proof of work, so
                each oracle query reaches it with probability 2^-20.
  out of domain the point is not resampled, so it lands where a quotient by
                (X - zeta) is undefined, the evaluation domain or the hiding
                commitment's, with probability at most 2|D|/|G|.

The challenge field is the cubic extension of Goldilocks; over the quadratic
one the batching term caps the Johnson-regime figure near 72 bits whatever the
queries, and the unique-decoding regime passes 100 bits only at about 88
queries, which the script also prints. The provable figure is the Johnson
regime (list decoding, multiplicity 3 <= m < k/2 with eta > 0) or the
unique-decoding regime, whichever is better. The conjectured figure
takes the query term at the full rate, as the usual conjecture does, and every
other term at its unique-decoding value, which is the least any analysis
charges. Each figure is the round-by-round error; against an adversary making
2^h oracle queries the state-restoration error is (2^h + 7) times it.

Usage: python3 se_bound.py
"""
import math

P = 2**64 - 2**32 + 1

# The deployed proof, as the second verifier reads it.
ROWS = 128              # trace rows
WIDTH = 14292 + 2       # AIR columns plus the hiding commitment's two random codewords
CONSTRAINTS = 14302     # constraints the AIR asserts
DEGREE = 7              # their degree
CHUNKS = 16             # quotient chunks
EXT = 3                 # degree of the challenge field over Goldilocks
CODEWORDS = 2           # random codewords the hiding commitment appends to each matrix
FOLDS = (4, 4, 2)       # FRI fold arities
ROUNDS = 7              # constraint challenge, out-of-domain point, batching, three folds, queries


def batched(ext=EXT):
    """Openings the batching challenge combines: the trace with its random
    codewords at two points, and at one point each quotient chunk's ext base
    coordinates and the mask's ext polynomials, each with the random codewords."""
    return 2 * WIDTH + CHUNKS * (ext + CODEWORDS) + (ext + CODEWORDS)


def terms(regime, queries, log_blowup, pow_bits, ext=EXT, m=None):
    G = P**ext
    k = 2 * ROWS                      # degree bound: the hiding commitment doubles the height
    D = k * 2**log_blowup
    rho = k / D
    kp = k + 2
    N = batched(ext)
    deg = max(DEGREE * (kp - 1) + (k - 1), kp + (CHUNKS - 1) * k + (kp - 1))
    grind = 2.0**(-pow_bits)
    if regime == "johnson":
        L = m / (rho - 2 * m / D)
        gap = (m + 0.5)**7 * D * D / (3 * rho**1.5 * G)
        return {
            "constraints": L * (CONSTRAINTS - 1) / G,
            "out-of-domain point": L * L * deg / (G - 2 * D) + 2 * D / G,
            "batching": (N - 1) * gap,
            "folding": max((a - 1) * (gap + (2 * m + 1) / math.sqrt(rho) * (D + 1) / G) for a in FOLDS),
            "queries": (math.sqrt(rho) * (1 + 1 / (2 * m)))**queries * grind,
        }
    unique = {
        "constraints": (CONSTRAINTS - 1) / G,
        "out-of-domain point": deg / (G - 2 * D) + 2 * D / G,
        "batching": (N - 1) * D / G,
        "folding": max((a - 1) * (D + 1) / G for a in FOLDS),
    }
    if regime == "unique":
        unique["queries"] = ((1 + kp / D) / 2)**queries * grind
    else:
        unique["queries"] = rho**queries * grind
    return unique


def johnson_ok(m, log_blowup):
    """The hypotheses of the Johnson-regime theorem: 3 <= m < k/2, and
    eta = sqrt(rho)(1 + 1/(2m)) - sqrt((k + 2)/|D|) > 0."""
    k = 2 * ROWS
    D = k * 2**log_blowup
    rho = k / D
    eta = math.sqrt(rho) * (1 + 1 / (2 * m)) - math.sqrt((k + 2) / D)
    return 3 <= m < k / 2 and rho - 2 * m / D > 0 and eta > 0 and math.sqrt(rho) * (1 + 1 / (2 * m)) < 1


def best(regime, queries, log_blowup, pow_bits, ext=EXT):
    """The largest error over the rounds, minimised over the multiplicity in the Johnson regime."""
    if regime != "johnson":
        t = terms(regime, queries, log_blowup, pow_bits, ext)
        return max(t.values()), None, t
    out = None
    for m in range(3, 4096):
        if not johnson_ok(m, log_blowup):
            continue
        t = terms(regime, queries, log_blowup, pow_bits, ext, m)
        w = max(t.values())
        if out is None or w < out[0]:
            out = (w, m, t)
    return out


def at_rows(rows, f):
    """Runs f with the trace height set to rows: zero knowledge at 88 queries
    over the quadratic extension needs 2(2*2 + 88) = 184 rows, so 256."""
    global ROWS
    old, ROWS = ROWS, rows
    try:
        f()
    finally:
        ROWS = old


def bits(x):
    return -math.log2(x)


def provable(queries, log_blowup, pow_bits, ext=EXT):
    j = best("johnson", queries, log_blowup, pow_bits, ext)
    u = best("unique", queries, log_blowup, pow_bits, ext)
    return max(bits(j[0]), bits(u[0]))


def conjectured(queries, log_blowup, pow_bits, ext=EXT):
    return bits(best("conjectured", queries, log_blowup, pow_bits, ext)[0])


def show(label, queries, log_blowup, pow_bits, ext=EXT):
    print(f"  {label}")
    for regime in ("johnson", "unique", "conjectured"):
        w, m, t = best(regime, queries, log_blowup, pow_bits, ext)
        parts = ", ".join(f"{n} {bits(v):.1f}" for n, v in t.items())
        mm = f" m={m}" if m else ""
        print(f"    {regime:<12} {bits(w):6.1f} bits{mm:<6}  {parts}")


SWEEP = [(44, 4, 20), (40, 4, 20), (50, 4, 20), (44, 3, 20), (54, 3, 20), (58, 3, 20),
         (40, 3, 8), (44, 2, 20), (40, 2, 8), (40, 1, 8)]


def main():
    print("ROUND-BY-ROUND KNOWLEDGE-SOUNDNESS ERROR OF THE PAYMENT PROOF, BITS")
    print("=" * 78)
    print(f"  batched openings N = {batched()}, constraints s = {CONSTRAINTS}, degree {DEGREE}, "
          f"{CHUNKS} chunks, folds {FOLDS}")
    print()
    show("deployed: 44 queries, blowup 16, 20 grinding bits, cubic extension", 44, 4, 20)
    show("40 queries, blowup 16, 20 grinding bits, cubic extension", 40, 4, 20)
    show("58 queries, blowup 8, 20 grinding bits, cubic extension", 58, 3, 20)
    show("the earlier setting: 40 queries, blowup 16, quadratic extension", 40, 4, 20, ext=2)
    show("40 queries, blowup 8, 20 grinding bits, quadratic extension", 40, 3, 20, ext=2)
    at_rows(256, lambda: show("88 queries, blowup 16, 20 grinding bits, quadratic extension, 256 rows", 88, 4, 20, ext=2))
    show("100 queries, blowup 8, 20 grinding bits, quadratic extension", 100, 3, 20, ext=2)
    print()
    w = best("johnson", 44, 4, 20)[0]
    print("STATE-RESTORATION ERROR AT THE DEPLOYED SETTING, (q + 7) TIMES THE ABOVE")
    print("=" * 78)
    for h in (32, 48, 64):
        print(f"  2^{h} oracle queries   {bits((2**h + ROUNDS) * w):6.1f} bits")
    print()
    print("THE SWEEP OF THE FRI PARAMETERS, CUBIC EXTENSION, WHOLE BITS ROUNDED DOWN")
    print("=" * 78)
    print(f"  {'queries':>7} {'blowup':>7} {'grind':>6} {'conjectured':>12} {'provable':>9} {'rows zk needs':>14}")
    for q, lb, g in SWEEP:
        print(f"  {q:>7} {2**lb:>7} {g:>6} {math.floor(conjectured(q, lb, g)):>12} {math.floor(provable(q, lb, g)):>9} {2 * (2 * EXT + q):>14}")


if __name__ == "__main__":
    main()
