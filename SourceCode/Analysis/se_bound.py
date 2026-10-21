"""Knowledge-soundness error of the deployed payment proof, round by round.

The interactive protocol is the zero-knowledge DEEP-ALI of Haboeck and Kindi,
whose round-by-round knowledge soundness Atapoor, Delpech de Saint Guilhem and
Kindi prove (ePrint 2024/1553, Theorems 2 and 3). Plonky3 departs from that
protocol in four places, and each changes one term:

  constraints   combined by the powers of one challenge, not by independent
                ones: the combination is a polynomial of degree s - 1 in it.
  batching      the N opened columns are combined by the powers of one
                challenge: the proximity gap is that of a curve of degree N - 1
                (Ben-Sasson, Carmon, Ishai, Kopparty, Saraf 2020, Theorem 1.6),
                N - 1 times the gap of a line.
  folding       arities 4, 4 and 2: a fold of arity a is a curve of degree a - 1.
  grinding      the query round is drawn only after a 20-bit proof of work, so
                each oracle query reaches it with probability 2^-20.

The provable figure is the Johnson regime (list decoding, multiplicity m >= 3)
or the unique-decoding regime, whichever is better. The conjectured figure
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
CHUNK_OPEN = 2 + 2      # a chunk's two base coordinates plus two random codewords
RANDOM_OPEN = 2 + 2     # the mask's two polynomials plus two random codewords
FOLDS = (4, 4, 2)       # FRI fold arities
ROUNDS = 7              # constraint challenge, out-of-domain point, batching, three folds, queries


def batched(width=WIDTH):
    """Columns the batching challenge combines: the trace at two points, each chunk and the mask at one."""
    return 2 * width + CHUNKS * CHUNK_OPEN + RANDOM_OPEN


def terms(regime, queries, log_blowup, pow_bits, ext=2, m=None):
    G = P**ext
    k = 2 * ROWS                      # degree bound: the hiding commitment doubles the height
    D = k * 2**log_blowup
    rho = k / D
    kp = k + 2
    N = batched()
    deg = max(DEGREE * (kp - 1) + (k - 1), kp + (CHUNKS - 1) * k + (kp - 1))
    grind = 2.0**(-pow_bits)
    if regime == "johnson":
        L = m / (rho - 2 * m / D)
        gap = (m + 0.5)**7 * D * D / (3 * rho**1.5 * G)
        return {
            "constraints": L * (CONSTRAINTS - 1) / G,
            "out-of-domain point": L * L * deg / (G - 2 * D),
            "batching": (N - 1) * gap,
            "folding": max((a - 1) * (gap + (2 * m + 1) / math.sqrt(rho) * (D + 1) / G) for a in FOLDS),
            "queries": (math.sqrt(rho) * (1 + 1 / (2 * m)))**queries * grind,
        }
    unique = {
        "constraints": (CONSTRAINTS - 1) / G,
        "out-of-domain point": deg / (G - 2 * D),
        "batching": (N - 1) * D / G,
        "folding": max((a - 1) * (D + 1) / G for a in FOLDS),
    }
    if regime == "unique":
        unique["queries"] = ((1 + kp / D) / 2)**queries * grind
    else:
        unique["queries"] = rho**queries * grind
    return unique


def johnson_ok(m, log_blowup):
    k = 2 * ROWS
    D = k * 2**log_blowup
    rho = k / D
    return rho - 2 * m / D > 0 and math.sqrt(rho) * (1 + 1 / (2 * m)) < 1


def best(regime, queries, log_blowup, pow_bits, ext=2):
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


def bits(x):
    return -math.log2(x)


def provable(queries, log_blowup, pow_bits, ext=2):
    j = best("johnson", queries, log_blowup, pow_bits, ext)
    u = best("unique", queries, log_blowup, pow_bits, ext)
    return max(bits(j[0]), bits(u[0]))


def conjectured(queries, log_blowup, pow_bits, ext=2):
    return bits(best("conjectured", queries, log_blowup, pow_bits, ext)[0])


def show(label, queries, log_blowup, pow_bits, ext=2):
    print(f"  {label}")
    for regime in ("johnson", "unique", "conjectured"):
        w, m, t = best(regime, queries, log_blowup, pow_bits, ext)
        parts = ", ".join(f"{n} {bits(v):.1f}" for n, v in t.items())
        mm = f" m={m}" if m else ""
        print(f"    {regime:<12} {bits(w):6.1f} bits{mm:<6}  {parts}")


def main():
    print("ROUND-BY-ROUND KNOWLEDGE-SOUNDNESS ERROR OF THE PAYMENT PROOF, BITS")
    print("=" * 78)
    print(f"  batched columns N = {batched()}, constraints s = {CONSTRAINTS}, degree {DEGREE}, "
          f"{CHUNKS} chunks, folds {FOLDS}")
    print()
    show("deployed: 40 queries, blowup 16, 20 grinding bits, degree-2 extension", 40, 4, 20)
    show("60 queries, blowup 16, 20 grinding bits", 60, 4, 20)
    show("40 queries, blowup 16, 20 grinding bits, degree-5 extension", 40, 4, 20, ext=5)
    show("50 queries, blowup 16, 20 grinding bits, degree-5 extension", 50, 4, 20, ext=5)
    print()
    w = best("johnson", 40, 4, 20)[0]
    print("STATE-RESTORATION ERROR AT THE DEPLOYED SETTING, (t + 7) TIMES THE ABOVE")
    print("=" * 78)
    for h in (32, 48, 64):
        print(f"  2^{h} oracle queries   {bits((2**h + ROUNDS) * w):6.1f} bits")
    print()
    print("THE SWEEP OF THE FRI PARAMETERS, SOUNDNESS COLUMNS, WHOLE BITS ROUNDED DOWN")
    print("=" * 78)
    print(f"  {'queries':>7} {'blowup':>7} {'grind':>6} {'conjectured':>12} {'provable':>9}")
    for q, lb, g in [(40, 4, 20), (40, 3, 8), (54, 3, 20), (84, 3, 16),
                     (40, 2, 8), (40, 2, 0), (40, 2, 16), (20, 2, 8), (30, 2, 8),
                     (60, 2, 8), (80, 2, 8), (80, 2, 20), (40, 1, 8)]:
        print(f"  {q:>7} {2**lb:>7} {g:>6} {math.floor(conjectured(q, lb, g)):>12} {math.floor(provable(q, lb, g)):>9}")


if __name__ == "__main__":
    main()
