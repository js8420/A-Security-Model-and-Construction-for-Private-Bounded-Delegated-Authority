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
  folding       arities 4, 4 and 4 at 256 rows: a fold of arity a is a curve of degree a - 1.
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
ROWS = 256              # trace rows
WIDTH = 14292 + 2       # AIR columns plus the hiding commitment's two random codewords
CONSTRAINTS = 14302     # constraints the AIR asserts
DEGREE = 7              # their degree
CHUNKS = 16             # quotient chunks
EXT = 5                 # degree of the challenge field over Goldilocks
DEPLOYED = (74, 4, 20)  # queries, log2 blowup, grinding bits
CODEWORDS = 2           # random codewords the hiding commitment appends to each matrix
FOLDS = (4, 4, 4)       # FRI fold arities at 256 rows
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


SWEEP = [(q, lb, g, e) for e in (3, 5) for lb, g in ((4, 20), (4, 30), (5, 20), (3, 20))
         for q in range(40, 101, 2)]


def against(w, h):
    """Bits of the state-restoration error against 2^h oracle queries."""
    return bits((2**h + ROUNDS) * w)


def main():
    q0, lb0, g0 = DEPLOYED
    print("ROUND-BY-ROUND KNOWLEDGE-SOUNDNESS ERROR OF THE PAYMENT PROOF, BITS")
    print("=" * 78)
    print(f"  {ROWS} rows, batched openings N = {batched()}, constraints s = {CONSTRAINTS}, degree {DEGREE}, "
          f"{CHUNKS} chunks, folds {FOLDS}")
    print()
    show(f"deployed: {q0} queries, blowup {2**lb0}, {g0} grinding bits, degree-5 extension", q0, lb0, g0)
    show("the earlier setting: 44 queries, blowup 16, 20 grinding bits, cubic extension", 44, 4, 20, ext=3)
    show("70 queries, blowup 16, 30 grinding bits, degree-5 extension", 70, 4, 30)
    show("60 queries, blowup 32, 20 grinding bits, degree-5 extension", 60, 5, 20)
    print()
    print("STATE-RESTORATION (NON-INTERACTIVE) ERROR, (2^h + 7) TIMES THE PROVABLE ROUND-BY-ROUND ERROR")
    print("=" * 78)
    rows = [("deployed, degree 5", q0, lb0, g0, 5), ("earlier, cubic", 44, 4, 20, 3)]
    print(f"  {'setting':<22} {'rbr':>7} {'2^32':>7} {'2^48':>7} {'2^64':>7}")
    for name, q, lb, g, e in rows:
        w = 2.0**-provable(q, lb, g, e)
        print(f"  {name:<22} {bits(w):7.1f} {against(w, 32):7.1f} {against(w, 48):7.1f} {against(w, 64):7.1f}")
    print()
    print("THE FEWEST QUERIES REACHING 100 PROVABLE BITS AGAINST 2^64 ORACLE QUERIES")
    print("=" * 78)
    print(f"  {'extension':>9} {'blowup':>7} {'grind':>6} {'queries':>8} {'2^64 bits':>10} {'rows zk needs':>14}")
    for e in (3, 5):
        for lb, g in ((4, 20), (4, 30), (5, 20), (3, 20)):
            hit = next(((q, against(2.0**-provable(q, lb, g, e), 64)) for q in range(40, 161, 2)
                        if against(2.0**-provable(q, lb, g, e), 64) >= 100), None)
            if hit:
                q, b = hit
                print(f"  {e:>9} {2**lb:>7} {g:>6} {q:>8} {b:>10.1f} {2 * (2 * e + q):>14}")
            else:
                top = max(against(2.0**-provable(q, lb, g, e), 64) for q in range(40, 161, 20))
                print(f"  {e:>9} {2**lb:>7} {g:>6} {'none':>8} {top:>10.1f} {'':>14}")


if __name__ == "__main__":
    main()
