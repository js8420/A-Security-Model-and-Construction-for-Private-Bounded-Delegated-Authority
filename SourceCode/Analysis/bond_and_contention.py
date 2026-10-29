"""Windows, bond ratios and capital for delegation profiles, and the delay an
adversary or a censoring set of proposers can impose on a forced transaction
on an OP Stack chain. Every figure is arithmetic on the paper's formulas and on
protocol constants, so one run is the result.

The challenger's bond is set when a challenge opens. Its fixed part, the
proving bond, is the price of proving one answer, which the Groth16 runs on
Pete measured, times a currency margin, converted to ether at deployment; it
is also the bounty a slash pays. Its variable part is what forcing the answer
in through Ethereum costs at the Ethereum base fee the domain records then,
times the fee factor, so it covers an answer forced in at up to that factor
times the fee at the challenge. The posting deposit is likewise set at the
challenge: one batch's postings at the domain's own fee, times the fee factor.
A posting forced in through Ethereum is refunded the same and no more. The
answer window and the slot are checked against the slowest proving run.

Run: python3 bond_and_contention.py WorkingHistory/run_TAG_posting.txt GROTH16_DIR WorkingHistory/run_TAG_forced.txt
where GROTH16_DIR holds one out_* folder with an onchain.txt per Groth16 run;
folders whose name holds "low" are runs at the low-memory setting.
"""
import math
import os
import re
import sys

DAY = 24.0  # hours

# Windows on Base, hours. Delta_f: the 12-hour sequencing window plus two
# hours on Ethereum, which the censorship table below sizes. sigma_x: a block's time lies within the sequencing window
# behind and max_sequencer_drift (1800 s) ahead of Ethereum's clock.
W_D = 8.0
# The posting wait w_p the dispute contract gives an answerer to deliver and
# post after a challenge is answered: at least Delta_f + sigma_x, so that a
# forced transaction sent at once lands inside it, plus the margin.
W_P = 30.0
DELTA_F = 12.0 + 2.0
SIGMA_X = 12.0 + 0.5
THETA = 1.0
# The monitor's margin: the decision time comes this long after the latest
# moment an honest agent's delivery can arrive, w_d + theta after the signed
# time, so the monitor has time to verify what arrives last.
MARGIN = 1.0
# The answer window w_a and the slot eta of the dispute contract. An answer
# must be proved and forced in before its deadline, so w_a covers the slowest
# measured proving time plus Delta_f + sigma_x; an agent finishes one answer
# per slot, so eta covers the slowest proving time.
W_A = 32.0
SLOT = 4.0
W_RATE = DAY
# The price of proving one answer: 64 vCPU at 3.616 USD an hour for the
# measured proving time. The proving bond is that price times the currency
# margin, so it still covers an answer if ether falls to 1 / MARGIN of its
# price at deployment.
VCPU_HOUR_64 = 3.616
CURRENCY_MARGIN = 2.0
# What the fee-dependent parts of the bond and the deposit are multiplied by:
# they cover a rise of the fee by this factor between the challenge and the
# answer or the postings.
FEE_FACTOR = 2
# The most settlements of one batch, so the most deliveries one batch's
# deposit refunds.
BATCH = 256


def runs(folder, proofs=1):
    """Every Groth16 run in the folder answering for this many batch proofs:
    name, setup and proving seconds, low-memory or not."""
    out = []
    for name in sorted(os.listdir(folder)):
        path = os.path.join(folder, name, "onchain.txt")
        if not name.startswith("out_") or not os.path.isfile(path):
            continue
        f = {}
        for line in open(path, encoding="utf8"):
            parts = line.split()
            if len(parts) == 2 and parts[0] in ("setup_seconds", "prove_seconds", "verifies", "stark_proofs"):
                f[parts[0]] = parts[1]
        if f.get("verifies") != "true" or "prove_seconds" not in f:
            raise SystemExit(f"{path}: not a verified Groth16 run")
        if int(f.get("stark_proofs", 1)) != proofs:
            continue
        out.append((name, float(f.get("setup_seconds", 0)), float(f["prove_seconds"]), "low" in name))
    if proofs == 1 and not any(not low for *_, low in out):
        raise SystemExit(f"no run at the default setting in {folder}")
    return out


def posted(path):
    usd = {}
    label = None
    for line in open(path, encoding="utf8"):
        m = re.match(r"\s+(proof, all chunks|one answer|one delivery)\s", line)
        if m:
            label = m.group(1)
            continue
        m = re.search(r"= ([0-9.]+) USD", line)
        if m and label:
            usd[label] = float(m.group(1))
            label = None
    if set(usd) != {"proof, all chunks", "one answer", "one delivery"}:
        raise SystemExit(f"no posting, answer and delivery cost in {path}")
    return usd["proof, all chunks"], usd["one answer"], usd["one delivery"]


def call_data(path):
    """Transactions and call data bytes of the proof's postings, of one answer
    and of one delivery, and the ETH price."""
    rows = {}
    usd = None
    for line in open(path, encoding="utf8"):
        m = re.match(r"\s+(proof, all chunks|one answer|one delivery)\s+(\d+) tx\s+[\d,]+ gas\s+([\d,]+) bytes", line)
        if m:
            rows[m.group(1)] = (int(m.group(2)), int(m.group(3).replace(",", "")))
        m = re.match(r"\s+ETH / USD, Chainlink on Base\s+([\d.]+)", line)
        if m:
            usd = float(m.group(1))
    if set(rows) != {"proof, all chunks", "one answer", "one delivery"} or usd is None:
        raise SystemExit(f"no postings, answer, delivery or ETH price in {path}")
    return rows["proof, all chunks"], rows["one answer"][1], rows["one delivery"][1], usd


def portal_gas(path):
    """The portal's L1 gas for one forced chunk, answer and delivery."""
    out = {}
    for line in open(path, encoding="utf8"):
        m = re.search(r"portal execution gas for one (chunk|answer|delivery) (\d+)", line)
        if m:
            out[m.group(1)] = int(m.group(2))
    if set(out) != {"chunk", "answer", "delivery"}:
        raise SystemExit(f"no portal gas for a chunk, an answer and a delivery in {path}")
    return out["chunk"], out["answer"], out["delivery"]


def forced(n_bytes, portal):
    """L1 gas of forcing one transaction in: the base cost, call data at the
    EIP-7623 floor on every byte, and the portal's work."""
    return 21000 + 40 * n_bytes + portal


POSTING, SENDING, DELIVERING = posted(sys.argv[1])
(CHUNKS, POSTED_BYTES), ANSWER_BYTES, DELIVERY_BYTES, ETH_USD = call_data(sys.argv[1])
PORTAL_CHUNK, PORTAL_ANSWER, PORTAL_DELIVERY = portal_gas(sys.argv[3])
FORCED_PROOF_GAS = CHUNKS * (21000 + PORTAL_CHUNK) + 40 * POSTED_BYTES
FORCED_DELIVERY_GAS = forced(DELIVERY_BYTES, PORTAL_DELIVERY)
FORCED_L1_GAS = FORCED_PROOF_GAS + BATCH * FORCED_DELIVERY_GAS
FORCED_ANSWER_GAS = forced(ANSWER_BYTES, PORTAL_ANSWER)
RUNS = runs(sys.argv[2])
PROVE_SECONDS = max(p for _, _, p, low in RUNS if not low)
T_ANS = max(st + p for _, st, p, _ in RUNS) / 3600
PROVING = VCPU_HOUR_64 * PROVE_SECONDS / 3600
# The proving bond in ether, rounded up to the microether, as the contract is deployed with.
PROVING_BOND_ETH = math.ceil(CURRENCY_MARGIN * PROVING / ETH_USD * 1e6) / 1e6
BOUNTY = PROVING_BOND_ETH * ETH_USD
QUIET_POSTING = POSTING + BATCH * DELIVERING
DEPOSIT = FEE_FACTOR * QUIET_POSTING


def bond_at(l1_gwei):
    """The challenger's bond in USD for a challenge opened at this Ethereum base fee."""
    return BOUNTY + FEE_FACTOR * FORCED_ANSWER_GAS * l1_gwei * 1e-9 * ETH_USD

def windows():
    w = W_D + THETA + MARGIN + DELTA_F + SIGMA_X
    k_w = math.ceil((w + THETA) / W_RATE) + 1
    w_a = T_ANS + DELTA_F + SIGMA_X
    print("WINDOWS ON BASE, HOURS")
    print("=" * 78)
    print(f"  delivery w_d                               {W_D:8.1f}")
    print(f"  posting wait w_p >= Delta_f + sigma_x + m  {W_P:8.1f}")
    assert W_P >= DELTA_F + SIGMA_X + MARGIN
    print(f"  forced inclusion Delta_f                   {DELTA_F:8.1f}")
    print(f"  clock bound sigma_x                        {SIGMA_X:8.1f}")
    print(f"  signed-time tolerance theta                {THETA:8.1f}")
    print(f"  monitor's margin m                         {MARGIN:8.1f}")
    print(f"  acceptance window w = w_d + theta + m + Delta_f + sigma_x {w:5.1f}")
    print(f"  decision time after the signed time, w - Delta_f - sigma_x {w - DELTA_F - SIGMA_X:4.1f}")
    print(f"  rate window W                              {W_RATE:8.1f}")
    print(f"  windows a bond covers, ceil((w+theta)/W)+1 {k_w:8d}")
    print(f"  slowest proving run, setup included          {T_ANS:8.2f}")
    print(f"  answer window w_a >= t_ans + Delta_f + sigma_x {w_a:6.1f}, set to {W_A:.0f}")
    print(f"  slot eta >= t_ans                              {T_ANS:6.2f}, set to {SLOT:.0f}")
    print(f"  one challenge forfeits by w_a + 2 eta           {W_A + 2 * SLOT:6.1f}")
    assert W_A >= w_a and SLOT >= T_ANS
    print()
    return k_w

def bond_ratio(k_w, W, T, c_over_a, peak_over_mean):
    return k_w * (W / T) * c_over_a * peak_over_mean

def profiles(k_w):
    """Each profile at one payment a minute on average, on one domain. The
    bonds' share of the budget is the ratio of the paper; the stake adds the
    bond again and the fixed bounty, so its share depends on the budget, which
    the rate, the mean price and the life give."""
    W = W_RATE
    rate = 1440.0
    one = (0.01, 0.01)
    three = (0.05 / 2.5, 0.05)
    rows = [
        ("Steady, one price, 30 days", 30 * DAY, one, 1.0),
        ("Peak 5x mean, 30 days", 30 * DAY, one, 5.0),
        ("Three prices, 30 days", 30 * DAY, three, 1.0),
        ("One day, one price", 1 * DAY, one, 1.0),
        ("One day, expiry 300 days", 1 * DAY, one, 1.0),
        ("One day, 5x peak, 3 prices", 1 * DAY, three, 5.0),
        ("That task, 30-day delegation", 30 * DAY, three, 5.0),
    ]
    print("BOND AS A SHARE OF THE BUDGET, RATE WINDOW W = 1 DAY, ONE PAYMENT A MINUTE")
    print("=" * 78)
    print(f"  {'':<34} {'B, USD':>9} {'bonds':>8} {'with stake':>11} {'stake adds':>11}")
    for name, T, (mean, cap), pm in rows:
        r = bond_ratio(k_w, W, T, cap / mean, pm)
        budget = rate * mean * T / W
        bonds = k_w * rate * pm * cap
        assert abs(bonds / budget - r) < 1e-9
        both = (2 * bonds + BOUNTY) / budget
        print(f"  {name:<34} {budget:>9.2f} {100 * r:7.1f}% {100 * both:10.1f}% {100 * (both - r):10.1f}")
    print(f"  The stake is the bond plus the bounty, {BOUNTY:.2f} USD, on each domain; the")
    print("  bounty is fixed in dollars, so it weighs more as the budget falls.")
    print("  A declared expiry longer than the task changes none of these: the bond")
    print("  follows the rate the task needs and the life it actually spends.")
    print()


def hiding_factor(T_d, T_a, W=W_RATE):
    # f = U / B for a task paying at the rate limit with the cap at the price:
    # U counts ceil(T_d/W)+1 windows at the limit, B the T_a/W windows it spends.
    return (math.ceil(T_d / W) + 1) / (T_a / W)

def trade_off(k_w):
    rate, price, T_a = 1440, 0.01, 30 * DAY
    B = rate * (T_a / DAY) * price
    bonds = k_w * rate * price
    print("HIDING FACTOR AND THE CAPITAL IT TAKES: ONE PAYMENT A MINUTE AT 0.01 USD")
    print("FOR 30 DAYS, B = %.2f USD, DEPOSIT MODE" % B)
    print("=" * 78)
    print(f"  {'declared expiry':<16} {'f':>6} {'bonds':>7} {'stake':>7} {'deposit':>8} {'funding fB':>11} {'total':>9} {'total/B':>8}")
    for mult in (1, 2, 5, 10):
        f = hiding_factor(mult * T_a, T_a)
        R = f * B
        stake = bonds + BOUNTY
        tot = R + bonds + stake + DEPOSIT
        print(f"  {f'{mult} x the task':<16} {f:>6.2f} {bonds:>7.2f} {stake:>7.2f} {DEPOSIT:>8.2f} {R:>11.2f} {tot:>9.2f} {tot / B:>8.2f}")
    print(f"  The stake is the bond plus the bounty, {BOUNTY:.2f}; without an answerer the total")
    print(f"  is less by the stake, {bonds + BOUNTY:.2f}. The deposit is one posting deposit at the measured")
    print("  Base fee, which the principal holds while a challenge of its own is open.")
    print(f"  Carrying the stake for the task costs {(bonds + BOUNTY) * (T_a / DAY) / 365 * 0.01:.4f} USD per percentage")
    print("  point of annual interest on it.")
    print("  The same f reached by a short declared life instead needs bonds of")
    for mult in (1, 2, 5, 10):
        f = hiding_factor(mult * T_a, T_a)
        print(f"    f = {f:5.2f}: about {100 * k_w * f * W_RATE / T_a:6.1f}% of B in bonds, plus funding fB")
    print()
    print("ONE-DAY TASK, ONE PRICE, UNDER A LONG DECLARED EXPIRY")
    print("=" * 78)
    T1 = 1 * DAY
    B1 = rate * price
    for days in (1, 30, 300):
        f = hiding_factor(days * DAY, T1)
        print(f"  declared {days:>3} days: f = {f:7.2f}, bonds / B = {100 * bond_ratio(k_w, W_RATE, T1, 1, 1):5.1f}%, funding fB = {f * B1:9.2f} USD")
    print()

# Delay purchasable against one forced transaction.
# Ethereum EIP-1559: base fee rises by 1/8 per full block; gas limit 60M.
# OP Stack ResourceMetering: 20M resource gas per L1 block, target 2M,
# denominator 8, so a full block multiplies the deposit base fee by 2.125.
def blocks_l1(budget_eth, base_gwei, gas_limit=60e6):
    per_block = gas_limit * base_gwei * 1e-9
    k = 0
    spent = 0.0
    while True:
        cost = per_block * 1.125 ** k
        if spent + cost > budget_eth:
            return k
        spent += cost
        k += 1

def blocks_deposit(budget_eth, base_gwei=1.0, limit=20e6, growth=2.125):
    k = 0
    spent = 0.0
    while True:
        cost = limit * base_gwei * 1e-9 * growth ** k
        if spent + cost > budget_eth:
            return k
        spent += cost
        k += 1

def contention():
    print("ETHEREUM BLOCKS AN ADVERSARY CAN KEEP A FORCED TRANSACTION OUT")
    print("=" * 78)
    print(f"  {'budget, ETH':>12} {'L1 base fee, gwei':>18} {'by filling L1':>14} {'by filling deposits':>20} {'minutes, worse':>15}")
    for budget in (10, 100, 1000, 10000):
        for base in (1, 10, 50):
            a = blocks_l1(budget, base)
            b = blocks_deposit(budget)
            print(f"  {budget:>12} {base:>18} {a:>14} {b:>20} {12 * max(a, b) / 60:>15.1f}")
    print()
    print("  The monitor tips nothing here; any priority fee it pays makes the adversary")
    print("  outbid it on every slot of every block, so the delay only shrinks. The last")
    print("  column is the longer of the two routes.")
    print()

# Proposers that exclude a transaction without being paid to. If a share alpha
# of slots go to proposers that include it, k slots all exclude it with
# probability (1 - alpha)^k.
def censorship():
    print("PROPOSERS THAT EXCLUDE A FORCED TRANSACTION")
    print("=" * 78)
    print(f"  {'including share':>16} {'P(out for 2 h, 600 slots)':>27} {'slots for 2^-40':>17} {'minutes':>9}")
    for alpha in (0.54, 0.21, 0.10, 0.052):
        p = (1 - alpha) ** 600
        k = math.ceil(40 / -math.log2(1 - alpha))
        print(f"  {alpha:>16.3f} {p:>27.2e} {k:>17} {12 * k / 60:>9.1f}")
    print()

# Targeted exclusion. An adversary pays each block's builder to leave one
# transaction out. A builder that is offered the forcing party's tip T for
# including it leaves it out only for more than T, so keeping it out for k
# blocks costs the adversary more than k T, while the forcing party pays T
# once. Excluding it pays only if k T stays below what the adversary gains.
def bribery():
    k = int(2 * 3600 / 12)
    print("BRIBING BUILDERS TO EXCLUDE ONE FORCED TRANSACTION FOR THE TWO-HOUR MARGIN")
    print("=" * 78)
    print(f"  blocks in the margin: {k}")
    print(f"  {'adversary gains, USD':>22} {'tip that makes it unprofitable, USD':>38}")
    for gain in (43.20, 432.00, 4320.00, 43200.00):
        print(f"  {gain:>22,.2f} {gain / k:>38,.4f}")
    print("  A block built by anyone the bribe does not reach includes it at once,")
    print("  so every such block only shortens the delay.")
    print()

if __name__ == "__main__":
    print("THE GROTH16 RUNS, SECONDS")
    print("=" * 78)
    for name, st, p, low in RUNS:
        print(f"  {name:<28} {'low memory' if low else 'default':<12} setup {st:7.1f}  prove {p:9.1f}")
    TWO = runs(sys.argv[2], 2)
    if any(not low for *_, low in TWO):
        print("  one answer for two batch proofs:")
        for name, st, p, low in TWO:
            print(f"  {name:<28} {'low memory' if low else 'default':<12} setup {st:7.1f}  prove {p:9.1f}")
        one = max(p for _, _, p, low in RUNS if not low)
        two = max(p for _, _, p, low in TWO if not low)
        print(f"  the second batch adds {two - one:.1f} s to the slower default run, {100 * (two - one) / one:.1f}% of one answer")
    print()
    print("THE CHALLENGER'S BOND AND THE BOUNTY")
    print("=" * 78)
    print(f"  proving one answer, the slower default run, {PROVE_SECONDS:.1f} s at {VCPU_HOUR_64} USD an hour {PROVING:10.4f} USD")
    print(f"  proving bond, {CURRENCY_MARGIN:.0f} x that at {ETH_USD} USD an ether, rounded up   {PROVING_BOND_ETH:.6f} ETH = {BOUNTY:.4f} USD")
    print(f"  it covers the proving while ether stays above {PROVING / PROVING_BOND_ETH:.2f} USD")
    print(f"  sending the answer on Base, measured                                  {SENDING:10.4f} USD")
    print(f"  forcing it in through Ethereum: {FORCED_ANSWER_GAS:,} L1 gas, measured on a fork")
    print(f"  bond at a challenge, proving bond + {FEE_FACTOR} x forcing at the Ethereum base fee then:")
    for g in (1, 10, 50, 200):
        forced_usd = FORCED_ANSWER_GAS * g * 1e-9 * ETH_USD
        print(f"    at {g:>4} gwei: {bond_at(g):9.2f} USD; forcing at {g} gwei costs {forced_usd:8.2f}, at {FEE_FACTOR * g} gwei {FEE_FACTOR * forced_usd:8.2f}")
    print(f"  An answer pays whenever the Ethereum base fee at the answer is at most {FEE_FACTOR} times")
    print("  the fee at the challenge and ether has not fallen below the bound above.")
    print()
    print("THE POSTING DEPOSIT, SET AT THE PRINCIPAL'S CHALLENGE")
    print("=" * 78)
    print(f"  posting the batch proof and {BATCH} sealed openings on Base, measured, USD {QUIET_POSTING:10.4f}")
    print(f"  the proof's postings: {CHUNKS} transactions, {POSTED_BYTES:,} bytes of call data")
    print(f"  deposit, {FEE_FACTOR} x the postings at the domain's fee then, at the measured fee  {DEPOSIT:10.4f} USD")
    print("  A posting forced in through Ethereum is refunded what it costs on the domain; what forcing adds")
    print("  is the answerer's:")
    print(f"  portal's L1 gas beyond call data, measured: one chunk {PORTAL_CHUNK:,}, one answer {PORTAL_ANSWER:,}, one delivery {PORTAL_DELIVERY:,}")
    print(f"  forcing every chunk and {BATCH} deliveries in, L1 gas      {FORCED_L1_GAS:>14,}")
    for gwei in (1.0, 10.0):
        eth = FORCED_L1_GAS * gwei * 1e-9
        print(f"    at {gwei:4.0f} gwei: {eth:.4f} ETH = {eth * ETH_USD:,.2f} USD, paid by the answerer only under censorship")
    print()
    k_w = windows()
    profiles(k_w)
    trade_off(k_w)
    contention()
    censorship()
    bribery()
