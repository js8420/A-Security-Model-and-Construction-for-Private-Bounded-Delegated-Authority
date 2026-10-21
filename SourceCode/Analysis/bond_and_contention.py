"""Windows, bond ratios and capital for delegation profiles, and the delay an
adversary or a censoring set of proposers can impose on a forced transaction
on an OP Stack chain. Every figure is arithmetic on the paper's formulas and on
protocol constants, so one run is the result.

Run: python3 bond_and_contention.py
"""
import math

DAY = 24.0  # hours

# Windows on Base, hours. Delta_f: the 12-hour sequencing window plus two
# hours on Ethereum, which the censorship table below sizes. sigma_x: a block's time lies within the sequencing window
# behind and max_sequencer_drift (1800 s) ahead of Ethereum's clock.
W_D = 8.0
DELTA_F = 12.0 + 2.0
SIGMA_X = 12.0 + 0.5
THETA = 1.0
# The monitor's margin: the decision time comes this long after the latest
# moment an honest agent's delivery can arrive, w_d + theta after the signed
# time, so the monitor has time to verify what arrives last.
MARGIN = 1.0
C_ANS = 82.0 / 60.0
W_RATE = DAY
# The challenger's bond, which is also the bounty a slash pays: set at the
# computed price of one answer, 64 vCPU at 3.616 USD an hour for 3,179.2 s.
BETA = 3.616 * 3179.2 / 3600

def windows():
    w = W_D + THETA + MARGIN + DELTA_F + SIGMA_X
    k_w = math.ceil((w + THETA) / W_RATE) + 1
    w_a = C_ANS + DELTA_F + SIGMA_X
    print("WINDOWS ON BASE, HOURS")
    print("=" * 78)
    print(f"  delivery w_d                               {W_D:8.1f}")
    print(f"  forced inclusion Delta_f                   {DELTA_F:8.1f}")
    print(f"  clock bound sigma_x                        {SIGMA_X:8.1f}")
    print(f"  signed-time tolerance theta                {THETA:8.1f}")
    print(f"  monitor's margin m                         {MARGIN:8.1f}")
    print(f"  acceptance window w = w_d + theta + m + Delta_f + sigma_x {w:5.1f}")
    print(f"  decision time after the signed time, w - Delta_f - sigma_x {w - DELTA_F - SIGMA_X:4.1f}")
    print(f"  rate window W                              {W_RATE:8.1f}")
    print(f"  windows a bond covers, ceil((w+theta)/W)+1 {k_w:8d}")
    print(f"  answer window at least c + Delta_f + sigma_x {w_a:6.1f}, set to 30")
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
        both = (2 * bonds + BETA) / budget
        print(f"  {name:<34} {budget:>9.2f} {100 * r:7.1f}% {100 * both:10.1f}% {100 * (both - r):10.1f}")
    print(f"  The stake is the bond plus the bounty, {BETA:.2f} USD, on each domain; the")
    print("  bounty is fixed in dollars, so it weighs more as the budget falls.")
    print("  A declared expiry longer than the task changes none of these: the bond")
    print("  follows the rate the task needs and the life it actually spends.")
    print()


def hiding_factor(T_d, T_a, W=W_RATE):
    return (math.ceil(T_d / W) + 1) / (math.ceil(T_a / W) + 1)

def trade_off(k_w):
    rate, price, T_a = 1440, 0.01, 30 * DAY
    B = rate * (T_a / DAY) * price
    bonds = k_w * rate * price
    print("HIDING FACTOR AND THE CAPITAL IT TAKES: ONE PAYMENT A MINUTE AT 0.01 USD")
    print("FOR 30 DAYS, B = %.2f USD, DEPOSIT MODE" % B)
    print("=" * 78)
    print(f"  {'declared expiry':<16} {'f':>6} {'bonds':>7} {'stake':>7} {'funding fB':>11} {'total':>9} {'total/B':>8}")
    for mult in (1, 2, 5, 10):
        f = hiding_factor(mult * T_a, T_a)
        R = f * B
        stake = bonds + BETA
        tot = R + bonds + stake
        print(f"  {f'{mult} x the task':<16} {f:>6.2f} {bonds:>7.2f} {stake:>7.2f} {R:>11.2f} {tot:>9.2f} {tot / B:>8.2f}")
    print(f"  The stake is the bond plus the bounty, {BETA:.2f}; without an answerer the total")
    print(f"  is less by the stake, {bonds + BETA:.2f}.")
    print(f"  Carrying the stake for the task costs {(bonds + BETA) * (T_a / DAY) / 365 * 0.01:.4f} USD per percentage")
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
    k_w = windows()
    profiles(k_w)
    trade_off(k_w)
    contention()
    censorship()
    bribery()
