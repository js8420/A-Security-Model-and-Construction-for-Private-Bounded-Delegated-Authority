"""Bond ratios for delegation profiles, one worked deployment's capital, and
the delay an adversary can buy against a forced transaction on an OP Stack
chain. Every figure is arithmetic on the paper's formulas and on protocol
constants, so one run is the result.

Run: python3 bond_and_contention.py
"""
import math

DAY = 24.0  # hours

# Assumption 1: total bonds over the budget, with W >= w + theta, are about
# 2 (W / T) (C / mean amount) (peak rate / mean rate).
def bond_ratio(W, T, c_over_a, peak_over_mean):
    return 2.0 * (W / T) * c_over_a * peak_over_mean

def profiles():
    W = DAY
    rows = [
        ("steady, one price, 30-day delegation", 30 * DAY, 1.0, 1.0),
        ("bursty, peak 5x the mean rate, 30 days", 30 * DAY, 1.0, 5.0),
        ("three prices 0.001/0.01/0.05, cap 2.5x mean, 30 days", 30 * DAY, 2.5, 1.0),
        ("one-day task, one price, steady", 1 * DAY, 1.0, 1.0),
        ("one-day task, bursty 5x, three prices", 1 * DAY, 2.5, 5.0),
        ("the same task under a standing 30-day delegation", 30 * DAY, 2.5, 5.0),
    ]
    print("BOND AS A SHARE OF THE BUDGET, RATE WINDOW W = 1 DAY")
    print("=" * 78)
    for name, T, ca, pm in rows:
        print(f"  {name:<56} {100 * bond_ratio(W, T, ca, pm):8.1f}%")
    print()

# The rate channel: the most that can settle over a declared life T_d is
# U = C * sum N (ceil(T_d / W) + 1); bonds are C * sum N (ceil((w+theta)/W) + 1).
def hiding(W, w_theta, T_d):
    return (math.ceil(w_theta / W) + 1) / (math.ceil(T_d / W) + 1)

def rate_channel():
    W, w_theta, T_a = DAY, 21.5, 30 * DAY
    print("HIDING FACTOR AGAINST BOND, TASK OF 30 DAYS, CAP AT THE PRICE")
    print("=" * 78)
    print(f"  {'declared expiry':<22} {'hiding factor U/B':>18} {'bonds / B':>12} {'bonds / U':>12}")
    for mult in (1, 2, 5, 10):
        T_d = mult * T_a
        f = (math.ceil(T_d / W) + 1) / (math.ceil(T_a / W) + 1)
        bu = hiding(W, w_theta, T_d)
        print(f"  {f'{mult} x the task':<22} {f:>18.2f} {100 * bu * f:>11.1f}% {100 * bu:>11.2f}%")
    print()

def capital():
    rate, days, price = 1440, 30, 0.01
    B = rate * days * price
    bond = 2 * rate * price
    deposit = 2 * B
    print("CAPITAL FOR ONE DEPLOYMENT: ONE PAYMENT A MINUTE AT 0.01 USD FOR 30 DAYS")
    print("=" * 78)
    print(f"  budget B                                   {B:10.2f} USD")
    print(f"  principal's funding R = Lu, hiding factor 2 {deposit:9.2f} USD")
    print(f"  agent's bonds, 2 r C                        {bond:9.2f} USD")
    print(f"  together                                    {deposit + bond:9.2f} USD")
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

if __name__ == "__main__":
    profiles()
    rate_channel()
    capital()
    contention()
