# Private Bounded Delegated Authority — artifact

Code and measurements for "A Security Model and Construction for Private
Bounded Delegated Authority".

Everything the paper reports is produced by the code here, and the constraint
systems are readable rather than summarised. That matters more than usual for
this paper: Section VII-H argues that a circuit missing a load-bearing
constraint is indistinguishable from a correct one by width, proving time,
proof size, or any suite of corruption tests, and can be caught only by reading
the constraint system. A paper making that argument has to publish the
constraint system.

## Layout

```
Circuits/          the AIR implementation and its harness (Rust, Plonky3 0.6.3)
  src/spend.rs         accountability: the consumed run, key derivation,
                       published shares and nullifiers
  src/whole.rs         compliance: policy clauses, C9 opening, allowlists,
                       non-revocation, payload digest
  src/composed.rs      the two halves as one statement, with their bindings
  src/revocation.rs    C8, non-membership against revoked unit ranges
  src/containment.rs   sub-delegation containment
  src/vacuous.rs       the compliance half with C9's policy binding removed,
                       used for the demonstration in Section VII-H
  src/spend2.rs        the second-invocation variant priced in Section VII-J
  src/trace.rs         witness generation, and every negative control
  src/main.rs          the harness: measures, checks, and emits the tables
SourceCode/        checkers and the reference implementation (Python 3)
WorkingHistory/    the run logs the paper's figures are traced to
```

## Reproducing the measurements

```
cd Circuits
cargo check --release          # ~15s, type-checks without running
cargo run  --release           # ~1h, prints every table in the paper
```

The run prints the component widths, the cost structure, the proving and
verification timings, the composed-against-separate comparison, and the body of
the correctness table, and it ends with the verdict line the paper quotes:
thirty-two negative controls rejected and twelve positive checks holding.

Timings are machine-dependent. Ours were taken on an Intel Core i7-10700 at
2.90 GHz with 32 GB under Windows 10. Widths, constraint counts and proof sizes
are deterministic and should reproduce exactly.

Section VII-A explains why the harness measures the way it does: several hundred
iterations per figure, configurations interleaved within batches so that drift
affects them equally, per-batch medians printed so drift is visible, and
quartiles rather than means. A single timing of a proving system is not a
measurement of it — the same quantity measured once returned between 765 and
835 ms across six runs of an unchanged circuit, and under this protocol two runs
of the frozen circuit agreed to three tenths of one percent.

## The checkers

Five scripts check the manuscript against itself and against the run logs. Each
targets a class of defect that ordinary proofreading does not catch, because
each involves two passages that are correct in isolation and wrong together.

```
python SourceCode/prosecheck.py    sentences that stop mid-clause; theorem
                                   environments nested inside each other;
                                   paragraphs saying the same thing twice;
                                   sentences repeating another in their own
                                   paragraph; abstract claims the body does
                                   not carry
python SourceCode/modelcheck.py    the definitions against the games: whether
                                   the policy split covers the tuple, whether a
                                   challenge may differ in a public field,
                                   whether the two games bound the same things,
                                   whether the abort and the construction's
                                   refusal are in the same units
python SourceCode/stalecheck.py    prose describing mechanisms the construction
                                   no longer has, across the manuscript, the
                                   reference implementation and the crate
python SourceCode/numcheck.py      every figure in the paper traced to a run
                                   log, and every derived figure recomputed
python SourceCode/survivors.py OLD.tex
                                   sentences carried through a rewrite, for the
                                   case where a correction lands beside the text
                                   it replaces
```

The first four run against the manuscript alone. `survivors.py` takes an earlier
copy as its argument and diffs, because the defect it looks for is invisible in
a single version: both sentences read correctly, and only their history says
which one was meant to go.

Two properties are worth stating because they are what makes the set worth
having. Each check reports when it cannot locate its subject, so a reworded
claim produces a finding rather than a silent pass. And each was validated by
making it fire on a document known to contain the defect before it was believed
on one that appeared clean.

## The reference implementation

```
python SourceCode/reference.py
```

A small executable model of the scheme, independent of the circuit. It exercises
what a constraint system cannot reach: the settlement domain's obligations, the
agent's operating rules, and the two clauses of the compliance predicate that no
proof enforces. Nineteen checks, all of which must pass, and five are worth
naming because propositions rest on them.

- With freshness (I5) enforced, a payload offered twice is admitted once.
  Without it, an agent repeats one payload past what its budget allows and
  `Extract` returns nothing: a successful overdraft leaving no evidence.
- C2 as a clause accepts a sequence that overdraws, because the cumulative total
  is supplied by the prover. The range check forbids running past the budget, so
  the agent must reset the counter, and the reset is what reveals the secret.
- Settled spend never exceeds the capacity the scheme reports as assigned, which
  is the model's inequality executed rather than asserted.
- Returning a run to the counter after a proof exists lets an extractor recover
  the agent's secret, which is why release is permitted only before proving.
- Nested revoked ranges defeat C8's single-exhibit argument and disjoint ones do
  not, which is what condition (I6) is for.
