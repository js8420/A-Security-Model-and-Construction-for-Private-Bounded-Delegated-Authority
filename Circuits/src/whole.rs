use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::Goldilocks;
use p3_poseidon2_air::num_cols;
use p3_uni_stark::{get_max_constraint_degree, get_symbolic_constraints, AirLayout, SubAirBuilder};

use crate::air::{policy_src, PolicyAir, ALL_CLAUSES, PAYLOAD_ELEMS, PAYLOAD_SRC, POLICY_ELEMS};
use crate::full::{C9_PERMUTATIONS, RATE};
use crate::hash::{DOMAIN_OPENING, DOMAIN_PAYLOAD, new_hash_air, output_offset, HashAir, HALF_FULL_ROUNDS, PARTIAL_ROUNDS, SBOX_DEGREE, WIDTH};
use crate::merkle::{MerkleAir, DIGEST};
use crate::revocation::NonMembershipAir;

type F = Goldilocks;

/// C9 absorbs the policy and nothing else. It absorbed the payload digest as
/// well until 3 September 2026, which made the sponge's output a function of
/// the payment: the public value the paper calls D.com changed with every
/// payment and could not be the value the principal signed at issuance.
pub const ABSORBED: usize = POLICY_ELEMS;

/// C7's own sponge over the six payload fields. The digest is its output's
/// first lane, which is also the share index, and a share index has to be a
/// single field element because the share equation multiplies by it.
pub const PAYLOAD_PERMUTATIONS: usize = PAYLOAD_ELEMS.div_ceil(RATE);

/// Glue columns the components are bound against: the revocation root, the
/// payload digest, and the two ends of the run of units the payment consumes.
/// The allowlist roots are no longer glue, because the policy carries them in
/// full and the components bind to those.
///
/// C8 is a statement about the units a payment consumes, so the glue carries
/// the run's endpoints and the composed circuit binds them to the run the
/// spend component charges. It carried the two ends of the consumed run until
/// the run began to wrap, at which point the run stopped being an interval and
/// the question C8 answers moved up a level.
pub const GLUE: usize = DIGEST + 3;

/// Public values a verifier supplies: the payload digest, the revocation
/// accumulator root, and the delegation commitment. Without them the proof
/// asserts that some satisfying assignment exists and nothing about which
/// delegation it belongs to.
pub const PUBLIC_VALUES: usize = 1 + DIGEST + DIGEST;

pub struct WholeAir<const R: usize, const MD: usize, const RD: usize> {
    policy: PolicyAir,
    hash: HashAir<R>,
    merchant: MerkleAir<R, MD>,
    category: MerkleAir<R, MD>,
    revocation: NonMembershipAir<R, RD>,
}

impl<const R: usize, const MD: usize, const RD: usize> WholeAir<R, MD, RD> {
    pub fn new() -> Self {
        Self {
            policy: PolicyAir::new(&ALL_CLAUSES),
            hash: new_hash_air::<R>(),
            merchant: MerkleAir::<R, MD>::new(),
            category: MerkleAir::<R, MD>::new(),
            revocation: NonMembershipAir::<R, RD>::new(),
        }
    }

    fn block_width(&self) -> usize {
        num_cols::<WIDTH, SBOX_DEGREE, R, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>()
    }

    /// What C7's sponge occupies, from the same expression the width uses. It
    /// has no standalone AIR to measure, and left out of the component table it
    /// shows up as cross-component binding, which is a component wearing the
    /// label of the glue.
    pub fn payload_cols(&self) -> usize {
        PAYLOAD_PERMUTATIONS * self.block_width()
    }

    /// Where the glue keeps the run of units C8 is checked against. The
    /// composed circuit binds these to the run the spend component consumes.
    pub(crate) fn glue_run_offset(&self) -> usize {
        let (_, _, _, _, _, rv) = self.offsets();
        rv + DIGEST + 1
    }

    fn offsets(&self) -> (usize, usize, usize, usize, usize, usize) {
        let p = BaseAir::<F>::width(&self.policy);
        let pl = p + C9_PERMUTATIONS * self.block_width();
        let h = pl + PAYLOAD_PERMUTATIONS * self.block_width();
        let mc = h + BaseAir::<F>::width(&self.merchant);
        let ct = mc + BaseAir::<F>::width(&self.category);
        let rv = ct + BaseAir::<F>::width(&self.revocation);
        (p, pl, h, mc, ct, rv)
    }
}

impl<const R: usize, const MD: usize, const RD: usize> BaseAir<F> for WholeAir<R, MD, RD> {
    fn width(&self) -> usize {
        let (_, _, _, _, _, rv) = self.offsets();
        rv + GLUE
    }

    fn num_public_values(&self) -> usize {
        PUBLIC_VALUES
    }
}

impl<const R: usize, const MD: usize, const RD: usize> WholeAir<R, MD, RD> {
    /// The constraints, placed at an offset so the composed circuit can hold
    /// them beside the spend component without a second copy of this body.
    pub(crate) fn constrain<AB>(&self, builder: &mut AB, base: usize)
    where
        AB: AirBuilder<F = F>,
    {
        self.constrain_with(builder, base, true);
    }

    /// The same constraints, with C9's binding of the absorbed lanes to the
    /// policy columns optionally omitted. `bind_policy = false` is not a
    /// configuration anyone should deploy; it exists so the evaluation can
    /// measure what a circuit missing that one binding proves, which is the
    /// claim \cref{sec:conclusion} rests on and which no cost table can show.
    pub(crate) fn constrain_with<AB>(&self, builder: &mut AB, base: usize, bind_policy: bool)
    where
        AB: AirBuilder<F = F>,
    {
        let (p0, pl0, h0, mc0, ct0, rv0) = self.offsets();
        let (p, pl, h, mc, ct, rv) = (
            base + p0,
            base + pl0,
            base + h0,
            base + mc0,
            base + ct0,
            base + rv0,
        );
        let bw = self.block_width();

        self.policy.constrain(builder, base);

        for i in 0..C9_PERMUTATIONS {
            let s = p + i * bw;
            let mut sub = SubAirBuilder::<AB, HashAir<R>, F>::new(builder, s..s + bw);
            self.hash.eval(&mut sub);
        }
        for i in 0..PAYLOAD_PERMUTATIONS {
            let s = pl + i * bw;
            let mut sub = SubAirBuilder::<AB, HashAir<R>, F>::new(builder, s..s + bw);
            self.hash.eval(&mut sub);
        }
        {
            let mut sub = SubAirBuilder::<AB, MerkleAir<R, MD>, F>::new(builder, h..mc);
            self.merchant.eval(&mut sub);
        }
        {
            let mut sub = SubAirBuilder::<AB, MerkleAir<R, MD>, F>::new(builder, mc..ct);
            self.category.eval(&mut sub);
        }
        {
            let mut sub =
                SubAirBuilder::<AB, NonMembershipAir<R, RD>, F>::new(builder, ct..rv);
            self.revocation.eval(&mut sub);
        }

        // Copied out before any assertion, because public_values() borrows the
        // builder and the assertions need it mutably.
        let pv: Vec<AB::Expr> = builder.public_values().iter().map(|v| (*v).into()).collect();
        let row = builder.main().current_slice().to_vec();
        let g_rroot = rv;
        let g_payload = rv + DIGEST;
        let g_run_lo = g_payload + 1;
        let g_run_hi = g_run_lo + 1;

        // C9 absorbs the policy and only the policy, each element tied to the
        // column the clauses read, so the commitment is over the policy the
        // principal committed and is the same for every payment under it.
        for e in 0..ABSORBED {
            let lane = p + (e / RATE) * bw + (e % RATE);
            if bind_policy {
                builder.assert_eq(row[base + policy_src(e)].clone(), row[lane].clone());
            }
        }

        // C7 absorbs the payment. Its digest is the sponge's output first lane,
        // which is the value the verifier supplies and the share index the
        // accountability half uses, so the two halves are about one payment.
        for e in 0..PAYLOAD_ELEMS {
            let lane = pl + (e / RATE) * bw + (e % RATE);
            builder.assert_eq(row[base + PAYLOAD_SRC[e]].clone(), row[lane].clone());
        }
        let pl_last = pl + (PAYLOAD_PERMUTATIONS - 1) * bw + output_offset::<R>();
        builder.assert_eq(row[pl_last].clone(), row[g_payload].clone());

        // The public values anchor the statement. Without them the proof says
        // only that a satisfying assignment exists, for no particular
        // delegation, against no particular accumulator, for no particular
        // payment.
        builder.assert_eq(row[g_payload].clone().into(), pv[0].clone());
        for j in 0..DIGEST {
            builder.assert_eq(row[g_rroot + j].clone().into(), pv[1 + j].clone());
        }

        // The commitment is the sponge's final output, and it is public, so the
        // policy the circuit reads is the policy the principal committed.
        let last = p + (C9_PERMUTATIONS - 1) * bw + output_offset::<R>();
        for j in 0..DIGEST {
            builder.assert_eq(row[last + j].clone().into(), pv[1 + DIGEST + j].clone());
        }

        // Each sponge starts at its own domain separator, not at zero, so the
        // same permutation used elsewhere cannot produce either output.
        for (start, perms, elems, domain) in [
            (p, C9_PERMUTATIONS, ABSORBED, DOMAIN_OPENING),
            (pl, PAYLOAD_PERMUTATIONS, PAYLOAD_ELEMS, DOMAIN_PAYLOAD),
        ] {
            builder.assert_eq(
                row[start + RATE].clone().into(),
                AB::Expr::from_u64(domain),
            );
            for lane in (RATE + 1)..WIDTH {
                builder.assert_zero(row[start + lane].clone());
            }

            // Chaining carries every lane the step does not absorb, not only
            // the capacity. A partial final chunk absorbs fewer than RATE
            // elements, and the rate lanes it leaves alone are bound by nothing
            // else: the prover would choose them and the output with them.
            for i in 1..perms {
                let taken = core::cmp::min(RATE, elems - i * RATE);
                let prev_out = start + (i - 1) * bw + output_offset::<R>();
                let next_in = start + i * bw;
                for lane in taken..WIDTH {
                    builder.assert_eq(row[prev_out + lane].clone(), row[next_in + lane].clone());
                }
            }
        }

        // Each subtree's recomputed root must be the root the policy commits
        // to, lane for lane. Binding one lane would let a prover exhibit any
        // tree agreeing with the committed root in a single element.
        let mroot = h + self.merchant.root_offset();
        let croot = mc + self.category.root_offset();
        let rroot = ct + self.revocation.root_offset();
        for j in 0..DIGEST {
            builder.assert_eq(row[base + crate::air::COL_MROOT + j].clone(), row[mroot + j].clone());
            builder.assert_eq(row[base + crate::air::COL_CROOT + j].clone(), row[croot + j].clone());
            builder.assert_eq(row[g_rroot + j].clone(), row[rroot + j].clone());
        }

        // A leaf is a digest, so the identifier it carries occupies its first
        // lane and the rest must be zero; otherwise the path proves inclusion
        // of any leaf agreeing with the identifier in one element. The
        // revocation leaf is exempt because it is a range record rather than an
        // identifier, and NonMembershipAir fixes its unused lane itself.
        builder.assert_eq(row[base + crate::air::COL_MID].clone(), row[h].clone());
        builder.assert_eq(row[base + crate::air::COL_CID].clone(), row[mc].clone());
        for j in 1..DIGEST {
            builder.assert_zero(row[h + j].clone());
            builder.assert_zero(row[mc + j].clone());
        }

        // The run C8 is checked against is the run the glue carries.
        let run = ct + self.revocation.run_offset();
        builder.assert_eq(row[g_run_lo].clone(), row[run].clone());
        builder.assert_eq(row[g_run_hi].clone(), row[run + 1].clone());
    }
}

impl<AB, const R: usize, const MD: usize, const RD: usize> Air<AB> for WholeAir<R, MD, RD>
where
    AB: AirBuilder<F = F>,
{
    fn eval(&self, builder: &mut AB) {
        self.constrain(builder, 0);
    }
}

pub fn measure<const R: usize, const MD: usize, const RD: usize>() -> (usize, usize, usize) {
    let a = WholeAir::<R, MD, RD>::new();
    let constraints = get_symbolic_constraints::<F, _>(&a, AirLayout::from_air::<F>(&a));
    let degree = get_max_constraint_degree::<F, _>(&a, AirLayout::from_air::<F>(&a));
    (BaseAir::<F>::width(&a), constraints.len(), degree)
}
