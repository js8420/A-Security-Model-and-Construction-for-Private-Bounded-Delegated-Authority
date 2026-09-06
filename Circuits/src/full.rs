use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::Goldilocks;
use p3_poseidon2_air::num_cols;
use p3_uni_stark::{get_max_constraint_degree, get_symbolic_constraints, AirLayout, SubAirBuilder};

use crate::air::{policy_src, PolicyAir, ALL_CLAUSES, POLICY_ELEMS};
use crate::hash::{DOMAIN_OPENING, new_hash_air, HashAir, HALF_FULL_ROUNDS, PARTIAL_ROUNDS, SBOX_DEGREE, WIDTH};

type F = Goldilocks;

/// Elements absorbed by C9: the policy scalars, both Merkle roots in full, and
/// the blinding value. The roots are DIGEST elements each rather than one, so
/// that the commitment fixes the whole root and not a single lane of it.
pub const C9_ELEMENTS: usize = POLICY_ELEMS;

/// Sponge rate at width 8 with a capacity of 4.
pub const RATE: usize = 4;

pub const C9_PERMUTATIONS: usize = C9_ELEMENTS.div_ceil(RATE);

/// Policy clauses plus the opening constraint, laid out as the policy columns
/// followed by one column block per permutation.
pub struct FullAir<const R: usize> {
    policy: PolicyAir,
    hash: HashAir<R>,
}

impl<const R: usize> FullAir<R> {
    pub fn new() -> Self {
        Self {
            policy: PolicyAir::new(&ALL_CLAUSES),
            hash: new_hash_air::<R>(),
        }
    }

    fn policy_width(&self) -> usize {
        BaseAir::<F>::width(&self.policy)
    }

    fn block_width(&self) -> usize {
        num_cols::<WIDTH, SBOX_DEGREE, R, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>()
    }
}

impl<const R: usize> BaseAir<F> for FullAir<R> {
    fn width(&self) -> usize {
        self.policy_width() + C9_PERMUTATIONS * self.block_width()
    }
}

impl<AB, const R: usize> Air<AB> for FullAir<R>
where
    AB: AirBuilder<F = F>,
{
    fn eval(&self, builder: &mut AB) {
        // Policy columns sit first, so the policy AIR reads absolute indices.
        self.policy.eval(builder);

        let base = self.policy_width();
        let bw = self.block_width();

        for i in 0..C9_PERMUTATIONS {
            let start = base + i * bw;
            let mut sub =
                SubAirBuilder::<AB, HashAir<R>, F>::new(builder, start..start + bw);
            self.hash.eval(&mut sub);
        }

        // Bind the absorbed elements to the policy columns the clauses read.
        // Without this the hash proves a statement about unrelated values and
        // every other constraint becomes vacuous.
        let row = builder.main().current_slice().to_vec();
        for e in 0..C9_ELEMENTS {
            let absorbed = base + (e / RATE) * bw + (e % RATE);
            builder.assert_eq(row[policy_src(e)].clone(), row[absorbed].clone());
        }

        // The sponge starts at its domain separator, not at zero. Without this
        // the initial capacity is a value the prover chooses, and the same
        // permutation would stand behind two uses with no way to tell them apart.
        builder.assert_eq(
            row[base + RATE].clone().into(),
            AB::Expr::from_u64(DOMAIN_OPENING),
        );
        for lane in (RATE + 1)..WIDTH {
            builder.assert_zero(row[base + lane].clone());
        }
    }
}

pub fn measure<const R: usize>() -> (usize, usize, usize) {
    let a = FullAir::<R>::new();
    let constraints = get_symbolic_constraints::<F, _>(&a, AirLayout::from_air::<F>(&a));
    let degree = get_max_constraint_degree::<F, _>(&a, AirLayout::from_air::<F>(&a));
    (BaseAir::<F>::width(&a), constraints.len(), degree)
}
