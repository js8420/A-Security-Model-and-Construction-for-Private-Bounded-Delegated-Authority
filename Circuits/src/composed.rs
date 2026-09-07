use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::Goldilocks;
use p3_uni_stark::{get_max_constraint_degree, get_symbolic_constraints, AirLayout};

use crate::air::{recompose, COL_AMOUNT, COL_B, COL_C, COL_G, RANGE_BITS};
use crate::spend::{SpendAir, COL_M, COL_SELF, COL_UNITS};
use crate::whole::{WholeAir, PUBLIC_VALUES};

type F = Goldilocks;

/// The compliance circuit and the accountability circuit as one statement.
///
/// Proved separately they satisfy their properties separately and neither
/// jointly: the compliance proof says a payment of some amount complies, the
/// accountability proof says some run of units was consumed, and nothing said
/// the two were about the same payment. Sharing the payload digest as a public
/// input is not enough, because the digest is not computed from the payment and
/// binds no field of it.
///
/// Two bindings close that here.
///
/// THE RUN. C8 proves the units a payment consumes are not revoked, and they
/// must be the units the spend component consumes, so the glue columns carrying
/// the run's endpoints are tied to the spend component's own.
///
/// THE UNITS. Proposition 8's pigeonhole needs the units a payment accounts for
/// to be at least the units its amount buys. The unit size u satisfies
/// u * m = B for the committed budget and the committed unit count. The charged
/// count then satisfies (units - 1) * u < amount <= units * u, which is the
/// upward rounding of Section VI-A stated as two comparisons. Without it an
/// agent settles any amount while accounting one unit.
///
/// An earlier form tied u to the padded tree, u * 2^DEPTH = B, which said every
/// delegation with a given unit size holds the same budget.
pub struct ComposedAir<
    const R: usize,
    const MD: usize,
    const RD: usize,
    const DEPTH: usize,
    const COVER: usize,
> {
    whole: WholeAir<R, MD, RD>,
    spend: SpendAir<R, DEPTH, COVER>,
}

/// units * u - amount; amount - (units - 1) * u - 1; and the cap fitting inside
/// the budget.
///
/// The last is a well-formedness condition on the policy rather than a fact
/// about the payment: a policy whose cap exceeds its budget admits payments no
/// honest agent could settle. Stating that condition and not enforcing it is
/// the failure this construction's evaluation is about, so it is enforced.
pub const RANGE_BLOCKS: usize = 3;

/// The unit size, witnessed and tied to the committed budget.
pub const EXTRA_COLS: usize = 1;

impl<
        const R: usize,
        const MD: usize,
        const RD: usize,
        const DEPTH: usize,
        const COVER: usize,
    > ComposedAir<R, MD, RD, DEPTH, COVER>
{
    pub fn new() -> Self {
        Self {
            whole: WholeAir::<R, MD, RD>::new(),
            spend: SpendAir::<R, DEPTH, COVER>::new(),
        }
    }

    pub fn whole_width(&self) -> usize {
        BaseAir::<F>::width(&self.whole)
    }

    pub fn spend_width(&self) -> usize {
        BaseAir::<F>::width(&self.spend)
    }

    /// The witnessed unit size, then the two comparison blocks.
    pub fn unit_col(&self) -> usize {
        self.whole_width() + self.spend_width()
    }
}

impl<
        const R: usize,
        const MD: usize,
        const RD: usize,
        const DEPTH: usize,
        const COVER: usize,
    > BaseAir<F> for ComposedAir<R, MD, RD, DEPTH, COVER>
{
    fn width(&self) -> usize {
        self.unit_col() + EXTRA_COLS + RANGE_BLOCKS * RANGE_BITS
    }

    /// The same nine a verifier of the compliance circuit supplies. The spend
    /// component reads the payload digest from the first of them, so the two
    /// halves are proved against one public statement rather than two.
    fn num_public_values(&self) -> usize {
        PUBLIC_VALUES
    }
}

impl<AB, const R: usize, const MD: usize, const RD: usize, const DEPTH: usize, const COVER: usize>
    Air<AB> for ComposedAir<R, MD, RD, DEPTH, COVER>
where
    AB: AirBuilder<F = F>,
{
    fn eval(&self, builder: &mut AB) {
        let w = self.whole_width();

        self.whole.constrain(builder, 0);
        self.spend.constrain(builder, w);

        let row = builder.main().current_slice().to_vec();

        let u_col = self.unit_col();
        let rb = u_col + EXTRA_COLS;

        let u: AB::Expr = row[u_col].clone().into();
        let amount: AB::Expr = row[COL_AMOUNT].clone().into();
        let units: AB::Expr = row[w + COL_UNITS].clone().into();
        let budget: AB::Expr = row[COL_B].clone().into();
        let m: AB::Expr = row[w + COL_M].clone().into();

        // The unit count the spend component charges against is the one the
        // budget determines: B = u * m. An earlier revision divided the budget
        // and had to bind two committed fields and their product; there is one
        // quantity here and one binding.
        builder.assert_eq(u.clone() * m.clone(), budget.clone());

        // What the delegation keeps for itself is committed on the same terms,
        // so the run check above is against a figure the principal signed and
        // not one the agent picks.
        builder.assert_eq(
            u.clone() * row[w + COL_SELF].clone().into(),
            row[COL_G].clone().into(),
        );

        // The run C8 is checked against is the run the payment consumes. Runs
        // are contiguous again, so the first and last positions bound it.
        let lo = self.whole.glue_run_offset();
        let pos = w + self.spend.pos_base();
        builder.assert_eq(row[lo].clone().into(), row[pos].clone().into());
        builder.assert_eq(
            row[lo + 1].clone().into() + AB::Expr::ONE,
            row[pos + COVER].clone().into(),
        );

        let one = AB::Expr::ONE;
        let gaps = [
            units.clone() * u.clone() - amount.clone(),
            amount - (units - one.clone()) * u - one,
            budget - row[COL_C].clone().into(),
        ];
        for (g, gap) in gaps.into_iter().enumerate() {
            let start = rb + g * RANGE_BITS;
            let bits: Vec<AB::Var> = row[start..start + RANGE_BITS].iter().cloned().collect();
            for b in &bits {
                builder.assert_bool(b.clone());
            }
            builder.assert_eq(gap, recompose::<AB>(&bits));
        }
    }
}

pub fn measure<
    const R: usize,
    const MD: usize,
    const RD: usize,
    const DEPTH: usize,
    const COVER: usize,
>() -> (usize, usize, usize) {
    let a = ComposedAir::<R, MD, RD, DEPTH, COVER>::new();
    let constraints = get_symbolic_constraints::<F, _>(&a, AirLayout::from_air::<F>(&a));
    let degree = get_max_constraint_degree::<F, _>(&a, AirLayout::from_air::<F>(&a));
    (BaseAir::<F>::width(&a), constraints.len(), degree)
}
