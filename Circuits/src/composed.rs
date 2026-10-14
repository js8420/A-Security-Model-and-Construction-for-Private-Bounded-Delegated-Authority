use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::Goldilocks;
use p3_uni_stark::{get_max_constraint_degree, get_symbolic_constraints, AirLayout};

use crate::air::{recompose, COL_AMOUNT, COL_B, COL_C, COL_T, RANGE_BITS};
use crate::air::COL_DOMAIN;
use crate::spend::{SpendAir, COL_DOM, COL_M, COL_UNITS, NODE_NULL, NODE_SHARE, PER_NODE};
use crate::whole::{WholeAir, PAYEE_LIMBS, PUBLIC_VALUES};

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
/// THE UNITS. The overdraft argument needs the units a payment accounts for
/// to be at least the units its amount buys. The unit size u satisfies
/// u * m = B for the committed budget and the committed unit count. The charged
/// count then satisfies (units - 1) * u < amount <= units * u, which is the
/// upward rounding of a payment's amount to whole units, stated as two
/// comparisons. Without it an
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

/// The statement a settlement is checked against, in public-value order: the
/// compliance half's nine values, the domain, then everything the reserve pays
/// or publishes. The reserve rebuilds each of these from its own record, so
/// a proof of one payment cannot answer for a settlement that paid a different
/// amount, to a different address, at a different time, or published shares
/// the proof did not compute.
pub const PV_DOMAIN: usize = PUBLIC_VALUES;
pub const PV_AMOUNT: usize = PV_DOMAIN + 1;
pub const PV_PAYEE: usize = PV_AMOUNT + 1;
pub const PV_TIME: usize = PV_PAYEE + PAYEE_LIMBS;
/// Every slot's two share lanes and its nullifier, slot by slot, in the order
/// Settle publishes them.
pub const PV_ELEMS: usize = PV_TIME + 1;
pub const ELEMS_PER_SLOT: usize = 3;

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

    /// The compliance circuit's values, the settlement domain, and what the
    /// reserve pays and publishes. The spend component reads the digest and the
    /// domain, so the two halves are proved against one public statement.
    fn num_public_values(&self) -> usize {
        PV_ELEMS + ELEMS_PER_SLOT * COVER
    }

    /// The S-box registers alone set the degree: 7 with none, 3 with one.
    /// Stated so the verifier does not re-derive it by evaluating every
    /// constraint symbolically, which inside the zkVM costs 293 million
    /// instructions. `check_degree` confirms it.
    fn max_constraint_degree(&self) -> Option<usize> {
        match R {
            0 => Some(7),
            1 => Some(3),
            _ => None,
        }
    }
}

impl<AB, const R: usize, const MD: usize, const RD: usize, const DEPTH: usize, const COVER: usize>
    Air<AB> for ComposedAir<R, MD, RD, DEPTH, COVER>
where
    AB: AirBuilder<F = F>,
{
    fn eval(&self, builder: &mut AB) {
        let w = self.whole_width();

        self.whole.constrain_payee(builder, 0, PV_PAYEE);
        self.spend.constrain(builder, w, PV_DOMAIN);

        let pv: Vec<AB::Expr> = builder.public_values().iter().map(|v| (*v).into()).collect();
        let row = builder.main().current_slice().to_vec();

        builder.assert_eq(row[COL_AMOUNT].clone().into(), pv[PV_AMOUNT].clone());
        builder.assert_eq(row[COL_T].clone().into(), pv[PV_TIME].clone());
        let nb = w + self.spend.node_base_pub();
        for c in 0..COVER {
            let n = nb + c * PER_NODE;
            let at = PV_ELEMS + ELEMS_PER_SLOT * c;
            builder.assert_eq(row[n + NODE_SHARE].clone().into(), pv[at].clone());
            builder.assert_eq(row[n + NODE_SHARE + 1].clone().into(), pv[at + 1].clone());
            builder.assert_eq(row[n + NODE_NULL].clone().into(), pv[at + 2].clone());
        }

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

        // The domain in the share index is the domain the payload names, which
        // the digest covers. Without this an agent could form the shares under
        // one domain and settle a payload naming another.
        builder.assert_eq(row[COL_DOMAIN].clone(), row[w + COL_DOM].clone());

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

/// Confirms the stated degree is the one symbolic evaluation finds, at every
/// instantiation this crate proves, so the quotient is split into the same
/// number of chunks with or without the statement.
pub fn check_degree() -> bool {
    fn one<const R: usize, const MD: usize, const RD: usize, const DEPTH: usize, const COVER: usize>(
        label: &str,
    ) -> bool {
        let a = ComposedAir::<R, MD, RD, DEPTH, COVER>::new();
        let layout = AirLayout::from_air::<F>(&a);
        let symbolic = get_max_constraint_degree::<F, _>(&a, layout);
        let stated = BaseAir::<F>::max_constraint_degree(&a);
        let mut agree = stated == Some(symbolic);
        for is_zk in [0usize, 1] {
            let derived = ((symbolic + is_zk).max(2) - 1).next_power_of_two().trailing_zeros() as usize;
            let used = p3_uni_stark::get_log_num_quotient_chunks::<F, _>(&a, layout, is_zk);
            agree &= derived == used;
        }
        println!("  {:<28} {:>9} {:>9} {:>7}", label, symbolic, format!("{stated:?}"), agree);
        agree
    }
    println!("  {:<28} {:>9} {:>9} {:>7}", "registers / MD RD DEPTH COVER", "symbolic", "stated", "agree");
    let mut ok = true;
    ok &= one::<0, 16, 32, 16, 64>("0 / 16 32 16 64");
    ok &= one::<1, 16, 32, 16, 64>("1 / 16 32 16 64");
    ok &= one::<0, 16, 32, 16, 14>("0 / 16 32 16 14");
    ok &= one::<1, 16, 32, 16, 14>("1 / 16 32 16 14");
    ok &= one::<0, 8, 8, 16, 14>("0 / 8 8 16 14");
    ok &= one::<1, 8, 8, 16, 14>("1 / 8 8 16 14");
    ok
}
