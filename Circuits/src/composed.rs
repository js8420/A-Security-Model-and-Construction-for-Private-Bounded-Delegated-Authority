use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::Goldilocks;
use p3_uni_stark::{get_max_constraint_degree, get_symbolic_constraints, AirLayout, SubAirBuilder};

use crate::air::{recompose, COL_AMOUNT, COL_B, COL_C, COL_T, RANGE_BITS};
use crate::air::COL_DOMAIN;
use crate::hash::{new_hash_air, output_offset, HashAir, DOMAIN_SECRET, WIDTH};
use crate::spend::{
    SpendAir, COL_BASE, COL_DOM, COL_M, COL_ROOT_KEY, COL_SECRET, COL_UNITS, NODE_NULL, NODE_SHARE,
    PER_NODE, SECRET_ELEMS,
};
use crate::merkle::DIGEST;
use crate::whole::{Anchors, WholeAir, PAYEE_LIMBS};

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
    hash: HashAir<R>,
    rows: usize,
    periodic: Vec<Vec<F>>,
}

/// units * u - amount; amount - (units - 1) * u - 1; and the cap fitting inside
/// the budget.
///
/// The last is a well-formedness condition on the policy rather than a fact
/// about the payment: a policy whose cap exceeds its budget admits payments no
/// honest agent could settle. Stating that condition and not enforcing it is
/// the failure this construction's evaluation is about, so it is enforced.
pub const RANGE_BLOCKS: usize = 3;

/// The unit size, witnessed, tied to the committed budget and to the public
/// unit size.
pub const EXTRA_COLS: usize = 1;

/// The public values are the delegation's terms once, then one block per
/// payment. A proof is of a batch: row i of the trace is payment i mod the
/// batch size, and each row is bound to its own block through periodic
/// columns the verifier evaluates itself, so one proof carries up to one
/// payment per row at no extra height. A batch of one is the single payment.
///
/// The terms are those the reserve records in the clear: D.com, the unit size,
/// the first index of the unit range and its declared length, and H(s). Each
/// was a free witness once, and each freedom was an overdraft.
pub const G_COM: usize = 0;
pub const G_UNIT: usize = G_COM + DIGEST;
pub const G_BASE: usize = G_UNIT + 1;
pub const G_RANGE: usize = G_BASE + 1;
pub const G_SECRET_HASH: usize = G_RANGE + 1;
pub const SECRET_HASH_LANES: usize = 4;
pub const GLOBALS: usize = G_SECRET_HASH + SECRET_HASH_LANES;

/// A payment's block: what the reserve pays, records or publishes for it. The
/// payload digest, the revocation root it was proved against, the domain, the
/// amount, the payee's limbs, the signed time, and every slot's two share
/// lanes and nullifier, slot by slot.
pub const R_DIGEST: usize = 0;
pub const R_ROOT: usize = R_DIGEST + 1;
pub const R_DOMAIN: usize = R_ROOT + DIGEST;
pub const R_AMOUNT: usize = R_DOMAIN + 1;
pub const R_PAYEE: usize = R_AMOUNT + 1;
pub const R_TIME: usize = R_PAYEE + PAYEE_LIMBS;
pub const R_ELEMS: usize = R_TIME + 1;
pub const ELEMS_PER_SLOT: usize = 3;

pub const fn row_width(cover: usize) -> usize {
    R_ELEMS + ELEMS_PER_SLOT * cover
}

impl<
        const R: usize,
        const MD: usize,
        const RD: usize,
        const DEPTH: usize,
        const COVER: usize,
    > ComposedAir<R, MD, RD, DEPTH, COVER>
{
    /// A batch of one, with every payment value zero: the shape the
    /// measurements and the degree check need, not a statement to prove.
    pub fn new() -> Self {
        Self::with_statements(1, vec![F::ZERO; row_width(COVER)])
    }

    /// The circuit proved against these public values: the terms, then one
    /// block per payment. The batch size is read from their length and must be
    /// a power of two no larger than the trace.
    pub fn from_public_values(pv: &[F]) -> Self {
        let rw = row_width(COVER);
        assert!(pv.len() > GLOBALS && (pv.len() - GLOBALS) % rw == 0, "public values are not terms and whole payments");
        let rows = (pv.len() - GLOBALS) / rw;
        Self::with_statements(rows, pv[GLOBALS..].to_vec())
    }

    fn with_statements(rows: usize, blocks: Vec<F>) -> Self {
        assert!(rows.is_power_of_two(), "a batch is a power of two of payments");
        let rw = row_width(COVER);
        let periodic = (0..rw).map(|j| (0..rows).map(|r| blocks[r * rw + j]).collect()).collect();
        Self {
            whole: WholeAir::<R, MD, RD>::new(),
            spend: SpendAir::<R, DEPTH, COVER>::new(),
            hash: new_hash_air::<R>(),
            rows,
            periodic,
        }
    }

    pub fn whole_width(&self) -> usize {
        BaseAir::<F>::width(&self.whole)
    }

    pub fn spend_width(&self) -> usize {
        BaseAir::<F>::width(&self.spend)
    }

    /// The witnessed unit size, then the comparison blocks.
    pub fn unit_col(&self) -> usize {
        self.whole_width() + self.spend_width()
    }

    /// The permutation that hashes the secret, after the comparison blocks.
    pub fn secret_block(&self) -> usize {
        self.unit_col() + EXTRA_COLS + RANGE_BLOCKS * RANGE_BITS
    }

    fn block_width(&self) -> usize {
        BaseAir::<F>::width(&self.hash)
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
        self.secret_block() + self.block_width()
    }

    /// The compliance circuit's values, the settlement domain, and what the
    /// reserve pays and publishes. The spend component reads the digest and the
    /// domain, so the two halves are proved against one public statement.
    fn num_public_values(&self) -> usize {
        GLOBALS + self.rows * row_width(COVER)
    }

    /// Each payment's block as columns the verifier evaluates at the
    /// out-of-domain point itself. They are also public values, so the
    /// Fiat-Shamir transcript absorbs them before any challenge is drawn.
    fn num_periodic_columns(&self) -> usize {
        row_width(COVER)
    }

    fn periodic_columns(&self) -> Vec<Vec<F>> {
        self.periodic.clone()
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
        let pv: Vec<AB::Expr> = builder.public_values().iter().map(|v| (*v).into()).collect();
        let per: Vec<AB::Expr> = builder.periodic_values().iter().map(|v| (*v).into()).collect();

        self.whole.constrain_anchored(
            builder,
            0,
            true,
            Anchors {
                digest: per[R_DIGEST].clone(),
                rroot: per[R_ROOT..R_ROOT + DIGEST].to_vec(),
                com: pv[G_COM..G_COM + DIGEST].to_vec(),
                payee: Some(per[R_PAYEE..R_PAYEE + PAYEE_LIMBS].to_vec()),
            },
        );
        self.spend.constrain_anchored(
            builder,
            w,
            false,
            per[R_DIGEST].clone(),
            per[R_DOMAIN].clone(),
            Some(pv[G_RANGE].clone()),
        );
        let sb = self.secret_block();
        {
            let bw = self.block_width();
            let mut sub = SubAirBuilder::<AB, HashAir<R>, F>::new(builder, sb..sb + bw);
            self.hash.eval(&mut sub);
        }

        let row = builder.main().current_slice().to_vec();

        builder.assert_eq(row[COL_AMOUNT].clone().into(), per[R_AMOUNT].clone());
        builder.assert_eq(row[COL_T].clone().into(), per[R_TIME].clone());
        builder.assert_eq(row[self.unit_col()].clone().into(), pv[G_UNIT].clone());
        builder.assert_eq(row[w + COL_BASE].clone().into(), pv[G_BASE].clone());

        // H(s) and the root key are one permutation of the secret: the secret
        // in the first lanes, the separator after it, zeros elsewhere. Its
        // output's first lanes are the root key the slots derive from and the
        // next four the public H(s).
        for j in 0..SECRET_ELEMS {
            builder.assert_eq(row[sb + j].clone(), row[w + COL_SECRET + j].clone());
        }
        builder.assert_eq(row[sb + SECRET_ELEMS].clone().into(), AB::Expr::from_u64(DOMAIN_SECRET));
        for lane in (SECRET_ELEMS + 1)..WIDTH {
            builder.assert_zero(row[sb + lane].clone());
        }
        let out = sb + output_offset::<R>();
        for j in 0..SECRET_ELEMS {
            builder.assert_eq(row[out + j].clone(), row[w + COL_ROOT_KEY + j].clone());
        }
        for j in 0..SECRET_HASH_LANES {
            builder.assert_eq(row[out + SECRET_ELEMS + j].clone().into(), pv[G_SECRET_HASH + j].clone());
        }
        let nb = w + self.spend.node_base_pub();
        for c in 0..COVER {
            let n = nb + c * PER_NODE;
            let at = R_ELEMS + ELEMS_PER_SLOT * c;
            builder.assert_eq(row[n + NODE_SHARE].clone().into(), per[at].clone());
            builder.assert_eq(row[n + NODE_SHARE + 1].clone().into(), per[at + 1].clone());
            builder.assert_eq(row[n + NODE_NULL].clone().into(), per[at + 2].clone());
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

        // The run C8 is checked against is the run the payment consumes, in
        // the absolute indices revocations name: the delegation's base plus
        // the run's offsets. Runs are contiguous, so the first and last
        // positions bound it.
        let lo = self.whole.glue_run_offset();
        let pos = w + self.spend.pos_base();
        let pbase: AB::Expr = row[w + COL_BASE].clone().into();
        builder.assert_eq(row[lo].clone().into(), pbase.clone() + row[pos].clone().into());
        builder.assert_eq(
            row[lo + 1].clone().into() + AB::Expr::ONE,
            pbase + row[pos + COVER].clone().into(),
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
        let mut agree = true;
        for rows in [1usize, 256] {
            let a = ComposedAir::<R, MD, RD, DEPTH, COVER>::from_public_values(
                &vec![F::ZERO; GLOBALS + rows * row_width(COVER)],
            );
            let layout = AirLayout::from_air::<F>(&a);
            let symbolic = get_max_constraint_degree::<F, _>(&a, layout);
            let stated = BaseAir::<F>::max_constraint_degree(&a);
            let mut here = stated == Some(symbolic);
            for is_zk in [0usize, 1] {
                let derived = ((symbolic + is_zk).max(2) - 1).next_power_of_two().trailing_zeros() as usize;
                let used = p3_uni_stark::get_log_num_quotient_chunks::<F, _>(&a, layout, is_zk);
                here &= derived == used;
            }
            println!("  {:<22} {:>5} {:>9} {:>9} {:>7}", label, rows, symbolic, format!("{stated:?}"), here);
            agree &= here;
        }
        agree
    }
    println!("  {:<22} {:>5} {:>9} {:>9} {:>7}", "registers / MD RD D C", "batch", "symbolic", "stated", "agree");
    let mut ok = true;
    ok &= one::<0, 16, 32, 16, 64>("0 / 16 32 16 64");
    ok &= one::<1, 16, 32, 16, 64>("1 / 16 32 16 64");
    ok &= one::<0, 16, 32, 16, 14>("0 / 16 32 16 14");
    ok &= one::<1, 16, 32, 16, 14>("1 / 16 32 16 14");
    ok &= one::<0, 8, 8, 16, 14>("0 / 8 8 16 14");
    ok &= one::<1, 8, 8, 16, 14>("1 / 8 8 16 14");
    ok
}
