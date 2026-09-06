use p3_air::{Air, AirBuilder, BaseAir};
use p3_goldilocks::Goldilocks;
use p3_uni_stark::{get_max_constraint_degree, get_symbolic_constraints, AirLayout};

use crate::whole::{WholeAir, PUBLIC_VALUES};

type F = Goldilocks;

/// The compliance circuit with one constraint removed: the binding of C9's
/// absorbed lanes to the policy columns the clauses read.
///
/// This is not a variant anyone should deploy. It exists to be measured. The
/// paper claims that a constraint can be cheap, load-bearing, and absent
/// without any cost figure showing it, and that claim is worth more
/// demonstrated than asserted. Removing this one binding leaves a circuit of
/// the same width, proving in the same time, producing a proof of the same
/// size, passing every other negative control --- and proving compliance with a
/// policy the principal never committed to.
///
/// The trace that goes with it carries a cap in the policy columns and a
/// different cap in the commitment. Under WholeAir it is rejected. Under this
/// AIR it verifies, and a verifier holding the delegation record cannot tell.
pub struct VacuousAir<const R: usize, const MD: usize, const RD: usize> {
    inner: WholeAir<R, MD, RD>,
}

impl<const R: usize, const MD: usize, const RD: usize> VacuousAir<R, MD, RD> {
    pub fn new() -> Self {
        Self { inner: WholeAir::<R, MD, RD>::new() }
    }
}

impl<const R: usize, const MD: usize, const RD: usize> BaseAir<F> for VacuousAir<R, MD, RD> {
    fn width(&self) -> usize {
        BaseAir::<F>::width(&self.inner)
    }

    fn num_public_values(&self) -> usize {
        PUBLIC_VALUES
    }
}

impl<AB, const R: usize, const MD: usize, const RD: usize> Air<AB> for VacuousAir<R, MD, RD>
where
    AB: AirBuilder<F = F>,
{
    fn eval(&self, builder: &mut AB) {
        self.inner.constrain_with(builder, 0, false);
    }
}

pub fn measure<const R: usize, const MD: usize, const RD: usize>() -> (usize, usize, usize) {
    let a = VacuousAir::<R, MD, RD>::new();
    let constraints = get_symbolic_constraints::<F, _>(&a, AirLayout::from_air::<F>(&a));
    let degree = get_max_constraint_degree::<F, _>(&a, AirLayout::from_air::<F>(&a));
    (BaseAir::<F>::width(&a), constraints.len(), degree)
}
