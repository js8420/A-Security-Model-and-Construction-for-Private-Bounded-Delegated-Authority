//! Constraint degrees stated rather than derived, for the AIRs that do not
//! state their own. Native only: the zkVM guests compile the AIR files, and a
//! change to any of them changes the program and its verifying key.

use p3_air::{Air, AirBuilder, BaseAir};
use p3_goldilocks::Goldilocks;
use p3_uni_stark::{get_max_constraint_degree, AirLayout};

type F = Goldilocks;

/// An AIR with its constraint degree computed once, at construction, and
/// stated to the prover and verifier from then on. ComposedAir states its own;
/// the cost study wraps every row in this, so that no row pays the symbolic
/// evaluation inside a timed proof or verification and another does not.
pub struct Stated<A> {
    air: A,
    degree: usize,
}

impl<A> Stated<A>
where
    A: BaseAir<F> + Air<p3_air::SymbolicAirBuilder<F>>,
{
    pub fn new(air: A) -> Self {
        let degree = get_max_constraint_degree::<F, _>(&air, AirLayout::from_air::<F>(&air));
        Self { air, degree }
    }
}

impl<G, A: BaseAir<G>> BaseAir<G> for Stated<A> {
    fn width(&self) -> usize {
        self.air.width()
    }

    fn num_public_values(&self) -> usize {
        self.air.num_public_values()
    }

    fn max_constraint_degree(&self) -> Option<usize> {
        Some(self.degree)
    }
}

impl<AB: AirBuilder, A: Air<AB>> Air<AB> for Stated<A> {
    fn eval(&self, builder: &mut AB) {
        self.air.eval(builder)
    }
}
