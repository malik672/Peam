use p3_challenger::{DuplexChallenger, FieldChallenger, GrindingChallenger};
use p3_field::Field;
use p3_koala_bear::{KoalaBear, Poseidon2KoalaBear};

mod errors;
pub use errors::*;

mod prover;
pub use prover::*;

mod verifier;
use serde::{Deserialize, Serialize};
pub use verifier::*;

mod utils;
pub use utils::*;

mod wrappers;
pub use wrappers::*;

const LEAN_ISA_VECTOR_LEN: usize = 8;

pub trait ChallengeSampler<F> {
    fn sample(&mut self) -> F;

    fn sample_vec(&mut self, len: usize) -> Vec<F>;

    fn sample_bits(&mut self, bits: usize) -> usize;
}

pub trait FSChallenger<EF: Field>:
    FieldChallenger<PF<EF>> + GrindingChallenger<Witness = PF<EF>> + ChallengerState
{
}

impl<F: Field, C: FieldChallenger<PF<F>> + GrindingChallenger<Witness = PF<F>> + ChallengerState>
    FSChallenger<F> for C
{
}

pub trait ChallengerState {
    fn state(&self) -> String;
}

impl ChallengerState for DuplexChallenger<KoalaBear, Poseidon2KoalaBear<16>, 16, 8> {
    fn state(&self) -> String {
        format!("{:?}", self.sponge_state)
    }
}


#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Proof<F> {
    pub proof_data: Vec<F>,
    pub padding: bool,
    pub proof_size: usize,
}