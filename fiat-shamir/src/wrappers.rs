use p3_challenger::{FieldChallenger, GrindingChallenger};
use p3_field::{ExtensionField, Field, PrimeCharacteristicRing};

use crate::*;

pub(crate) type PF<F> = <F as PrimeCharacteristicRing>::PrimeSubfield;

pub trait FSProver<EF: PrimeCharacteristicRing>: ChallengeSampler<EF> {
    fn add_base_scalars(&mut self, scalars: &[PF<EF>]);
    fn add_extension_scalars(&mut self, scalars: &[EF]);
    fn add_extension_scalar(&mut self, scalar: EF);
    fn hint_base_scalars(&mut self, scalars: &[PF<EF>]);
    fn hint_extension_scalars(&mut self, scalars: &[EF]);
    fn pow_grinding(&mut self, bits: usize);
}

impl<EF, Challenger> FSProver<EF> for ProverState<PF<EF>, EF, Challenger>
where
    EF: ExtensionField<PF<EF>>,
    PF<EF>: Field,
    Challenger: FieldChallenger<PF<EF>> + GrindingChallenger<Witness = PF<EF>>,
{
    fn add_base_scalars(&mut self, scalars: &[PF<EF>]) {
        self.add_base_scalars(scalars);
    }

    fn add_extension_scalars(&mut self, scalars: &[EF]) {
        self.add_extension_scalars(scalars);
    }

    fn add_extension_scalar(&mut self, scalar: EF) {
        self.add_extension_scalar(scalar);
    }

    fn hint_base_scalars(&mut self, scalars: &[PF<EF>]) {
        self.hint_base_scalars(scalars);
    }

    fn hint_extension_scalars(&mut self, scalars: &[EF]) {
        self.hint_extension_scalars(scalars);
    }

    fn pow_grinding(&mut self, bits: usize) {
        self.pow_grinding(bits);
    }
}

pub trait FSVerifier<EF: PrimeCharacteristicRing>: ChallengeSampler<EF> {
    fn next_base_scalars_vec(&mut self, n: usize) -> Result<Vec<PF<EF>>, ProofError>;
    fn next_base_scalars_const<const N: usize>(&mut self) -> Result<[PF<EF>; N], ProofError>;
    fn next_extension_scalar(&mut self) -> Result<EF, ProofError>;
    fn next_extension_scalars_vec(&mut self, n: usize) -> Result<Vec<EF>, ProofError>;
    fn next_extension_scalars_const<const N: usize>(&mut self) -> Result<[EF; N], ProofError>;
    fn receive_hint_base_scalars(&mut self, n: usize) -> Result<Vec<PF<EF>>, ProofError>;
    fn receive_hint_extension_scalars(&mut self, n: usize) -> Result<Vec<EF>, ProofError>;
    fn check_pow_grinding(&mut self, bits: usize) -> Result<(), ProofError>;
}

impl<EF, Challenger> FSVerifier<EF> for VerifierState<PF<EF>, EF, Challenger>
where
    EF: ExtensionField<PF<EF>>,
    PF<EF>: Field,
    Challenger: FieldChallenger<PF<EF>> + GrindingChallenger<Witness = PF<EF>>,
{
    fn next_base_scalars_vec(&mut self, n: usize) -> Result<Vec<PF<EF>>, ProofError> {
        self.next_base_scalars_vec(n)
    }

    fn next_base_scalars_const<const N: usize>(&mut self) -> Result<[PF<EF>; N], ProofError> {
        self.next_base_scalars_const::<N>()
    }

    fn next_extension_scalar(&mut self) -> Result<EF, ProofError> {
        self.next_extension_scalar()
    }

    fn next_extension_scalars_vec(&mut self, n: usize) -> Result<Vec<EF>, ProofError> {
        self.next_extension_scalars_vec(n)
    }

    fn next_extension_scalars_const<const N: usize>(&mut self) -> Result<[EF; N], ProofError> {
        self.next_extension_scalars_const::<N>()
    }

    fn receive_hint_base_scalars(&mut self, n: usize) -> Result<Vec<PF<EF>>, ProofError> {
        self.receive_hint_base_scalars(n)
    }

    fn receive_hint_extension_scalars(&mut self, n: usize) -> Result<Vec<EF>, ProofError> {
        self.receive_hint_extension_scalars(n)
    }

    fn check_pow_grinding(&mut self, bits: usize) -> Result<(), ProofError> {
        self.check_pow_grinding(bits)
    }
}
