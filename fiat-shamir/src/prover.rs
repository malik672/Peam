use crate::*;
use p3_challenger::{FieldChallenger, GrindingChallenger};
use p3_field::{ExtensionField, Field};
use std::fmt::Debug;

/// State held by the prover in a Fiat-Shamir protocol.
///
/// This struct tracks the prover's transcript data and manages interaction
/// with a cryptographic challenger. It collects data to be sent to the verifier,
/// maintains the current transcript for challenge derivation, and supports
/// hints and proof-of-work (PoW) grinding mechanisms.
#[derive(Debug)]
pub struct ProverState<F, EF, Challenger> {
    /// Cryptographic challenger used to sample challenges and observe data.
    challenger: Challenger,

    /// Transcript data (proof data) accumulated during protocol execution,
    /// to be sent to the verifier.
    proof_data: Vec<F>,

    /// Indicates whether padding is used for alignment by LEAN_ISA_VECTOR_LEN (set to true for recursion)
    padding: bool,

    // number of empty field elements, added to simplify the recursive proof, but could be removed to reduce proof size
    n_zeros: usize,

    /// Marker to keep track of the extension field type without storing it explicitly.
    _extension_field: std::marker::PhantomData<EF>,
}

impl<F, EF, Challenger> ProverState<F, EF, Challenger>
where
    EF: ExtensionField<F>,
    F: Field,
    Challenger: FieldChallenger<F> + GrindingChallenger<Witness = F>,
{
    /// Create a new prover state with a given domain separator and challenger.
    ///
    /// # Arguments
    /// - `domain_separator`: Used to bind this transcript to a specific protocol context.
    /// - `challenger`: The initial cryptographic challenger state.
    ///
    /// # Returns
    /// A fresh `ProverState` ready to accumulate data.
    #[must_use]
    pub fn new(challenger: Challenger, padding: bool) -> Self
    where
        Challenger: Clone,
    {
        Self {
            challenger,
            proof_data: Vec::new(),
            padding,
            n_zeros: 0,
            _extension_field: std::marker::PhantomData,
        }
    }

    pub fn challenger(&self) -> &Challenger {
        &self.challenger
    }

    pub fn proof_size(&self) -> usize {
        self.proof_data.len() - self.n_zeros
    }

    pub fn into_proof(self) -> Proof<F> {
        let proof_size = self.proof_size();
        Proof {
            proof_data: self.proof_data,
            padding: self.padding,
            proof_size,
        }
    }

    /// Append base field scalars to the transcript and observe them in the challenger.
    ///
    /// # Arguments
    /// - `scalars`: Slice of base field elements to append.
    pub fn add_base_scalars(&mut self, scalars: &[F]) {
        // Extend the proof data vector with these scalars.
        self.proof_data.extend(scalars);

        // Notify the challenger that these scalars have been committed.
        self.challenger.observe_slice(scalars);
    }

    /// Append extension field scalars to the transcript.
    ///
    /// Internally, these are flattened to base field scalars.
    ///
    /// # Arguments
    /// - `scalars`: Slice of extension field elements to append.
    pub fn add_extension_scalars(&mut self, scalars: &[EF]) {
        // Flatten each extension scalar into base scalars and delegate.
        for ef in scalars {
            let mut base_scalars = ef.as_basis_coefficients_slice().to_vec();
            if self.padding {
                self.n_zeros += LEAN_ISA_VECTOR_LEN - base_scalars.len();
                base_scalars.resize(LEAN_ISA_VECTOR_LEN, F::ZERO);
            }
            self.add_base_scalars(&base_scalars);
        }
    }

    /// Append a single extension field scalar to the transcript.
    ///
    /// # Arguments
    /// - `scalar`: Extension field element to append.
    pub fn add_extension_scalar(&mut self, scalar: EF) {
        // Call the multi-scalar function with a one-element slice.
        self.add_extension_scalars(&[scalar]);
    }

    /// Append base field scalars to the transcript as hints.
    ///
    /// Unlike `add_base_scalars`, hints are not observed by the challenger.
    ///
    /// # Arguments
    /// - `scalars`: Slice of base field elements to append.
    pub fn hint_base_scalars(&mut self, scalars: &[F]) {
        assert!(scalars.len() % LEAN_ISA_VECTOR_LEN == 0);
        // Only extend proof data, no challenger observation.
        self.proof_data.extend(scalars);
    }

    /// Append extension field scalars to the transcript as hints.
    ///
    /// # Arguments
    /// - `scalars`: Slice of extension field elements to append.
    pub fn hint_extension_scalars(&mut self, scalars: &[EF]) {
        assert!(scalars.len() % LEAN_ISA_VECTOR_LEN == 0);
        // Flatten extension field scalars and append as base field scalars.
        self.proof_data.extend(flatten_scalars_to_base(scalars));
    }

    /// Sample a new random extension field element from the challenger.
    ///
    /// # Returns
    /// A new challenge element in the extension field.
    pub fn sample(&mut self) -> EF {
        self.challenger.sample_algebra_element()
    }

    pub fn sample_vec(&mut self, len: usize) -> Vec<EF> {
        (0..len).map(|_| self.sample()).collect()
    }

    /// Sample random bits from the challenger.
    ///
    /// # Arguments
    /// - `bits`: Number of bits to sample.
    ///
    /// # Returns
    /// A uniformly random value with `bits` bits.
    pub fn sample_bits(&mut self, bits: usize) -> usize {
        self.challenger.sample_bits(bits)
    }

    /// Perform PoW grinding and append the witness to the transcript.
    ///
    /// # Arguments
    /// - `bits`: Number of bits of grinding difficulty. If zero, no grinding is performed.
    pub fn pow_grinding(&mut self, bits: usize) {
        // Skip grinding entirely if difficulty is zero.
        if bits == 0 {
            return;
        }

        // Perform grinding and obtain a witness element in the base field.
        let witness = self.challenger.grind(bits);

        // Append the witness to the proof data.
        self.proof_data.push(witness);
        if self.padding {
            for _ in 0..LEAN_ISA_VECTOR_LEN - 1 {
                self.proof_data.push(F::ZERO);
                self.n_zeros += 1;
            }
        }
    }
}

impl<F, EF, Challenger> ChallengeSampler<EF> for ProverState<F, EF, Challenger>
where
    EF: ExtensionField<F>,
    F: Field,
    Challenger: FieldChallenger<F> + GrindingChallenger<Witness = F>,
{
    fn sample_bits(&mut self, bits: usize) -> usize {
        self.sample_bits(bits)
    }

    fn sample(&mut self) -> EF {
        self.sample()
    }

    fn sample_vec(&mut self, len: usize) -> Vec<EF> {
        self.sample_vec(len)
    }
}
