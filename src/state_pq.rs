use crate::crypto::pq;
use peam_consensus_types::containers::block::SignedBlockWithAttestation;
use peam_ssz::ssz::HashTreeRoot;
use peam_state::state::{SignatureVerifier, State};
use peam_state::state_metrics::TransitionMetricsSink;
use peam_storage::SignedBlockProcessor;

/// A [`SignatureVerifier`] that performs full post-quantum aggregate-signature
/// verification for each attestation and the block proposer.
pub struct PqSignatureVerifier;
pub struct PqBlockProcessor;

impl SignatureVerifier for PqSignatureVerifier {
    #[inline]
    fn verify_signed_block(
        &self,
        signed: &SignedBlockWithAttestation,
        state: &State,
    ) -> Result<(), String> {
        let block = &signed.message.block;
        let attestations = block.body.attestations.as_slice();
        let proofs = signed.signature.attestation_signatures.as_slice();
        if attestations.len() != proofs.len() {
            return Err(format!(
                "attestation signatures count {} does not match attestations {}",
                proofs.len(),
                attestations.len()
            ));
        }
        if !proofs.is_empty() {
            static PQ_AGG_VERIFIER_INIT: std::sync::Once = std::sync::Once::new();
            PQ_AGG_VERIFIER_INIT.call_once(pq::setup_aggregate_verifier);
        }

        let validators = state.validators.as_slice();
        let mut public_keys = Vec::new();

        for (att, proof) in attestations.iter().zip(proofs.iter()) {
            public_keys.clear();
            let bit_len = att.aggregation_bits.len;
            for (byte_idx, byte) in att.aggregation_bits.data.iter().copied().enumerate() {
                let mut remaining = byte;
                while remaining != 0 {
                    let bit = remaining.trailing_zeros() as usize;
                    let idx = byte_idx * 8 + bit;
                    if idx >= bit_len {
                        break;
                    }
                    let validator = validators
                        .get(idx)
                        .ok_or_else(|| "validator index out of range".to_string())?;
                    public_keys.push(validator.attestation_pubkey);
                    remaining &= remaining - 1;
                }
            }
            if public_keys.is_empty() {
                return Err("attestation aggregate participants must be non-empty".to_string());
            }
            let message = att.data.hash_tree_root();
            if let Err(err) = pq::verify_aggregate_signature(
                &public_keys,
                &message,
                proof.proof_data.as_slice(),
                att.data.slot.0.0 as u32,
            ) {
                return Err(err);
            }
        }

        let proposer_idx = block.proposer_index.0.0 as usize;
        let proposer_pubkey = validators
            .get(proposer_idx)
            .map(|validator| validator.proposal_pubkey)
            .ok_or_else(|| "proposer index out of range".to_string())?;
        let proposer_message = block.hash_tree_root();
        pq::verify_signature(
            &proposer_pubkey,
            block.slot.0.0 as u32,
            &proposer_message,
            &signed.signature.proposer_signature,
        )?;
        Ok(())
    }
}

impl SignedBlockProcessor for PqBlockProcessor {
    #[inline]
    fn process_signed_block(
        state: &mut State,
        signed: &SignedBlockWithAttestation,
    ) -> Result<(), String> {
        let verifier = PqSignatureVerifier;
        state.process_signed_block_with_verifier(signed, &verifier)
    }

    #[inline]
    fn process_signed_block_with_metrics<M: TransitionMetricsSink>(
        state: &mut State,
        signed: &SignedBlockWithAttestation,
        metrics: &M,
    ) -> Result<(), String> {
        let verifier = PqSignatureVerifier;
        state.process_signed_block_with_verifier_and_sink(signed, &verifier, metrics)
    }
}

pub trait StatePqExt {
    fn process_signed_block(&mut self, signed: &SignedBlockWithAttestation) -> Result<(), String>;

    fn process_signed_block_with_metrics<M: TransitionMetricsSink>(
        &mut self,
        signed: &SignedBlockWithAttestation,
        metrics: &M,
    ) -> Result<(), String>;
}

impl StatePqExt for State {
    #[inline]
    fn process_signed_block(&mut self, signed: &SignedBlockWithAttestation) -> Result<(), String> {
        let verifier = PqSignatureVerifier;
        self.process_signed_block_with_verifier(signed, &verifier)
    }

    #[inline]
    fn process_signed_block_with_metrics<M: TransitionMetricsSink>(
        &mut self,
        signed: &SignedBlockWithAttestation,
        metrics: &M,
    ) -> Result<(), String> {
        let verifier = PqSignatureVerifier;
        self.process_signed_block_with_verifier_and_sink(signed, &verifier, metrics)
    }
}
