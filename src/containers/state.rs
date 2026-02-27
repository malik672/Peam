//! Beacon-chain state representation and transition logic.
//!
//! This module defines [`State`], the core consensus state object, together with
//! all state-transition functions: slot processing, block-header application,
//! attestation processing, and full signed-block import.
//!
//! # SSZ layout — fixed section (208 bytes)
//!
//! | Byte range | Size | Field |
//! |------------|------|-------|
//! | 0 – 7      | 8 B  | `config.genesis_time` |
//! | 8 – 15     | 8 B  | `slot` |
//! | 16 – 127   | 112 B| `latest_block_header` |
//! | 128 – 167  | 40 B | `latest_justified` |
//! | 168 – 207  | 40 B | `latest_finalized` |
//! | 208 – 231  | 24 B | variable-field offsets (6 × 4 B, little-endian) |
//!
//! Variable fields follow in order: `historical_block_hashes`, `justified_slots`,
//! `validators`, `balances`, `justifications_roots`, `justifications_validators`.

use crate::containers::block::SignedBlockWithAttestation;
use crate::containers::block::{Attestations, Block, BlockHeader};
use crate::containers::checkpoint::Checkpoint;
use crate::containers::config::Config;
use crate::containers::validator::Validator;
use crate::crypto::pq;
use crate::slot::{self, Slot};
use crate::ssz::hash::merkleize_tree_root_11;
use crate::ssz::{HashTreeRoot, SszDecode, SszEncode};
use crate::types::bitlist::BitList;
use crate::types::bytes::Bytes32;
use crate::types::collections::SszList;
use crate::types::uint::Uint64;
use crate::unsafe_vec::write_at;
use crate::unsafe_vec::write_bytes_at;

/// Maximum number of historical block roots retained in [`HistoricalBlockHashes`].
///
/// The list grows by `1 + skipped_slots` on every block import and must not exceed
/// this capacity.
pub const HISTORICAL_ROOTS_LIMIT: usize = 262_144;

/// Maximum number of validators in the active registry (`validators` and `balances`).
pub const VALIDATOR_REGISTRY_LIMIT: usize = 4_096;

/// Maximum number of per-attestation validator bits in [`JustificationValidators`].
pub const JUSTIFICATION_VALIDATORS_LIMIT: usize = 1_073_741_824;

/// Ordered list of historical parent block roots, one entry per slot since genesis.
///
/// Length equals the current slot number. Entries for skipped slots are
/// [`Bytes32::zero()`].
pub type HistoricalBlockHashes = SszList<Bytes32, HISTORICAL_ROOTS_LIMIT>;

/// Ordered list of justification checkpoint roots, parallel to the slot timeline.
pub type JustificationRoots = SszList<Bytes32, HISTORICAL_ROOTS_LIMIT>;

/// SSZ list of active [`Validator`] records, indexed by `ValidatorIndex`.
pub type Validators = SszList<Validator, VALIDATOR_REGISTRY_LIMIT>;

/// SSZ list of validator balances (Gwei), parallel index to [`Validators`].
pub type Balances = SszList<Uint64, VALIDATOR_REGISTRY_LIMIT>;

/// Compact bitfield tracking which slots have been justified since the last finalization.
///
/// Bit `i` is set when slot `finalized.slot + 1 + i` has been justified.
/// The window shifts left (via [`shift_justified_window`]) whenever finality advances.
pub type JustifiedSlots = BitList<HISTORICAL_ROOTS_LIMIT>;

/// Aggregate bitfield of validator participation across all pending justification
/// attestations.
pub type JustificationValidators = BitList<JUSTIFICATION_VALIDATORS_LIMIT>;

/// `HashTreeRoot(BlockBody { attestations: [] })` — the body root used in the genesis
/// block header.
///
/// Pre-computed to avoid hashing an empty body on every genesis construction.
// HashTreeRoot(BlockBody { attestations: [] }).
const EMPTY_BLOCK_BODY_ROOT_BYTES: [u8; 32] = [
    0xdb, 0xa9, 0x67, 0x1b, 0xac, 0x95, 0x13, 0xc9, 0x48, 0x2f, 0x14, 0x16, 0xa5, 0x3a, 0xab, 0xd2,
    0xc6, 0xce, 0x90, 0xd5, 0xa5, 0xf8, 0x65, 0xce, 0x5a, 0x55, 0xc7, 0x75, 0x32, 0x5c, 0x91, 0x36,
];

/// `HashTreeRoot` of the fixed genesis block header used by this client.
pub const GENESIS_BLOCK_HEADER_ROOT_BYTES: [u8; 32] = [
    0xed, 0x01, 0xb1, 0x82, 0x5c, 0x7b, 0x11, 0x2c, 0x8b, 0x9c, 0x6e, 0x0f, 0x41, 0xc4, 0xd4, 0x9e,
    0x40, 0x0f, 0xc1, 0x20, 0x42, 0x55, 0x82, 0xe5, 0x33, 0xc3, 0x32, 0xa6, 0xac, 0x46, 0x08, 0x2e,
];

/// The full consensus state of a lean-Ethereum beacon node.
///
/// `State` is the single source of truth for fork-choice and block validation.
/// It is SSZ-serialized for disk persistence and for computing `block.state_root`.
///
/// # Safety
///
/// [`SszDecode::decode_ssz`] trusts that callers have validated SSZ offsets/lengths
/// before decoding. Use [`State::decode_ssz_checked`] for untrusted or external input.
/// Safety: callers must validate SSZ offsets/lengths before decoding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct State {
    /// Chain-level configuration (currently only `genesis_time`).
    pub config: Config,

    /// Current slot number; advances by one for each slot processed.
    pub slot: Slot,

    /// Header of the most recently imported block.
    ///
    /// `state_root` is zeroed while a block transition is in-flight; it is written
    /// back after the post-state root is verified in [`State::state_transition`].
    pub latest_block_header: BlockHeader,

    /// Most recently justified checkpoint (root + slot).
    pub latest_justified: Checkpoint,

    /// Most recently finalized checkpoint (root + slot).
    pub latest_finalized: Checkpoint,

    /// Slot-progress history used to keep a deterministic "timeline" length.
    ///
    /// Invariant: after processing a header at slot `N`, this vector length is `N`.
    ///
    /// Update rule in `process_block_header_assuming_slot`:
    /// - append exactly one `block.parent_root` entry
    /// - append `num_empty_slots` zero roots for skipped slots
    ///
    /// So each header import contributes `1 + num_empty_slots` entries.
    pub historical_block_hashes: HistoricalBlockHashes,

    /// Compact bitset of slots that have been justified since the last finalization.
    ///
    /// Bit `i` corresponds to slot `latest_finalized.slot + 1 + i`.
    pub justified_slots: JustifiedSlots,

    /// Active validator registry, indexed by `ValidatorIndex`.
    pub validators: Validators,

    /// Validator balances in Gwei, parallel index to [`State::validators`].
    pub balances: Balances,

    /// Checkpoint roots recorded for each justification event.
    pub justifications_roots: JustificationRoots,

    /// Aggregated validator participation bits across pending justification attestations.
    pub justifications_validators: JustificationValidators,
}

impl State {
    /// Production startup path.
    ///
    /// Constructs a genesis [`State`] with an empty validator set and all checkpoints
    /// at slot 0. Use this when booting a fresh node without pre-seeded validators.
    #[inline]
    pub fn generate_genesis_empty(genesis_time: Uint64) -> State {
        let validators = Validators::new(vec![]).expect("empty validators");
        let empty_body_root = Bytes32::from(EMPTY_BLOCK_BODY_ROOT_BYTES);
        let balances = SszList::new(vec![]).expect("balances list");
        let latest_block_header = BlockHeader {
            slot: Slot(Uint64(0)),
            proposer_index: crate::containers::validator::ValidatorIndex(Uint64(0)),
            parent_root: Bytes32::zero(),
            state_root: Bytes32::zero(),
            body_root: empty_body_root,
        };
        let genesis_root = Bytes32::from(GENESIS_BLOCK_HEADER_ROOT_BYTES);

        State {
            config: Config { genesis_time },
            slot: Slot(Uint64(0)),
            latest_block_header,
            latest_justified: Checkpoint {
                root: genesis_root,
                slot: Slot(Uint64(0)),
            },
            latest_finalized: Checkpoint {
                root: genesis_root,
                slot: Slot(Uint64(0)),
            },

            // Defaults for these lists.
            historical_block_hashes: SszList::new(vec![]).expect("historical list"),
            justified_slots: BitList::new(vec![]).expect("justified slots"),
            validators,
            balances,
            justifications_roots: SszList::new(vec![]).expect("justifications roots"),
            justifications_validators: BitList::new(vec![]).expect("justifications validators"),
        }
    }

    /// Generic genesis constructor for tests, fixtures, and custom validator sets.
    ///
    /// Initializes balances to zero for each entry in `validators`.
    pub fn generate_genesis(genesis_time: Uint64, validators: Validators) -> State {
        let empty_body_root = Bytes32::from(EMPTY_BLOCK_BODY_ROOT_BYTES);
        let num_validators = validators.data.len();
        let mut balances_vec: Vec<Uint64> = Vec::with_capacity(num_validators);
        unsafe { balances_vec.set_len(num_validators) };
        for i in 0..num_validators {
            unsafe { write_at(&mut balances_vec, i, Uint64(0)) };
        }
        let balances = SszList::new(balances_vec).expect("balances list");
        let latest_block_header = BlockHeader {
            slot: Slot(Uint64(0)),
            proposer_index: crate::containers::validator::ValidatorIndex(Uint64(0)),
            parent_root: Bytes32::zero(),
            state_root: Bytes32::zero(),
            body_root: empty_body_root,
        };
        let genesis_root = Bytes32::from(GENESIS_BLOCK_HEADER_ROOT_BYTES);

        State {
            config: Config { genesis_time },
            slot: Slot(Uint64(0)),
            latest_block_header,
            latest_justified: Checkpoint {
                root: genesis_root,
                slot: Slot(Uint64(0)),
            },
            latest_finalized: Checkpoint {
                root: genesis_root,
                slot: Slot(Uint64(0)),
            },

            // Defaults for these lists.
            historical_block_hashes: SszList::new(vec![]).expect("historical list"),
            justified_slots: BitList::new(vec![]).expect("justified slots"),
            validators,
            balances,
            justifications_roots: SszList::new(vec![]).expect("justifications roots"),
            justifications_validators: BitList::new(vec![]).expect("justifications validators"),
        }
    }

    /// Advances state from `self.slot` up to (but not past) `target_slot`.
    ///
    /// For each slot step, if `latest_block_header.state_root` is still zero it is
    /// filled with the current [`hash_tree_root`] before the counter advances.
    ///
    /// # Errors
    ///
    /// Returns `Err` if `target_slot <= self.slot`.
    #[inline]
    pub fn process_slots(&mut self, target_slot: Slot) -> Result<(), String> {
        if self.slot >= target_slot {
            return Err("target slot must be in the future".to_string());
        }

        while self.slot < target_slot {
            if self.latest_block_header.state_root == Bytes32::zero() {
                let root = self.hash_tree_root();
                self.latest_block_header.state_root = Bytes32::from(root);
            }
            self.slot = Slot(Uint64(self.slot.0.0 + 1));
        }

        Ok(())
    }

    /// Validates and applies `block` as the new latest block header.
    ///
    /// Requires `block.slot == self.slot`; delegates to
    /// [`process_block_header_assuming_slot`] for the remaining checks.
    ///
    /// # Errors
    ///
    /// Returns `Err` if `block.slot != self.slot` or if any header invariant fails.
    #[inline]
    pub fn process_block_header(&mut self, block: BlockHeader) -> Result<(), String> {
        if block.slot != self.slot {
            return Err("block slot does not match state slot".to_string());
        }
        self.process_block_header_assuming_slot(block)
    }

    /// Core block-header validation, called after the slot has already been confirmed
    /// to match.
    ///
    /// Checks (in order):
    /// 1. `block.slot > latest_block_header.slot`
    /// 2. `block.proposer_index` is the correct proposer for `self.slot`
    /// 3. `block.parent_root == HashTreeRoot(latest_block_header)`
    ///
    /// Appends `1 + num_empty_slots` entries to [`historical_block_hashes`] and
    /// stages the new header with a zeroed `state_root` (filled later by
    /// [`state_transition`]).
    #[inline]
    fn process_block_header_assuming_slot(&mut self, block: BlockHeader) -> Result<(), String> {
        if block.slot <= self.latest_block_header.slot {
            return Err("block slot not greater than latest header slot".to_string());
        }

        let num_validators = self.validators.data.len() as u64;
        if !block
            .proposer_index
            .is_proposer_for(self.slot, num_validators)
        {
            return Err("block proposer index does not match expected proposer".to_string());
        }

        let expected_parent = self.latest_block_header.hash_tree_root();
        if block.parent_root != Bytes32::from(expected_parent) {
            return Err("block parent root does not match latest header root".to_string());
        }

        let block_slot = block.slot.0.0;
        let latest_slot = self.latest_block_header.slot.0.0;
        let num_empty_slots = block_slot - latest_slot - 1;

        // Always record one parent linkage for the imported header.
        self.historical_block_hashes.data.push(block.parent_root);
        if num_empty_slots > 0 {
            // For skipped slots between `latest_slot` and `block_slot`, append
            // zero placeholders so history length still tracks slot progress.
            let add = num_empty_slots as usize;
            let data = &mut self.historical_block_hashes.data;
            let start = data.len();
            data.reserve(add);
            unsafe { data.set_len(start + add) };
            for i in 0..add {
                unsafe { write_at(data, start + i, Bytes32::zero()) };
            }
        }

        let mut header = block;
        // Stage header with zero state_root while block processing is still in-flight.
        // `state_transition` sets it to the verified post-state root after root check passes.
        header.state_root = Bytes32::zero();
        self.latest_block_header = header;
        Ok(())
    }

    /// Applies a full block (header + body) after first advancing the slot.
    ///
    /// Calls [`process_block_header`] then [`process_block_body`].
    #[inline]
    pub fn process_block(&mut self, block: &Block) -> Result<(), String> {
        let header = block.header();
        self.process_block_header(header)?;
        self.process_block_body(&block.body, header.body_root)
    }

    /// Applies a full block (header + body) assuming the slot has already been
    /// advanced to match.
    ///
    /// Used internally by [`state_transition`], which drives slot advancement
    /// separately via [`process_slots`].
    #[inline]
    fn process_block_assuming_slot(&mut self, block: &Block) -> Result<(), String> {
        let header = block.header();
        self.process_block_header_assuming_slot(header)?;
        self.process_block_body(&block.body, header.body_root)
    }

    /// Validates the block body root and processes all included attestations.
    ///
    /// # Errors
    ///
    /// Returns `Err` if `HashTreeRoot(body) != expected_root` or if any
    /// attestation is invalid (see [`process_attestations`]).
    #[inline]
    pub fn process_block_body(
        &mut self,
        body: &crate::containers::block::BlockBody,
        expected_root: Bytes32,
    ) -> Result<(), String> {
        let body_root = body.hash_tree_root();
        if expected_root != Bytes32::from(body_root) {
            return Err("block body root does not match header".to_string());
        }
        self.process_attestations(&body.attestations)?;
        Ok(())
    }

    /// Executes a complete state transition for `block`, including post-state root check.
    ///
    /// Steps:
    /// 1. [`process_slots`] — advance to `block.slot`
    /// 2. [`process_block_assuming_slot`] — apply header and body
    /// 3. Compute `HashTreeRoot(self)` and verify it equals `block.state_root`
    /// 4. Write the verified root back into `latest_block_header.state_root`
    ///
    /// # Errors
    ///
    /// Returns `Err` if slot advancement, block processing, or the post-state root
    /// check fails.
    #[inline]
    pub fn state_transition(&mut self, block: &Block) -> Result<(), String> {
        self.process_slots(block.slot)?;
        self.process_block_assuming_slot(block)?;
        let computed_root = Bytes32::from(self.hash_tree_root());
        if computed_root != block.state_root {
            return Err("post-state root does not match block.state_root".to_string());
        }
        // Promote the staged header root immediately after successful verification.
        self.latest_block_header.state_root = computed_root;
        Ok(())
    }

    /// Processes all attestations in a block body, updating justification and
    /// finalization state.
    ///
    /// For each attestation (skipping those that fail eligibility checks):
    /// - target slot must not be in the future
    /// - target slot must be after source slot
    /// - target slot must be justifiable (per [`slot::is_justifiable_after`])
    /// - source slot must already be justified
    /// - supermajority threshold: `3 * participants >= 2 * total_validators`
    ///
    /// When all checks pass, the attestation's target becomes `latest_justified`
    /// and its slot is recorded in [`justified_slots`]. If target immediately
    /// follows source, the source is also finalized.
    ///
    /// # Errors
    ///
    /// Returns `Err` only for internal state-shape failures (for example,
    /// [`set_justified_slot`] overflow). Malformed/stale attestations are
    /// ignored (soft-fail) so a block is not invalidated by irrelevant votes.
    #[inline]
    pub fn process_attestations(&mut self, attestations: &Attestations) -> Result<(), String> {
        let total_validators = self.validators.data.len();
        if total_validators == 0 {
            return Ok(());
        }
        for att in attestations.data.iter() {
            if att.data.slot > self.slot {
                continue;
            }
            if att.data.target.slot < att.data.source.slot {
                continue;
            }
            if att.data.head.slot < att.data.target.slot {
                continue;
            }
            if att.data.slot < att.data.head.slot {
                continue;
            }
            if !is_known_chain_root(self, &att.data.head.root)
                || !is_known_chain_root(self, &att.data.source.root)
                || !is_known_chain_root(self, &att.data.target.root)
            {
                continue;
            }
            if !slot::is_justifiable_after(att.data.target.slot, self.latest_finalized.slot)? {
                continue;
            }
            if is_slot_justified(
                &self.justified_slots,
                self.latest_finalized.slot,
                att.data.target.slot,
            ) {
                continue;
            }
            if !is_slot_justified(
                &self.justified_slots,
                self.latest_finalized.slot,
                att.data.source.slot,
            ) {
                continue;
            }
            let participants = set_bits(&att.aggregation_bits);
            if participants.is_empty() {
                continue;
            }
            if 3 * participants.len() < 2 * total_validators {
                continue;
            }
            self.latest_justified = att.data.target.clone();
            set_justified_slot(
                &mut self.justified_slots,
                self.latest_finalized.slot,
                att.data.target.slot,
            )?;

            // Minimal finalization rule: finalize the source if it immediately precedes target.
            if att.data.target.slot.0.0 == att.data.source.slot.0.0 + 1
                && att.data.source.slot > self.latest_finalized.slot
            {
                let old_finalized = self.latest_finalized.slot;
                self.latest_finalized = att.data.source.clone();
                let delta = (self.latest_finalized.slot.0.0 - old_finalized.0.0) as usize;
                shift_justified_window(&mut self.justified_slots, delta);
            }
        }
        Ok(())
    }

    /// Imports a signed block, dispatching to the appropriate [`SignatureVerifier`]
    /// based on the active feature flags.
    pub fn process_signed_block(
        &mut self,
        signed: &SignedBlockWithAttestation,
    ) -> Result<(), String> {
        #[cfg(feature = "pq_crypto")]
        {
            let verifier = PqSignatureVerifier;
            self.process_signed_block_with_verifier(signed, &verifier)
        }

        #[cfg(not(feature = "pq_crypto"))]
        {
            let verifier = StructuralSignatureVerifier;
            self.process_signed_block_with_verifier(signed, &verifier)
        }
    }

    /// Imports a signed block using the provided [`SignatureVerifier`].
    ///
    /// Steps:
    /// 1. [`SignedBlockWithAttestation::validate_basic`] — structural pre-checks
    /// 2. `verifier.verify_signed_block` — signature / participant verification
    /// 3. [`state_transition`] — full state transition with post-state root check
    ///
    /// # Errors
    ///
    /// Returns `Err` if any step fails.
    pub fn process_signed_block_with_verifier<V: SignatureVerifier>(
        &mut self,
        signed: &SignedBlockWithAttestation,
        verifier: &V,
    ) -> Result<(), String> {
        signed.validate_basic()?;
        let block = &signed.message.block;
        verifier.verify_signed_block(signed, self)?;
        self.state_transition(block)
    }
}

/// Verifies the signature(s) attached to a [`SignedBlockWithAttestation`].
///
/// Implementations range from no-op (for testing) to full post-quantum
/// aggregate-signature verification.
pub trait SignatureVerifier {
    /// Verify all signatures in `signed` against the current `state`.
    ///
    /// # Errors
    ///
    /// Returns `Err` with a human-readable description if verification fails.
    fn verify_signed_block(
        &self,
        signed: &SignedBlockWithAttestation,
        state: &State,
    ) -> Result<(), String>;
}

/// A [`SignatureVerifier`] that accepts every block unconditionally.
///
/// Intended for unit tests and simulation harnesses where cryptographic
/// verification is not required.
pub struct NoopSignatureVerifier;

impl SignatureVerifier for NoopSignatureVerifier {
    fn verify_signed_block(
        &self,
        _signed: &SignedBlockWithAttestation,
        _state: &State,
    ) -> Result<(), String> {
        Ok(())
    }
}

/// A [`SignatureVerifier`] that enforces structural invariants without
/// performing cryptographic signature verification.
///
/// Checks:
/// - `proposer_index` is within the validator registry
/// - all aggregation-bit indices are within the validator registry
/// - each attestation signature's `participants` field matches
///   `attestation.aggregation_bits`
/// - the proposer attestation has exactly one participant, matching
///   `block.proposer_index`
pub struct StructuralSignatureVerifier;

impl SignatureVerifier for StructuralSignatureVerifier {
    fn verify_signed_block(
        &self,
        signed: &SignedBlockWithAttestation,
        state: &State,
    ) -> Result<(), String> {
        let validators_len = state.validators.data.len();
        let block = &signed.message.block;
        if (block.proposer_index.0).0 as usize >= validators_len {
            return Err("proposer index out of range".to_string());
        }

        for att in block.body.attestations.data.iter() {
            for idx in set_bits(&att.aggregation_bits) {
                if idx >= validators_len {
                    return Err("validator index out of range".to_string());
                }
            }
        }
        for (att, proof) in block
            .body
            .attestations
            .data
            .iter()
            .zip(signed.signature.attestation_signatures.data.iter())
        {
            if proof.participants != att.aggregation_bits {
                return Err(
                    "attestation signature participants do not match aggregation bits".to_string(),
                );
            }
        }

        let proposer_attestation = &signed.message.proposer_attestation;
        let proposer_bits = set_bits(&proposer_attestation.aggregation_bits);
        if proposer_bits.len() != 1 {
            return Err("proposer attestation must have exactly one participant".to_string());
        }
        if proposer_bits[0] != (block.proposer_index.0).0 as usize {
            return Err("proposer attestation does not match proposer index".to_string());
        }

        Ok(())
    }
}

/// A [`SignatureVerifier`] that performs full post-quantum aggregate-signature
/// verification for each attestation and the block proposer.
///
/// Only compiled when the `pq_crypto` feature is enabled.
pub struct PqSignatureVerifier;

impl SignatureVerifier for PqSignatureVerifier {
    fn verify_signed_block(
        &self,
        _signed: &SignedBlockWithAttestation,
        _state: &State,
    ) -> Result<(), String> {
        let signed = _signed;
        let state = _state;
        let block = &signed.message.block;
        pq::setup_aggregate_verifier();

        for (att, proof) in block
            .body
            .attestations
            .data
            .iter()
            .zip(signed.signature.attestation_signatures.data.iter())
        {
            if proof.participants != att.aggregation_bits {
                return Err(
                    "attestation signature participants do not match aggregation bits".to_string(),
                );
            }
            let mut public_keys = Vec::new();
            for idx in set_bits(&att.aggregation_bits) {
                let validator = state
                    .validators
                    .data
                    .get(idx)
                    .ok_or_else(|| "validator index out of range".to_string())?;
                public_keys.push(validator.pubkey);
            }
            if !public_keys.is_empty() {
                let message = att.data.hash_tree_root();
                pq::verify_aggregate_signature(
                    &public_keys,
                    &message,
                    proof.proof_data.as_slice(),
                    att.data.slot.0.0 as u32,
                )?;
            }
        }

        let proposer_attestation = &signed.message.proposer_attestation;
        let proposer_idx = block.proposer_index.0.0 as usize;
        let proposer = state
            .validators
            .data
            .get(proposer_idx)
            .ok_or_else(|| "proposer index out of range".to_string())?;
        let proposer_message = proposer_attestation.data.hash_tree_root();
        pq::verify_signature(
            &proposer.pubkey,
            proposer_attestation.data.slot.0.0 as u32,
            &proposer_message,
            &signed.signature.proposer_signature,
        )?;
        Ok(())
    }
}

/// Returns the indices of all set bits in `bits`, in ascending order.
fn set_bits<const LIMIT: usize>(bits: &BitList<LIMIT>) -> Vec<usize> {
    let mut out = Vec::new();
    let len = bits.len();
    for i in 0..len {
        let byte = bits.data[i / 8];
        if (byte & (1u8 << (i % 8))) != 0 {
            out.push(i);
        }
    }
    out
}

#[inline]
fn is_known_chain_root(state: &State, root: &Bytes32) -> bool {
    if *root == Bytes32::zero() {
        return true;
    }
    if *root == state.latest_justified.root
        || *root == state.latest_finalized.root
        || *root == Bytes32::from(state.latest_block_header.hash_tree_root())
    {
        return true;
    }
    state.historical_block_hashes.data.iter().any(|v| v == root)
}

/// Returns `true` if `slot` is recorded as justified in the sliding window.
///
/// Slots at or below `finalized` are considered implicitly justified.
/// For slots above `finalized`, checks bit `slot - finalized - 1` in `justified`.
fn is_slot_justified(justified: &JustifiedSlots, finalized: Slot, slot: Slot) -> bool {
    if slot <= finalized {
        return true;
    }
    let idx = (slot.0.0 - finalized.0.0 - 1) as usize;
    if idx >= justified.len() {
        return false;
    }
    let byte = idx / 8;
    let bit = idx % 8;
    if byte >= justified.data.len() {
        return false;
    }
    (justified.data[byte] & (1u8 << bit)) != 0
}

/// Records `slot` as justified in the sliding window relative to `finalized`.
///
/// Slots at or below `finalized` are no-ops. Grows the bitfield storage as needed.
///
/// # Errors
///
/// Returns `Err` if `slot - finalized - 1 >= HISTORICAL_ROOTS_LIMIT`.
fn set_justified_slot(
    justified: &mut JustifiedSlots,
    finalized: Slot,
    slot: Slot,
) -> Result<(), String> {
    if slot <= finalized {
        return Ok(());
    }
    let idx = (slot.0.0 - finalized.0.0 - 1) as usize;
    if idx >= HISTORICAL_ROOTS_LIMIT {
        return Err("justified slot exceeds limit".to_string());
    }
    let new_len = idx + 1;
    if new_len > justified.len() {
        justified.len = new_len;
    }
    let byte_len = (justified.len + 7) / 8;
    if justified.data.len() < byte_len {
        justified.data.resize(byte_len, 0u8);
    }
    let byte = idx / 8;
    let bit = idx % 8;
    justified.data[byte] |= 1u8 << bit;
    Ok(())
}

/// Shifts the justified-slot window left by `delta` positions, discarding entries
/// that have fallen below the new finalization point.
///
/// After a finality advance of `delta` slots, bits `[delta, len)` are moved to
/// `[0, len - delta)`. If `delta >= len`, the window is cleared entirely.
fn shift_justified_window(justified: &mut JustifiedSlots, delta: usize) {
    if delta == 0 || justified.len() == 0 {
        return;
    }
    if delta >= justified.len() {
        justified.len = 0;
        justified.data.clear();
        return;
    }
    let new_len = justified.len() - delta;
    let mut new_data = vec![0u8; (new_len + 7) / 8];
    for i in 0..new_len {
        let src = i + delta;
        let src_byte = src / 8;
        let src_bit = src % 8;
        if src_byte < justified.data.len() && (justified.data[src_byte] & (1u8 << src_bit)) != 0 {
            let dst_byte = i / 8;
            let dst_bit = i % 8;
            new_data[dst_byte] |= 1u8 << dst_bit;
        }
    }
    justified.len = new_len;
    justified.data = new_data;
}

/// SSZ serialization for [`State`].
///
/// Produces a byte vector with the fixed section (208 bytes) followed by
/// six variable-length fields. See the [module-level SSZ layout][self] for the
/// full field-offset table.
///
/// # Safety
///
/// Uses `unsafe` pointer writes via [`write_bytes_at`] for performance; callers
/// must not mutate the returned buffer while it is in use.
impl SszEncode for State {
    fn encode_ssz(&self) -> Vec<u8> {
        let fixed_len = 8 + 8 + 112 + 40 + 40;
        let offsets_len = 4 * 6;
        let mut fixed = Vec::with_capacity(fixed_len + offsets_len);
        unsafe { fixed.set_len(fixed_len + offsets_len) };

        let hist = self.historical_block_hashes.encode_ssz();
        let justified = self.justified_slots.encode_ssz();
        let validators = self.validators.encode_ssz();
        let balances = self.balances.encode_ssz();
        let roots = self.justifications_roots.encode_ssz();
        let just_validators = self.justifications_validators.encode_ssz();
        let variable_len = hist.len()
            + justified.len()
            + validators.len()
            + balances.len()
            + roots.len()
            + just_validators.len();
        let mut variable = Vec::with_capacity(variable_len);
        unsafe { variable.set_len(variable_len) };
        let mut var_pos = 0usize;

        unsafe { write_bytes_at(&mut fixed, 0, &self.config.genesis_time.0.to_le_bytes()) };
        unsafe { write_bytes_at(&mut fixed, 8, &self.slot.0.0.to_le_bytes()) };
        unsafe {
            write_bytes_at(
                &mut fixed,
                16,
                &self.latest_block_header.slot.0.0.to_le_bytes(),
            )
        };
        unsafe {
            write_bytes_at(
                &mut fixed,
                24,
                &self.latest_block_header.proposer_index.0.0.to_le_bytes(),
            )
        };
        unsafe {
            write_bytes_at(
                &mut fixed,
                32,
                self.latest_block_header.parent_root.as_ref(),
            )
        };
        unsafe { write_bytes_at(&mut fixed, 64, self.latest_block_header.state_root.as_ref()) };
        unsafe { write_bytes_at(&mut fixed, 96, self.latest_block_header.body_root.as_ref()) };
        unsafe { write_bytes_at(&mut fixed, 128, self.latest_justified.root.as_ref()) };
        unsafe {
            write_bytes_at(
                &mut fixed,
                160,
                &self.latest_justified.slot.0.0.to_le_bytes(),
            )
        };
        unsafe { write_bytes_at(&mut fixed, 168, self.latest_finalized.root.as_ref()) };
        unsafe {
            write_bytes_at(
                &mut fixed,
                200,
                &self.latest_finalized.slot.0.0.to_le_bytes(),
            )
        };

        let mut offsets = [0u32; 6];
        let mut off_idx = 0usize;
        let mut offset = fixed_len + offsets_len;

        // Note: offsets are computed from trusted lengths; no extra checks here by design.
        offsets[off_idx] = offset as u32;
        off_idx += 1;
        offset += hist.len();
        unsafe { write_bytes_at(&mut variable, var_pos, &hist) };
        var_pos += hist.len();

        // Note: offsets are computed from trusted lengths; no extra checks here by design.
        offsets[off_idx] = offset as u32;
        off_idx += 1;
        offset += justified.len();
        unsafe { write_bytes_at(&mut variable, var_pos, &justified) };
        var_pos += justified.len();

        // Note: offsets are computed from trusted lengths; no extra checks here by design.
        offsets[off_idx] = offset as u32;
        off_idx += 1;
        offset += validators.len();
        unsafe { write_bytes_at(&mut variable, var_pos, &validators) };
        var_pos += validators.len();

        // Note: offsets are computed from trusted lengths; no extra checks here by design.
        offsets[off_idx] = offset as u32;
        off_idx += 1;
        offset += balances.len();
        unsafe { write_bytes_at(&mut variable, var_pos, &balances) };
        var_pos += balances.len();

        // Note: offsets are computed from trusted lengths; no extra checks here by design.
        offsets[off_idx] = offset as u32;
        off_idx += 1;
        offset += roots.len();
        unsafe { write_bytes_at(&mut variable, var_pos, &roots) };
        var_pos += roots.len();

        // Note: offsets are computed from trusted lengths; no extra checks here by design.
        offsets[off_idx] = offset as u32;
        unsafe { write_bytes_at(&mut variable, var_pos, &just_validators) };

        let mut off_pos = fixed_len;
        for off in offsets {
            unsafe { write_bytes_at(&mut fixed, off_pos, &off.to_le_bytes()) };
            off_pos += 4;
        }

        fixed.extend_from_slice(&variable);
        fixed
    }
}

/// SSZ deserialization for [`State`] — **trusts** that offsets are valid.
///
/// For untrusted input use [`State::decode_ssz_checked`], which validates the
/// fixed-section length and all field offsets before decoding.
impl SszDecode for State {
    fn decode_ssz(bytes: &[u8]) -> Result<Self, String> {
        let _fixed_len = 8 + 8 + 112 + 40 + 40 + (4 * 6);
        let config = Config::decode_ssz(&bytes[0..8])?;
        let slot = Slot::decode_ssz(&bytes[8..16])?;
        let latest_block_header = BlockHeader::decode_ssz(&bytes[16..128])?;
        let latest_justified = Checkpoint::decode_ssz(&bytes[128..168])?;
        let latest_finalized = Checkpoint::decode_ssz(&bytes[168..208])?;

        let mut offsets = [0u32; 6];
        let mut off_idx = 208;
        for i in 0..6 {
            let mut buf = [0u8; 4];
            buf.copy_from_slice(&bytes[off_idx..off_idx + 4]);
            offsets[i] = u32::from_le_bytes(buf);
            off_idx += 4;
        }

        let scope = bytes.len();
        let mut bounds = [0usize; 7];
        for i in 0..6 {
            bounds[i] = offsets[i] as usize;
        }
        bounds[6] = scope;

        let hist = SszList::decode_ssz(&bytes[bounds[0]..bounds[1]])?;
        let justified = BitList::decode_ssz(&bytes[bounds[1]..bounds[2]])?;
        let validators = SszList::decode_ssz(&bytes[bounds[2]..bounds[3]])?;
        let balances = SszList::decode_ssz(&bytes[bounds[3]..bounds[4]])?;
        let roots = SszList::decode_ssz(&bytes[bounds[4]..bounds[5]])?;
        let just_validators = BitList::decode_ssz(&bytes[bounds[5]..bounds[6]])?;

        Ok(State {
            config,
            slot,
            latest_block_header,
            latest_justified,
            latest_finalized,
            historical_block_hashes: hist,
            justified_slots: justified,
            validators,
            balances,
            justifications_roots: roots,
            justifications_validators: just_validators,
        })
    }
}

impl State {
    /// Bounds-checked SSZ deserialization for untrusted input.
    ///
    /// Validates:
    /// - total length is at least the fixed-section size (232 bytes)
    /// - first variable-field offset equals the fixed-section length
    /// - all offsets are monotonically non-decreasing and within `bytes.len()`
    ///
    /// # Errors
    ///
    /// Returns `Err` if any length or offset check fails, or if an inner
    /// `decode_ssz_checked` call fails.
    pub fn decode_ssz_checked(bytes: &[u8]) -> Result<Self, String> {
        let fixed_len = 8 + 8 + 112 + 40 + 40 + (4 * 6);
        if bytes.len() < fixed_len {
            return Err("State input shorter than fixed section".to_string());
        }
        let config = Config::decode_ssz_checked(&bytes[0..8])?;
        let slot = Slot::decode_ssz_checked(&bytes[8..16])?;
        let latest_block_header = BlockHeader::decode_ssz_checked(&bytes[16..128])?;
        let latest_justified = Checkpoint::decode_ssz_checked(&bytes[128..168])?;
        let latest_finalized = Checkpoint::decode_ssz_checked(&bytes[168..208])?;

        let mut offsets = [0u32; 6];
        let mut off_idx = 208;
        for i in 0..6 {
            let mut buf = [0u8; 4];
            buf.copy_from_slice(&bytes[off_idx..off_idx + 4]);
            offsets[i] = u32::from_le_bytes(buf);
            off_idx += 4;
        }

        let scope = bytes.len();
        let mut bounds = [0usize; 7];
        for i in 0..6 {
            bounds[i] = offsets[i] as usize;
        }
        bounds[6] = scope;

        let fixed_end = fixed_len;
        if bounds[0] != fixed_end {
            return Err("State first offset must equal fixed section length".to_string());
        }
        let mut prev = fixed_end;
        for b in bounds.iter().take(6) {
            if *b < fixed_end || *b < prev || *b > scope {
                return Err("State offsets are invalid".to_string());
            }
            prev = *b;
        }

        let hist = SszList::decode_ssz_checked(&bytes[bounds[0]..bounds[1]])?;
        let justified = BitList::decode_ssz_checked(&bytes[bounds[1]..bounds[2]])?;
        let validators = SszList::decode_ssz_checked(&bytes[bounds[2]..bounds[3]])?;
        let balances = SszList::decode_ssz_checked(&bytes[bounds[3]..bounds[4]])?;
        let roots = SszList::decode_ssz_checked(&bytes[bounds[4]..bounds[5]])?;
        let just_validators = BitList::decode_ssz_checked(&bytes[bounds[5]..bounds[6]])?;

        Ok(State {
            config,
            slot,
            latest_block_header,
            latest_justified,
            latest_finalized,
            historical_block_hashes: hist,
            justified_slots: justified,
            validators,
            balances,
            justifications_roots: roots,
            justifications_validators: just_validators,
        })
    }
}

/// Computes the SSZ Merkle hash-tree root of [`State`].
///
/// Hashes all 11 fields individually and merklizes them with a balanced
/// 11-leaf tree via [`merkleize_tree_root_11`].
impl HashTreeRoot for State {
    fn hash_tree_root(&self) -> [u8; 32] {
        let field_roots = [
            Bytes32::from(self.config.hash_tree_root()),
            Bytes32::from(self.slot.hash_tree_root()),
            Bytes32::from(self.latest_block_header.hash_tree_root()),
            Bytes32::from(self.latest_justified.hash_tree_root()),
            Bytes32::from(self.latest_finalized.hash_tree_root()),
            Bytes32::from(self.historical_block_hashes.hash_tree_root()),
            Bytes32::from(self.justified_slots.hash_tree_root()),
            Bytes32::from(self.validators.hash_tree_root()),
            Bytes32::from(self.balances.hash_tree_root()),
            Bytes32::from(self.justifications_roots.hash_tree_root()),
            Bytes32::from(self.justifications_validators.hash_tree_root()),
        ];
        let root = merkleize_tree_root_11(&field_roots);
        *root.as_ref()
    }
}
