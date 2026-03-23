//! state representation and transition logic.
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

use rapidhash::RapidHashMap;

use std::sync::OnceLock;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;
use tracing::{info, warn};

use crate::containers::block::SignedBlockWithAttestation;
use crate::containers::block::{Attestations, Block, BlockHeader};
use crate::containers::checkpoint::Checkpoint;
use crate::containers::config::Config;
use crate::containers::state_metrics::{NoopTransitionMetricsSink, TransitionMetricsSink};
use crate::containers::validator::Validator;
use crate::crypto::pq;
use crate::metrics::MetricsRegistry;
use crate::slot::{self, Slot};
use crate::ssz::hash::merkleize;
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
        let latest_block_header = BlockHeader {
            slot: Slot(Uint64(0)),
            proposer_index: crate::containers::validator::ValidatorIndex(Uint64(0)),
            parent_root: Bytes32::zero(),
            state_root: Bytes32::zero(),
            body_root: empty_body_root,
        };
        let mut state = State {
            config: Config { genesis_time },
            slot: Slot(Uint64(0)),
            latest_block_header,
            latest_justified: Checkpoint {
                root: Bytes32::zero(),
                slot: Slot(Uint64(0)),
            },
            latest_finalized: Checkpoint {
                root: Bytes32::zero(),
                slot: Slot(Uint64(0)),
            },
            historical_block_hashes: SszList::new(vec![]).expect("historical block hashes"),
            justified_slots: BitList::default(),
            validators,
            balances: SszList::default(),
            justifications_roots: SszList::default(),
            justifications_validators: BitList::default(),
        };
        let mut tmp = state.clone();
        tmp.latest_block_header.state_root = Bytes32::zero();
        let state_root = Bytes32::from(tmp.hash_tree_root());
        state.latest_block_header.state_root = state_root;
        state
    }

    /// Generic genesis constructor for tests, fixtures, and custom validator sets.
    ///
    /// Initializes balances to zero for each entry in `validators`.
    #[inline]
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
        let mut state = State {
            config: Config { genesis_time },
            slot: Slot(Uint64(0)),
            latest_block_header,
            latest_justified: Checkpoint {
                root: Bytes32::zero(),
                slot: Slot(Uint64(0)),
            },
            latest_finalized: Checkpoint {
                root: Bytes32::zero(),
                slot: Slot(Uint64(0)),
            },

            historical_block_hashes: SszList::new(vec![]).expect("historical block hashes"),
            justified_slots: BitList::default(),
            validators,
            balances,
            justifications_roots: SszList::default(),
            justifications_validators: BitList::default(),
        };
        let mut tmp = state.clone();
        tmp.latest_block_header.state_root = Bytes32::zero();
        let state_root = Bytes32::from(tmp.hash_tree_root());
        state.latest_block_header.state_root = state_root;
        state
    }

    /// Advances state from `self.slot` to `target_slot`.
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
                self.latest_block_header.state_root = Bytes32::from(self.hash_tree_root());
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
        // seed checkpoint roots with the parent anchor root so attestation
        // source/target roots line up across clients.
        if self.latest_block_header.slot == Slot(Uint64(0)) {
            self.latest_justified.root = block.parent_root;
            self.latest_finalized.root = block.parent_root;
        }

        let block_slot = block.slot.0.0;
        let latest_slot = self.latest_block_header.slot.0.0;
        let num_empty_slots = block_slot - latest_slot - 1;

        // Record the parent root for the previous slot.
        self.historical_block_hashes.data.push(block.parent_root);

        // For skipped slots between `latest_slot` and `block_slot`, append zero
        // placeholders so history length still tracks slot progress.
        if num_empty_slots > 0 {
            let add = num_empty_slots as usize;
            let data = &mut self.historical_block_hashes.data;
            let start = data.len();
            data.reserve(add);
            unsafe { data.set_len(start + add) };
            for i in 0..add {
                unsafe { write_at(data, start + i, Bytes32::zero()) };
            }
        }

        // Extend justified_slots to cover all slots up to (block.slot - 1).
        // matches across clients, even before attestation processing grows it.
        let last_materialized = block_slot.saturating_sub(1);
        let fin_slot = self.latest_finalized.slot.0.0;
        if last_materialized > fin_slot {
            let required_len = (last_materialized - fin_slot) as usize;
            if required_len > self.justified_slots.len() {
                self.justified_slots.len = required_len;
                let byte_len = (required_len + 7) / 8;
                if self.justified_slots.data.len() < byte_len {
                    self.justified_slots.data.resize(byte_len, 0u8);
                }
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

    #[inline]
    fn state_transition_inner<M: TransitionMetricsSink>(
        &mut self,
        block: &Block,
        metrics: &M,
    ) -> Result<(), String> {
        let total_start = Instant::now();
        let old_finalized = self.latest_finalized;
        let pre_slot = self.slot.0.0;
        let pre_header_slot = self.latest_block_header.slot.0.0;
        let pre_header_root = Bytes32::from(self.latest_block_header.hash_tree_root());
        let pre_justified = self.latest_justified;
        let pre_finalized = self.latest_finalized;

        let slots_start = Instant::now();
        let slots_before = self.slot.0.0;
        self.process_slots(block.slot)?;
        let slots_after = self.slot.0.0;
        let capture_trace_roots = state_root_trace_enabled();
        let post_slots_root = if capture_trace_roots {
            Some(Bytes32::from(self.hash_tree_root()))
        } else {
            None
        };
        metrics.observe_slots_processing_time(slots_start);
        let advanced_slots = slots_after - slots_before;
        metrics.add_slots_processed(advanced_slots);

        let block_start = Instant::now();
        let header = block.header();
        self.process_block_header_assuming_slot(header)?;
        let post_header_root = if capture_trace_roots {
            Some(Bytes32::from(self.hash_tree_root()))
        } else {
            None
        };

        let body_root = block.body.hash_tree_root();
        if header.body_root != Bytes32::from(body_root) {
            return Err("block body root does not match header".to_string());
        }

        let att_start = Instant::now();
        let att_count = block.body.attestations.data.len();
        self.process_attestations(&block.body.attestations)?;
        let post_attestations_root = if capture_trace_roots {
            Some(Bytes32::from(self.hash_tree_root()))
        } else {
            None
        };
        metrics.observe_attestations_processing_time(att_start);
        metrics.add_attestations_processed(att_count as u64);
        metrics.observe_block_processing_time(block_start);

        let computed_root = Bytes32::from(self.hash_tree_root());
        if computed_root != block.state_root {
            warn!(
                block_slot = block.slot.0.0,
                block_parent = ?block.parent_root,
                block_state_root = ?block.state_root,
                computed_state_root = ?computed_root,
                pre_slot,
                pre_header_slot,
                pre_header_root = ?pre_header_root,
                pre_justified_slot = pre_justified.slot.0.0,
                pre_justified_root = ?pre_justified.root,
                pre_finalized_slot = pre_finalized.slot.0.0,
                pre_finalized_root = ?pre_finalized.root,
                post_slots_root = ?post_slots_root,
                post_header_root = ?post_header_root,
                post_attestations_root = ?post_attestations_root,
                post_slot = self.slot.0.0,
                post_header_slot = self.latest_block_header.slot.0.0,
                post_header_root = ?Bytes32::from(self.latest_block_header.hash_tree_root()),
                post_justified_slot = self.latest_justified.slot.0.0,
                post_justified_root = ?self.latest_justified.root,
                post_finalized_slot = self.latest_finalized.slot.0.0,
                post_finalized_root = ?self.latest_finalized.root,
                body_attestations = att_count,
                "state transition state-root mismatch trace"
            );
            return Err("block state root does not match computed state root".to_string());
        } else {
            self.latest_block_header.state_root = computed_root;
        }

        if self.latest_justified.slot > pre_justified.slot
            || self.latest_finalized.slot > pre_finalized.slot
        {
            info!(
                block_slot = block.slot.0.0,
                block_root = ?Bytes32::from(block.hash_tree_root()),
                pre_justified_slot = pre_justified.slot.0.0,
                post_justified_slot = self.latest_justified.slot.0.0,
                pre_finalized_slot = pre_finalized.slot.0.0,
                post_finalized_slot = self.latest_finalized.slot.0.0,
                "consensus checkpoints advanced"
            );
        }

        if self.latest_finalized.slot > old_finalized.slot {
            metrics.inc_finalizations_success();
        }
        metrics.observe_state_transition_time(total_start);

        Ok(())
    }

    /// Processes all attestations in a block body, updating justification and
    /// finalization state.
    ///
    /// For each attestation (skipping those that fail eligibility checks):
    /// - source slot must already be justified
    /// - target slot must not already be justified
    /// - neither checkpoint root may be zero
    /// - source/target checkpoints must match `historical_block_hashes`
    /// - target slot must be strictly greater than source slot
    /// - target slot must be justifiable after the original finalized slot
    /// - votes are accumulated per `target.root` across attestations, and
    ///   supermajority is checked as `3 * votes_for_root >= 2 * total_validators`
    ///
    /// When all checks pass, the attestation's target becomes `latest_justified`
    /// and its slot is recorded in [`justified_slots`]. If target is the next
    /// valid justifiable slot after source, the source is also finalized.
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
        if self
            .justifications_roots
            .data
            .iter()
            .any(|root| *root == Bytes32::zero())
        {
            return Err("zero hash is not allowed in justifications roots".to_string());
        }
        let mut justification_votes: Option<RapidHashMap<Bytes32, JustificationVotes>> = None;
        let mut root_to_slot = build_historical_root_slots(&self.historical_block_hashes.data);
        let latest_root = Bytes32::from(self.latest_block_header.hash_tree_root());
        if latest_root != Bytes32::zero() && !root_to_slot.contains_key(&latest_root) {
            root_to_slot.insert(latest_root, self.latest_block_header.slot);
        }
        let trace_attestations = attestation_trace_enabled();
        let pre_justified_slot = self.latest_justified.slot;
        let pre_finalized_slot = self.latest_finalized.slot;

        let mut finalized_slot = self.latest_finalized.slot;
        let mut stats = AttestationDecisionStats::default();
        let total_attestations = attestations.data.len();

        for att in attestations.data.iter() {
            if att.data.target.slot <= att.data.source.slot {
                if trace_attestations {
                    stats.target_below_source += 1;
                    log_attestation_decision_sample(
                        "target_below_source",
                        att,
                        self.slot,
                        finalized_slot,
                    );
                }
                continue;
            }
            // Ignore votes carrying zero-hash checkpoints.
            if att.data.source.root == Bytes32::zero() || att.data.target.root == Bytes32::zero() {
                if trace_attestations {
                    stats.zero_checkpoint_root += 1;
                    log_attestation_decision_sample(
                        "zero_checkpoint_root",
                        att,
                        self.slot,
                        finalized_slot,
                    );
                }
                continue;
            }
            let source_slot_idx = att.data.source.slot.0.0 as usize;
            let source_matches = self
                .historical_block_hashes
                .data
                .get(source_slot_idx)
                .map_or(false, |root| *root == att.data.source.root);
            if !source_matches {
                if trace_attestations {
                    stats.source_root_slot_mismatch += 1;
                    log_attestation_slot_mismatch_sample(
                        "source_root_slot_mismatch",
                        att,
                        self.slot,
                        finalized_slot,
                        None,
                        att.data.source.slot,
                    );
                }
                continue;
            }
            let target_slot_idx = att.data.target.slot.0.0 as usize;
            let target_matches = self
                .historical_block_hashes
                .data
                .get(target_slot_idx)
                .map_or(false, |root| *root == att.data.target.root)
                || (target_slot_idx == self.historical_block_hashes.data.len()
                    && att.data.target.slot == self.latest_block_header.slot
                    && att.data.target.root == latest_root);
            if !target_matches {
                if trace_attestations {
                    stats.target_root_slot_mismatch += 1;
                    log_attestation_slot_mismatch_sample(
                        "target_root_slot_mismatch",
                        att,
                        self.slot,
                        finalized_slot,
                        None,
                        att.data.target.slot,
                    );
                }
                continue;
            }
            if !slot::is_justifiable_after(att.data.target.slot, finalized_slot)? {
                if trace_attestations {
                    stats.target_not_justifiable += 1;
                    log_attestation_decision_sample(
                        "target_not_justifiable_after_finalized",
                        att,
                        self.slot,
                        finalized_slot,
                    );
                }
                continue;
            }
            if is_slot_justified(&self.justified_slots, finalized_slot, att.data.target.slot) {
                if trace_attestations {
                    stats.target_already_justified += 1;
                }
                continue;
            }
            if !is_slot_justified(&self.justified_slots, finalized_slot, att.data.source.slot) {
                if trace_attestations {
                    stats.source_not_justified += 1;
                    log_attestation_decision_sample(
                        "source_not_justified",
                        att,
                        self.slot,
                        finalized_slot,
                    );
                }
                continue;
            }
            if trace_attestations {
                stats.eligible_votes += 1;
            }

            let votes_map = justification_votes
                .get_or_insert_with(|| decode_justification_votes(self, total_validators));
            let votes = votes_map
                .entry(att.data.target.root)
                .or_insert_with(|| JustificationVotes::new(total_validators));
            merge_participant_votes_from_bits(votes, &att.aggregation_bits, total_validators);
            if 3 * votes.count < 2 * total_validators {
                if trace_attestations {
                    stats.vote_below_supermajority += 1;
                    log_vote_threshold_sample(
                        "vote_below_supermajority",
                        att,
                        self.slot,
                        finalized_slot,
                        votes.count,
                        total_validators,
                    );
                }
                continue;
            }
            let vote_count = votes.count;
            if trace_attestations {
                stats.justified_updates += 1;
                log_vote_threshold_sample(
                    "justification_supermajority_reached",
                    att,
                    self.slot,
                    finalized_slot,
                    vote_count,
                    total_validators,
                );
            }
            self.latest_justified = Checkpoint {
                root: att.data.target.root,
                slot: att.data.target.slot,
            };
            set_justified_slot(
                &mut self.justified_slots,
                finalized_slot,
                att.data.target.slot,
            )?;
            votes_map.remove(&att.data.target.root);

            let next_valid_justifiable = is_next_valid_justifiable_slot(
                att.data.source.slot,
                att.data.target.slot,
                finalized_slot,
            );
            let should_finalize_source = next_valid_justifiable;
            if finality_trace_enabled() {
                info!(
                    target: "peam::containers::state",
                    source_slot = att.data.source.slot.0.0,
                    source_root = ?att.data.source.root,
                    target_slot = att.data.target.slot.0.0,
                    target_root = ?att.data.target.root,
                    head_slot = att.data.head.slot.0.0,
                    head_root = ?att.data.head.root,
                    state_slot = self.slot.0.0,
                    pre_justified_slot = self.latest_justified.slot.0.0,
                    pre_finalized_slot = finalized_slot.0.0,
                    vote_count,
                    total_validators,
                    next_valid_justifiable,
                    should_finalize_source,
                    "peam finality decision"
                );
            }
            if should_finalize_source {
                if trace_attestations {
                    stats.finalized_updates += 1;
                    log_attestation_decision_sample(
                        "finalized_source_update",
                        att,
                        self.slot,
                        finalized_slot,
                    );
                }
                let old_finalized = self.latest_finalized.slot;
                self.latest_finalized = Checkpoint {
                    root: att.data.source.root,
                    slot: att.data.source.slot,
                };
                // Invariant: source.slot > old_finalized, so delta is strictly positive.
                let delta = (self.latest_finalized.slot.0.0 - old_finalized.0.0) as usize;
                shift_justified_window(&mut self.justified_slots, delta);
                finalized_slot = self.latest_finalized.slot;
                let mut missing_root_to_slot = false;
                votes_map.retain(|root, _| match root_to_slot.get(root) {
                    Some(slot) => *slot > finalized_slot,
                    None => {
                        missing_root_to_slot = true;
                        false
                    }
                });
                if missing_root_to_slot {
                    return Err("justification root missing from root_to_slot".to_string());
                }
            }
        }
        if let Some(votes) = justification_votes {
            encode_justification_votes(self, votes, total_validators)?;
        }
        if trace_attestations && total_attestations > 0 {
            tracing::info!(
                state_slot = self.slot.0.0,
                attestations_total = total_attestations,
                pre_justified_slot = pre_justified_slot.0.0,
                post_justified_slot = self.latest_justified.slot.0.0,
                pre_finalized_slot = pre_finalized_slot.0.0,
                post_finalized_slot = self.latest_finalized.slot.0.0,
                eligible_votes = stats.eligible_votes,
                justified_updates = stats.justified_updates,
                finalized_updates = stats.finalized_updates,
                future_slot = stats.future_slot,
                target_below_source = stats.target_below_source,
                head_below_target = stats.head_below_target,
                slot_below_head = stats.slot_below_head,
                zero_checkpoint_root = stats.zero_checkpoint_root,
                unknown_head_root = stats.unknown_head_root,
                source_root_slot_mismatch = stats.source_root_slot_mismatch,
                target_root_slot_mismatch = stats.target_root_slot_mismatch,
                target_not_justifiable = stats.target_not_justifiable,
                target_already_justified = stats.target_already_justified,
                source_not_justified = stats.source_not_justified,
                empty_participants = stats.empty_participants,
                vote_below_supermajority = stats.vote_below_supermajority,
                "attestation processing summary"
            );
        }
        Ok(())
    }

    /// Imports a signed block using the canonical post-quantum verifier.
    #[inline]
    pub fn process_signed_block(
        &mut self,
        signed: &SignedBlockWithAttestation,
    ) -> Result<(), String> {
        let verifier = PqSignatureVerifier;
        self.process_signed_block_with_verifier(signed, &verifier)
    }

    /// Imports a signed block using the provided [`SignatureVerifier`].
    ///
    /// Steps:
    /// 1. [`SignedBlockWithAttestation::validate_basic`] — structural pre-checks
    /// 2. `verifier.verify_signed_block` — signature / participant verification
    /// 3. internal state transition — full transition with post-state root check
    ///
    /// # Errors
    ///
    /// Returns `Err` if any step fails.
    #[inline]
    pub fn process_signed_block_with_verifier<V: SignatureVerifier>(
        &mut self,
        signed: &SignedBlockWithAttestation,
        verifier: &V,
    ) -> Result<(), String> {
        self.process_signed_block_with_verifier_and_sink(
            signed,
            verifier,
            &NoopTransitionMetricsSink,
        )
    }

    /// Like [`process_signed_block`] but records sub-step timings in the
    /// provided [`MetricsRegistry`].
    #[inline]
    pub fn process_signed_block_with_metrics(
        &mut self,
        signed: &SignedBlockWithAttestation,
        metrics: &MetricsRegistry,
    ) -> Result<(), String> {
        let verifier = PqSignatureVerifier;
        self.process_signed_block_with_verifier_and_sink(signed, &verifier, metrics)
    }

    #[inline]
    fn process_signed_block_with_verifier_and_sink<
        V: SignatureVerifier,
        M: TransitionMetricsSink,
    >(
        &mut self,
        signed: &SignedBlockWithAttestation,
        verifier: &V,
        metrics: &M,
    ) -> Result<(), String> {
        signed.validate_basic()?;
        let block = &signed.message.block;
        let pre_state_slot = self.slot;
        let pre_justified_slot = self.latest_justified.slot;
        let pre_finalized_slot = self.latest_finalized.slot;
        let trace_attestations = attestation_trace_enabled();
        if trace_attestations {
            log_imported_block_attestation_envelope_sample(
                "state_transition_input",
                signed,
                pre_state_slot,
                pre_justified_slot,
                pre_finalized_slot,
            );
        }
        verifier.verify_signed_block(signed, self)?;
        // Run the transition on a working copy so rejected blocks cannot
        // partially mutate the live state.
        let mut working_state = self.clone();
        match working_state.state_transition_inner(block, metrics) {
            Ok(()) => {
                *self = working_state;
                if trace_attestations {
                    tracing::info!(
                        block_root = ?Bytes32::from(block.hash_tree_root()),
                        block_slot = block.slot.0.0,
                        body_attestation_count = block.body.attestations.data.len(),
                        pre_state_slot = pre_state_slot.0.0,
                        post_state_slot = self.slot.0.0,
                        pre_justified_slot = pre_justified_slot.0.0,
                        post_justified_slot = self.latest_justified.slot.0.0,
                        pre_finalized_slot = pre_finalized_slot.0.0,
                        post_finalized_slot = self.latest_finalized.slot.0.0,
                        "state transition imported block attestation outcome"
                    );
                }
                Ok(())
            }
            Err(err) => {
                if trace_attestations {
                    tracing::info!(
                        block_root = ?Bytes32::from(block.hash_tree_root()),
                        block_slot = block.slot.0.0,
                        body_attestation_count = block.body.attestations.data.len(),
                        pre_state_slot = pre_state_slot.0.0,
                        pre_justified_slot = pre_justified_slot.0.0,
                        pre_finalized_slot = pre_finalized_slot.0.0,
                        err = %err,
                        "state transition rejected imported block"
                    );
                }
                Err(err)
            }
        }
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

/// A [`SignatureVerifier`] that performs full post-quantum aggregate-signature
/// verification for each attestation and the block proposer.
pub struct PqSignatureVerifier;

impl SignatureVerifier for PqSignatureVerifier {
    #[inline]
    fn verify_signed_block(
        &self,
        signed: &SignedBlockWithAttestation,
        state: &State,
    ) -> Result<(), String> {
        let block = &signed.message.block;
        let attestations = &block.body.attestations.data;
        let proofs = &signed.signature.attestation_signatures.data;
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

        let validators = &state.validators.data;
        let mut public_keys = Vec::new();

        for (att, proof) in attestations.iter().zip(proofs.iter()) {
            public_keys.clear();
            let bit_len = att.aggregation_bits.len();
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
                    public_keys.push(validator.pubkey);
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

        let proposer_attestation = &signed.message.proposer_attestation;
        let proposer_idx = block.proposer_index.0.0 as usize;
        let proposer = validators
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

#[derive(Default)]
struct AttestationDecisionStats {
    eligible_votes: usize,
    justified_updates: usize,
    finalized_updates: usize,
    future_slot: usize,
    target_below_source: usize,
    head_below_target: usize,
    slot_below_head: usize,
    zero_checkpoint_root: usize,
    unknown_head_root: usize,
    source_root_slot_mismatch: usize,
    target_root_slot_mismatch: usize,
    target_not_justifiable: usize,
    target_already_justified: usize,
    source_not_justified: usize,
    empty_participants: usize,
    vote_below_supermajority: usize,
}

#[inline]
fn attestation_trace_enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| {
        std::env::var("PEAM_TRACE_ATTESTATIONS")
            .ok()
            .map(|value| match value.to_ascii_lowercase().as_str() {
                "1" | "true" | "yes" | "on" => true,
                "0" | "false" | "no" | "off" => false,
                _ => false,
            })
            .unwrap_or(false)
    })
}

#[inline]
//remove in prod
fn finality_trace_enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| {
        std::env::var("PEAM_TRACE_FINALITY")
            .ok()
            .map(|value| match value.to_ascii_lowercase().as_str() {
                "1" | "true" | "yes" | "on" => true,
                "0" | "false" | "no" | "off" => false,
                _ => false,
            })
            .unwrap_or(false)
    })
}

#[inline]
fn state_root_trace_enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| {
        std::env::var("PEAM_TRACE_STATE_ROOTS")
            .ok()
            .map(|value| match value.to_ascii_lowercase().as_str() {
                "1" | "true" | "yes" | "on" => true,
                "0" | "false" | "no" | "off" => false,
                _ => false,
            })
            .unwrap_or(false)
    })
}

fn log_attestation_decision_sample(
    reason: &'static str,
    att: &crate::containers::attestation::Attestation,
    state_slot: Slot,
    finalized_slot: Slot,
) {
    static LOGGED: AtomicUsize = AtomicUsize::new(0);
    if LOGGED.fetch_add(1, Ordering::Relaxed) >= 256 {
        return;
    }
    let data = &att.data;
    tracing::info!(
        reason,
        state_slot = state_slot.0.0,
        finalized_slot = finalized_slot.0.0,
        att_slot = data.slot.0.0,
        head_slot = data.head.slot.0.0,
        source_slot = data.source.slot.0.0,
        target_slot = data.target.slot.0.0,
        head_root = ?data.head.root,
        source_root = ?data.source.root,
        target_root = ?data.target.root,
        participants_len_bits = att.aggregation_bits.len(),
        "attestation decision sample"
    );
}

#[inline]
fn log_attestation_slot_mismatch_sample(
    reason: &'static str,
    att: &crate::containers::attestation::Attestation,
    state_slot: Slot,
    finalized_slot: Slot,
    resolved_slot: Option<Slot>,
    expected_slot: Slot,
) {
    static LOGGED: AtomicUsize = AtomicUsize::new(0);
    if LOGGED.fetch_add(1, Ordering::Relaxed) >= 256 {
        return;
    }
    let data = &att.data;
    tracing::info!(
        reason,
        state_slot = state_slot.0.0,
        finalized_slot = finalized_slot.0.0,
        att_slot = data.slot.0.0,
        head_slot = data.head.slot.0.0,
        source_slot = data.source.slot.0.0,
        target_slot = data.target.slot.0.0,
        resolved_slot = resolved_slot.map(|slot| slot.0.0),
        expected_slot = expected_slot.0.0,
        head_root = ?data.head.root,
        source_root = ?data.source.root,
        target_root = ?data.target.root,
        participants_len_bits = att.aggregation_bits.len(),
        "attestation root-to-slot mismatch sample"
    );
}

#[inline]
fn log_vote_threshold_sample(
    reason: &'static str,
    att: &crate::containers::attestation::Attestation,
    state_slot: Slot,
    finalized_slot: Slot,
    votes_count: usize,
    total_validators: usize,
) {
    static LOGGED: AtomicUsize = AtomicUsize::new(0);
    if LOGGED.fetch_add(1, Ordering::Relaxed) >= 256 {
        return;
    }
    let data = &att.data;
    tracing::info!(
        reason,
        state_slot = state_slot.0.0,
        finalized_slot = finalized_slot.0.0,
        att_slot = data.slot.0.0,
        source_slot = data.source.slot.0.0,
        target_slot = data.target.slot.0.0,
        target_root = ?data.target.root,
        votes_count,
        total_validators,
        participants_len_bits = att.aggregation_bits.len(),
        "attestation vote threshold sample"
    );
}

#[inline]
fn log_imported_block_attestation_envelope_sample(
    reason: &'static str,
    signed: &SignedBlockWithAttestation,
    pre_state_slot: Slot,
    pre_justified_slot: Slot,
    pre_finalized_slot: Slot,
) {
    static LOGGED: AtomicUsize = AtomicUsize::new(0);
    if LOGGED.fetch_add(1, Ordering::Relaxed) >= 256 {
        return;
    }
    let block = &signed.message.block;
    let proposer = &signed.message.proposer_attestation.data;
    let first_body_att = block.body.attestations.data.first();
    tracing::info!(
        reason,
        block_root = ?Bytes32::from(block.hash_tree_root()),
        block_slot = block.slot.0.0,
        parent_root = ?block.parent_root,
        body_attestation_count = block.body.attestations.data.len(),
        pre_state_slot = pre_state_slot.0.0,
        pre_justified_slot = pre_justified_slot.0.0,
        pre_finalized_slot = pre_finalized_slot.0.0,
        proposer_att_slot = proposer.slot.0.0,
        proposer_head_slot = proposer.head.slot.0.0,
        proposer_source_slot = proposer.source.slot.0.0,
        proposer_target_slot = proposer.target.slot.0.0,
        proposer_head_root = ?proposer.head.root,
        proposer_source_root = ?proposer.source.root,
        proposer_target_root = ?proposer.target.root,
        first_body_att_slot = first_body_att.map(|att| att.data.slot.0.0),
        first_body_head_slot = first_body_att.map(|att| att.data.head.slot.0.0),
        first_body_source_slot = first_body_att.map(|att| att.data.source.slot.0.0),
        first_body_target_slot = first_body_att.map(|att| att.data.target.slot.0.0),
        first_body_head_root = ?first_body_att.map(|att| att.data.head.root),
        first_body_source_root = ?first_body_att.map(|att| att.data.source.root),
        first_body_target_root = ?first_body_att.map(|att| att.data.target.root),
        first_body_participants_len_bits = first_body_att.map(|att| att.aggregation_bits.len()),
        "state transition imported block attestation envelope sample"
    );
}

#[derive(Clone, Debug)]
struct JustificationVotes {
    bits: Vec<u8>,
    count: usize,
}

impl JustificationVotes {
    #[inline]
    fn new(validator_count: usize) -> Self {
        Self {
            bits: vec![0u8; validator_count.div_ceil(8)],
            count: 0,
        }
    }
}

#[inline]
fn merge_participant_votes_from_bits<const LIMIT: usize>(
    votes: &mut JustificationVotes,
    participants: &BitList<LIMIT>,
    validator_count: usize,
) {
    // Caller invariant: validator_count > 0 and participants has at least one set bit.
    let max_bits = participants.len().min(validator_count);
    let full_bytes = max_bits / 8;
    for byte_idx in 0..full_bytes {
        let mut new_bits = participants.data.get(byte_idx).copied().unwrap_or(0u8);
        new_bits &= !votes.bits[byte_idx];
        votes.bits[byte_idx] |= new_bits;
        votes.count += new_bits.count_ones() as usize;
    }

    let remainder = max_bits % 8;
    if remainder == 0 {
        return;
    }
    let mask = (1u8 << remainder) - 1;
    let mut new_bits = participants.data.get(full_bytes).copied().unwrap_or(0u8) & mask;
    new_bits &= !votes.bits[full_bytes];
    votes.bits[full_bytes] |= new_bits;
    votes.count += new_bits.count_ones() as usize;
}
#[inline]
fn bit_is_set(data: &[u8], len_bits: usize, index: usize) -> bool {
    if index >= len_bits {
        return false;
    }
    let byte = index / 8;
    let bit = index % 8;
    if byte >= data.len() {
        return false;
    }
    (data[byte] & (1u8 << bit)) != 0
}

#[inline]
fn set_bit(data: &mut [u8], index: usize) {
    let byte = index / 8;
    let bit = index % 8;
    if byte < data.len() {
        data[byte] |= 1u8 << bit;
    }
}

#[inline]
fn decode_justification_votes(
    state: &State,
    validator_count: usize,
) -> RapidHashMap<Bytes32, JustificationVotes> {
    let mut out = RapidHashMap::default();
    if validator_count == 0 || state.justifications_roots.data.is_empty() {
        return out;
    }
    let byte_count = validator_count.div_ceil(8);
    let byte_aligned = validator_count % 8 == 0;
    for (root_idx, root) in state.justifications_roots.data.iter().copied().enumerate() {
        let mut votes = JustificationVotes::new(validator_count);
        if byte_aligned {
            let base_byte = root_idx * byte_count;
            let end_byte = base_byte + byte_count;
            if end_byte <= state.justifications_validators.data.len() {
                votes
                    .bits
                    .copy_from_slice(&state.justifications_validators.data[base_byte..end_byte]);
                votes.count = votes.bits.iter().map(|b| b.count_ones() as usize).sum();
            }
        } else {
            let base = root_idx * validator_count;
            for validator_id in 0..validator_count {
                let flat_idx = base + validator_id;
                if bit_is_set(
                    &state.justifications_validators.data,
                    state.justifications_validators.len,
                    flat_idx,
                ) {
                    let byte = validator_id / 8;
                    let bit = validator_id % 8;
                    votes.bits[byte] |= 1u8 << bit;
                    votes.count += 1;
                }
            }
        }
        out.insert(root, votes);
    }
    out
}

#[inline]
fn encode_justification_votes(
    state: &mut State,
    votes: RapidHashMap<Bytes32, JustificationVotes>,
    validator_count: usize,
) -> Result<(), String> {
    let mut roots = votes.keys().copied().collect::<Vec<_>>();
    roots.sort_unstable_by_key(|root| root.as_array());
    let flat_len = roots
        .len()
        .checked_mul(validator_count)
        .ok_or_else(|| "justification vote bitmap overflow".to_string())?;
    if flat_len > JUSTIFICATION_VALIDATORS_LIMIT {
        return Err("justification vote bitmap exceeds limit".to_string());
    }
    let byte_count = validator_count.div_ceil(8);
    let byte_aligned = validator_count % 8 == 0;
    let mut flat_data = vec![0u8; flat_len.div_ceil(8)];
    for (root_idx, root) in roots.iter().enumerate() {
        if let Some(root_votes) = votes.get(root) {
            if byte_aligned {
                let dst_start = root_idx * byte_count;
                flat_data[dst_start..dst_start + byte_count]
                    .copy_from_slice(&root_votes.bits[..byte_count]);
            } else {
                for validator_id in 0..validator_count {
                    if bit_is_set(&root_votes.bits, validator_count, validator_id) {
                        let flat_idx = root_idx * validator_count + validator_id;
                        set_bit(&mut flat_data, flat_idx);
                    }
                }
            }
        }
    }
    state.justifications_roots = SszList::new(roots).expect("justifications roots");
    state.justifications_validators = BitList {
        data: flat_data,
        len: flat_len,
    };
    Ok(())
}

#[inline]
fn build_historical_root_slots(historical_roots: &[Bytes32]) -> RapidHashMap<Bytes32, Slot> {
    let mut out = RapidHashMap::default();
    for (slot_idx, root) in historical_roots.iter().copied().enumerate() {
        if root != Bytes32::zero() {
            out.insert(root, Slot(Uint64(slot_idx as u64)));
        }
    }
    out
}

/// Returns `true` if `slot` is recorded as justified in the sliding window.
///
/// Slots at or below `finalized` are considered implicitly justified.
/// For slots above `finalized`, checks bit `slot - finalized - 1` in `justified`.
#[inline]
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
#[inline]
fn set_justified_slot(
    justified: &mut JustifiedSlots,
    finalized: Slot,
    slot: Slot,
) -> Result<(), String> {
    // Caller invariant (process_attestations): slot is strictly after finalized.
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

#[inline]
fn is_next_valid_justifiable_slot(source: Slot, target: Slot, finalized: Slot) -> bool {
    if target <= source {
        return false;
    }
    for raw_slot in (source.0.0 + 1)..target.0.0 {
        let slot = Slot(Uint64(raw_slot));
        if slot::is_justifiable_after(slot, finalized).unwrap_or(false) {
            return false;
        }
    }
    true
}

/// Shifts the justified-slot window left by `delta` positions, discarding entries
/// that have fallen below the new finalization point.
///
/// After a finality advance of `delta` slots, bits `[delta, len)` are moved to
/// `[0, len - delta)`. If `delta >= len`, the window is cleared entirely.
#[inline]
fn shift_justified_window(justified: &mut JustifiedSlots, delta: usize) {
    // Caller invariant: delta is strictly positive.
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
    #[inline]
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
    #[inline]
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
    #[inline]
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

/// Computes the consensus hash-tree root of [`State`].
///
/// For lean-client interop, the consensus state root excludes local-only
/// `balances` metadata and hashes the 10 consensus fields.
impl HashTreeRoot for State {
    #[inline]
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
            Bytes32::from(self.justifications_roots.hash_tree_root()),
            Bytes32::from(self.justifications_validators.hash_tree_root()),
        ];
        let root = merkleize(&field_roots);
        *root.as_ref()
    }
}
