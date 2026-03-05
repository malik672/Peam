use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use leansig::signature::SignatureSchemeSecretKey;
use libp2p::PeerId;
use tokio::task::JoinHandle;
use tokio::time::MissedTickBehavior;
use tracing::{debug, warn};

use crate::containers::attestation::{
    AggregatedSignatureProof, Attestation, AttestationData, PROOF_MAX_BYTES, SignedAttestation,
    VALIDATOR_REGISTRY_LIMIT,
};
use crate::containers::block::{
    ATTESTATIONS_LIMIT, Block, BlockBody, BlockSignatures, BlockWithAttestation,
    SignedBlockWithAttestation,
};
use crate::containers::checkpoint::Checkpoint;
use crate::containers::gossip::{GossipAttestation, GossipBlock};
use crate::containers::req_resp::{BlocksByRootRequest, Status};
use crate::containers::state::State;
use crate::containers::validator::ValidatorIndex;
use crate::fork_choice::ForkChoiceStore;
use crate::metrics::MetricsRegistry;
use crate::networking::{
    LeanRequestMessage, LeanResponseMessage, LeanSupportedProtocol, NetworkEvent, P2pCommand,
};
use crate::slot::{
    ACCEPTANCE_INTERVAL_INDEX, INTERVALS_PER_SLOT, SAFE_TARGET_INTERVAL_INDEX, SLOT_DURATION_SECS,
    Slot, interval_index_from_unix_millis, slot_index_from_unix_millis, unix_now_millis,
};
use crate::ssz::{HashTreeRoot, SszEncode};
use crate::storage::{FileStore, Store};
use crate::types::bitlist::BitList;
use crate::types::bytes::{ByteList, Bytes32};
use crate::types::collections::SszList;
use crate::types::uint::Uint64;

use super::head::{aggregate_attestations, proposal_head_from_pending};

#[inline]
pub(super) fn spawn_strict_slot_clock(genesis_time_secs: u64) -> Arc<AtomicU64> {
    let now = unix_now_millis().unwrap_or(0);
    let initial_slot = slot_index_from_unix_millis(genesis_time_secs, now);
    let slot_clock = Arc::new(AtomicU64::new(initial_slot));
    let slot_clock_task = Arc::clone(&slot_clock);
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(SLOT_DURATION_SECS));
        ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
        loop {
            ticker.tick().await;
            let Some(now_millis) = unix_now_millis() else {
                continue;
            };
            let slot = slot_index_from_unix_millis(genesis_time_secs, now_millis);
            slot_clock_task.store(slot, Ordering::Relaxed);
        }
    });
    slot_clock
}

#[inline]
pub(super) fn spawn_consensus_lifecycle_task(
    genesis_time_secs: u64,
    fork_choice: Arc<RwLock<Option<ForkChoiceStore>>>,
    pending_attestations: Arc<RwLock<Vec<Attestation>>>,
    pending_block_attestations: Arc<RwLock<Vec<Attestation>>>,
    metrics: Arc<MetricsRegistry>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let interval_millis = ((SLOT_DURATION_SECS * 1_000) / INTERVALS_PER_SLOT).max(1);
        let mut ticker = tokio::time::interval(Duration::from_millis(interval_millis));
        ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
        loop {
            ticker.tick().await;
            let Some(now_millis) = unix_now_millis() else {
                continue;
            };
            let interval = interval_index_from_unix_millis(genesis_time_secs, now_millis);
            let drained = {
                let mut pending = pending_attestations
                    .write()
                    .expect("pending attestations lock");
                pending.drain(..).collect::<Vec<_>>()
            };
            let agg_start = Instant::now();
            let aggregated = aggregate_attestations(drained);
            if !aggregated.is_empty() {
                metrics
                    .fc_committee_aggregation_time
                    .observe_duration(agg_start);
                pending_block_attestations
                    .write()
                    .expect("pending block attestations lock")
                    .extend(aggregated.iter().cloned());
            }
            let mut fc_guard = fork_choice.write().expect("fork choice lock");
            let Some(fc) = fc_guard.as_mut() else {
                continue;
            };
            for attestation in &aggregated {
                fc.on_attestation(attestation);
            }
            if interval == SAFE_TARGET_INTERVAL_INDEX {
                fc.update_safe_target();
            }
            if interval == ACCEPTANCE_INTERVAL_INDEX {
                fc.accept_new_votes();
            }
        }
    })
}

#[inline]
pub(super) fn apply_devnet_pq_validator_pubkeys(state: &mut State) {
    for (i, validator) in state.validators.data.iter_mut().enumerate() {
        if let Ok((pubkey, _secret_key)) = crate::crypto::pq::key_gen_for_devnet_validator(i) {
            validator.pubkey = pubkey;
        }
    }
}

#[inline]
pub(super) fn spawn_signed_attestation_task(
    genesis_time_secs: u64,
    local_validator_index: usize,
    attestation_topic: String,
    p2p_tx: tokio::sync::mpsc::Sender<P2pCommand>,
    is_syncing: Arc<AtomicBool>,
    state: Arc<RwLock<State>>,
    fork_choice: Arc<RwLock<Option<ForkChoiceStore>>>,
    pending_attestations: Arc<RwLock<Vec<Attestation>>>,
    metrics: Arc<MetricsRegistry>,
) -> Option<JoinHandle<()>> {
    let (local_pubkey, local_secret_key) =
        match crate::crypto::pq::key_gen_for_devnet_validator(local_validator_index) {
            Ok(v) => v,
            Err(err) => {
                warn!("failed to derive local signing key: {err}");
                return None;
            }
        };

    {
        let guard = state.read().expect("state lock");
        let Some(v) = guard.validators.data.get(local_validator_index) else {
            warn!("local validator index {local_validator_index} out of range; signing disabled");
            return None;
        };
        if v.pubkey != local_pubkey {
            warn!("local validator pubkey mismatch; signing disabled");
            return None;
        }
    }

    Some(tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(SLOT_DURATION_SECS));
        ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);

        loop {
            ticker.tick().await;
            if is_syncing.load(Ordering::Relaxed) {
                continue;
            }
            let Some(now_millis) = unix_now_millis() else {
                continue;
            };
            let mut slot = slot_index_from_unix_millis(genesis_time_secs, now_millis);

            let att_data = {
                let guard = state.read().expect("state lock");
                let head_root = proposal_head_from_pending(&fork_choice, &pending_attestations)
                    .unwrap_or_else(|| Bytes32::from(guard.latest_block_header.hash_tree_root()));
                let source = guard.latest_justified;
                let finalized_slot = guard.latest_finalized.slot;

                let (mut head, target) = {
                    let fc_guard = fork_choice.read().expect("fork choice lock");
                    if let Some(fc) = fc_guard.as_ref() {
                        let head = fc.checkpoint_for_root(head_root).unwrap_or(Checkpoint {
                            root: head_root,
                            slot: guard.slot,
                        });
                        let target = fc.attestation_target(finalized_slot).unwrap_or(source);
                        (head, target)
                    } else {
                        (
                            Checkpoint {
                                root: head_root,
                                slot: guard.slot,
                            },
                            source,
                        )
                    }
                };

                // Keep attestation fields internally coherent and avoid producing
                // degenerate target==source attestations rejected by other clients.
                if head.slot < target.slot {
                    head = target;
                }
                if target.slot <= source.slot
                    || !matches!(
                        crate::slot::is_justifiable_after(target.slot, finalized_slot),
                        Ok(true)
                    )
                {
                    continue;
                }
                if slot < head.slot.0.0 {
                    slot = head.slot.0.0;
                }
                AttestationData {
                    slot: Slot(Uint64(slot)),
                    head,
                    target,
                    source,
                }
            };

            let message_root = att_data.hash_tree_root();
            let epoch = slot as u64;
            if !local_secret_key.get_activation_interval().contains(&epoch) {
                warn!(
                    "skipping attestation signing: key not active at epoch {}",
                    epoch
                );
                continue;
            }
            if !local_secret_key.get_prepared_interval().contains(&epoch) {
                warn!(
                    "skipping attestation signing: key not prepared at epoch {}",
                    epoch
                );
                continue;
            }
            let sign_start = Instant::now();
            let signature = match crate::crypto::pq::sign_message(
                &local_secret_key,
                slot as u32,
                &message_root,
            ) {
                Ok(sig) => {
                    metrics
                        .pq_attestation_signing_time
                        .observe_duration(sign_start);
                    metrics.pq_attestation_signatures_total.inc();
                    sig
                }
                Err(err) => {
                    warn!("failed to sign attestation: {err}");
                    continue;
                }
            };
            let mut bits = vec![false; local_validator_index + 1];
            bits[local_validator_index] = true;
            if let Ok(bitlist) = BitList::new(bits) {
                pending_attestations
                    .write()
                    .expect("pending attestations lock")
                    .push(Attestation {
                        aggregation_bits: bitlist,
                        data: att_data.clone(),
                    });
            }

            let signed = SignedAttestation {
                validator_id: Uint64(local_validator_index as u64),
                message: att_data,
                signature,
            };
            let payload = GossipAttestation {
                attestation: signed,
            }
            .encode_ssz();
            let _ = p2p_tx
                .send(P2pCommand::Publish {
                    topic: attestation_topic.clone(),
                    payload,
                })
                .await;
        }
    }))
}

#[inline]
fn compute_state_root_for_block(state: &State, block: &Block) -> Result<Bytes32, String> {
    let mut temp = state.clone();
    if block.slot > temp.slot {
        temp.process_slots(block.slot)?;
    }
    let header = block.header();
    temp.process_block_header(header)?;
    temp.process_block_body(&block.body, header.body_root)?;
    Ok(Bytes32::from(temp.hash_tree_root()))
}

#[inline]
fn set_bits(bits: &BitList<VALIDATOR_REGISTRY_LIMIT>) -> Vec<usize> {
    let mut out = Vec::new();
    let bit_len = bits.len();
    for (byte_idx, byte) in bits.data.iter().copied().enumerate() {
        let mut remaining = byte;
        while remaining != 0 {
            let bit = remaining.trailing_zeros() as usize;
            let idx = byte_idx * 8 + bit;
            if idx >= bit_len {
                break;
            }
            out.push(idx);
            remaining &= remaining - 1;
        }
    }
    out
}

#[inline]
fn build_block_attestation_payload(
    slot: u64,
    pending_block_attestations: &Arc<RwLock<Vec<Attestation>>>,
    metrics: &MetricsRegistry,
) -> (Vec<Attestation>, Vec<AggregatedSignatureProof>) {
    let drained = {
        let mut pending = pending_block_attestations
            .write()
            .expect("pending block attestations lock");
        std::mem::take(&mut *pending)
    };
    if drained.is_empty() {
        return (Vec::new(), Vec::new());
    }

    let aggregated = aggregate_attestations(drained);
    let mut attestations = Vec::with_capacity(aggregated.len().min(ATTESTATIONS_LIMIT));
    let mut proofs = Vec::with_capacity(aggregated.len().min(ATTESTATIONS_LIMIT));

    for attestation in aggregated.into_iter().take(ATTESTATIONS_LIMIT) {
        let participants = set_bits(&attestation.aggregation_bits);
        if participants.is_empty() {
            continue;
        }

        let mut public_keys = Vec::with_capacity(participants.len());
        let mut secret_keys = Vec::with_capacity(participants.len());
        let mut signable = true;
        for validator_index in participants {
            let Ok((public_key, secret_key)) =
                crate::crypto::pq::key_gen_for_devnet_validator(validator_index)
            else {
                signable = false;
                break;
            };
            if !secret_key.get_activation_interval().contains(&slot)
                || !secret_key.get_prepared_interval().contains(&slot)
            {
                signable = false;
                break;
            }
            public_keys.push(public_key);
            secret_keys.push(secret_key);
        }
        if !signable || public_keys.is_empty() {
            metrics.pq_aggregated_signatures_invalid_total.inc();
            continue;
        }
        metrics
            .pq_attestations_in_aggregated_signatures_total
            .add(public_keys.len() as u64);

        let message_root = attestation.data.hash_tree_root();
        let secret_key_refs = secret_keys.iter().collect::<Vec<_>>();
        metrics.pq_aggregated_signatures_total.inc();
        let aggregate_start = Instant::now();
        let proof_bytes = match crate::crypto::pq::sign_aggregate_concat(
            &public_keys,
            &secret_key_refs,
            slot as u32,
            &message_root,
        ) {
            Ok(proof_bytes) => {
                metrics
                    .pq_aggregated_signing_time
                    .observe_duration(aggregate_start);
                metrics.pq_aggregated_signatures_valid_total.inc();
                proof_bytes
            }
            Err(err) => {
                metrics.pq_aggregated_signatures_invalid_total.inc();
                warn!("failed to aggregate attestation signatures for block production: {err}");
                continue;
            }
        };
        let proof_data = match ByteList::<PROOF_MAX_BYTES>::new(proof_bytes) {
            Ok(proof_data) => proof_data,
            Err(err) => {
                metrics.pq_aggregated_signatures_invalid_total.inc();
                warn!("failed to encode aggregate proof bytes: {err}");
                continue;
            }
        };

        proofs.push(AggregatedSignatureProof {
            participants: attestation.aggregation_bits.clone(),
            proof_data,
        });
        attestations.push(attestation);
    }

    (attestations, proofs)
}

#[inline]
pub(super) fn spawn_block_production_task(
    genesis_time_secs: u64,
    local_validator_index: usize,
    block_topic: String,
    p2p_tx: tokio::sync::mpsc::Sender<P2pCommand>,
    is_syncing: Arc<AtomicBool>,
    state: Arc<RwLock<State>>,
    store: Arc<RwLock<FileStore>>,
    fork_choice: Arc<RwLock<Option<ForkChoiceStore>>>,
    pending_block_attestations: Arc<RwLock<Vec<Attestation>>>,
    metrics: Arc<MetricsRegistry>,
) -> Option<JoinHandle<()>> {
    let (local_pubkey, local_secret_key) =
        match crate::crypto::pq::key_gen_for_devnet_validator(local_validator_index) {
            Ok(v) => v,
            Err(err) => {
                warn!("failed to derive local proposer key: {err}");
                return None;
            }
        };

    {
        let guard = state.read().expect("state lock");
        let Some(v) = guard.validators.data.get(local_validator_index) else {
            warn!(
                "local validator index {local_validator_index} out of range; block production disabled"
            );
            return None;
        };
        if v.pubkey != local_pubkey {
            warn!("local validator pubkey mismatch; block production disabled");
            return None;
        }
    }

    Some(tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(SLOT_DURATION_SECS));
        ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);

        loop {
            ticker.tick().await;
            if is_syncing.load(Ordering::Relaxed) {
                continue;
            }
            let Some(now_millis) = unix_now_millis() else {
                continue;
            };
            let slot = slot_index_from_unix_millis(genesis_time_secs, now_millis);

            let (validator_count, state_slot) = {
                let guard = state.read().expect("state lock");
                (guard.validators.data.len(), guard.slot.0.0)
            };

            if validator_count == 0 {
                continue;
            }
            if slot <= state_slot {
                continue;
            }
            if slot % (validator_count as u64) != local_validator_index as u64 {
                continue;
            }

            // Align a temporary state to this slot first; block parent_root must
            // reference the post-slot latest header root.
            let pre_state = state.read().expect("state lock").clone();
            let block_slot = crate::slot::Slot(Uint64(slot));
            let (parent_root, source) = {
                let mut temp = pre_state.clone();
                if block_slot > temp.slot {
                    if let Err(err) = temp.process_slots(block_slot) {
                        warn!("failed to advance temp state for block production: {err}");
                        continue;
                    }
                }
                (
                    Bytes32::from(temp.latest_block_header.hash_tree_root()),
                    temp.latest_justified,
                )
            };
            let (block_attestations, attestation_proofs) =
                build_block_attestation_payload(slot, &pending_block_attestations, &metrics);

            let mut block = Block {
                slot: block_slot,
                proposer_index: ValidatorIndex(Uint64(local_validator_index as u64)),
                parent_root,
                state_root: Bytes32::zero(),
                body: BlockBody {
                    attestations: SszList::new(block_attestations)
                        .expect("attestations within limit"),
                },
            };

            let state_root = match compute_state_root_for_block(&pre_state, &block) {
                Ok(root) => root,
                Err(err) => {
                    warn!("failed to compute state root for produced block: {err}");
                    continue;
                }
            };
            block.state_root = state_root;
            let block_root = Bytes32::from(block.hash_tree_root());

            let mut proposer_bits = vec![false; local_validator_index + 1];
            proposer_bits[local_validator_index] = true;
            let proposer_attestation = Attestation {
                aggregation_bits: match crate::types::bitlist::BitList::new(proposer_bits) {
                    Ok(v) => v,
                    Err(err) => {
                        warn!("failed to build proposer attestation bits: {err}");
                        continue;
                    }
                },
                data: AttestationData {
                    slot: block_slot,
                    head: Checkpoint {
                        root: block_root,
                        slot: block_slot,
                    },
                    target: Checkpoint {
                        root: block_root,
                        slot: block_slot,
                    },
                    source,
                },
            };

            let proposer_message = proposer_attestation.data.hash_tree_root();
            let epoch = slot as u64;
            if !local_secret_key.get_activation_interval().contains(&epoch) {
                warn!("skipping block proposal: key not active at epoch {}", epoch);
                continue;
            }
            if !local_secret_key.get_prepared_interval().contains(&epoch) {
                warn!(
                    "skipping block proposal: key not prepared at epoch {}",
                    epoch
                );
                continue;
            }
            let proposer_sign_start = Instant::now();
            let proposer_signature = match crate::crypto::pq::sign_message(
                &local_secret_key,
                slot as u32,
                &proposer_message,
            ) {
                Ok(sig) => {
                    metrics
                        .pq_proposer_signing_time
                        .observe_duration(proposer_sign_start);
                    metrics.pq_proposer_signatures_total.inc();
                    sig
                }
                Err(err) => {
                    warn!("failed to sign proposer attestation: {err}");
                    continue;
                }
            };

            let signed = SignedBlockWithAttestation {
                message: BlockWithAttestation {
                    block,
                    proposer_attestation,
                },
                signature: BlockSignatures {
                    attestation_signatures: SszList::new(attestation_proofs)
                        .expect("attestation proofs within limit"),
                    proposer_signature,
                },
            };
            let root = Bytes32::from(signed.message.block.hash_tree_root());

            let imported = {
                let mut state_guard = state.write().expect("state lock");
                let mut store_guard = store.write().expect("store lock");
                if let Err(err) = store_guard.put_signed_block_with_metrics(
                    root,
                    signed.clone(),
                    &mut state_guard,
                    &metrics,
                ) {
                    warn!("failed to import locally produced block: {err}");
                    false
                } else {
                    let mut fc = fork_choice.write().expect("fork choice lock");
                    if fc.is_none() {
                        if let Ok(new_fc) =
                            ForkChoiceStore::new(signed.clone(), state_guard.clone())
                        {
                            *fc = Some(new_fc);
                        }
                    } else if let Some(fc) = fc.as_mut() {
                        if let Err(err) = fc.on_block(signed.clone(), state_guard.clone()) {
                            warn!("fork_choice on_block failed for locally produced block: {err}");
                        }
                    }
                    true
                }
            };
            if !imported {
                continue;
            }

            let payload = GossipBlock {
                block: signed.clone(),
            }
            .encode_ssz();
            let _ = p2p_tx
                .send(P2pCommand::Publish {
                    topic: block_topic.clone(),
                    payload,
                })
                .await;
        }
    }))
}

#[inline]
fn build_local_status(state: &Arc<RwLock<State>>, store: &Arc<RwLock<FileStore>>) -> Status {
    let state_guard = state.read().expect("state lock");
    let store_guard = store.read().expect("store lock");
    let (head_root, head_slot) = match store_guard.head() {
        Some(root) => match store_guard.get_block(&root) {
            Some(block) => (root, Uint64(block.slot.0.0)),
            None => (
                Bytes32::from(state_guard.latest_block_header.hash_tree_root()),
                Uint64(state_guard.slot.0.0),
            ),
        },
        None => (
            Bytes32::from(state_guard.latest_block_header.hash_tree_root()),
            Uint64(state_guard.slot.0.0),
        ),
    };
    let finalized_root = store_guard
        .finalized()
        .unwrap_or(state_guard.latest_finalized.root);
    Status {
        fork_digest: Bytes32::zero(),
        finalized_root,
        finalized_epoch: state_guard.latest_finalized.slot.0,
        head_root,
        head_slot,
    }
}

#[inline]
fn import_backfill_chain(
    state: &Arc<RwLock<State>>,
    store: &Arc<RwLock<FileStore>>,
    fork_choice: &Arc<RwLock<Option<ForkChoiceStore>>>,
    fetched_newest_to_oldest: &[SignedBlockWithAttestation],
) -> bool {
    if fetched_newest_to_oldest.is_empty() {
        return true;
    }

    let mut state_guard = state.write().expect("state lock");
    let mut store_guard = store.write().expect("store lock");
    let mut fc_guard = fork_choice.write().expect("fork choice lock");

    // Replay backfill blocks from the known parent state, not the live head
    // state. The live state may already be at a higher wall-clock slot.
    let sync_anchor_state = State::generate_genesis(
        state_guard.config.genesis_time,
        state_guard.validators.clone(),
    );
    let oldest = fetched_newest_to_oldest
        .last()
        .expect("non-empty checked above");
    let parent_root = oldest.message.block.parent_root;
    let mut replay_state = if parent_root == Bytes32::zero() {
        sync_anchor_state.clone()
    } else {
        match store_guard.get_block(&parent_root) {
            Some(parent_block) => {
                if let Some(parent_state) = store_guard.get_state(&parent_block.state_root) {
                    parent_state
                } else {
                    warn!(
                        "sync import fallback: parent state missing root={:?} parent_block={parent_root:?}, using anchor state",
                        parent_block.state_root
                    );
                    sync_anchor_state.clone()
                }
            }
            None => {
                warn!(
                    "sync import fallback: known parent block missing root={parent_root:?}, using anchor state"
                );
                sync_anchor_state.clone()
            }
        }
    };

    let mut imported = 0usize;
    for signed in fetched_newest_to_oldest.iter().rev() {
        let root = Bytes32::from(signed.message.block.hash_tree_root());
        if store_guard.get_block(&root).is_some() {
            continue;
        }
        let block = &signed.message.block;
        let expected_parent = Bytes32::from(replay_state.latest_block_header.hash_tree_root());
        if replay_state.slot >= block.slot {
            // Remote peers may return anchor/genesis blocks (slot 0, parent 0x00..00)
            // during backfill. These are non-importable via state_transition and can
            // be safely skipped when building local continuity.
            if block.slot.0.0 == 0 || block.parent_root == Bytes32::zero() {
                debug!(
                    "sync import skipping anchor/genesis-like block root={root:?} slot={} parent={:?}",
                    block.slot.0.0, block.parent_root
                );
                continue;
            }
            warn!(
                "sync import failed root={root:?} err=target slot must be in the future replay_slot={} block_slot={} expected_parent={expected_parent:?} block_parent={:?}",
                replay_state.slot.0.0, block.slot.0.0, block.parent_root
            );
            return false;
        }
        if let Err(err) = store_guard.put_signed_block(root, signed.clone(), &mut replay_state) {
            warn!(
                "sync import failed root={root:?} err={err} replay_slot={} block_slot={} expected_parent={expected_parent:?} block_parent={:?}",
                replay_state.slot.0.0, block.slot.0.0, block.parent_root
            );
            return false;
        }
        imported += 1;
        if fc_guard.is_none() {
            if let Ok(new_fc) = ForkChoiceStore::new(signed.clone(), replay_state.clone()) {
                *fc_guard = Some(new_fc);
            }
        } else if let Some(fc) = fc_guard.as_mut() {
            if let Err(err) = fc.on_block(signed.clone(), replay_state.clone()) {
                warn!("fork_choice on_block failed during sync import: {err}");
            }
        }
    }

    // Restore wall-clock slot progression after replay.
    let live_target_slot = state_guard.slot;
    *state_guard = replay_state;
    if state_guard.slot < live_target_slot
        && let Err(err) = state_guard.process_slots(live_target_slot)
    {
        warn!(
            "sync import: failed to advance replayed state to live slot target={} current={} err={}",
            live_target_slot.0.0, state_guard.slot.0.0, err
        );
    }
    debug!("sync import finished imported_blocks={imported}");
    true
}

#[inline]
fn parent_matches_sync_anchor(
    state: &Arc<RwLock<State>>,
    parent_root: Bytes32,
    oldest_slot: crate::slot::Slot,
) -> bool {
    if parent_root == Bytes32::zero() {
        return true;
    }

    let state_guard = state.read().expect("state lock");
    let mut anchor = State::generate_genesis(
        state_guard.config.genesis_time,
        state_guard.validators.clone(),
    );
    if oldest_slot > anchor.slot && anchor.process_slots(oldest_slot).is_err() {
        return false;
    }
    Bytes32::from(anchor.latest_block_header.hash_tree_root()) == parent_root
}

#[inline]
pub(super) fn spawn_status_sync_task(
    p2p_tx: tokio::sync::mpsc::Sender<P2pCommand>,
    peers: crate::networking::PeerManager,
    mut events_rx: tokio::sync::broadcast::Receiver<NetworkEvent>,
    state: Arc<RwLock<State>>,
    store: Arc<RwLock<FileStore>>,
    fork_choice: Arc<RwLock<Option<ForkChoiceStore>>>,
    is_syncing: Arc<AtomicBool>,
    sync_target_slot: Arc<AtomicU64>,
    sync_pending_depth: Arc<AtomicU64>,
    _metrics: Arc<MetricsRegistry>,
) -> JoinHandle<()> {
    const SYNC_SLOT_LAG_THRESHOLD: u64 = 0;
    const MAX_BACKFILL_DEPTH: usize = 512;
    const SYNC_REQUEST_TIMEOUT: Duration = Duration::from_secs(4);

    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(2));
        ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);

        let mut active_peer: Option<String> = None;
        let mut pending_root: Option<Bytes32> = None;
        let mut pending_since: Option<Instant> = None;
        let mut fetched_chain_newest_to_oldest: Vec<SignedBlockWithAttestation> = Vec::new();

        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    if let Some(root) = pending_root {
                        if let Some(since) = pending_since {
                            if since.elapsed() < SYNC_REQUEST_TIMEOUT {
                                continue;
                            }
                            warn!(
                                "sync request timed out root={:?} peer={} depth={}",
                                root,
                                active_peer.as_deref().unwrap_or("none"),
                                fetched_chain_newest_to_oldest.len()
                            );
                        }
                        pending_root = None;
                        pending_since = None;
                        fetched_chain_newest_to_oldest.clear();
                        is_syncing.store(false, Ordering::Relaxed);
                        sync_target_slot.store(0, Ordering::Relaxed);
                        sync_pending_depth.store(0, Ordering::Relaxed);
                        active_peer = None;
                    }
                    let peer_list = peers.list().await;
                    if peer_list.is_empty() {
                        is_syncing.store(false, Ordering::Relaxed);
                        sync_target_slot.store(0, Ordering::Relaxed);
                        sync_pending_depth.store(0, Ordering::Relaxed);
                        active_peer = None;
                        pending_since = None;
                        continue;
                    }
                    let status = build_local_status(&state, &store);
                    let request = LeanRequestMessage::Status(status);
                    let payload = request.encode_ssz();
                    for peer_id_str in peer_list {
                        let Ok(peer_id) = peer_id_str.parse::<PeerId>() else {
                            continue;
                        };
                        let _ = p2p_tx.send(P2pCommand::SendRequest {
                            peer: peer_id,
                            protocol: LeanSupportedProtocol::StatusV1.protocol_id(),
                            payload: payload.clone(),
                        }).await;
                    }
                    // Wait for whichever peer returns an ahead status first.
                    active_peer = None;
                }
                recv = events_rx.recv() => {
                    let Ok(event) = recv else {
                        continue;
                    };
                    let NetworkEvent::ReqRespResponse { peer_id, protocol, payload } = event else {
                        continue;
                    };
                    let Some(kind) = LeanSupportedProtocol::parse_protocol_id(&protocol) else {
                        continue;
                    };
                    match kind {
                        LeanSupportedProtocol::StatusV1 => {
                            if pending_root.is_some() {
                                continue;
                            }
                            let remote_status = match LeanResponseMessage::decode_ssz(kind, &payload) {
                                Ok(LeanResponseMessage::Status(remote_status)) => remote_status,
                                Ok(other) => {
                                    debug!(
                                        "sync status decode unexpected variant peer={} protocol={} variant={:?}",
                                        peer_id, protocol, other
                                    );
                                    continue;
                                }
                                Err(err) => {
                                    warn!(
                                        "sync status decode failed peer={} protocol={} bytes={} err={}",
                                        peer_id, protocol, payload.len(), err
                                    );
                                    continue;
                                }
                            };
                            let local_status = build_local_status(&state, &store);
                            let local_head_slot = local_status.head_slot.0;
                            debug!(
                                "sync status peer={} local_head={} local_finalized={} remote_head={} remote_finalized={}",
                                peer_id,
                                local_head_slot,
                                local_status.finalized_epoch.0,
                                remote_status.head_slot.0,
                                remote_status.finalized_epoch.0
                            );
                            if remote_status.head_slot.0 <= local_head_slot + SYNC_SLOT_LAG_THRESHOLD {
                                is_syncing.store(false, Ordering::Relaxed);
                                pending_root = None;
                                pending_since = None;
                                fetched_chain_newest_to_oldest.clear();
                                sync_target_slot.store(0, Ordering::Relaxed);
                                sync_pending_depth.store(0, Ordering::Relaxed);
                                active_peer = None;
                                continue;
                            }
                            is_syncing.store(true, Ordering::Relaxed);
                            sync_target_slot.store(remote_status.head_slot.0, Ordering::Relaxed);
                            sync_pending_depth.store(0, Ordering::Relaxed);
                            pending_root = Some(remote_status.head_root);
                            pending_since = Some(Instant::now());
                            fetched_chain_newest_to_oldest.clear();
                            active_peer = Some(peer_id.clone());
                            let Ok(remote_peer) = peer_id.parse::<PeerId>() else {
                                pending_root = None;
                                pending_since = None;
                                is_syncing.store(false, Ordering::Relaxed);
                                sync_target_slot.store(0, Ordering::Relaxed);
                                sync_pending_depth.store(0, Ordering::Relaxed);
                                active_peer = None;
                                continue;
                            };
                            let roots = match SszList::new(vec![remote_status.head_root]) {
                                Ok(roots) => roots,
                                Err(_) => {
                                    pending_root = None;
                                    pending_since = None;
                                    is_syncing.store(false, Ordering::Relaxed);
                                    sync_target_slot.store(0, Ordering::Relaxed);
                                    sync_pending_depth.store(0, Ordering::Relaxed);
                                    active_peer = None;
                                    continue;
                                }
                            };
                            let request = LeanRequestMessage::BlocksByRoot(BlocksByRootRequest { roots });
                            debug!(
                                "sync requesting root={:?} from peer={}",
                                remote_status.head_root, peer_id
                            );
                            let _ = p2p_tx.send(P2pCommand::SendRequest {
                                peer: remote_peer,
                                protocol: LeanSupportedProtocol::BlocksByRootV1.protocol_id(),
                                payload: request.encode_ssz(),
                            }).await;
                        }
                        LeanSupportedProtocol::BlocksByRootV1 => {
                            if let Some(expected_peer) = &active_peer {
                                if expected_peer != &peer_id {
                                    continue;
                                }
                            } else {
                                active_peer = Some(peer_id.clone());
                            }
                            let Some(target_root) = pending_root else {
                                continue;
                            };
                            let resp = match LeanResponseMessage::decode_ssz(kind, &payload) {
                                Ok(LeanResponseMessage::BlocksByRoot(resp)) => resp,
                                Ok(other) => {
                                    debug!(
                                        "sync blocks decode unexpected variant peer={} protocol={} variant={:?}",
                                        peer_id, protocol, other
                                    );
                                    continue;
                                }
                                Err(err) => {
                                    warn!(
                                        "sync blocks decode failed peer={} protocol={} bytes={} err={}",
                                        peer_id, protocol, payload.len(), err
                                    );
                                    continue;
                                }
                            };
                            let maybe_signed = resp
                                .blocks
                                .data
                                .iter()
                                .find(|signed| Bytes32::from(signed.message.block.hash_tree_root()) == target_root)
                                .cloned();
                            let Some(signed) = maybe_signed else {
                                debug!(
                                    "sync response missing target root={:?} peer={} blocks={}",
                                    target_root,
                                    peer_id,
                                    resp.blocks.data.len()
                                );
                                pending_root = None;
                                pending_since = None;
                                fetched_chain_newest_to_oldest.clear();
                                is_syncing.store(false, Ordering::Relaxed);
                                sync_target_slot.store(0, Ordering::Relaxed);
                                sync_pending_depth.store(0, Ordering::Relaxed);
                                active_peer = None;
                                continue;
                            };

                            let parent_root = signed.message.block.parent_root;
                            let signed_slot = signed.message.block.slot;
                            fetched_chain_newest_to_oldest.push(signed);
                            sync_pending_depth.store(
                                fetched_chain_newest_to_oldest.len() as u64,
                                Ordering::Relaxed,
                            );
                            if fetched_chain_newest_to_oldest.len() > MAX_BACKFILL_DEPTH {
                                warn!("sync aborted: backfill depth exceeded {MAX_BACKFILL_DEPTH}");
                                pending_root = None;
                                pending_since = None;
                                fetched_chain_newest_to_oldest.clear();
                                is_syncing.store(false, Ordering::Relaxed);
                                sync_target_slot.store(0, Ordering::Relaxed);
                                sync_pending_depth.store(0, Ordering::Relaxed);
                                active_peer = None;
                                continue;
                            }

                            let parent_known_or_anchor = {
                                let store_guard = store.read().expect("store lock");
                                parent_root == Bytes32::zero()
                                    || store_guard.get_block(&parent_root).is_some()
                                    || parent_matches_sync_anchor(
                                        &state,
                                        parent_root,
                                        signed_slot,
                                    )
                            };
                            if parent_known_or_anchor {
                                let imported = import_backfill_chain(
                                    &state,
                                    &store,
                                    &fork_choice,
                                    &fetched_chain_newest_to_oldest,
                                );
                                if imported {
                                    warn!("sync imported {} blocks", fetched_chain_newest_to_oldest.len());
                                } else {
                                    warn!(
                                        "sync import_backfill_chain failed depth={}",
                                        fetched_chain_newest_to_oldest.len()
                                    );
                                }
                                pending_root = None;
                                pending_since = None;
                                fetched_chain_newest_to_oldest.clear();
                                is_syncing.store(false, Ordering::Relaxed);
                                sync_target_slot.store(0, Ordering::Relaxed);
                                sync_pending_depth.store(0, Ordering::Relaxed);
                                active_peer = None;
                                continue;
                            }

                            pending_root = Some(parent_root);
                            pending_since = Some(Instant::now());
                            let Ok(remote_peer) = peer_id.parse::<PeerId>() else {
                                pending_root = None;
                                pending_since = None;
                                fetched_chain_newest_to_oldest.clear();
                                is_syncing.store(false, Ordering::Relaxed);
                                sync_target_slot.store(0, Ordering::Relaxed);
                                sync_pending_depth.store(0, Ordering::Relaxed);
                                active_peer = None;
                                continue;
                            };
                            let roots = match SszList::new(vec![parent_root]) {
                                Ok(roots) => roots,
                                Err(_) => {
                                    pending_root = None;
                                    pending_since = None;
                                    fetched_chain_newest_to_oldest.clear();
                                    is_syncing.store(false, Ordering::Relaxed);
                                    sync_target_slot.store(0, Ordering::Relaxed);
                                    sync_pending_depth.store(0, Ordering::Relaxed);
                                    active_peer = None;
                                    continue;
                                }
                            };
                            let request = LeanRequestMessage::BlocksByRoot(BlocksByRootRequest { roots });
                            debug!(
                                "sync backfill requesting parent root={:?} from peer={}",
                                parent_root, peer_id
                            );
                            let _ = p2p_tx.send(P2pCommand::SendRequest {
                                peer: remote_peer,
                                protocol: LeanSupportedProtocol::BlocksByRootV1.protocol_id(),
                                payload: request.encode_ssz(),
                            }).await;
                        }
                    }
                }
            }
        }
    })
}
