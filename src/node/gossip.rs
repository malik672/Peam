use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock, RwLock};
use std::time::{Duration, Instant};

use libp2p::gossipsub::TopicHash;
use tokio::task::JoinHandle;
use tokio::time::MissedTickBehavior;

use crate::containers::attestation::{Attestation, SignedAttestation, VALIDATOR_REGISTRY_LIMIT};
use crate::containers::block::SignedBlockWithAttestation;
use crate::containers::state::State;
use crate::fork_choice::ForkChoiceStore;
use crate::logfmt::{short_checkpoint, short_root, short_slot_root};
use crate::metrics::MetricsRegistry;
use crate::networking::GossipContext;
use crate::networking::gossipsub::lean::message::LeanGossipsubMessage;
use crate::networking::gossipsub::validate::{
    ValidationResult, is_retryable_unknown_roots_ignore, validate_basic_message,
    validate_with_context,
};
use crate::ssz::HashTreeRoot;
use crate::storage::Store;
use crate::types::bitlist::BitList;
use crate::types::bytes::Bytes32;
use tracing::{info, warn};

use super::tasks::PendingBlockAttestation;

const DEFERRED_GOSSIP_MAX_ENTRIES: usize = 256;
const DEFERRED_GOSSIP_TTL: Duration = Duration::from_secs(6);
const DEFERRED_GOSSIP_RETRY_INTERVAL: Duration = Duration::from_millis(200);

#[derive(Clone)]
pub struct DeferredGossipMessage {
    pub topic: String,
    pub payload: Vec<u8>,
    pub first_seen: Instant,
    pub last_retry: Instant,
}

#[inline]
pub fn queue_deferred_unknown_root_gossip(
    buffer: &Arc<RwLock<Vec<DeferredGossipMessage>>>,
    topic: String,
    payload: Vec<u8>,
) {
    let now = Instant::now();
    let mut guard = buffer.write().expect("deferred gossip lock");
    if guard
        .iter()
        .any(|entry| entry.topic == topic && entry.payload == payload)
    {
        return;
    }
    if guard.len() >= DEFERRED_GOSSIP_MAX_ENTRIES {
        let _ = guard.remove(0);
    }
    guard.push(DeferredGossipMessage {
        topic,
        payload,
        first_seen: now,
        last_retry: now,
    });
}

pub fn spawn_deferred_gossip_retry_task<S: Store + Send + Sync + 'static>(
    state: Arc<RwLock<State>>,
    store: Arc<RwLock<S>>,
    fork_choice: Arc<RwLock<Option<ForkChoiceStore>>>,
    pending_attestations: Arc<RwLock<Vec<Attestation>>>,
    pending_individual_attestations: Arc<RwLock<Vec<SignedAttestation>>>,
    pending_block_attestations: Arc<RwLock<Vec<PendingBlockAttestation>>>,
    deferred_gossip: Arc<RwLock<Vec<DeferredGossipMessage>>>,
    gossip_context: Arc<dyn GossipContext>,
    is_aggregator: bool,
    metrics: Arc<MetricsRegistry>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(DEFERRED_GOSSIP_RETRY_INTERVAL);
        ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
        loop {
            ticker.tick().await;
            let now = Instant::now();
            let mut ready = Vec::new();
            {
                let mut guard = deferred_gossip.write().expect("deferred gossip lock");
                let mut remaining = Vec::with_capacity(guard.len());
                for mut entry in guard.drain(..) {
                    if now.duration_since(entry.first_seen) > DEFERRED_GOSSIP_TTL {
                        continue;
                    }
                    if now.duration_since(entry.last_retry) < DEFERRED_GOSSIP_RETRY_INTERVAL {
                        remaining.push(entry);
                        continue;
                    }
                    let topic_hash = TopicHash::from_raw(entry.topic.clone());
                    let decoded = match LeanGossipsubMessage::decode(&topic_hash, &entry.payload) {
                        Ok(decoded) => decoded,
                        Err(_) => continue,
                    };
                    match validate_basic_message(&decoded) {
                        ValidationResult::Accept => {}
                        ValidationResult::Ignore(reason)
                            if is_retryable_unknown_roots_ignore(&reason) =>
                        {
                            entry.last_retry = now;
                            remaining.push(entry);
                            continue;
                        }
                        ValidationResult::Ignore(_) | ValidationResult::Reject(_) => continue,
                    }
                    match validate_with_context(&decoded, gossip_context.as_ref()) {
                        ValidationResult::Accept => {
                            ready.push((entry.topic, entry.payload));
                        }
                        ValidationResult::Ignore(reason)
                            if is_retryable_unknown_roots_ignore(&reason) =>
                        {
                            entry.last_retry = now;
                            remaining.push(entry);
                        }
                        ValidationResult::Ignore(_) | ValidationResult::Reject(_) => {}
                    }
                }
                *guard = remaining;
            }
            for (topic, payload) in ready.drain(..) {
                handle_gossip_event(
                    &topic,
                    &payload,
                    &state,
                    &store,
                    &fork_choice,
                    &pending_attestations,
                    &pending_individual_attestations,
                    &pending_block_attestations,
                    is_aggregator,
                    &metrics,
                );
            }
        }
    })
}

#[inline]
fn bitlist_has_any_set(bits: &BitList<VALIDATOR_REGISTRY_LIMIT>) -> bool {
    bits.data.iter().copied().any(|byte| byte != 0)
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
fn log_pending_attestation_sample(reason: &'static str, attestation: &Attestation) {
    if !attestation_trace_enabled() {
        return;
    }
    static LOGGED: AtomicUsize = AtomicUsize::new(0);
    if LOGGED.fetch_add(1, Ordering::Relaxed) >= 256 {
        return;
    }
    let data = &attestation.data;
    tracing::info!(
        reason,
        att_slot = data.slot.0.0,
        head_slot = data.head.slot.0.0,
        source_slot = data.source.slot.0.0,
        target_slot = data.target.slot.0.0,
        head_root = ?data.head.root,
        source_root = ?data.source.root,
        target_root = ?data.target.root,
        participants_len_bits = attestation.aggregation_bits.len,
        "pending attestation ingress sample"
    );
}

#[inline]
fn log_imported_block_attestation_payload_sample(
    reason: &'static str,
    block_root: Bytes32,
    signed: &SignedBlockWithAttestation,
) {
    if !attestation_trace_enabled() {
        return;
    }
    static LOGGED: AtomicUsize = AtomicUsize::new(0);
    if LOGGED.fetch_add(1, Ordering::Relaxed) >= 256 {
        return;
    }
    let block = &signed.message.block;
    let proposer = &signed.message.proposer_attestation.data;
    let first_body_att = block.body.attestations.first();
    tracing::info!(
        reason,
        block_root = ?block_root,
        block_slot = block.slot.0.0,
        parent_root = ?block.parent_root,
        body_attestation_count = block.body.attestations.len(),
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
        first_body_participants_len_bits = first_body_att.map(|att| att.aggregation_bits.len),
        "imported block attestation payload sample"
    );
}

#[inline]
fn enqueue_proposer_attestation_from_signed_block(
    pending_attestations: &Arc<RwLock<Vec<Attestation>>>,
    signed: &SignedBlockWithAttestation,
) {
    let proposer_attestation = signed.message.proposer_attestation.clone();
    log_pending_attestation_sample(
        "from_imported_block_proposer_attestation",
        &proposer_attestation,
    );
    pending_attestations
        .write()
        .expect("pending attestations lock")
        .push(proposer_attestation);
}

/// Decode and dispatch a single gossipsub message, updating shared state.
///
/// Deserializes `payload` according to `topic` into a [`LeanGossipsubMessage`],
/// then branches on the message type:
///
/// - **Block** — acquires write locks on `state` and `store`, imports the block
///   via `Store::put_signed_block`, then either initializes fork-choice (if not
///   yet set) or calls `ForkChoiceStore::on_block`. Silently ignored on
///   decode or import failure.
///
/// - **Attestation / AttestationSubnet** — bounds-checks the validator index,
///   and (when running as an aggregator) enqueues the signed attestation for
///   aggregation and later gossip on the `/aggregation` topic.
#[inline]
pub fn handle_gossip_event<S: Store + Send + Sync + 'static>(
    topic: &str,
    payload: &[u8],
    state: &Arc<RwLock<State>>,
    store: &Arc<RwLock<S>>,
    fork_choice: &Arc<RwLock<Option<ForkChoiceStore>>>,
    pending_attestations: &Arc<RwLock<Vec<Attestation>>>,
    pending_individual_attestations: &Arc<RwLock<Vec<SignedAttestation>>>,
    pending_block_attestations: &Arc<RwLock<Vec<PendingBlockAttestation>>>,
    is_aggregator: bool,
    metrics: &Arc<MetricsRegistry>,
) {
    let topic_hash = TopicHash::from_raw(topic.to_string());
    let msg = match LeanGossipsubMessage::decode(&topic_hash, payload) {
        Ok(msg) => msg,
        Err(err) => {
            warn!("gossip decode failed topic={topic} err={err:?}");
            return;
        }
    };
    match msg {
        LeanGossipsubMessage::Block(block) => {
            let block_start = Instant::now();
            let signed = block.block.clone();
            let root = Bytes32::from(signed.message.block.hash_tree_root());
            let mut state_guard = state.write().expect("state lock");
            let mut store_guard = store.write().expect("store lock");
            match store_guard.put_signed_block_with_metrics(
                root,
                signed.clone(),
                &mut state_guard,
                metrics,
            ) {
                Ok(()) => {
                    log_imported_block_attestation_payload_sample(
                        "from_gossip_imported_block",
                        root,
                        &signed,
                    );
                    // Use the block's exact post-state for fork choice, not
                    // the live state — the replay fallback may have diverged.
                    let fc_state = store_guard
                        .get_state(&root)
                        .unwrap_or_else(|| state_guard.clone());
                    let mut fc = fork_choice.write().expect("fork choice lock");
                    if fc.is_none() {
                        match ForkChoiceStore::new(signed.clone(), fc_state.clone()) {
                            Ok(new_fc) => {
                                *fc = Some(new_fc);
                            }
                            Err(err) => {
                                warn!(
                                    block = %short_slot_root(signed.message.block.slot.0.0, &root),
                                    err = %err,
                                    "gossip block fork-choice init failed"
                                );
                            }
                        }
                    } else if let Some(fc) = fc.as_mut() {
                        if let Err(err) = fc.on_block(signed.clone(), fc_state) {
                            warn!(
                                block = %short_slot_root(signed.message.block.slot.0.0, &root),
                                err = %err,
                                "gossip block fork-choice update failed"
                            );
                        }
                    }
                    info!(
                        block = %short_slot_root(signed.message.block.slot.0.0, &root),
                        parent = %short_root(&signed.message.block.parent_root),
                        "gossip block imported"
                    );
                    enqueue_proposer_attestation_from_signed_block(pending_attestations, &signed);
                    metrics
                        .fc_block_processing_time
                        .observe_duration(block_start);
                }
                Err(err) => {
                    warn!(
                        block = %short_slot_root(signed.message.block.slot.0.0, &root),
                        parent = %short_root(&signed.message.block.parent_root),
                        err = %err,
                        "gossip block import failed"
                    );
                }
            }
        }
        LeanGossipsubMessage::AttestationSubnet { attestation, .. } => {
            let att_start = Instant::now();
            let att = &attestation.attestation;
            let idx = att.validator_id.0 as usize;
            if idx >= VALIDATOR_REGISTRY_LIMIT {
                metrics.fc_attestations_invalid_total.inc();
                return;
            }
            if is_aggregator {
                pending_individual_attestations
                    .write()
                    .expect("pending individual attestations lock")
                    .push(att.clone());
                metrics.fc_attestations_valid_total.inc();
                metrics
                    .fc_attestation_validation_time
                    .observe_duration(att_start);
            }
        }
        LeanGossipsubMessage::AggregatedAttestation(attestation) => {
            let att_start = Instant::now();
            let att = &attestation.attestation;
            if !bitlist_has_any_set(&att.proof.participants) {
                metrics.fc_attestations_invalid_total.inc();
                return;
            }
            info!(
                slot = att.data.slot.0.0,
                head = %short_checkpoint(&att.data.head),
                target = %short_checkpoint(&att.data.target),
                source = %short_checkpoint(&att.data.source),
                participants_len_bits = att.proof.participants.len,
                "gossip attestation aggregate received"
            );
            let pending = Attestation {
                aggregation_bits: att.proof.participants.clone(),
                data: att.data.clone(),
            };
            log_pending_attestation_sample("from_gossip_aggregated_attestation", &pending);
            pending_attestations
                .write()
                .expect("pending attestations lock")
                .push(pending);
            pending_block_attestations
                .write()
                .expect("pending block attestations lock")
                .push(PendingBlockAttestation {
                    attestation: Attestation {
                        aggregation_bits: att.proof.participants.clone(),
                        data: att.data.clone(),
                    },
                    proof: Some(att.proof.clone()),
                });
            metrics.fc_attestations_valid_total.inc();
            metrics
                .fc_attestation_validation_time
                .observe_duration(att_start);
        }
    }
}
