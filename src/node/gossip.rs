use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock, RwLock};
use std::time::Instant;

use libp2p::gossipsub::TopicHash;

use crate::containers::attestation::{Attestation, SignedAttestation, VALIDATOR_REGISTRY_LIMIT};
use crate::containers::block::SignedBlockWithAttestation;
use crate::containers::state::State;
use crate::fork_choice::ForkChoiceStore;
use crate::metrics::MetricsRegistry;
use crate::networking::gossipsub::lean::message::LeanGossipsubMessage;
use crate::ssz::HashTreeRoot;
use crate::storage::Store;
use crate::types::bitlist::BitList;
use crate::types::bytes::Bytes32;
use tracing::warn;

use super::tasks::PendingBlockAttestation;

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
        participants_len_bits = attestation.aggregation_bits.len(),
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
    let first_body_att = block.body.attestations.data.first();
    tracing::info!(
        reason,
        block_root = ?block_root,
        block_slot = block.slot.0.0,
        parent_root = ?block.parent_root,
        body_attestation_count = block.body.attestations.data.len(),
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
                    let mut fc = fork_choice.write().expect("fork choice lock");
                    if fc.is_none() {
                        match ForkChoiceStore::new(signed.clone(), state_guard.clone()) {
                            Ok(new_fc) => {
                                *fc = Some(new_fc);
                            }
                            Err(err) => {
                                warn!("fork choice init failed root={root:?} err={err}");
                            }
                        }
                    } else if let Some(fc) = fc.as_mut() {
                        if let Err(err) = fc.on_block(signed.clone(), state_guard.clone()) {
                            warn!("fork choice on_block failed root={root:?} err={err}");
                        }
                    }
                    enqueue_proposer_attestation_from_signed_block(pending_attestations, &signed);
                    metrics
                        .fc_block_processing_time
                        .observe_duration(block_start);
                }
                Err(err) => {
                    warn!("block import failed root={root:?} err={err}");
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
