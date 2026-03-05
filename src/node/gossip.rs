use std::sync::{Arc, RwLock};
use std::time::Instant;

use libp2p::gossipsub::TopicHash;

use crate::containers::attestation::{Attestation, VALIDATOR_REGISTRY_LIMIT};
use crate::containers::state::State;
use crate::fork_choice::ForkChoiceStore;
use crate::metrics::MetricsRegistry;
use crate::networking::gossipsub::lean::message::LeanGossipsubMessage;
use crate::ssz::HashTreeRoot;
use crate::storage::Store;
use crate::types::bitlist::BitList;
use crate::types::bytes::Bytes32;
use tracing::warn;

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
/// - **Attestation / AttestationSubnet** — reconstructs a single-validator
///   [`Attestation`] from the `SignedAttestation`, bounds-checks the validator
///   index, and appends it to `pending_attestations`. A separate lifecycle task
///   promotes these votes into fork-choice at interval boundaries.
///   Silently ignored if the validator index is out of range or the bitlist
///   construction fails.
#[inline]
pub fn handle_gossip_event<S: Store + Send + Sync + 'static>(
    topic: &str,
    payload: &[u8],
    state: &Arc<RwLock<State>>,
    store: &Arc<RwLock<S>>,
    fork_choice: &Arc<RwLock<Option<ForkChoiceStore>>>,
    pending_attestations: &Arc<RwLock<Vec<Attestation>>>,
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
                &metrics,
            ) {
                Ok(()) => {
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
                    metrics
                        .fc_block_processing_time
                        .observe_duration(block_start);
                }
                Err(err) => {
                    warn!("block import failed root={root:?} err={err}");
                }
            }
        }
        LeanGossipsubMessage::Attestation(att) => {
            let att_start = Instant::now();
            let att = &att.attestation;
            let idx = att.validator_id.0 as usize;
            if idx >= VALIDATOR_REGISTRY_LIMIT {
                metrics.fc_attestations_invalid_total.inc();
                return;
            }
            let mut bits = vec![false; idx + 1];
            bits[idx] = true;
            if let Ok(bitlist) = BitList::new(bits) {
                let aggregated = Attestation {
                    aggregation_bits: bitlist,
                    data: att.message.clone(),
                };
                pending_attestations
                    .write()
                    .expect("pending attestations lock")
                    .push(aggregated.clone());
                metrics.fc_attestations_valid_total.inc();
                metrics
                    .fc_attestation_validation_time
                    .observe_duration(att_start);
            } else {
                metrics.fc_attestations_invalid_total.inc();
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
            let mut bits = vec![false; idx + 1];
            bits[idx] = true;
            if let Ok(bitlist) = BitList::new(bits) {
                let aggregated = Attestation {
                    aggregation_bits: bitlist,
                    data: att.message.clone(),
                };
                pending_attestations
                    .write()
                    .expect("pending attestations lock")
                    .push(aggregated.clone());
                metrics.fc_attestations_valid_total.inc();
                metrics
                    .fc_attestation_validation_time
                    .observe_duration(att_start);
            } else {
                metrics.fc_attestations_invalid_total.inc();
            }
        }
    }
}
