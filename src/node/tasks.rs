use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use tokio::task::JoinHandle;
use tokio::time::MissedTickBehavior;
use tracing::warn;

use crate::containers::attestation::{Attestation, AttestationData, SignedAttestation};
use crate::containers::checkpoint::Checkpoint;
use crate::containers::gossip::GossipAttestation;
use crate::containers::state::State;
use crate::fork_choice::ForkChoiceStore;
use crate::networking::P2pCommand;
use crate::slot::{
    ACCEPTANCE_INTERVAL_INDEX, INTERVALS_PER_SLOT, SAFE_TARGET_INTERVAL_INDEX, SLOT_DURATION_SECS,
    interval_index_from_unix_millis, next_slot_boundary_delay, slot_index_from_unix_millis,
    unix_now_millis,
};
use crate::ssz::{HashTreeRoot, SszEncode};
use crate::types::bytes::Bytes32;
use crate::types::uint::Uint64;

use super::head::{aggregate_attestations, proposal_head_from_pending};

#[inline]
pub(super) fn spawn_strict_slot_clock(genesis_time_secs: u64) -> Arc<AtomicU64> {
    let now = unix_now_millis().unwrap_or(0);
    let initial_slot = slot_index_from_unix_millis(genesis_time_secs, now);
    let delay = next_slot_boundary_delay(genesis_time_secs, now);
    let slot_clock = Arc::new(AtomicU64::new(initial_slot));
    let slot_clock_task = Arc::clone(&slot_clock);
    tokio::spawn(async move {
        let start = tokio::time::Instant::now() + delay;
        let mut ticker = tokio::time::interval_at(start, Duration::from_secs(SLOT_DURATION_SECS));
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
            let aggregated = aggregate_attestations(drained);
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
    state: Arc<RwLock<State>>,
    fork_choice: Arc<RwLock<Option<ForkChoiceStore>>>,
    pending_attestations: Arc<RwLock<Vec<Attestation>>>,
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
        let now = unix_now_millis().unwrap_or(0);
        let delay = next_slot_boundary_delay(genesis_time_secs, now);
        let start = tokio::time::Instant::now() + delay;
        let mut ticker = tokio::time::interval_at(start, Duration::from_secs(SLOT_DURATION_SECS));
        ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);

        loop {
            ticker.tick().await;
            let Some(now_millis) = unix_now_millis() else {
                continue;
            };
            let mut slot = slot_index_from_unix_millis(genesis_time_secs, now_millis);

            let att_data = {
                let guard = state.read().expect("state lock");
                let mut head_slot = guard.slot;
                let target = guard.latest_justified;
                let source = guard.latest_justified;
                if head_slot < target.slot {
                    head_slot = target.slot;
                }
                if slot < head_slot.0.0 {
                    slot = head_slot.0.0;
                }
                let head_root = proposal_head_from_pending(&fork_choice, &pending_attestations)
                    .unwrap_or_else(|| Bytes32::from(guard.latest_block_header.hash_tree_root()));
                AttestationData {
                    slot: crate::slot::Slot(Uint64(slot)),
                    head: Checkpoint {
                        root: head_root,
                        slot: head_slot,
                    },
                    target,
                    source,
                }
            };

            let message_root = att_data.hash_tree_root();
            let signature = match crate::crypto::pq::sign_message(
                &local_secret_key,
                slot as u32,
                &message_root,
            ) {
                Ok(sig) => sig,
                Err(err) => {
                    warn!("failed to sign attestation: {err}");
                    continue;
                }
            };

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
