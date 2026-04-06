use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use leansig::serialization::Serializable;
use leansig::signature::SignatureSchemeSecretKey;
use tokio::task::JoinHandle;
use tokio::time::MissedTickBehavior;
use tracing::{info, warn};

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
use crate::containers::state::State;
use crate::containers::validator::ValidatorIndex;
use crate::fork_choice::ForkChoiceStore;
use crate::metrics::MetricsRegistry;
use crate::networking::P2pCommand;
use crate::slot::{
    ACCEPTANCE_INTERVAL_INDEX, AGGREGATION_INTERVAL_INDEX, ATTESTATION_INTERVAL_INDEX,
    INTERVALS_PER_SLOT, SAFE_TARGET_INTERVAL_INDEX, SLOT_DURATION_SECS, Slot,
    interval_index_from_unix_millis, slot_index_from_unix_millis, unix_now_millis,
};
use crate::ssz::{HashTreeRoot, SszEncode};
use crate::storage::FileStore;
use crate::types::bitlist::BitList;
use crate::types::bytes::{ByteList, Bytes32, Bytes52};
use crate::types::collections::SszList;
use crate::types::uint::Uint64;

use super::head::{aggregate_attestations, proposal_head_from_pending};

#[derive(Clone)]
pub struct PendingBlockAttestation {
    pub attestation: Attestation,
    pub proof: Option<AggregatedSignatureProof>,
}

#[derive(Clone)]
pub(super) struct DevnetValidatorKeyMaterial {
    pub pubkey: Bytes52,
    pub secret_key: Arc<crate::crypto::pq::LeanSigSecretKey>,
}

pub(super) type DevnetValidatorKeyCache = Arc<Vec<Option<DevnetValidatorKeyMaterial>>>;

#[inline]
pub(super) fn build_devnet_pq_validator_keys(validator_count: usize) -> DevnetValidatorKeyCache {
    let mut keys = Vec::with_capacity(validator_count);
    for i in 0..validator_count {
        let material = match crate::crypto::pq::key_gen_for_devnet_validator(i) {
            Ok((pubkey, secret_key)) => Some(DevnetValidatorKeyMaterial {
                pubkey,
                secret_key: Arc::new(secret_key),
            }),
            Err(err) => {
                warn!("failed to derive devnet validator key {i}: {err}");
                None
            }
        };
        keys.push(material);
    }
    Arc::new(keys)
}

#[inline]
pub(super) fn build_devnet_pq_validator_keys_from_hash_sig_dir(
    hash_sig_keys_dir: &Path,
    validator_count: usize,
) -> Result<DevnetValidatorKeyCache, String> {
    let mut keys = Vec::with_capacity(validator_count);
    for i in 0..validator_count {
        let pk_path = hash_sig_keys_dir.join(format!("validator_{i}_pk.ssz"));
        let sk_path = hash_sig_keys_dir.join(format!("validator_{i}_sk.ssz"));

        let pk_bytes = std::fs::read(&pk_path)
            .map_err(|err| format!("failed to read {}: {err}", pk_path.display()))?;
        if pk_bytes.len() != 52 {
            return Err(format!(
                "invalid public key length for {}: expected {}, got {}",
                pk_path.display(),
                52,
                pk_bytes.len()
            ));
        }

        let sk_bytes = std::fs::read(&sk_path)
            .map_err(|err| format!("failed to read {}: {err}", sk_path.display()))?;
        let secret_key = crate::crypto::pq::LeanSigSecretKey::from_bytes(&sk_bytes)
            .map_err(|err| format!("failed to decode {}: {err:?}", sk_path.display()))?;

        keys.push(Some(DevnetValidatorKeyMaterial {
            pubkey: Bytes52::from_slice(&pk_bytes),
            secret_key: Arc::new(secret_key),
        }));
    }
    Ok(Arc::new(keys))
}
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
            }
            let mut fc_guard = fork_choice.write().expect("fork choice lock");
            let Some(fc) = fc_guard.as_mut() else {
                continue;
            };
            let mut unresolved = Vec::new();
            for attestation in &aggregated {
                if !fc.on_attestation(attestation) {
                    unresolved.push(attestation.clone());
                }
            }
            let finalized_slot = fc.latest_finalized().slot;
            if interval == SAFE_TARGET_INTERVAL_INDEX {
                fc.update_safe_target();
            }
            if interval == ACCEPTANCE_INTERVAL_INDEX {
                fc.accept_new_votes();
            }
            drop(fc_guard);
            if !unresolved.is_empty() {
                unresolved.retain(|att| att.data.target.slot > finalized_slot);
                pending_attestations
                    .write()
                    .expect("pending attestations lock")
                    .extend(unresolved);
            }
        }
    })
}

/// Filters loaded keys against the genesis state's validator public keys.
///
/// Only keys whose derived/loaded public key matches the corresponding
/// validator's public key in the genesis state are retained.  Keys that
/// don't match are discarded so Peam never signs with a key that other
/// clients cannot verify against the shared genesis config.
#[inline]
pub(super) fn filter_keys_against_genesis(
    state: &State,
    key_cache: DevnetValidatorKeyCache,
) -> DevnetValidatorKeyCache {
    let mut filtered: Vec<Option<DevnetValidatorKeyMaterial>> = Vec::with_capacity(key_cache.len());
    let mut kept = 0usize;
    let mut dropped = 0usize;
    for (i, maybe_key) in key_cache.iter().enumerate() {
        let Some(key) = maybe_key else {
            filtered.push(None);
            continue;
        };
        let matches = state
            .validators
            .data
            .get(i)
            .map_or(false, |v| v.pubkey == key.pubkey);
        if matches {
            filtered.push(Some(key.clone()));
            kept += 1;
        } else {
            tracing::warn!(
                validator_index = i,
                "loaded key pubkey does not match genesis state; dropping"
            );
            filtered.push(None);
            dropped += 1;
        }
    }
    tracing::info!(
        kept,
        dropped,
        "validator key filtering against genesis state"
    );
    Arc::new(filtered)
}

#[inline]
pub(super) fn spawn_signed_attestation_task(
    genesis_time_secs: u64,
    local_validator_index: usize,
    attestation_topic: String,
    p2p_tx: tokio::sync::mpsc::Sender<P2pCommand>,
    _is_syncing: Arc<AtomicBool>,
    state: Arc<RwLock<State>>,
    fork_choice: Arc<RwLock<Option<ForkChoiceStore>>>,
    pending_attestations: Arc<RwLock<Vec<Attestation>>>,
    pending_individual_attestations: Arc<RwLock<Vec<SignedAttestation>>>,
    devnet_validator_keys: DevnetValidatorKeyCache,
    metrics: Arc<MetricsRegistry>,
    is_aggregator: bool,
) -> Option<JoinHandle<()>> {
    let Some(Some(local_key)) = devnet_validator_keys.get(local_validator_index) else {
        warn!("failed to get local signing key from cache");
        return None;
    };
    let local_pubkey = local_key.pubkey;
    let local_secret_key = Arc::clone(&local_key.secret_key);

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
        let interval_millis = ((SLOT_DURATION_SECS * 1_000) / INTERVALS_PER_SLOT).max(1);
        let mut ticker = tokio::time::interval(Duration::from_millis(interval_millis));
        ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
        let mut last_signed_slot: Option<u64> = None;

        loop {
            ticker.tick().await;
            let Some(now_millis) = unix_now_millis() else {
                continue;
            };
            let interval = interval_index_from_unix_millis(genesis_time_secs, now_millis);
            if interval != ATTESTATION_INTERVAL_INDEX {
                continue;
            }
            let mut slot = slot_index_from_unix_millis(genesis_time_secs, now_millis);

            let att_data = {
                let guard = state.read().expect("state lock");
                let source = guard.latest_justified;
                let finalized_slot = guard.latest_finalized.slot;
                let pending_head_root =
                    proposal_head_from_pending(&fork_choice, &pending_attestations);

                let (mut head, target) = {
                    let fc_guard = fork_choice.read().expect("fork choice lock");
                    if let Some(fc) = fc_guard.as_ref() {
                        let head_root = pending_head_root.unwrap_or_else(|| fc.head());
                        let head = fc.checkpoint_for_root(head_root).unwrap_or(Checkpoint {
                            root: head_root,
                            slot: Slot(Uint64(fc.head_slot())),
                        });
                        let target = fc.attestation_target(finalized_slot).unwrap_or(source);
                        (head, target)
                    } else {
                        (
                            Checkpoint {
                                root: Bytes32::from(guard.latest_block_header.hash_tree_root()),
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
            if last_signed_slot == Some(slot) {
                continue;
            }

            let message_root = att_data.hash_tree_root();
            let epoch = slot;
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
                local_secret_key.as_ref(),
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
            let signed = SignedAttestation {
                validator_id: Uint64(local_validator_index as u64),
                message: att_data,
                signature,
            };
            info!(
                slot,
                validator_id = local_validator_index,
                target_slot = signed.message.target.slot.0.0,
                target_root = ?signed.message.target.root,
                source_slot = signed.message.source.slot.0.0,
                source_root = ?signed.message.source.root,
                "published attestation"
            );
            if is_aggregator {
                pending_individual_attestations
                    .write()
                    .expect("pending individual attestations lock")
                    .push(signed.clone());
            }
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
            last_signed_slot = Some(slot);
        }
    }))
}

#[inline]
pub(super) fn spawn_attestation_aggregation_task(
    genesis_time_secs: u64,
    aggregation_topic: String,
    p2p_tx: tokio::sync::mpsc::Sender<P2pCommand>,
    pending_individual_attestations: Arc<RwLock<Vec<SignedAttestation>>>,
    pending_attestations: Arc<RwLock<Vec<Attestation>>>,
    pending_block_attestations: Arc<RwLock<Vec<PendingBlockAttestation>>>,
    devnet_validator_keys: DevnetValidatorKeyCache,
    local_validator_index: usize,
    attestation_committee_count: u64,
    metrics: Arc<MetricsRegistry>,
) -> Option<JoinHandle<()>> {
    Some(tokio::spawn(async move {
        let interval_millis = ((SLOT_DURATION_SECS * 1_000) / INTERVALS_PER_SLOT).max(1);
        let mut ticker = tokio::time::interval(Duration::from_millis(interval_millis));
        ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
        loop {
            ticker.tick().await;
            let Some(now_millis) = unix_now_millis() else {
                continue;
            };
            let interval = interval_index_from_unix_millis(genesis_time_secs, now_millis);
            if interval != AGGREGATION_INTERVAL_INDEX {
                continue;
            }
            if attestation_committee_count == 0 {
                continue;
            }
            let slot = slot_index_from_unix_millis(genesis_time_secs, now_millis);
            let subnet_id = (local_validator_index as u64) % attestation_committee_count;
            let drained = {
                let mut pending = pending_individual_attestations
                    .write()
                    .expect("pending individual attestations lock");
                pending.drain(..).collect::<Vec<_>>()
            };
            if drained.is_empty() {
                continue;
            }

            let aggregated = aggregate_signed_attestations(
                drained,
                &devnet_validator_keys,
                &metrics,
                slot,
                attestation_committee_count,
                subnet_id,
            );
            if aggregated.is_empty() {
                continue;
            }
            for (attestation, proof) in aggregated {
                pending_attestations
                    .write()
                    .expect("pending attestations lock")
                    .push(attestation.clone());
                pending_block_attestations
                    .write()
                    .expect("pending block attestations lock")
                    .push(PendingBlockAttestation {
                        attestation: attestation.clone(),
                        proof: Some(proof.clone()),
                    });
                let payload = crate::containers::gossip::GossipAggregatedAttestation {
                    attestation: crate::containers::attestation::SignedAggregatedAttestation {
                        data: attestation.data.clone(),
                        proof,
                    },
                }
                .encode_ssz();
                let _ = p2p_tx
                    .send(P2pCommand::Publish {
                        topic: aggregation_topic.clone(),
                        payload,
                    })
                    .await;
                info!(
                    slot = attestation.data.slot.0.0,
                    target_slot = attestation.data.target.slot.0.0,
                    target_root = ?attestation.data.target.root,
                    source_slot = attestation.data.source.slot.0.0,
                    source_root = ?attestation.data.source.root,
                    participants_len_bits = attestation.aggregation_bits.len,
                    "published aggregated attestation"
                );
            }
        }
    }))
}

#[inline]
fn set_bits(bits: &BitList<VALIDATOR_REGISTRY_LIMIT>) -> Vec<usize> {
    let mut out = Vec::new();
    let bit_len = bits.len;
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
fn aggregate_signed_attestations(
    signed_attestations: Vec<SignedAttestation>,
    devnet_validator_keys: &DevnetValidatorKeyCache,
    metrics: &MetricsRegistry,
    slot: u64,
    attestation_committee_count: u64,
    subnet_id: u64,
) -> Vec<(Attestation, AggregatedSignatureProof)> {
    #[derive(Default)]
    struct Group {
        data: Option<AttestationData>,
        entries: Vec<(usize, Bytes52, crate::types::bytes::Bytes3112)>,
    }

    let mut grouped: rapidhash::RapidHashMap<[u8; 32], Group> = rapidhash::RapidHashMap::default();
    for signed in signed_attestations {
        if signed.message.slot.0.0 != slot {
            continue;
        }
        if attestation_committee_count == 0 {
            continue;
        }
        let idx = signed.validator_id.0 as usize;
        if (signed.validator_id.0 % attestation_committee_count) != subnet_id {
            continue;
        }
        let Some(Some(key_material)) = devnet_validator_keys.get(idx) else {
            continue;
        };
        let message_root = signed.message.hash_tree_root();
        let epoch = signed.message.slot.0.0 as u32;
        if crate::crypto::pq::verify_signature(
            &key_material.pubkey,
            epoch,
            &message_root,
            &signed.signature,
        )
        .is_err()
        {
            continue;
        }
        let data_root = message_root;
        let entry = grouped.entry(data_root).or_default();
        if entry.data.is_none() {
            entry.data = Some(signed.message.clone());
        }
        if entry.entries.iter().any(|(seen, _, _)| *seen == idx) {
            continue;
        }
        entry
            .entries
            .push((idx, key_material.pubkey, signed.signature));
    }

    let mut out = Vec::new();
    for (_root, mut group) in grouped {
        let Some(data) = group.data.take() else {
            continue;
        };
        if group.entries.is_empty() {
            continue;
        }
        group.entries.sort_by_key(|(idx, _, _)| *idx);

        let mut participants = Vec::with_capacity(group.entries.len());
        let mut public_keys = Vec::with_capacity(group.entries.len());
        let mut signatures = Vec::with_capacity(group.entries.len());
        for (idx, pubkey, signature) in group.entries {
            participants.push(idx);
            public_keys.push(pubkey);
            signatures.push(signature);
        }
        let Some(max_idx) = participants.iter().copied().max() else {
            continue;
        };
        let mut bits = vec![false; max_idx + 1];
        for idx in participants.iter().copied() {
            bits[idx] = true;
        }
        let Ok(bitlist) = BitList::new(bits) else {
            continue;
        };

        let message_root = data.hash_tree_root();
        let aggregate_start = Instant::now();
        let proof_bytes = match crate::crypto::pq::aggregate_signatures(
            &public_keys,
            &signatures,
            &message_root,
            data.slot.0.0 as u32,
        ) {
            Ok(bytes) => {
                metrics
                    .pq_aggregated_signing_time
                    .observe_duration(aggregate_start);
                metrics.pq_aggregated_signatures_total.inc();
                metrics.pq_aggregated_signatures_valid_total.inc();
                metrics
                    .pq_attestations_in_aggregated_signatures_total
                    .add(public_keys.len() as u64);
                bytes
            }
            Err(err) => {
                metrics.pq_aggregated_signatures_invalid_total.inc();
                warn!("failed to aggregate attestation signatures: {err}");
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
        out.push((
            Attestation {
                aggregation_bits: bitlist.clone(),
                data,
            },
            AggregatedSignatureProof {
                participants: bitlist,
                proof_data,
            },
        ));
    }
    out
}

#[inline]
fn build_block_attestation_payload(
    slot: u64,
    pending_block_attestations: &Arc<RwLock<Vec<PendingBlockAttestation>>>,
    devnet_validator_keys: &DevnetValidatorKeyCache,
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

    let mut attestations = Vec::new();
    let mut proofs = Vec::new();
    let mut unaggregated = Vec::new();

    for entry in drained {
        if let Some(proof) = entry.proof {
            let mut attestation = entry.attestation;
            if attestation.aggregation_bits != proof.participants {
                attestation.aggregation_bits = proof.participants.clone();
            }
            attestations.push(attestation);
            proofs.push(proof);
        } else {
            unaggregated.push(entry.attestation);
        }
    }

    if attestations.len() >= ATTESTATIONS_LIMIT {
        attestations.truncate(ATTESTATIONS_LIMIT);
        proofs.truncate(ATTESTATIONS_LIMIT);
        return (attestations, proofs);
    }

    let remaining = ATTESTATIONS_LIMIT - attestations.len();
    let aggregated = aggregate_attestations(unaggregated);

    for attestation in aggregated.into_iter().take(remaining) {
        let participants = set_bits(&attestation.aggregation_bits);
        if participants.is_empty() {
            continue;
        }

        let mut public_keys = Vec::with_capacity(participants.len());
        let mut secret_key_refs = Vec::with_capacity(participants.len());
        let mut signable = true;
        for validator_index in participants {
            let Some(Some(key_material)) = devnet_validator_keys.get(validator_index) else {
                signable = false;
                break;
            };
            let secret_key = key_material.secret_key.as_ref();
            if !secret_key.get_activation_interval().contains(&slot)
                || !secret_key.get_prepared_interval().contains(&slot)
            {
                signable = false;
                break;
            }
            public_keys.push(key_material.pubkey);
            secret_key_refs.push(secret_key);
        }
        if !signable || public_keys.is_empty() {
            metrics.pq_aggregated_signatures_invalid_total.inc();
            continue;
        }
        metrics
            .pq_attestations_in_aggregated_signatures_total
            .add(public_keys.len() as u64);

        let message_root = attestation.data.hash_tree_root();
        metrics.pq_aggregated_signatures_total.inc();
        let aggregate_start = Instant::now();
        let attestation_slot = attestation.data.slot.0.0 as u32;
        let proof_bytes = match crate::crypto::pq::sign_aggregate(
            &public_keys,
            &secret_key_refs,
            attestation_slot,
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
fn produce_block_with_signatures(
    pre_state: &State,
    slot: u64,
    local_validator_index: usize,
    local_secret_key: &crate::crypto::pq::LeanSigSecretKey,
    proposer_target: Checkpoint,
    pending_block_attestations: &Arc<RwLock<Vec<PendingBlockAttestation>>>,
    devnet_validator_keys: &DevnetValidatorKeyCache,
    metrics: &MetricsRegistry,
) -> Option<(SignedBlockWithAttestation, State)> {
    let block_slot = crate::slot::Slot(Uint64(slot));
    let (parent_root, source) = {
        let mut temp = pre_state.clone();
        if block_slot > temp.slot {
            if let Err(err) = temp.process_slots(block_slot) {
                warn!("failed to advance temp state for block production: {err}");
                return None;
            }
        }
        (
            Bytes32::from(temp.latest_block_header.hash_tree_root()),
            temp.latest_justified,
        )
    };
    let (block_attestations, attestation_proofs) = build_block_attestation_payload(
        slot,
        pending_block_attestations,
        devnet_validator_keys,
        metrics,
    );

    let mut block = Block {
        slot: block_slot,
        proposer_index: ValidatorIndex(Uint64(local_validator_index as u64)),
        parent_root,
        state_root: Bytes32::zero(),
        body: BlockBody {
            attestations: SszList::new(block_attestations).expect("attestations within limit"),
        },
    };

    let mut post_state = pre_state.clone();
    if block.slot > post_state.slot {
        if let Err(err) = post_state.process_slots(block.slot) {
            warn!("failed to advance temp state for block production: {err}");
            return None;
        }
    }
    let header = block.header();
    if let Err(err) = post_state.process_block_header(header) {
        warn!("failed to process produced block header: {err}");
        return None;
    }
    if let Err(err) = post_state.process_block_body(&block.body, header.body_root) {
        warn!("failed to process produced block body: {err}");
        return None;
    }
    let state_root = Bytes32::from(post_state.hash_tree_root());
    block.state_root = state_root;
    post_state.latest_block_header.state_root = state_root;
    let block_root = Bytes32::from(block.hash_tree_root());

    let mut proposer_bits = vec![false; local_validator_index + 1];
    proposer_bits[local_validator_index] = true;
    let mut target = proposer_target;
    if target.slot < source.slot {
        target = source;
    }
    if target.slot > block_slot {
        target = Checkpoint {
            root: block_root,
            slot: block_slot,
        };
    }
    let proposer_attestation = Attestation {
        aggregation_bits: match crate::types::bitlist::BitList::new(proposer_bits) {
            Ok(v) => v,
            Err(err) => {
                warn!("failed to build proposer attestation bits: {err}");
                return None;
            }
        },
        data: AttestationData {
            slot: block_slot,
            head: Checkpoint {
                root: block_root,
                slot: block_slot,
            },
            target,
            source,
        },
    };

    let proposer_message = proposer_attestation.data.hash_tree_root();
    let epoch = slot;
    if !local_secret_key.get_activation_interval().contains(&epoch) {
        warn!("skipping block proposal: key not active at epoch {}", epoch);
        return None;
    }
    if !local_secret_key.get_prepared_interval().contains(&epoch) {
        warn!(
            "skipping block proposal: key not prepared at epoch {}",
            epoch
        );
        return None;
    }
    let proposer_sign_start = Instant::now();
    let proposer_signature =
        match crate::crypto::pq::sign_message(local_secret_key, slot as u32, &proposer_message) {
            Ok(sig) => {
                metrics
                    .pq_proposer_signing_time
                    .observe_duration(proposer_sign_start);
                metrics.pq_proposer_signatures_total.inc();
                sig
            }
            Err(err) => {
                warn!("failed to sign proposer attestation: {err}");
                return None;
            }
        };

    Some((
        SignedBlockWithAttestation {
            message: BlockWithAttestation {
                block,
                proposer_attestation,
            },
            signature: BlockSignatures {
                attestation_signatures: SszList::new(attestation_proofs)
                    .expect("attestation proofs within limit"),
                proposer_signature,
            },
        },
        post_state,
    ))
}

#[inline]
fn requeue_block_attestations(
    pending_block_attestations: &Arc<RwLock<Vec<PendingBlockAttestation>>>,
    attestations: &[Attestation],
) {
    if attestations.is_empty() {
        return;
    }
    pending_block_attestations
        .write()
        .expect("pending block attestations lock")
        .extend(
            attestations
                .iter()
                .cloned()
                .map(|attestation| PendingBlockAttestation {
                    attestation,
                    proof: None,
                }),
        );
}

#[inline]
pub(super) fn spawn_block_production_task(
    genesis_time_secs: u64,
    local_validator_index: usize,
    block_topic: String,
    p2p_tx: tokio::sync::mpsc::Sender<P2pCommand>,
    _is_syncing: Arc<AtomicBool>,
    state: Arc<RwLock<State>>,
    store: Arc<RwLock<FileStore>>,
    fork_choice: Arc<RwLock<Option<ForkChoiceStore>>>,
    pending_block_attestations: Arc<RwLock<Vec<PendingBlockAttestation>>>,
    devnet_validator_keys: DevnetValidatorKeyCache,
    metrics: Arc<MetricsRegistry>,
) -> Option<JoinHandle<()>> {
    let Some(Some(local_key)) = devnet_validator_keys.get(local_validator_index) else {
        warn!("failed to get local proposer key from cache");
        return None;
    };
    let local_pubkey = local_key.pubkey;
    let local_secret_key = Arc::clone(&local_key.secret_key);

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
            if slot != state_slot + 1 {
                // Avoid proposing on stale state that is multiple slots behind.
                continue;
            }
            if slot % (validator_count as u64) != local_validator_index as u64 {
                continue;
            }

            let mut imported_block: Option<SignedBlockWithAttestation> = None;
            for attempt in 0..2 {
                let pre_state = state.read().expect("state lock").clone();
                let proposer_target = {
                    let source = pre_state.latest_justified;
                    let finalized_slot = pre_state.latest_finalized.slot;
                    let fc_guard = fork_choice.read().expect("fork choice lock");
                    fc_guard
                        .as_ref()
                        .and_then(|fc| fc.attestation_target(finalized_slot))
                        .unwrap_or(source)
                };
                let Some((signed, post_state)) = produce_block_with_signatures(
                    &pre_state,
                    slot,
                    local_validator_index,
                    local_secret_key.as_ref(),
                    proposer_target,
                    &pending_block_attestations,
                    &devnet_validator_keys,
                    &metrics,
                ) else {
                    break;
                };
                let root = Bytes32::from(signed.message.block.hash_tree_root());

                let import_result = {
                    let mut state_guard = state.write().expect("state lock");
                    let mut store_guard = store.write().expect("store lock");
                    match store_guard.put_prevalidated_signed_block_with_metrics(
                        root,
                        &signed,
                        &mut state_guard,
                        post_state,
                        &metrics,
                    ) {
                        Ok(()) => {
                            let mut fc = fork_choice.write().expect("fork choice lock");
                            if fc.is_none() {
                                if let Ok(new_fc) =
                                    ForkChoiceStore::new(signed.clone(), state_guard.clone())
                                {
                                    *fc = Some(new_fc);
                                }
                            } else if let Some(fc) = fc.as_mut()
                                && let Err(err) = fc.on_block(signed.clone(), state_guard.clone())
                            {
                                warn!(
                                    "fork_choice on_block failed for locally produced block: {err}"
                                );
                            }
                            Ok(())
                        }
                        Err(err) => Err(err),
                    }
                };

                match import_result {
                    Ok(()) => {
                        imported_block = Some(signed);
                        break;
                    }
                    Err(err) => {
                        let parent_mismatch =
                            err.contains("block parent root does not match latest header root");
                        if parent_mismatch {
                            requeue_block_attestations(
                                &pending_block_attestations,
                                &signed.message.block.body.attestations.data,
                            );
                            if attempt == 0 {
                                continue;
                            }
                            warn!("failed to import locally produced block after retry: {err}");
                            break;
                        }
                        warn!("failed to import locally produced block: {err}");
                        break;
                    }
                }
            }

            let Some(signed) = imported_block else {
                continue;
            };

            let root = Bytes32::from(signed.message.block.hash_tree_root());
            info!(
                root = ?root,
                slot = signed.message.block.slot.0.0,
                parent_root = ?signed.message.block.parent_root,
                attestation_count = signed.message.block.body.attestations.data.len(),
                "local block produced and imported"
            );

            let payload = GossipBlock { block: signed }.encode_ssz();
            let _ = p2p_tx
                .send(P2pCommand::Publish {
                    topic: block_topic.clone(),
                    payload,
                })
                .await;
        }
    }))
}
