use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock, RwLock};
use std::time::{Duration, Instant};

use libp2p::PeerId;
use peam_consensus_types::containers::attestation::Attestation;
use peam_consensus_types::containers::block::{
    SignedBlockWithAttestation, proposer_attestation_present,
};
use peam_consensus_types::containers::req_resp::{
    BlocksByRangeResponse, BlocksByRootRequest, MAX_BLOCKS_PER_REQUEST,
};
use peam_consensus_types::types::bytes::Bytes32;
use peam_consensus_types::types::collections::SszList;
use peam_fork_choice::fork_choice::ForkChoiceStore;
use rapidhash::{RapidHashMap, RapidHashSet};
use tokio::task::JoinHandle;
use tokio::time::MissedTickBehavior;
use tracing::{debug, info, warn};

use peam_state::state::State;
use crate::logfmt::short_root;
use crate::metrics::MetricsRegistry;
use crate::networking::{
    LeanRequestMessage, LeanResponseMessage, LeanSupportedProtocol, NetworkEvent, P2pCommand,
};
use crate::ssz::HashTreeRoot;
use peam_storage::{FileStore, Store};

use super::backfill::{
    build_local_status, import_backfill_chain, import_streamed_range_chain,
    parent_matches_sync_anchor,
};
use super::pending::PendingBackfill;

#[inline]
fn update_sync_observability(
    metrics: &MetricsRegistry,
    pending: &PendingBackfill,
    in_flight_roots: &RapidHashSet<Bytes32>,
) {
    let request_active =
        !pending.pending_roots.is_empty() || pending.pending_range_start_slot.is_some();
    let request_age_seconds = pending
        .pending_since
        .map(|since| since.elapsed().as_secs())
        .unwrap_or(0);

    metrics
        .sync_inflight_roots
        .store(in_flight_roots.len() as u64, Ordering::Relaxed);
    metrics
        .sync_request_active
        .store(if request_active { 1 } else { 0 }, Ordering::Relaxed);
    metrics
        .sync_request_age_seconds
        .store(request_age_seconds, Ordering::Relaxed);
    metrics.sync_pending_root_request.store(
        if !pending.pending_roots.is_empty() {
            1
        } else {
            0
        },
        Ordering::Relaxed,
    );
    metrics.sync_pending_range_request.store(
        if pending.pending_range_start_slot.is_some() {
            1
        } else {
            0
        },
        Ordering::Relaxed,
    );
    metrics.sync_active_peer_selected.store(
        if pending.active_peer.is_some() { 1 } else { 0 },
        Ordering::Relaxed,
    );
}

#[inline]
async fn request_roots_from_peer(
    p2p_tx: &tokio::sync::mpsc::Sender<P2pCommand>,
    peer_id_str: &str,
    roots: &[Bytes32],
) -> bool {
    if roots.is_empty() || roots.len() > MAX_BLOCKS_PER_REQUEST {
        return false;
    }
    let Ok(peer) = peer_id_str.parse::<PeerId>() else {
        return false;
    };
    let roots = match SszList::new(roots.to_vec()) {
        Ok(roots) => roots,
        Err(_) => return false,
    };
    let request = LeanRequestMessage::BlocksByRoot(BlocksByRootRequest { roots });
    let payload = request.encode_ssz();
    p2p_tx
        .send(P2pCommand::SendRequest {
            peer,
            protocol: LeanSupportedProtocol::BlocksByRootV1.protocol_id(),
            payload,
        })
        .await
        .is_ok()
}

#[inline]
async fn request_root_with_fanout(
    p2p_tx: &tokio::sync::mpsc::Sender<P2pCommand>,
    peers: &crate::networking::PeerManager,
    preferred_peer_id: &str,
    roots: &[Bytes32],
    max_peers: usize,
) -> usize {
    let mut requested = 0usize;
    if request_roots_from_peer(p2p_tx, preferred_peer_id, roots).await {
        requested += 1;
    }
    if requested >= max_peers {
        return requested;
    }
    let peer_list = peers.list().await;
    for peer_id_str in peer_list {
        if peer_id_str == preferred_peer_id {
            continue;
        }
        if request_roots_from_peer(p2p_tx, &peer_id_str, roots).await {
            requested += 1;
        }
        if requested >= max_peers {
            break;
        }
    }
    requested
}

#[inline]
fn select_root_batch(
    pending_parent_roots: &RapidHashMap<Bytes32, String>,
    max_roots: usize,
) -> (Vec<Bytes32>, Option<String>) {
    let mut roots = Vec::with_capacity(max_roots.min(pending_parent_roots.len()));
    let mut preferred_peer = None;
    for (root, peer_id) in pending_parent_roots.iter().take(max_roots) {
        roots.push(*root);
        if preferred_peer.is_none() {
            preferred_peer = Some(peer_id.clone());
        }
    }
    (roots, preferred_peer)
}

#[inline]
fn root_batch_sample(roots: &[Bytes32]) -> Vec<String> {
    roots.iter().take(4).map(short_root).collect()
}

#[inline]
async fn flush_pending_parent_fetches(
    p2p_tx: &tokio::sync::mpsc::Sender<P2pCommand>,
    peers: &crate::networking::PeerManager,
    pending_parent_roots: &mut RapidHashMap<Bytes32, String>,
    pending: &mut PendingBackfill,
    in_flight_roots: &mut RapidHashSet<Bytes32>,
    metrics: &MetricsRegistry,
    max_fanout_peers: usize,
) -> bool {
    if !pending.pending_roots.is_empty()
        || pending.pending_range_start_slot.is_some()
        || pending_parent_roots.is_empty()
    {
        return false;
    }

    let (roots, Some(preferred_peer_id)) =
        select_root_batch(pending_parent_roots, MAX_BLOCKS_PER_REQUEST)
    else {
        return false;
    };
    if roots.is_empty() {
        return false;
    }

    let requested =
        request_root_with_fanout(p2p_tx, peers, &preferred_peer_id, &roots, max_fanout_peers).await;
    if requested == 0 {
        return false;
    }

    for root in &roots {
        in_flight_roots.insert(*root);
        pending_parent_roots.remove(root);
    }
    pending.set_pending_roots(preferred_peer_id.clone(), roots.clone());
    update_sync_observability(metrics, pending, in_flight_roots);
    info!(
        peer = preferred_peer_id,
        requested_roots = roots.len(),
        fanout_peers = requested,
        sample_roots = ?root_batch_sample(&roots),
        remaining_queued_parents = pending_parent_roots.len(),
        "sync backfill flushed parent root batch"
    );
    true
}

#[inline]
async fn broadcast_status_to_peers(
    p2p_tx: &tokio::sync::mpsc::Sender<P2pCommand>,
    peers: &crate::networking::PeerManager,
    state: &Arc<RwLock<State>>,
    store: &Arc<RwLock<FileStore>>,
) -> usize {
    let peer_list = peers.list().await;
    if peer_list.is_empty() {
        return 0;
    }
    let status = build_local_status(state, store);
    let request = LeanRequestMessage::Status(status);
    let payload = request.encode_ssz();
    let mut sent = 0usize;
    for peer_id_str in peer_list {
        let Ok(peer_id) = peer_id_str.parse::<PeerId>() else {
            continue;
        };
        if p2p_tx
            .send(P2pCommand::SendRequest {
                peer: peer_id,
                protocol: LeanSupportedProtocol::StatusV1.protocol_id(),
                payload: payload.clone(),
            })
            .await
            .is_ok()
        {
            sent += 1;
        }
    }
    sent
}

#[inline]
fn enqueue_proposer_attestations_from_backfill_chain(
    pending_attestations: &Arc<RwLock<Vec<Attestation>>>,
    fetched_chain_newest_to_oldest: &[SignedBlockWithAttestation],
) {
    if fetched_chain_newest_to_oldest.is_empty() {
        return;
    }
    let mut pending = pending_attestations
        .write()
        .expect("pending attestations lock");
    for signed in fetched_chain_newest_to_oldest {
        log_sync_proposer_attestation_sample("from_sync_backfill_import", signed);
        if proposer_attestation_present(&signed.message.proposer_attestation) {
            pending.push(signed.message.proposer_attestation.clone());
        }
    }
    if attestation_trace_enabled() {
        info!(
            count = fetched_chain_newest_to_oldest.len(),
            "sync queued proposer attestations from imported backfill chain"
        );
    }
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
fn log_sync_proposer_attestation_sample(
    reason: &'static str,
    signed: &SignedBlockWithAttestation,
) {
    if !attestation_trace_enabled() {
        return;
    }
    static LOGGED: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    if LOGGED.fetch_add(1, Ordering::Relaxed) >= 256 {
        return;
    }
    let block = &signed.message.block;
    let proposer = &signed.message.proposer_attestation.data;
    info!(
        reason,
        block_root = ?Bytes32::from(block.hash_tree_root()),
        block_slot = block.slot.0.0,
        proposer_att_slot = proposer.slot.0.0,
        proposer_head_slot = proposer.head.slot.0.0,
        proposer_source_slot = proposer.source.slot.0.0,
        proposer_target_slot = proposer.target.slot.0.0,
        proposer_head_root = ?proposer.head.root,
        proposer_source_root = ?proposer.source.root,
        proposer_target_root = ?proposer.target.root,
        body_attestation_count = block.body.attestations.len(),
        "sync proposer attestation payload sample"
    );
}

#[inline]
pub(crate) fn spawn_status_sync_task(
    p2p_tx: tokio::sync::mpsc::Sender<P2pCommand>,
    peers: crate::networking::PeerManager,
    mut events_rx: tokio::sync::broadcast::Receiver<NetworkEvent>,
    state: Arc<RwLock<State>>,
    store: Arc<RwLock<FileStore>>,
    fork_choice: Arc<RwLock<Option<ForkChoiceStore>>>,
    pending_attestations: Arc<RwLock<Vec<Attestation>>>,
    is_syncing: Arc<AtomicBool>,
    sync_target_slot: Arc<AtomicU64>,
    sync_pending_depth: Arc<AtomicU64>,
    metrics: Arc<MetricsRegistry>,
) -> JoinHandle<()> {
    const SYNC_SLOT_LAG_THRESHOLD: u64 = 0;
    const MAX_BACKFILL_DEPTH: usize = 512;
    const SYNC_REQUEST_TIMEOUT: Duration = Duration::from_secs(4);
    const SYNC_MAINTENANCE_INTERVAL: Duration = Duration::from_millis(100);
    const STATUS_PROBE_INTERVAL: Duration = Duration::from_secs(1);
    // Strict in-flight dedup: only one outbound request per root at a time.
    const BLOCKS_BY_ROOT_FANOUT_PEERS: usize = 1;

    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(SYNC_MAINTENANCE_INTERVAL);
        ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
        let mut last_status_probe = Instant::now()
            .checked_sub(STATUS_PROBE_INTERVAL)
            .unwrap_or_else(Instant::now);

        let mut pending = PendingBackfill::default();
        let mut pending_parent_roots = RapidHashMap::<Bytes32, String>::default();
        // Single-flight guard: while a root is in this set, never schedule it again.
        let mut in_flight_roots = RapidHashSet::<Bytes32>::default();
        update_sync_observability(&metrics, &pending, &in_flight_roots);

        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    update_sync_observability(&metrics, &pending, &in_flight_roots);
                    if !pending.pending_roots.is_empty() || pending.pending_range_start_slot.is_some() {
                        if let Some(since) = pending.pending_since {
                            if since.elapsed() < SYNC_REQUEST_TIMEOUT {
                                // Keep waiting for the in-flight response.
                            } else {
                                warn!(
                                    "sync request timed out roots={:?} range_start={:?} range_count={:?} peer={} depth={}",
                                    pending.pending_roots,
                                    pending.pending_range_start_slot,
                                    pending.pending_range_count,
                                    pending.active_peer.as_deref().unwrap_or("none"),
                                    pending.fetched_chain_newest_to_oldest.len()
                                );
                                for root in &pending.pending_roots {
                                    in_flight_roots.remove(&root);
                                }
                                pending.pending_roots.clear();
                                pending.pending_since = None;
                                pending.fetched_chain_newest_to_oldest.clear();
                                pending.active_peer = None;
                                sync_pending_depth.store(0, Ordering::Relaxed);
                                update_sync_observability(&metrics, &pending, &in_flight_roots);
                                // Retry quickly against fresh peer statuses.
                                last_status_probe = Instant::now()
                                    .checked_sub(STATUS_PROBE_INTERVAL)
                                    .unwrap_or_else(Instant::now);
                            }
                        }
                    }
                    if !pending.pending_roots.is_empty() || pending.pending_range_start_slot.is_some() {
                        continue;
                    }
                    if flush_pending_parent_fetches(
                        &p2p_tx,
                        &peers,
                        &mut pending_parent_roots,
                        &mut pending,
                        &mut in_flight_roots,
                        &metrics,
                        BLOCKS_BY_ROOT_FANOUT_PEERS,
                    )
                    .await
                    {
                        continue;
                    }
                    if last_status_probe.elapsed() < STATUS_PROBE_INTERVAL {
                        continue;
                    }
                    last_status_probe = Instant::now();
                    let sent = broadcast_status_to_peers(&p2p_tx, &peers, &state, &store).await;
                    if sent == 0 && sync_target_slot.load(Ordering::Relaxed) == 0 {
                        is_syncing.store(false, Ordering::Relaxed);
                        sync_pending_depth.store(0, Ordering::Relaxed);
                    }
                    // Wait for whichever peer returns an ahead status first.
                    pending.active_peer = None;
                    update_sync_observability(&metrics, &pending, &in_flight_roots);
                }
                recv = events_rx.recv() => {
                    let event = match recv {
                        Ok(event) => event,
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                            warn!("sync events channel lagged, skipped {n} events");
                            continue;
                        }
                        Err(err) => {
                            warn!("sync events channel closed err={err}");
                            return;
                        }
                    };
                    let NetworkEvent::ReqRespResponse { peer_id, protocol, payload } = event else {
                        continue;
                    };
                    update_sync_observability(&metrics, &pending, &in_flight_roots);
                    let Some(kind) = LeanSupportedProtocol::parse_protocol_id(&protocol) else {
                        continue;
                    };
                    match kind {
                        LeanSupportedProtocol::StatusV1 => {
                            if !pending.pending_roots.is_empty() || pending.pending_range_start_slot.is_some() {
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
                                local_status.finalized_slot.0,
                                remote_status.head_slot.0,
                                remote_status.finalized_slot.0
                            );
                            let current_target = sync_target_slot.load(Ordering::Relaxed);
                            let remote_head_matches_local =
                                remote_status.head_root == local_status.head_root;
                            let needs_root_backfill = !remote_head_matches_local
                                && remote_status.head_slot.0 + SYNC_SLOT_LAG_THRESHOLD
                                    >= local_head_slot;
                            if !needs_root_backfill {
                                if current_target != 0 && local_head_slot >= current_target {
                                    is_syncing.store(false, Ordering::Relaxed);
                                    pending.reset();
                                    in_flight_roots.clear();
                                    sync_target_slot.store(0, Ordering::Relaxed);
                                    sync_pending_depth.store(0, Ordering::Relaxed);
                                    update_sync_observability(&metrics, &pending, &in_flight_roots);
                                }
                                continue;
                            }
                            debug!(
                                "sync scheduling unknown remote head root peer={} slot={} root={:?}",
                                peer_id,
                                remote_status.head_slot.0,
                                remote_status.head_root
                            );
                            is_syncing.store(true, Ordering::Relaxed);
                            sync_target_slot.fetch_max(remote_status.head_slot.0, Ordering::Relaxed);
                            sync_pending_depth.store(0, Ordering::Relaxed);
                            if !in_flight_roots.insert(remote_status.head_root) {
                                debug!(
                                    "sync dedup skipped scheduling already in-flight root={:?} peer={}",
                                    remote_status.head_root, peer_id
                                );
                                continue;
                            }
                            pending.set_target(peer_id.clone(), remote_status.head_root);
                            update_sync_observability(&metrics, &pending, &in_flight_roots);
                            debug!(
                                "sync requesting root={:?} from peer={}",
                                remote_status.head_root,
                                peer_id,
                            );
                            let requested = request_root_with_fanout(
                                &p2p_tx,
                                &peers,
                                &peer_id,
                                &[remote_status.head_root],
                                BLOCKS_BY_ROOT_FANOUT_PEERS,
                            )
                            .await;
                            if requested == 0 {
                                warn!(
                                    "sync failed to dispatch blocks_by_root request root={:?}",
                                    remote_status.head_root
                                );
                                in_flight_roots.remove(&remote_status.head_root);
                                pending.reset();
                                update_sync_observability(&metrics, &pending, &in_flight_roots);
                            }
                        }
                        LeanSupportedProtocol::BlocksByRangeV1 => {
                            let Some(expected_start_slot) = pending.pending_range_start_slot else {
                                continue;
                            };
                            let expected_count =
                                pending.pending_range_count.unwrap_or(MAX_BLOCKS_PER_REQUEST as u64);
                            let response = match BlocksByRangeResponse::decode_ssz_checked(&payload) {
                                Ok(response) => response,
                                Err(err) => {
                                    warn!(
                                        "sync range decode failed peer={} protocol={} bytes={} err={}",
                                        peer_id, protocol, payload.len(), err
                                    );
                                    continue;
                                }
                            };
                            let blocks = response.blocks.into_inner();
                            let last_slot = blocks
                                .last()
                                .map(|block| block.message.block.slot.0.0)
                                .unwrap_or(expected_start_slot.saturating_sub(1));
                            debug!(
                                "sync range response peer={} start_slot={} expected_count={} received_blocks={} last_slot={}",
                                peer_id,
                                expected_start_slot,
                                expected_count,
                                blocks.len(),
                                last_slot
                            );
                            let imported = import_streamed_range_chain(
                                &state,
                                &store,
                                &fork_choice,
                                &blocks,
                            );
                            pending.reset();
                            sync_pending_depth.store(0, Ordering::Relaxed);
                            update_sync_observability(&metrics, &pending, &in_flight_roots);
                            let local_head = build_local_status(&state, &store).head_slot.0;
                            let target = sync_target_slot.load(Ordering::Relaxed);
                            if imported && local_head < target {
                                is_syncing.store(true, Ordering::Relaxed);
                                last_status_probe = Instant::now()
                                    .checked_sub(STATUS_PROBE_INTERVAL)
                                    .unwrap_or_else(Instant::now);
                            } else if imported {
                                is_syncing.store(false, Ordering::Relaxed);
                                sync_target_slot.store(0, Ordering::Relaxed);
                            } else {
                                is_syncing.store(false, Ordering::Relaxed);
                            }
                        }
                        LeanSupportedProtocol::BlocksByRootV1 => {
                            if pending.pending_roots.is_empty() {
                                continue;
                            }
                            let signed = match LeanResponseMessage::decode_ssz(kind, &payload) {
                                Ok(LeanResponseMessage::BlocksByRoot(signed)) => signed,
                                Ok(other) => {
                                    debug!(
                                        "sync blocks decode unexpected variant peer={} protocol={} variant={:?}",
                                        peer_id, protocol, other
                                    );
                                    continue;
                                }
                                Err(err) => {
                                    if err.contains("empty BlocksByRoot response payload") {
                                        debug!(
                                            "sync blocks empty response peer={} protocol={} bytes={}",
                                            peer_id, protocol, payload.len()
                                        );
                                        continue;
                                    }
                                    warn!(
                                        "sync blocks decode failed peer={} protocol={} bytes={} err={}",
                                        peer_id, protocol, payload.len(), err
                                    );
                                    continue;
                                }
                            };
                            let signed_root =
                                Bytes32::from(signed.message.block.hash_tree_root());
                            if !pending.pending_roots.contains(&signed_root) {
                                debug!(
                                    "sync response root not in pending batch pending_roots={:?} got={:?} peer={}",
                                    pending.pending_roots,
                                    signed_root,
                                    peer_id
                                );
                                // Don't reset sync on a single incomplete response; wait for
                                // timeout-driven retry.
                                continue;
                            }
                            in_flight_roots.remove(&signed_root);
                            pending.pending_roots.retain(|root| *root != signed_root);
                            if pending.pending_roots.is_empty() {
                                pending.pending_since = None;
                            }
                            let remaining_pending = pending.pending_roots.len();
                            pending.active_peer = Some(peer_id.clone());
                            update_sync_observability(&metrics, &pending, &in_flight_roots);

                            let parent_root = signed.message.block.parent_root;
                            let signed_slot = signed.message.block.slot;
                            pending.fetched_chain_newest_to_oldest.push(signed);
                            sync_pending_depth.store(
                                pending.fetched_chain_newest_to_oldest.len() as u64,
                                Ordering::Relaxed,
                            );
                            if pending.fetched_chain_newest_to_oldest.len() > MAX_BACKFILL_DEPTH {
                                warn!("sync aborted: backfill depth exceeded {MAX_BACKFILL_DEPTH}");
                                pending.reset();
                                in_flight_roots.clear();
                                is_syncing.store(false, Ordering::Relaxed);
                                sync_target_slot.store(0, Ordering::Relaxed);
                                sync_pending_depth.store(0, Ordering::Relaxed);
                                update_sync_observability(&metrics, &pending, &in_flight_roots);
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
                            debug!(
                                "sync blocks_by_root accepted root={:?} slot={} parent={:?} depth={} target_root={:?} peer={} parent_known_or_anchor={}",
                                signed_root,
                                signed_slot.0.0,
                                parent_root,
                                pending.fetched_chain_newest_to_oldest.len(),
                                signed_root,
                                peer_id,
                                parent_known_or_anchor
                            );
                            debug!(
                                peer = %peer_id,
                                received_root = %short_root(&signed_root),
                                parent_root = %short_root(&parent_root),
                                remaining_pending_roots = remaining_pending,
                                queued_parent_roots = pending_parent_roots.len(),
                                chain_depth = pending.fetched_chain_newest_to_oldest.len(),
                                "sync backfill batch progress"
                            );
                            if parent_known_or_anchor {
                                let oldest = pending
                                    .fetched_chain_newest_to_oldest
                                    .last()
                                    .map(|block| {
                                        (
                                            Bytes32::from(
                                                block.message.block.hash_tree_root(),
                                            ),
                                            block.message.block.slot.0.0,
                                            block.message.block.parent_root,
                                        )
                                    });
                                let newest = pending
                                    .fetched_chain_newest_to_oldest
                                    .first()
                                    .map(|block| {
                                        (
                                            Bytes32::from(
                                                block.message.block.hash_tree_root(),
                                            ),
                                            block.message.block.slot.0.0,
                                            block.message.block.parent_root,
                                        )
                                    });
                                debug!(
                                    "sync importing chain depth={} oldest={:?} newest={:?} peer={}",
                                    pending.fetched_chain_newest_to_oldest.len(),
                                    oldest,
                                    newest,
                                    peer_id
                                );
                                let imported_blocks = import_backfill_chain(
                                    &state,
                                    &store,
                                    &fork_choice,
                                    &pending.fetched_chain_newest_to_oldest,
                                );
                                match imported_blocks {
                                    Some(imported) if imported > 0 => {
                                        enqueue_proposer_attestations_from_backfill_chain(
                                            &pending_attestations,
                                            &pending.fetched_chain_newest_to_oldest,
                                        );
                                        warn!("sync imported {imported} blocks");
                                    }
                                    Some(_) => {
                                        debug!(
                                            "sync import completed without new blocks depth={}",
                                            pending.fetched_chain_newest_to_oldest.len()
                                        );
                                    }
                                    None => {
                                        warn!(
                                            "sync import_backfill_chain failed depth={}",
                                            pending.fetched_chain_newest_to_oldest.len()
                                        );
                                    }
                                }
                                let local_head = build_local_status(&state, &store).head_slot.0;
                                let target = sync_target_slot.load(Ordering::Relaxed);
                                pending.reset();
                                in_flight_roots.clear();
                                sync_pending_depth.store(0, Ordering::Relaxed);
                                update_sync_observability(&metrics, &pending, &in_flight_roots);
                                if target != 0 && local_head < target {
                                    is_syncing.store(true, Ordering::Relaxed);
                                    last_status_probe = Instant::now()
                                        .checked_sub(STATUS_PROBE_INTERVAL)
                                        .unwrap_or_else(Instant::now);
                                } else {
                                    is_syncing.store(false, Ordering::Relaxed);
                                    sync_target_slot.store(0, Ordering::Relaxed);
                                }
                                continue;
                            }
                            pending_parent_roots
                                .entry(parent_root)
                                .or_insert_with(|| peer_id.clone());
                            update_sync_observability(&metrics, &pending, &in_flight_roots);
                            debug!(
                                "sync queued missing parent root child_root={:?} child_slot={} parent_root={:?} depth={} peer={}",
                                signed_root,
                                signed_slot.0.0,
                                parent_root,
                                pending.fetched_chain_newest_to_oldest.len(),
                                peer_id
                            );
                            if pending.pending_roots.is_empty() {
                                let flushed = flush_pending_parent_fetches(
                                    &p2p_tx,
                                    &peers,
                                    &mut pending_parent_roots,
                                    &mut pending,
                                    &mut in_flight_roots,
                                    &metrics,
                                    BLOCKS_BY_ROOT_FANOUT_PEERS,
                                )
                                .await;
                                if !flushed && pending_parent_roots.is_empty() {
                                    last_status_probe = Instant::now()
                                        .checked_sub(STATUS_PROBE_INTERVAL)
                                        .unwrap_or_else(Instant::now);
                                }
                            }
                        }
                    }
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use rapidhash::RapidHashMap;

    use peam_consensus_types::types::bytes::Bytes32;

    use super::select_root_batch;

    #[test]
    fn select_root_batch_limits_batch_size_and_returns_peer() {
        let mut pending = RapidHashMap::default();
        pending.insert(Bytes32::from([1; 32]), "peer-a".to_string());
        pending.insert(Bytes32::from([2; 32]), "peer-b".to_string());
        pending.insert(Bytes32::from([3; 32]), "peer-c".to_string());

        let (roots, preferred_peer) = select_root_batch(&pending, 2);

        assert_eq!(roots.len(), 2);
        assert!(preferred_peer.is_some());
        for root in roots {
            assert!(pending.contains_key(&root));
        }
    }
}
