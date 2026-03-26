use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock, RwLock};

use tracing::{debug, info, warn};

use crate::containers::block::SignedBlockWithAttestation;
use crate::containers::req_resp::Status;
use crate::containers::state::State;
use crate::fork_choice::ForkChoiceStore;
use crate::slot::Slot;
use crate::ssz::HashTreeRoot;
use crate::storage::{FileStore, Store};
use crate::types::bytes::Bytes32;
use crate::types::uint::Uint64;

#[inline]
pub(super) fn build_local_status(
    state: &Arc<RwLock<State>>,
    _store: &Arc<RwLock<FileStore>>,
) -> Status {
    let state_guard = state.read().expect("state lock");
    Status {
        finalized_root: state_guard.latest_finalized.root,
        finalized_slot: state_guard.latest_finalized.slot.0,
        head_root: Bytes32::from(state_guard.latest_block_header.hash_tree_root()),
        head_slot: Uint64(state_guard.latest_block_header.slot.0.0),
    }
}

#[inline]
pub(super) fn import_backfill_chain(
    state: &Arc<RwLock<State>>,
    store: &Arc<RwLock<FileStore>>,
    fork_choice: &Arc<RwLock<Option<ForkChoiceStore>>>,
    fetched_newest_to_oldest: &[SignedBlockWithAttestation],
) -> Option<usize> {
    if fetched_newest_to_oldest.is_empty() {
        return Some(0);
    }

    let oldest = fetched_newest_to_oldest
        .last()
        .expect("non-empty checked above");
    let newest = fetched_newest_to_oldest
        .first()
        .expect("non-empty checked above");

    let mut state_guard = state.write().expect("state lock");
    let mut store_guard = store.write().expect("store lock");
    let mut fc_guard = fork_choice.write().expect("fork choice lock");

    // Replay backfill blocks from the known parent state, not the live head
    // state. The live state may already be at a higher wall-clock slot.
    let sync_anchor_state =
        sync_anchor_state_for_import_slot(&state_guard, oldest.message.block.slot).unwrap_or_else(
            || {
            warn!(
                "sync import fallback: failed to derive anchor state at slot={} from genesis, using raw genesis",
                oldest.message.block.slot.0.0
            );
            State::generate_genesis(state_guard.config.genesis_time, state_guard.validators.clone())
        },
        );
    let parent_root = oldest.message.block.parent_root;
    debug!(
        "sync import chain start depth={} oldest_root={:?} oldest_slot={} oldest_parent={:?} newest_root={:?} newest_slot={} live_slot={} live_head_root={:?} anchor_slot={} anchor_header_root={:?}",
        fetched_newest_to_oldest.len(),
        Bytes32::from(oldest.message.block.hash_tree_root()),
        oldest.message.block.slot.0.0,
        parent_root,
        Bytes32::from(newest.message.block.hash_tree_root()),
        newest.message.block.slot.0.0,
        state_guard.slot.0.0,
        Bytes32::from(state_guard.latest_block_header.hash_tree_root()),
        sync_anchor_state.slot.0.0,
        Bytes32::from(sync_anchor_state.latest_block_header.hash_tree_root())
    );
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
    let trace_attestations = backfill_attestation_trace_enabled();
    for signed in fetched_newest_to_oldest.iter().rev() {
        let root = Bytes32::from(signed.message.block.hash_tree_root());
        if store_guard.get_block(&root).is_some() {
            debug!(
                "sync import skipping already-known block root={:?} slot={}",
                root, signed.message.block.slot.0.0
            );
            continue;
        }
        if trace_attestations {
            log_backfill_attestation_payload_sample(signed, root, replay_state.slot);
        }
        let block = &signed.message.block;
        let expected_parent = Bytes32::from(replay_state.latest_block_header.hash_tree_root());
        debug!(
            "sync import replay step root={:?} slot={} parent={:?} replay_slot={} expected_parent={:?}",
            root, block.slot.0.0, block.parent_root, replay_state.slot.0.0, expected_parent
        );
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
            return None;
        }
        if let Err(err) =
            store_guard.put_backfill_signed_block(root, signed.clone(), &mut replay_state)
        {
            warn!(
                "sync import failed root={root:?} err={err} replay_slot={} block_slot={} expected_parent={expected_parent:?} block_parent={:?}",
                replay_state.slot.0.0, block.slot.0.0, block.parent_root
            );
            return None;
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

    if imported == 0 {
        debug!("sync import finished imported_blocks=0 (state unchanged)");
        return Some(0);
    }

    // Merge replay result into live state without allowing checkpoint/slot rollback.
    // Only replace the full state when the replay chain agrees with the live head;
    // otherwise gossip already imported a different block at the same slot and we
    // must preserve the live latest_block_header to avoid breaking gossip continuity.
    let live_target_slot = state_guard.slot;
    let live_justified = state_guard.latest_justified;
    let live_finalized = state_guard.latest_finalized;

    let replay_extends_live = if replay_state.slot > state_guard.slot {
        true
    } else if replay_state.slot == state_guard.slot {
        Bytes32::from(replay_state.latest_block_header.hash_tree_root())
            == Bytes32::from(state_guard.latest_block_header.hash_tree_root())
    } else {
        false
    };

    if replay_extends_live {
        *state_guard = replay_state;
    } else {
        if replay_state.latest_justified.slot > state_guard.latest_justified.slot {
            state_guard.latest_justified = replay_state.latest_justified;
        }
        if replay_state.latest_finalized.slot > state_guard.latest_finalized.slot {
            state_guard.latest_finalized = replay_state.latest_finalized;
        }
    }
    if state_guard.latest_justified.slot < live_justified.slot {
        state_guard.latest_justified = live_justified;
    }
    if state_guard.latest_finalized.slot < live_finalized.slot {
        state_guard.latest_finalized = live_finalized;
    }
    if state_guard.slot < live_target_slot
        && let Err(err) = state_guard.process_slots(live_target_slot)
    {
        warn!(
            "sync import: failed to advance replayed state to live slot target={} current={} err={}",
            live_target_slot.0.0, state_guard.slot.0.0, err
        );
    }
    info!("sync import finished imported_blocks={imported}");
    Some(imported)
}

#[inline]
pub(super) fn import_streamed_range_chain(
    state: &Arc<RwLock<State>>,
    store: &Arc<RwLock<FileStore>>,
    fork_choice: &Arc<RwLock<Option<ForkChoiceStore>>>,
    fetched_oldest_to_newest: &[SignedBlockWithAttestation],
) -> bool {
    if fetched_oldest_to_newest.is_empty() {
        debug!("sync range import finished imported_blocks=0 (empty response)");
        return true;
    }

    let mut state_guard = state.write().expect("state lock");
    let mut store_guard = store.write().expect("store lock");
    let mut fc_guard = fork_choice.write().expect("fork choice lock");
    let mut imported = 0usize;

    for signed in fetched_oldest_to_newest {
        let root = Bytes32::from(signed.message.block.hash_tree_root());
        if store_guard.get_block(&root).is_some() {
            debug!(
                "sync range import skipping already-known block root={:?} slot={}",
                root, signed.message.block.slot.0.0
            );
            continue;
        }
        if let Err(err) =
            store_guard.put_backfill_signed_block(root, signed.clone(), &mut state_guard)
        {
            warn!(
                "sync range import failed root={root:?} slot={} err={err}",
                signed.message.block.slot.0.0
            );
            return false;
        }
        imported += 1;
        if let Some(fc) = fc_guard.as_mut() {
            if let Err(err) = fc.on_block(signed.clone(), state_guard.clone()) {
                warn!("fork_choice on_block failed during range sync import: {err}");
            }
        } else if let Ok(new_fc) = ForkChoiceStore::new(signed.clone(), state_guard.clone()) {
            *fc_guard = Some(new_fc);
        }
    }

    info!("sync range import finished imported_blocks={imported}");
    true
}

#[inline]
pub(super) fn parent_matches_sync_anchor(
    state: &Arc<RwLock<State>>,
    parent_root: Bytes32,
    oldest_slot: Slot,
) -> bool {
    if parent_root == Bytes32::zero() {
        return true;
    }

    let state_guard = state.read().expect("state lock");
    let Some(anchor) = sync_anchor_state_for_import_slot(&state_guard, oldest_slot) else {
        return false;
    };
    Bytes32::from(anchor.latest_block_header.hash_tree_root()) == parent_root
}

#[inline]
fn sync_anchor_state_for_import_slot(state: &State, import_slot: Slot) -> Option<State> {
    let mut anchor = State::generate_genesis(state.config.genesis_time, state.validators.clone());
    if import_slot > anchor.slot {
        if anchor.process_slots(import_slot).is_err() {
            return None;
        }
        // Backfill replays blocks through `state_transition`, which expects
        // target_slot > state.slot. Keep the anchor parent root seeded from
        // `process_slots(import_slot)` but rewind one slot so the first replay
        // block at `import_slot` can be applied.
        if import_slot.0.0 > 0 {
            anchor.slot = Slot(Uint64(import_slot.0.0 - 1));
        }
    }
    Some(anchor)
}

#[inline]
fn backfill_attestation_trace_enabled() -> bool {
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
fn log_backfill_attestation_payload_sample(
    signed: &SignedBlockWithAttestation,
    block_root: Bytes32,
    replay_slot: Slot,
) {
    static LOGGED: AtomicUsize = AtomicUsize::new(0);
    if LOGGED.fetch_add(1, Ordering::Relaxed) >= 256 {
        return;
    }
    let block = &signed.message.block;
    let proposer = &signed.message.proposer_attestation.data;
    let attestation_count = block.body.attestations.data.len();
    let first_attestation = block.body.attestations.data.first();
    info!(
        block_root = ?block_root,
        block_slot = block.slot.0.0,
        replay_slot = replay_slot.0.0,
        parent_root = ?block.parent_root,
        attestation_count,
        proposer_att_slot = proposer.slot.0.0,
        proposer_head_slot = proposer.head.slot.0.0,
        proposer_source_slot = proposer.source.slot.0.0,
        proposer_target_slot = proposer.target.slot.0.0,
        proposer_head_root = ?proposer.head.root,
        proposer_source_root = ?proposer.source.root,
        proposer_target_root = ?proposer.target.root,
        first_body_att_slot = first_attestation.map(|att| att.data.slot.0.0),
        first_body_head_slot = first_attestation.map(|att| att.data.head.slot.0.0),
        first_body_source_slot = first_attestation.map(|att| att.data.source.slot.0.0),
        first_body_target_slot = first_attestation.map(|att| att.data.target.slot.0.0),
        first_body_head_root = ?first_attestation.map(|att| att.data.head.root),
        first_body_source_root = ?first_attestation.map(|att| att.data.source.root),
        first_body_target_root = ?first_attestation.map(|att| att.data.target.root),
        first_body_participants_len_bits =
            first_attestation.map(|att| att.aggregation_bits.len()),
        "sync backfill attestation payload sample"
    );
}
