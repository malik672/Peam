//! Application-level req/resp request handlers.
//!
//! [`ReqRespHandler`] is the trait that the networking layer calls for every
//! inbound request. Two implementations are provided:
//!
//! - [`NoopReqRespHandler`] — ignores all requests (useful in tests).
//! - [`StoreReqRespHandler`] — serves requests from a live [`Store`] and
//!   [`State`].

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock, RwLock};
use tracing::{debug, info};

use crate::containers::req_resp::{MAX_BLOCKS_PER_ROOT_REQUEST, Status};
use crate::ssz::HashTreeRoot;
use crate::storage::Store;
use crate::types::bytes::Bytes32;
use crate::types::uint::Uint64;

use super::reqresp_messages::{LeanRequestMessage, LeanResponseMessage};


/// Handles inbound req/resp requests and optionally returns a response.
///
/// Implementations must be `Send + Sync` because they are called from async
/// networking tasks.
pub trait ReqRespHandler: Send + Sync {
    /// Called for each inbound request.
    ///
    /// Returns zero or more response messages to send back.
    fn on_request(&self, request: LeanRequestMessage) -> Vec<LeanResponseMessage>;
}

/// A [`ReqRespHandler`] that ignores every request.
///
/// Useful in tests or when req/resp responses are not required.
pub struct NoopReqRespHandler;

/// [`ReqRespHandler`] impl — always returns `None`.
impl ReqRespHandler for NoopReqRespHandler {
    fn on_request(&self, _request: LeanRequestMessage) -> Vec<LeanResponseMessage> {
        Vec::new()
    }
}

/// A [`ReqRespHandler`] backed by a live [`Store`] and [`State`].
///
/// Handles:
/// - `Status` — responds with a freshly-built status derived from the current
///   head/finalized/justified checkpoints.
/// - `BlocksByRoot` — looks up each requested root in the store and returns
///   the found signed blocks (up to [`MAX_BLOCKS_BY_ROOT_RESPONSE`]).
pub struct StoreReqRespHandler<S: Store + Send + Sync + 'static> {
    state: Arc<RwLock<crate::containers::state::State>>,
    store: Arc<RwLock<S>>,
}

impl<S: Store + Send + Sync + 'static> StoreReqRespHandler<S> {
    /// Creates a new handler sharing `state` and `store` via `Arc<RwLock<…>>`.
    pub fn new(state: Arc<RwLock<crate::containers::state::State>>, store: Arc<RwLock<S>>) -> Self {
        Self { state, store }
    }

    /// Constructs a [`Status`] from the current store/state snapshot.
    ///
    /// Falls back to `latest_block_header` values when the store has no head.
    #[inline]
    fn build_status(&self) -> Status {
        static STATUS_LOGS: OnceLock<AtomicUsize> = OnceLock::new();
        let state = self.state.read().expect("state lock");
        let store = self.store.read().expect("store lock");
        let store_head = store.head();
        let (head_root, head_slot) = store
            .head()
            .and_then(|root| {
                store
                    .get_block(&root)
                    .map(|block| (root, Uint64(block.slot.0.0)))
            })
            .unwrap_or_else(|| {
                (
                    Bytes32::from(state.latest_block_header.hash_tree_root()),
                    Uint64(state.slot.0.0),
                )
            });
        let finalized_root = store.finalized().unwrap_or(state.latest_finalized.root);
        if head_slot.0 == 0 {
            let counter = STATUS_LOGS.get_or_init(|| AtomicUsize::new(0));
            if counter.fetch_add(1, Ordering::Relaxed) < 64 {
                info!(
                    store_head = ?store_head,
                    status_head_root = ?head_root,
                    status_head_slot = head_slot.0,
                    status_finalized_root = ?finalized_root,
                    status_finalized_slot = state.latest_finalized.slot.0.0,
                    state_slot = state.slot.0.0,
                    state_latest_header_slot = state.latest_block_header.slot.0.0,
                    state_latest_header_root = ?Bytes32::from(state.latest_block_header.hash_tree_root()),
                    "reqresp build_status returning genesis-like view"
                );
            }
        }
        Status {
            finalized_root,
            finalized_slot: state.latest_finalized.slot.0,
            head_root,
            head_slot,
        }
    }
}

/// [`ReqRespHandler`] implementation for [`StoreReqRespHandler`].
impl<S: Store + Send + Sync + 'static> ReqRespHandler for StoreReqRespHandler<S> {
    fn on_request(&self, request: LeanRequestMessage) -> Vec<LeanResponseMessage> {
        match request {
            LeanRequestMessage::Status(_) => vec![LeanResponseMessage::Status(self.build_status())],
            LeanRequestMessage::BlocksByRoot(req) => {
                // Return one block per response chunk, preserving request order.
                let store = self.store.read().expect("store lock");
                let mut blocks = Vec::new();
                for root in req
                    .roots
                    .data
                    .iter()
                    .take(MAX_BLOCKS_PER_ROOT_REQUEST)
                {
                    if let Some(found) = store.get_signed_block(root) {
                        blocks.push(LeanResponseMessage::BlocksByRoot(found));
                    } else {
                        // DEVNET4_REMOVE: temporary sync diagnostics.
                        debug!("reqresp blocks_by_root missing root={:?}", root);
                    }
                }
                blocks
            }
        }
    }
}
