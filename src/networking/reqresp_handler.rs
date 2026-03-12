//! Application-level req/resp request handlers.
//!
//! [`ReqRespHandler`] is the trait that the networking layer calls for every
//! inbound request. Two implementations are provided:
//!
//! - [`NoopReqRespHandler`] — ignores all requests (useful in tests).
//! - [`StoreReqRespHandler`] — serves requests from a live [`Store`] and
//!   [`State`].

use std::sync::{Arc, RwLock};
use tracing::debug;

use crate::containers::req_resp::Status;
use crate::ssz::HashTreeRoot;
use crate::storage::Store;
use crate::types::bytes::Bytes32;
use crate::types::uint::Uint64;

use super::reqresp_messages::{LeanRequestMessage, LeanResponseMessage};

/// Maximum number of blocks returned in a single `BlocksByRoot` response.
const MAX_BLOCKS_BY_ROOT_RESPONSE: usize = 128;

/// Handles inbound req/resp requests and optionally returns a response.
///
/// Implementations must be `Send + Sync` because they are called from async
/// networking tasks.
pub trait ReqRespHandler: Send + Sync {
    /// Called for each inbound request.
    ///
    /// Returns `Some(response)` to reply, or `None` to send no response.
    fn on_request(&self, request: LeanRequestMessage) -> Option<LeanResponseMessage>;
}

/// A [`ReqRespHandler`] that ignores every request.
///
/// Useful in tests or when req/resp responses are not required.
pub struct NoopReqRespHandler;

/// [`ReqRespHandler`] impl — always returns `None`.
impl ReqRespHandler for NoopReqRespHandler {
    fn on_request(&self, _request: LeanRequestMessage) -> Option<LeanResponseMessage> {
        None
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
        let state = self.state.read().expect("state lock");
        let store = self.store.read().expect("store lock");
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
        Status {
            fork_digest: Bytes32::zero(),
            finalized_root,
            finalized_epoch: state.latest_finalized.slot.0,
            head_root,
            head_slot,
        }
    }
}

/// [`ReqRespHandler`] implementation for [`StoreReqRespHandler`].
impl<S: Store + Send + Sync + 'static> ReqRespHandler for StoreReqRespHandler<S> {
    fn on_request(&self, request: LeanRequestMessage) -> Option<LeanResponseMessage> {
        match request {
            LeanRequestMessage::Status(_) => Some(LeanResponseMessage::Status(self.build_status())),
            LeanRequestMessage::BlocksByRoot(req) => {
                // Interop compatibility: return at most one block per response chunk.
                // SignedBlockWithAttestation, not a wrapped list.
                let store = self.store.read().expect("store lock");
                let mut block = None;
                for root in req.roots.data.iter().take(MAX_BLOCKS_BY_ROOT_RESPONSE) {
                    if let Some(found) = store.get_signed_block(root) {
                        block = Some(found);
                        break;
                    } else {
                        // DEVNET4_REMOVE: temporary sync diagnostics.
                        debug!("reqresp blocks_by_root missing root={:?}", root);
                    }
                }
                block.map(LeanResponseMessage::BlocksByRoot)
            }
        }
    }
}
