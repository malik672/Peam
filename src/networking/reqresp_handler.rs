use std::sync::{Arc, RwLock};

use crate::containers::req_resp::{BlocksByRootResponse, Status};
use crate::ssz::HashTreeRoot;
use crate::storage::Store;
use crate::types::bytes::Bytes32;
use crate::types::collections::SszList;
use crate::types::uint::Uint64;

use super::reqresp_messages::{LeanRequestMessage, LeanResponseMessage};

const MAX_BLOCKS_BY_ROOT_RESPONSE: usize = 128;

pub trait ReqRespHandler: Send + Sync {
    fn on_request(&self, request: LeanRequestMessage) -> Option<LeanResponseMessage>;
}

pub struct NoopReqRespHandler;

impl ReqRespHandler for NoopReqRespHandler {
    fn on_request(&self, _request: LeanRequestMessage) -> Option<LeanResponseMessage> {
        None
    }
}

pub struct StoreReqRespHandler<S: Store + Send + Sync + 'static> {
    state: Arc<RwLock<crate::containers::state::State>>,
    store: Arc<RwLock<S>>,
}

impl<S: Store + Send + Sync + 'static> StoreReqRespHandler<S> {
    pub fn new(
        state: Arc<RwLock<crate::containers::state::State>>,
        store: Arc<RwLock<S>>,
    ) -> Self {
        Self { state, store }
    }

    fn build_status(&self) -> Status {
        let state = self.state.read().expect("state lock");
        Status {
            fork_digest: Bytes32::zero(),
            finalized_root: state.latest_finalized.root,
            finalized_epoch: state.latest_finalized.slot.0,
            head_root: Bytes32::from(state.latest_block_header.hash_tree_root()),
            head_slot: Uint64(state.slot.0 .0),
        }
    }
}

impl<S: Store + Send + Sync + 'static> ReqRespHandler for StoreReqRespHandler<S> {
    fn on_request(&self, request: LeanRequestMessage) -> Option<LeanResponseMessage> {
        match request {
            LeanRequestMessage::Status(_) => Some(LeanResponseMessage::Status(self.build_status())),
            LeanRequestMessage::BlocksByRoot(req) => {
                // Return up to MAX_BLOCKS_BY_ROOT_RESPONSE blocks found in the store.
                let store = self.store.read().expect("store lock");
                let mut blocks = Vec::new();
                for root in req
                    .roots
                    .data
                    .iter()
                    .take(MAX_BLOCKS_BY_ROOT_RESPONSE)
                {
                    if let Some(block) = store.get_signed_block(root) {
                        blocks.push(block);
                    }
                }
                let blocks = SszList::new(blocks).ok()?;
                Some(LeanResponseMessage::BlocksByRoot(BlocksByRootResponse { blocks }))
            }
        }
    }
}
