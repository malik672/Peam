use std::time::Instant;

use crate::containers::block::SignedBlockWithAttestation;
use crate::types::bytes::Bytes32;

#[derive(Default)]
pub(super) struct PendingBackfill {
    pub active_peer: Option<String>,
    pub pending_root: Option<Bytes32>,
    pub pending_since: Option<Instant>,
    pub fetched_chain_newest_to_oldest: Vec<SignedBlockWithAttestation>,
}

impl PendingBackfill {
    #[inline]
    pub fn reset(&mut self) {
        self.active_peer = None;
        self.pending_root = None;
        self.pending_since = None;
        self.fetched_chain_newest_to_oldest.clear();
    }

    #[inline]
    pub fn set_target(&mut self, peer_id: String, root: Bytes32) {
        self.active_peer = Some(peer_id);
        self.pending_root = Some(root);
        self.pending_since = Some(Instant::now());
        self.fetched_chain_newest_to_oldest.clear();
    }
}
