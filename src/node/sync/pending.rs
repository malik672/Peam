use std::time::Instant;

use peam_consensus_types::containers::block::SignedBlockWithAttestation;
use peam_consensus_types::types::bytes::Bytes32;

#[derive(Default)]
pub(super) struct PendingBackfill {
    pub active_peer: Option<String>,
    pub pending_roots: Vec<Bytes32>,
    pub pending_range_start_slot: Option<u64>,
    pub pending_range_count: Option<u64>,
    pub pending_since: Option<Instant>,
    pub fetched_chain_newest_to_oldest: Vec<SignedBlockWithAttestation>,
}

impl PendingBackfill {
    #[inline]
    pub fn reset(&mut self) {
        self.active_peer = None;
        self.pending_roots.clear();
        self.pending_range_start_slot = None;
        self.pending_range_count = None;
        self.pending_since = None;
        self.fetched_chain_newest_to_oldest.clear();
    }

    #[inline]
    pub fn set_target(&mut self, peer_id: String, root: Bytes32) {
        self.active_peer = Some(peer_id);
        self.pending_roots.clear();
        self.pending_roots.push(root);
        self.pending_since = Some(Instant::now());
        self.fetched_chain_newest_to_oldest.clear();
    }

    #[inline]
    pub fn set_pending_roots(&mut self, peer_id: String, roots: Vec<Bytes32>) {
        self.active_peer = Some(peer_id);
        self.pending_roots = roots;
        self.pending_since = Some(Instant::now());
    }
}
