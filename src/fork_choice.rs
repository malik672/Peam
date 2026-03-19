use rapidhash::RapidHashMap;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::containers::attestation::Attestation;
use crate::containers::block::SignedBlockWithAttestation;
use crate::containers::checkpoint::Checkpoint;
use crate::containers::state::State;
use crate::slot::Slot;
use crate::ssz::HashTreeRoot;
use crate::types::bitlist::BitList;
use crate::types::bytes::Bytes32;
use crate::types::uint::Uint64;

const JUSTIFICATION_LOOKBACK_SLOTS: u64 = 3;

/// The store is initialized from an anchor block and its post-state (typically the genesis
/// block or a finalized checkpoint), then updated incrementally as blocks and attestations
/// arrive. The canonical head is the leaf at the tip of the heaviest subtree rooted at
/// `latest_justified`.
///
/// # Invariants
///
/// - `head` always points to a root present in `blocks`.
/// - Every root in `blocks` has a corresponding entry in `states` and `parents`.
/// - `children[parent]` contains `root` iff `parents[root] == parent`.
/// - `latest_justified` and `latest_finalized` reflect the post-state of the most
///   recently imported block.
#[derive(Debug, Clone)]
pub struct ForkChoiceStore {
    /// Root of the current canonical head block.
    head: Bytes32,
    /// Root considered safe for target selection.
    safe_target: Bytes32,
    /// Slot number of the current canonical head block.
    head_slot: u64,
    /// Most recently seen justified checkpoint (updated on every `on_block`).
    latest_justified: Checkpoint,
    /// Previously seen justified checkpoint (set to old `latest_justified` on change).
    previous_justified: Checkpoint,
    /// Most recently seen finalized checkpoint (updated on every `on_block`).
    latest_finalized: Checkpoint,
    /// Total number of chain reorganizations detected.
    reorgs_total: u64,
    /// Number of validators in the active registry.
    validator_count: usize,
    /// All imported blocks keyed by block root.
    blocks: RapidHashMap<Bytes32, SignedBlockWithAttestation>,
    /// Post-execution states keyed by the block root that produced them.
    states: RapidHashMap<Bytes32, State>,
    /// Maps each block root to its parent root.
    parents: RapidHashMap<Bytes32, Bytes32>,
    /// Maps each block root to its direct children roots.
    children: RapidHashMap<Bytes32, Vec<Bytes32>>,
    /// Latest vote target per validator index (validator_id → block root).
    latest_votes: RapidHashMap<usize, Bytes32>,
    /// Newly received votes that are not yet active for fork choice.
    latest_new_votes: RapidHashMap<usize, Bytes32>,
}

#[derive(Debug, Clone, Copy)]
pub struct ForkChoiceNodeSnapshot {
    pub root: Bytes32,
    pub slot: u64,
    pub parent_root: Bytes32,
    pub proposer_index: u64,
    pub weight: usize,
}

impl ForkChoiceStore {
    /// Initialize from an anchor block + post-state.
    ///
    /// `State::state_transition` verifies `hash_tree_root(post_state_with_staged_header) ==
    /// block.state_root`, then writes `latest_block_header.state_root = block.state_root`.
    /// So the stable invariant available here is the header field equality, not
    /// `hash_tree_root(anchor_state) == block.state_root`.
    pub fn new(
        anchor_block: SignedBlockWithAttestation,
        anchor_state: State,
    ) -> Result<Self, String> {
        let block = anchor_block.message.block.clone();
        if !state_matches_block_root(&anchor_state, block.state_root) {
            return Err("anchor block state root does not match post-state invariants".to_string());
        }
        let root = Bytes32::from(block.hash_tree_root());
        let slot = block.slot.0.0;
        let mut blocks = RapidHashMap::default();
        let mut states = RapidHashMap::default();
        let mut parents = RapidHashMap::default();
        let mut children: RapidHashMap<Bytes32, Vec<Bytes32>> = RapidHashMap::default();
        blocks.insert(root, anchor_block);
        states.insert(root, anchor_state.clone());
        parents.insert(root, block.parent_root);
        children.entry(block.parent_root).or_default().push(root);
        let mut store = Self {
            head: root,
            safe_target: root,
            head_slot: slot,
            latest_justified: anchor_state.latest_justified,
            previous_justified: anchor_state.latest_justified,
            latest_finalized: anchor_state.latest_finalized,
            reorgs_total: 0,
            validator_count: anchor_state.validators.data.len(),
            blocks,
            states,
            parents,
            children,
            latest_votes: RapidHashMap::default(),
            latest_new_votes: RapidHashMap::default(),
        };
        // Align checkpoints with the anchor block (leanSpec behavior).
        store.override_checkpoint_roots(root);
        Ok(store)
    }

    /// Import a new block and its post-state into the store.
    ///
    /// Inserts the block and state into their respective maps, links the parent/child
    /// relationship, updates `latest_justified` and `latest_finalized` from the post-state,
    /// then re-runs `find_head`. If `find_head` returns a known block root, head and
    /// head_slot are updated from that block; otherwise head falls back to the new block
    /// if it is at a higher slot than the current head.
    ///
    /// Returns `Err` if the post-state root does not satisfy the block's state_root field.
    #[inline]
    pub fn on_block(
        &mut self,
        signed_block: SignedBlockWithAttestation,
        post_state: State,
    ) -> Result<(), String> {
        let block = signed_block.message.block.clone();
        let proposer_attestation = signed_block.message.proposer_attestation.clone();
        if !state_matches_block_root(&post_state, block.state_root) {
            return Err("post-state root does not match block.state_root invariants".to_string());
        }
        let root = Bytes32::from(block.hash_tree_root());
        let slot = block.slot.0.0;
        self.blocks.insert(root, signed_block);
        self.states.insert(root, post_state.clone());
        self.parents.insert(root, block.parent_root);
        self.children
            .entry(block.parent_root)
            .or_default()
            .push(root);

        // Block-included attestations are already verified in block processing,
        // so they become immediately active votes.
        for att in block.body.attestations.data.iter() {
            apply_vote_to(&self.blocks, &mut self.latest_votes, att);
        }
        apply_vote_to(&self.blocks, &mut self.latest_votes, &proposer_attestation);
        // Keep checkpoint progression monotonic even when importing side branches.
        // This prevents sync/backfill replay from regressing fork-choice checkpoints.
        if post_state.latest_justified.slot > self.latest_justified.slot {
            self.previous_justified = self.latest_justified;
            self.latest_justified = post_state.latest_justified;
        }
        if post_state.latest_finalized.slot > self.latest_finalized.slot {
            self.latest_finalized = post_state.latest_finalized;
        }
        let old_head = self.head;
        let head = self.find_head();
        if let Some(head_block) = self.blocks.get(&head) {
            self.head = head;
            self.head_slot = head_block.message.block.slot.0.0;
        } else if slot > self.head_slot {
            self.head = root;
            self.head_slot = slot;
        }
        if self.head_change_is_reorg(old_head, self.head) {
            self.reorgs_total += 1;
        }
        self.refresh_safe_target();
        Ok(())
    }

    /// Buffer an aggregated attestation as a new vote (not yet active).
    ///
    /// Records the latest vote for each attesting validator (identified by set bits in
    /// `aggregation_bits`) as a vote for `attestation.data.target.root`. Attestations
    /// whose target root is not yet known to the store are silently ignored (equivocation
    /// protection: we only count votes for blocks we have already validated).
    pub fn on_attestation(&mut self, attestation: &Attestation) -> bool {
        apply_vote_to(&self.blocks, &mut self.latest_new_votes, attestation)
    }

    /// Promote newly received votes into active fork-choice votes.
    #[inline]
    pub fn accept_new_votes(&mut self) {
        if self.latest_new_votes.is_empty() {
            return;
        }
        let pending = std::mem::take(&mut self.latest_new_votes);
        for (validator_id, root) in pending {
            self.latest_votes.insert(validator_id, root);
        }
        let old_head = self.head;
        let head = self.find_head();
        if let Some(head_block) = self.blocks.get(&head) {
            self.head = head;
            self.head_slot = head_block.message.block.slot.0.0;
        }
        if self.head_change_is_reorg(old_head, self.head) {
            self.reorgs_total += 1;
        }
        self.refresh_safe_target();
    }

    /// Recompute safe target from currently active votes.
    #[inline]
    pub fn update_safe_target(&mut self) {
        self.refresh_safe_target();
    }

    /// Apply pending attestations, then return a fresh proposal parent root.
    #[inline]
    pub fn get_proposal_head_with_pending<'a, I>(&mut self, pending_votes: I) -> Bytes32
    where
        I: IntoIterator<Item = &'a Attestation>,
    {
        for attestation in pending_votes {
            let _ = apply_vote_to(&self.blocks, &mut self.latest_new_votes, attestation);
        }
        self.accept_new_votes();
        self.get_proposal_head()
    }

    /// Return a fresh proposal parent root from currently applied votes.
    #[inline]
    pub fn get_proposal_head(&mut self) -> Bytes32 {
        self.accept_new_votes();
        let head = self.find_head();
        if let Some(head_block) = self.blocks.get(&head) {
            self.head = head;
            self.head_slot = head_block.message.block.slot.0.0;
        }
        self.head
    }

    /// Walk the tree from `latest_justified` toward the leaves, picking the heaviest child
    /// at each step (tie-broken by lexicographically smaller block root).
    ///
    /// Returns the current `self.head` unchanged if the justified root is not in the store.
    #[inline]
    fn find_head(&self) -> Bytes32 {
        let start = self.latest_justified.root;
        if !self.blocks.contains_key(&start) {
            return self.head;
        }
        let mut current = start;
        loop {
            let Some(children) = self.children.get(&current) else {
                return current;
            };
            if children.is_empty() {
                return current;
            }
            let mut best = children[0];
            let mut best_weight = self.subtree_weight(best);
            for child in children.iter().skip(1) {
                let weight = self.subtree_weight(*child);
                if weight > best_weight
                    || (weight == best_weight && child.as_array() < best.as_array())
                {
                    best = *child;
                    best_weight = weight;
                }
            }
            current = best;
        }
    }

    #[inline]
    fn refresh_safe_target(&mut self) {
        if self.validator_count == 0 {
            self.safe_target = self.head;
            return;
        }
        let finalized_root = self.latest_finalized.root;
        let anchor_root = if self.blocks.contains_key(&finalized_root) {
            finalized_root
        } else if self.blocks.contains_key(&self.latest_justified.root) {
            self.latest_justified.root
        } else {
            self.head
        };
        let mut best_root = anchor_root;
        let mut best_slot = self
            .blocks
            .get(&best_root)
            .map(|block| block.message.block.slot.0.0)
            .unwrap_or(self.head_slot);

        for (root, block) in &self.blocks {
            if !self.is_descendant(*root, anchor_root) {
                continue;
            }
            let vote_weight = self.subtree_weight(*root);
            if 3 * vote_weight < 2 * self.validator_count {
                continue;
            }
            let slot = block.message.block.slot.0.0;
            if slot > best_slot || (slot == best_slot && root.as_array() < best_root.as_array()) {
                best_root = *root;
                best_slot = slot;
            }
        }
        self.safe_target = best_root;
    }

    #[inline]
    fn subtree_weight(&self, root: Bytes32) -> usize {
        let mut weight = 0usize;
        for vote in self.latest_votes.values() {
            if self.is_descendant(*vote, root) {
                weight += 1;
            }
        }
        weight
    }

    #[inline]
    fn is_descendant(&self, mut node: Bytes32, ancestor: Bytes32) -> bool {
        if node == ancestor {
            return true;
        }
        while let Some(parent) = self.parents.get(&node) {
            if *parent == ancestor {
                return true;
            }
            if *parent == Bytes32::zero() {
                break;
            }
            node = *parent;
        }
        false
    }

    #[inline]
    pub fn head(&self) -> Bytes32 {
        self.head
    }

    #[inline]
    pub fn latest_justified(&self) -> Checkpoint {
        self.latest_justified
    }

    #[inline]
    pub fn latest_finalized(&self) -> Checkpoint {
        self.latest_finalized
    }

    /// Override checkpoint roots to the given anchor root.
    ///
    /// Used for checkpoint sync initialization to match leanSpec behavior.
    #[inline]
    pub fn override_checkpoint_roots(&mut self, anchor_root: Bytes32) {
        self.latest_justified.root = anchor_root;
        self.latest_finalized.root = anchor_root;
        self.previous_justified.root = anchor_root;
        self.safe_target = anchor_root;
        self.head = anchor_root;
        if let Some(block) = self.blocks.get(&anchor_root) {
            self.head_slot = block.message.block.slot.0.0;
        }
    }

    #[inline]
    pub fn safe_target(&self) -> Bytes32 {
        self.safe_target
    }

    #[inline]
    pub fn head_slot(&self) -> u64 {
        self.head_slot
    }

    #[inline]
    pub fn previous_justified(&self) -> Checkpoint {
        self.previous_justified
    }

    #[inline]
    pub fn reorgs_total(&self) -> u64 {
        self.reorgs_total
    }

    #[inline]
    pub fn validator_count(&self) -> usize {
        self.validator_count
    }

    #[inline]
    pub fn head_validator_count(&self) -> usize {
        self.states
            .get(&self.head)
            .map(|state| state.validators.data.len())
            .unwrap_or(0)
    }

    #[inline]
    pub fn safe_target_slot(&self) -> u64 {
        self.blocks
            .get(&self.safe_target)
            .map(|b| b.message.block.slot.0.0)
            .unwrap_or(self.head_slot)
    }

    #[inline]
    pub fn gossip_signatures_count(&self) -> usize {
        self.latest_new_votes.len()
    }

    #[inline]
    pub fn latest_votes_count(&self) -> usize {
        self.latest_votes.len()
    }

    #[inline]
    pub fn node_snapshots(&self) -> Vec<ForkChoiceNodeSnapshot> {
        let mut nodes = Vec::with_capacity(self.blocks.len());
        for (root, block) in &self.blocks {
            let slot = block.message.block.slot.0.0;
            let parent_root = block.message.block.parent_root;
            let proposer_index = block.message.block.proposer_index.0.0;
            let weight = self.subtree_weight(*root);
            nodes.push(ForkChoiceNodeSnapshot {
                root: *root,
                slot,
                parent_root,
                proposer_index,
                weight,
            });
        }
        nodes.sort_by(|a, b| {
            a.slot
                .cmp(&b.slot)
                .then_with(|| a.root.as_array().cmp(&b.root.as_array()))
        });
        nodes
    }

    /// Returns a `(root, slot)` checkpoint for `root` if the block exists in the store.
    #[inline]
    pub fn checkpoint_for_root(&self, root: Bytes32) -> Option<Checkpoint> {
        let block = self.blocks.get(&root)?;
        Some(Checkpoint {
            root,
            slot: Slot(Uint64(block.message.block.slot.0.0)),
        })
    }

    /// Computes an attestation target checkpoint from the current head/safe-target view.
    ///
    /// Mirrors the Ream devnet-2 strategy:
    /// - start from head,
    /// - walk back at most `JUSTIFICATION_LOOKBACK_SLOTS` while above safe-target slot,
    /// - then walk back until slot is justifiable after `finalized_slot`.
    #[inline]
    pub fn attestation_target(&self, finalized_slot: Slot) -> Option<Checkpoint> {
        let mut target_root = self.head;
        let safe_slot = self
            .blocks
            .get(&self.safe_target)
            .map(|b| b.message.block.slot.0.0)
            .unwrap_or(self.head_slot);

        for _ in 0..JUSTIFICATION_LOOKBACK_SLOTS {
            let target_slot = self.blocks.get(&target_root)?.message.block.slot.0.0;
            if target_slot <= safe_slot {
                break;
            }
            let parent = *self.parents.get(&target_root)?;
            if parent == Bytes32::zero() {
                break;
            }
            target_root = parent;
        }

        loop {
            let target_slot = self.blocks.get(&target_root)?.message.block.slot.0.0;
            let target = Slot(Uint64(target_slot));
            match crate::slot::is_justifiable_after(target, finalized_slot) {
                Ok(true) => break,
                Ok(false) => {
                    let parent = *self.parents.get(&target_root)?;
                    if parent == Bytes32::zero() {
                        break;
                    }
                    target_root = parent;
                }
                Err(_) => return None,
            }
        }

        let target = self.checkpoint_for_root(target_root)?;
        if target.slot < self.latest_justified.slot {
            return Some(self.latest_justified);
        }
        Some(target)
    }

    /// Walk from `old_head` and `new_head` to their common ancestor and return
    /// the depth of the reorg (distance from old head to common ancestor).
    pub fn reorg_depth(&self, old_head: Bytes32, new_head: Bytes32) -> u64 {
        let mut ancestors_of_new: std::collections::HashSet<Bytes32> =
            std::collections::HashSet::new();
        let mut node = new_head;
        ancestors_of_new.insert(node);
        loop {
            match self.parents.get(&node) {
                Some(parent) if *parent != Bytes32::zero() => {
                    ancestors_of_new.insert(*parent);
                    node = *parent;
                }
                _ => break,
            }
        }
        let mut depth = 0u64;
        node = old_head;
        while !ancestors_of_new.contains(&node) {
            match self.parents.get(&node) {
                Some(parent) if *parent != Bytes32::zero() => {
                    depth += 1;
                    node = *parent;
                }
                _ => break,
            }
        }
        depth
    }

    #[inline]
    fn head_change_is_reorg(&self, old_head: Bytes32, new_head: Bytes32) -> bool {
        if old_head == new_head {
            return false;
        }
        let mut node = new_head;
        loop {
            if node == old_head {
                return false;
            }
            match self.parents.get(&node) {
                Some(parent) if *parent != Bytes32::zero() => node = *parent,
                _ => return true,
            }
        }
    }

}

#[inline]
fn state_matches_block_root(state: &State, expected: Bytes32) -> bool {
    state.latest_block_header.state_root == expected
        || Bytes32::from(state.hash_tree_root()) == expected
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
fn log_vote_drop_unknown_head_sample(attestation: &Attestation) {
    if !attestation_trace_enabled() {
        return;
    }
    static LOGGED: AtomicUsize = AtomicUsize::new(0);
    if LOGGED.fetch_add(1, Ordering::Relaxed) >= 256 {
        return;
    }
    let data = &attestation.data;
    tracing::info!(
        att_slot = data.slot.0.0,
        head_slot = data.head.slot.0.0,
        source_slot = data.source.slot.0.0,
        target_slot = data.target.slot.0.0,
        head_root = ?data.head.root,
        source_root = ?data.source.root,
        target_root = ?data.target.root,
        participants_len_bits = attestation.aggregation_bits.len(),
        "fork choice dropped attestation vote: unknown head root"
    );
}

#[inline]
fn apply_vote_to(
    blocks: &RapidHashMap<Bytes32, SignedBlockWithAttestation>,
    votes: &mut RapidHashMap<usize, Bytes32>,
    attestation: &Attestation,
) -> bool {
    let Some(vote_root) = resolve_vote_root(blocks, attestation) else {
        log_vote_drop_unknown_head_sample(attestation);
        return false;
    };
    for validator_id in bitlist_indices(&attestation.aggregation_bits) {
        votes.insert(validator_id, vote_root);
    }
    true
}

#[inline]
fn resolve_vote_root(
    blocks: &RapidHashMap<Bytes32, SignedBlockWithAttestation>,
    attestation: &Attestation,
) -> Option<Bytes32> {
    let head_root = attestation.data.head.root;
    blocks.contains_key(&head_root).then_some(head_root)
}

#[inline]
fn bitlist_indices<const LIMIT: usize>(bits: &BitList<LIMIT>) -> Vec<usize> {
    let mut out = Vec::new();
    let len = bits.len();
    for i in 0..len {
        let byte = i / 8;
        let bit = i % 8;
        if byte >= bits.data.len() {
            break;
        }
        if (bits.data[byte] & (1u8 << bit)) != 0 {
            out.push(i);
        }
    }
    out
}
