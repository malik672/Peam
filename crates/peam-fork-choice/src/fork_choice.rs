use peam_consensus_types::containers::attestation::{
    Attestation, AttestationData, VALIDATOR_REGISTRY_LIMIT,
};
use peam_consensus_types::containers::block::{
    Block, BlockSignatures, BlockWithAttestation, SignedBlockWithAttestation,
    proposer_attestation_present,
};
use peam_consensus_types::containers::checkpoint::Checkpoint;
use peam_consensus_types::slot::{Slot, is_justifiable_after};
use peam_consensus_types::types::bitlist::BitList;
use peam_consensus_types::types::bytes::{Bytes32, Bytes3112};
use peam_consensus_types::types::collections::SszList;
use peam_consensus_types::types::uint::Uint64;
use peam_ssz::ssz::HashTreeRoot;
use peam_state::state::State;
use rapidhash::{RapidHashMap, RapidHashSet};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::logfmt::{short_checkpoint, short_slot_root};

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
    /// Arena-backed fork-choice nodes keyed by insertion order.
    nodes: Vec<ProtoNode>,
    /// Maps each known block root to its node index in `nodes`.
    node_indices: RapidHashMap<Bytes32, usize>,
    /// Latest vote target per validator index (validator_id → block root).
    latest_votes: RapidHashMap<usize, Bytes32>,
    /// Newly received votes that are not yet active for fork choice.
    latest_new_votes: RapidHashMap<usize, Bytes32>,
}

#[derive(Debug, Clone)]
struct ProtoNode {
    root: Bytes32,
    parent: Option<usize>,
    children: Vec<usize>,
    slot: u64,
    proposer_index: u64,
    /// Aggregate subtree vote weight from active validator votes.
    weight: i64,
    /// Heaviest direct child, tie-broken by higher slot, then lexicographically smaller root.
    best_child: Option<usize>,
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
        let nodes = vec![ProtoNode {
            root,
            parent: None,
            children: Vec::new(),
            slot,
            proposer_index: block.proposer_index.0.0,
            weight: 0,
            best_child: None,
        }];
        let mut node_indices = RapidHashMap::default();
        node_indices.insert(root, 0);
        let mut store = Self {
            head: root,
            safe_target: root,
            head_slot: slot,
            latest_justified: anchor_state.latest_justified,
            previous_justified: anchor_state.latest_justified,
            latest_finalized: anchor_state.latest_finalized,
            reorgs_total: 0,
            validator_count: anchor_state.validators.len(),
            blocks,
            states,
            parents,
            children,
            nodes,
            node_indices,
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
        self.import_block_internal(signed_block, post_state, true)
    }

    /// Preview the proposer-attestation data that should be derived from the
    /// post-import fork-choice view of `block`, without applying the proposer's
    /// own vote to that preview.
    pub fn preview_proposer_attestation_data(
        &self,
        block: Block,
        post_state: State,
    ) -> Result<AttestationData, String> {
        let block_root = Bytes32::from(block.hash_tree_root());
        let block_slot = block.slot;
        let mut preview = self.clone();
        let preview_signed = placeholder_signed_block(block)?;
        preview.import_block_internal(preview_signed, post_state, false)?;

        let source = preview.latest_justified;
        let mut target = preview
            .attestation_target(preview.latest_finalized.slot)
            .unwrap_or(source);
        if target.slot < source.slot {
            target = source;
        }
        if target.slot > block_slot {
            target = Checkpoint {
                root: block_root,
                slot: block_slot,
            };
        }
        let head = preview
            .checkpoint_for_root(preview.head())
            .unwrap_or(Checkpoint {
                root: block_root,
                slot: block_slot,
            });

        Ok(AttestationData {
            slot: block_slot,
            head,
            target,
            source,
        })
    }

    #[inline]
    fn import_block_internal(
        &mut self,
        signed_block: SignedBlockWithAttestation,
        post_state: State,
        include_proposer_attestation: bool,
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
        self.insert_proto_node(root, block.parent_root, slot, block.proposer_index.0.0);

        // Block-included attestations are already verified in block processing,
        // so they become immediately active votes.
        for att in block.body.attestations.iter() {
            let _ = self.apply_attestation_votes(att, VoteDisposition::Active);
        }
        if include_proposer_attestation && proposer_attestation_present(&proposer_attestation) {
            let _ = self.apply_attestation_votes(&proposer_attestation, VoteDisposition::Active);
        }
        // Keep checkpoint progression monotonic even when importing side branches.
        // This prevents sync/backfill replay from regressing fork-choice checkpoints.
        if post_state.latest_justified.slot > self.latest_justified.slot {
            self.previous_justified = self.latest_justified;
            self.latest_justified = post_state.latest_justified;
        }
        let finalized_advanced = post_state.latest_finalized.slot > self.latest_finalized.slot;
        if finalized_advanced {
            self.latest_finalized = post_state.latest_finalized;
        }
        if finalized_advanced {
            let pruned = self.prune_finalized_history();
            if pruned > 0 {
                tracing::debug!(
                    finalized_root = ?self.latest_finalized.root,
                    finalized_slot = self.latest_finalized.slot.0.0,
                    pruned_blocks = pruned,
                    retained_blocks = self.blocks.len(),
                    "fork choice pruned finalized history"
                );
            }
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
        self.refresh_safe_target();
        self.record_head_change(old_head, "block_import");
        if finalized_advanced {
            self.log_finality_table("block_import");
        }
        Ok(())
    }

    /// Buffer an aggregated attestation as a new vote (not yet active).
    ///
    /// Records the latest vote for each attesting validator (identified by set bits in
    /// `aggregation_bits`) as a vote for `attestation.data.target.root`. Attestations
    /// whose target root is not yet known to the store are silently ignored (equivocation
    /// protection: we only count votes for blocks we have already validated).
    pub fn on_attestation(&mut self, attestation: &Attestation) -> bool {
        self.apply_attestation_votes(attestation, VoteDisposition::Pending)
    }

    /// Promote newly received votes into active fork-choice votes.
    #[inline]
    pub fn accept_new_votes(&mut self) {
        if self.latest_new_votes.is_empty() {
            return;
        }
        let pending = std::mem::take(&mut self.latest_new_votes);
        for (validator_id, root) in pending {
            self.set_latest_vote(validator_id, root);
        }
        let old_head = self.head;
        let head = self.find_head();
        if let Some(head_block) = self.blocks.get(&head) {
            self.head = head;
            self.head_slot = head_block.message.block.slot.0.0;
        }
        self.refresh_safe_target();
        self.record_head_change(old_head, "attestation_votes");
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
            let _ = self.apply_attestation_votes(attestation, VoteDisposition::Pending);
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
    /// at each step (tie-broken by higher slot, then lexicographically smaller block root).
    ///
    /// Returns the current `self.head` unchanged if the justified root is not in the store.
    #[inline]
    fn find_head(&self) -> Bytes32 {
        let start = self.latest_justified.root;
        let Some(&start_idx) = self.node_indices.get(&start) else {
            return self.head;
        };
        let mut current = start_idx;
        while let Some(best_child) = self.nodes[current].best_child {
            current = best_child;
        }
        self.nodes[current].root
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
        self.node_indices
            .get(&root)
            .and_then(|idx| self.nodes.get(*idx))
            .map(|node| node.weight.max(0) as usize)
            .unwrap_or(0)
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
            .map(|state| state.validators.len())
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
        let mut snapshots = Vec::with_capacity(self.nodes.len());
        for node in &self.nodes {
            let parent_root = self
                .parents
                .get(&node.root)
                .copied()
                .unwrap_or(Bytes32::zero());
            snapshots.push(ForkChoiceNodeSnapshot {
                root: node.root,
                slot: node.slot,
                parent_root,
                proposer_index: node.proposer_index,
                weight: node.weight.max(0) as usize,
            });
        }
        snapshots.sort_by(|a, b| {
            a.slot
                .cmp(&b.slot)
                .then_with(|| a.root.as_array().cmp(&b.root.as_array()))
        });
        snapshots
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
            match is_justifiable_after(target, finalized_slot) {
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
    fn record_head_change(&mut self, old_head: Bytes32, trigger: &'static str) {
        if old_head == self.head {
            return;
        }

        let old_slot = self
            .blocks
            .get(&old_head)
            .map(|block| block.message.block.slot.0.0)
            .unwrap_or(0);
        let new_slot = self.head_slot;
        if self.head_change_is_reorg(old_head, self.head) {
            let depth = self.reorg_depth(old_head, self.head);
            self.reorgs_total += 1;
            tracing::info!(
                "Fork choice reorg detected ({trigger}): {} -> {} | depth={} | safe={} | justified={} | finalized={} | total_reorgs={}",
                short_slot_root(old_slot, &old_head),
                short_slot_root(new_slot, &self.head),
                depth,
                short_slot_root(self.safe_target_slot(), &self.safe_target),
                short_checkpoint(&self.latest_justified),
                short_checkpoint(&self.latest_finalized),
                self.reorgs_total,
            );
        }

        tracing::info!(
            "Fork choice head updated ({trigger}): {} -> {} | safe={} | justified={} | prev_justified={} | finalized={}",
            short_slot_root(old_slot, &old_head),
            short_slot_root(new_slot, &self.head),
            short_slot_root(self.safe_target_slot(), &self.safe_target),
            short_checkpoint(&self.latest_justified),
            short_checkpoint(&self.previous_justified),
            short_checkpoint(&self.latest_finalized),
        );
    }

    #[inline]
    fn log_finality_table(&self, trigger: &'static str) {
        let table = format!(
            concat!(
                "\n+--------------------+-----------------+\n",
                "| Checkpoint         | Slot:Root       |\n",
                "+--------------------+-----------------+\n",
                "| Head               | {:<15} |\n",
                "| Safe Target        | {:<15} |\n",
                "| Justified          | {:<15} |\n",
                "| Previous Justified | {:<15} |\n",
                "| Finalized          | {:<15} |\n",
                "+--------------------+-----------------+\n",
                "| Reorgs Total       | {:<15} |\n",
                "+--------------------+-----------------+"
            ),
            short_slot_root(self.head_slot, &self.head),
            short_slot_root(self.safe_target_slot(), &self.safe_target),
            short_checkpoint(&self.latest_justified),
            short_checkpoint(&self.previous_justified),
            short_checkpoint(&self.latest_finalized),
            self.reorgs_total,
        );
        tracing::info!("Fork choice finality advanced ({trigger}){table}");
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

    #[inline]
    fn insert_proto_node(
        &mut self,
        root: Bytes32,
        parent_root: Bytes32,
        slot: u64,
        proposer_index: u64,
    ) {
        if self.node_indices.contains_key(&root) {
            return;
        }
        let node_idx = self.nodes.len();
        self.nodes.push(ProtoNode {
            root,
            parent: None,
            children: Vec::new(),
            slot,
            proposer_index,
            weight: 0,
            best_child: None,
        });
        self.node_indices.insert(root, node_idx);

        if let Some(&parent_idx) = self.node_indices.get(&parent_root) {
            self.attach_child(parent_idx, node_idx);
        }
        self.attach_known_children(root, node_idx);
    }

    #[inline]
    fn attach_known_children(&mut self, parent_root: Bytes32, parent_idx: usize) {
        let Some(child_roots) = self.children.get(&parent_root).cloned() else {
            return;
        };
        for child_root in child_roots {
            if child_root == parent_root {
                continue;
            }
            let Some(&child_idx) = self.node_indices.get(&child_root) else {
                continue;
            };
            self.attach_child(parent_idx, child_idx);
        }
    }

    #[inline]
    fn attach_child(&mut self, parent_idx: usize, child_idx: usize) {
        if self.nodes[child_idx].parent == Some(parent_idx) {
            return;
        }
        if self.nodes[child_idx].parent.is_some() {
            return;
        }
        self.nodes[child_idx].parent = Some(parent_idx);
        if !self.nodes[parent_idx].children.contains(&child_idx) {
            self.nodes[parent_idx].children.push(child_idx);
        }
        self.recompute_best_child(parent_idx);
        let child_weight = self.nodes[child_idx].weight;
        if child_weight != 0 {
            self.propagate_weight_from_index(parent_idx, child_weight);
        }
    }

    #[inline]
    fn recompute_best_child(&mut self, parent_idx: usize) {
        let child_indices = self.nodes[parent_idx].children.clone();
        let mut best_child = None;
        for child_idx in child_indices {
            best_child = match best_child {
                Some(current_best) if !self.child_is_better(child_idx, current_best) => {
                    Some(current_best)
                }
                _ => Some(child_idx),
            };
        }
        self.nodes[parent_idx].best_child = best_child;
    }

    #[inline]
    fn child_is_better(&self, candidate_idx: usize, incumbent_idx: usize) -> bool {
        let candidate = &self.nodes[candidate_idx];
        let incumbent = &self.nodes[incumbent_idx];
        candidate.weight > incumbent.weight
            || (candidate.weight == incumbent.weight
                && (candidate.slot > incumbent.slot
                    || (candidate.slot == incumbent.slot
                        && candidate.root.as_array() < incumbent.root.as_array())))
    }

    #[inline]
    fn propagate_weight_from_index(&mut self, start_idx: usize, delta: i64) {
        let mut current = Some(start_idx);
        while let Some(idx) = current {
            self.nodes[idx].weight += delta;
            debug_assert!(self.nodes[idx].weight >= 0);
            let parent = self.nodes[idx].parent;
            if let Some(parent_idx) = parent {
                self.recompute_best_child(parent_idx);
            }
            current = parent;
        }
    }

    #[inline]
    fn set_latest_vote(&mut self, validator_id: usize, root: Bytes32) {
        let previous = self.latest_votes.insert(validator_id, root);
        if previous == Some(root) {
            return;
        }
        if let Some(old_root) = previous {
            self.apply_vote_delta(old_root, -1);
        }
        self.apply_vote_delta(root, 1);
    }

    #[inline]
    fn apply_vote_delta(&mut self, root: Bytes32, delta: i64) {
        let Some(&node_idx) = self.node_indices.get(&root) else {
            return;
        };
        self.propagate_weight_from_index(node_idx, delta);
    }

    #[inline]
    fn apply_attestation_votes(
        &mut self,
        attestation: &Attestation,
        disposition: VoteDisposition,
    ) -> bool {
        let Some(vote_root) = resolve_vote_root(&self.blocks, attestation) else {
            log_vote_drop_unknown_head_sample(attestation);
            return false;
        };
        for validator_id in bitlist_indices(&attestation.aggregation_bits) {
            match disposition {
                VoteDisposition::Active => self.set_latest_vote(validator_id, vote_root),
                VoteDisposition::Pending => {
                    self.latest_new_votes.insert(validator_id, vote_root);
                }
            }
        }
        true
    }

    fn prune_finalized_history(&mut self) -> usize {
        let finalized_root = self.latest_finalized.root;
        if finalized_root == Bytes32::zero() || !self.blocks.contains_key(&finalized_root) {
            return 0;
        }

        let old_blocks = std::mem::take(&mut self.blocks);
        let old_states = std::mem::take(&mut self.states);
        let old_parents = std::mem::take(&mut self.parents);
        let old_children = std::mem::take(&mut self.children);
        let old_latest_votes = std::mem::take(&mut self.latest_votes);
        let old_latest_new_votes = std::mem::take(&mut self.latest_new_votes);

        let mut kept_roots = RapidHashSet::default();
        let mut stack = vec![finalized_root];
        while let Some(root) = stack.pop() {
            if !kept_roots.insert(root) {
                continue;
            }
            if let Some(children) = old_children.get(&root) {
                for child in children {
                    if old_blocks.contains_key(child) {
                        stack.push(*child);
                    }
                }
            }
        }

        let mut blocks = RapidHashMap::default();
        let mut states = RapidHashMap::default();
        let mut parents = RapidHashMap::default();
        let mut children: RapidHashMap<Bytes32, Vec<Bytes32>> = RapidHashMap::default();
        let mut nodes = Vec::new();
        let mut node_indices = RapidHashMap::default();
        let mut build_stack = vec![(finalized_root, None::<usize>)];

        while let Some((root, parent_idx)) = build_stack.pop() {
            if node_indices.contains_key(&root) {
                continue;
            }
            let Some(signed) = old_blocks.get(&root).cloned() else {
                continue;
            };
            let Some(state) = old_states.get(&root).cloned() else {
                continue;
            };
            let slot = signed.message.block.slot.0.0;
            let proposer_index = signed.message.block.proposer_index.0.0;
            let idx = nodes.len();
            node_indices.insert(root, idx);
            blocks.insert(root, signed);
            states.insert(root, state);
            nodes.push(ProtoNode {
                root,
                parent: parent_idx,
                children: Vec::new(),
                slot,
                proposer_index,
                weight: 0,
                best_child: None,
            });

            if let Some(parent_idx) = parent_idx {
                let parent_root = nodes[parent_idx].root;
                nodes[parent_idx].children.push(idx);
                parents.insert(root, parent_root);
                children.entry(parent_root).or_default().push(root);
            } else {
                parents.insert(root, Bytes32::zero());
            }

            if let Some(child_roots) = old_children.get(&root) {
                for child_root in child_roots.iter().rev() {
                    if kept_roots.contains(child_root) {
                        build_stack.push((*child_root, Some(idx)));
                    }
                }
            }
        }

        self.blocks = blocks;
        self.states = states;
        self.parents = parents;
        self.children = children;
        self.nodes = nodes;
        self.node_indices = node_indices;

        for idx in (0..self.nodes.len()).rev() {
            self.recompute_best_child(idx);
        }

        self.latest_votes = old_latest_votes
            .into_iter()
            .filter_map(|(validator_id, root)| {
                normalize_pruned_vote_root(root, finalized_root, &kept_roots, &old_parents)
                    .map(|normalized| (validator_id, normalized))
            })
            .collect();
        self.latest_new_votes = old_latest_new_votes
            .into_iter()
            .filter_map(|(validator_id, root)| {
                normalize_pruned_vote_root(root, finalized_root, &kept_roots, &old_parents)
                    .map(|normalized| (validator_id, normalized))
            })
            .collect();

        let active_vote_roots: Vec<Bytes32> = self.latest_votes.values().copied().collect();
        for root in active_vote_roots {
            self.apply_vote_delta(root, 1);
        }

        let finalized_slot = self.latest_finalized.slot.0.0;
        if !self.node_indices.contains_key(&self.latest_justified.root) {
            self.latest_justified = self.latest_finalized;
        }
        if !self
            .node_indices
            .contains_key(&self.previous_justified.root)
        {
            self.previous_justified = self.latest_justified;
        }
        if !self.node_indices.contains_key(&self.safe_target) {
            self.safe_target = finalized_root;
        }

        self.head = self.find_head();
        self.head_slot = self
            .blocks
            .get(&self.head)
            .map(|block| block.message.block.slot.0.0)
            .unwrap_or(finalized_slot);
        if !self.node_indices.contains_key(&self.head) {
            self.head = finalized_root;
            self.head_slot = finalized_slot;
        }
        self.refresh_safe_target();

        old_blocks.len().saturating_sub(self.blocks.len())
    }
}

#[derive(Clone, Copy)]
enum VoteDisposition {
    Active,
    Pending,
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
        participants_len_bits = attestation.aggregation_bits.len,
        "fork choice dropped attestation vote: unknown head root"
    );
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
fn normalize_pruned_vote_root(
    root: Bytes32,
    finalized_root: Bytes32,
    kept_roots: &RapidHashSet<Bytes32>,
    old_parents: &RapidHashMap<Bytes32, Bytes32>,
) -> Option<Bytes32> {
    if kept_roots.contains(&root) {
        return Some(root);
    }
    let mut cursor = finalized_root;
    loop {
        if cursor == root {
            return Some(finalized_root);
        }
        let Some(parent) = old_parents.get(&cursor) else {
            return None;
        };
        if *parent == Bytes32::zero() {
            return None;
        }
        cursor = *parent;
    }
}

#[inline]
fn bitlist_indices<const LIMIT: usize>(bits: &BitList<LIMIT>) -> Vec<usize> {
    let mut out = Vec::new();
    let len = bits.len;
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

#[inline]
fn placeholder_signed_block(block: Block) -> Result<SignedBlockWithAttestation, String> {
    let block_root = Bytes32::from(block.hash_tree_root());
    let proposer_index = block.proposer_index.0.0 as usize;
    if proposer_index >= VALIDATOR_REGISTRY_LIMIT {
        return Err(format!(
            "proposer validator index {proposer_index} exceeds registry limit {}",
            VALIDATOR_REGISTRY_LIMIT
        ));
    }

    let mut proposer_bits = vec![false; proposer_index + 1];
    proposer_bits[proposer_index] = true;
    let aggregation_bits = BitList::new(proposer_bits)?;
    let checkpoint = Checkpoint {
        root: block_root,
        slot: block.slot,
    };

    Ok(SignedBlockWithAttestation {
        message: BlockWithAttestation {
            block,
            proposer_attestation: Attestation {
                aggregation_bits,
                data: AttestationData {
                    slot: checkpoint.slot,
                    head: checkpoint,
                    target: checkpoint,
                    source: checkpoint,
                },
            },
        },
        signature: BlockSignatures {
            attestation_signatures: SszList::new(Vec::new())
                .expect("empty attestation signatures fit within limit"),
            proposer_signature: Bytes3112::zero(),
        },
    })
}
