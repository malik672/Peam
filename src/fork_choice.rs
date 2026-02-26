use rapidhash::RapidHashMap;

use crate::containers::attestation::Attestation;
use crate::containers::block::SignedBlockWithAttestation;
use crate::containers::checkpoint::Checkpoint;
use crate::containers::state::State;
use crate::ssz::HashTreeRoot;
use crate::types::bitlist::BitList;
use crate::types::bytes::Bytes32;

/// Minimal fork-choice store aligned with Ream's anchor + head model.
#[derive(Debug, Clone)]
pub struct ForkChoiceStore {
    head: Bytes32,
    head_slot: u64,
    latest_justified: Checkpoint,
    latest_finalized: Checkpoint,
    blocks: RapidHashMap<Bytes32, SignedBlockWithAttestation>,
    states: RapidHashMap<Bytes32, State>,
    parents: RapidHashMap<Bytes32, Bytes32>,
    children: RapidHashMap<Bytes32, Vec<Bytes32>>,
    latest_votes: RapidHashMap<usize, Bytes32>,
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
        Ok(Self {
            head: root,
            head_slot: slot,
            latest_justified: anchor_state.latest_justified,
            latest_finalized: anchor_state.latest_finalized,
            blocks,
            states,
            parents,
            children,
            latest_votes: RapidHashMap::default(),
        })
    }

    /// Import a new block + post-state; updates head if slot is higher.
    pub fn on_block(
        &mut self,
        signed_block: SignedBlockWithAttestation,
        post_state: State,
    ) -> Result<(), String> {
        let block = signed_block.message.block.clone();
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
        self.latest_justified = post_state.latest_justified;
        self.latest_finalized = post_state.latest_finalized;
        let head = self.find_head();
        if let Some(head_block) = self.blocks.get(&head) {
            self.head = head;
            self.head_slot = head_block.message.block.slot.0.0;
        } else if slot > self.head_slot {
            self.head = root;
            self.head_slot = slot;
        }
        Ok(())
    }

    /// Process aggregated attestation votes and update head.
    pub fn on_attestation(&mut self, attestation: &Attestation) {
        let target_root = attestation.data.target.root;
        if !self.blocks.contains_key(&target_root) {
            return;
        }
        for validator_id in bitlist_indices(&attestation.aggregation_bits) {
            self.latest_votes.insert(validator_id, target_root);
        }
        let head = self.find_head();
        if let Some(head_block) = self.blocks.get(&head) {
            self.head = head;
            self.head_slot = head_block.message.block.slot.0.0;
        }
    }

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

    fn subtree_weight(&self, root: Bytes32) -> usize {
        let mut weight = 0usize;
        for vote in self.latest_votes.values() {
            if self.is_descendant(*vote, root) {
                weight += 1;
            }
        }
        weight
    }

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

    pub fn head(&self) -> Bytes32 {
        self.head
    }

    pub fn latest_justified(&self) -> Checkpoint {
        self.latest_justified
    }

    pub fn latest_finalized(&self) -> Checkpoint {
        self.latest_finalized
    }
}

#[inline]
fn state_matches_block_root(state: &State, expected: Bytes32) -> bool {
    state.latest_block_header.state_root == expected
        || Bytes32::from(state.hash_tree_root()) == expected
}

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
