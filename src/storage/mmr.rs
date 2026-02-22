use crate::ssz::hash::hash_nodes;
use crate::types::bytes::Bytes32;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MmrInclusionProof {
    pub leaf_index: u64,
    pub leaf_count: u64,
    pub leaf: Bytes32,
    pub mountain_start: u64,
    pub mountain_size: u64,
    pub local_siblings: Vec<Bytes32>,
    pub left_peaks: Vec<Bytes32>,
    pub right_peaks: Vec<Bytes32>,
}

#[derive(Clone, Debug, Default)]
pub struct FinalizedMmr {
    leaves: Vec<Bytes32>,
}

impl FinalizedMmr {
    pub fn from_leaves(leaves: Vec<Bytes32>) -> Self {
        Self { leaves }
    }

    pub fn size(&self) -> usize {
        self.leaves.len()
    }

    pub fn last(&self) -> Option<Bytes32> {
        self.leaves.last().copied()
    }

    pub fn append(&mut self, root: Bytes32) {
        self.leaves.push(root);
    }

    pub fn root(&self) -> Bytes32 {
        mmr_root_from_leaves(&self.leaves)
    }

    pub fn leaves(&self) -> &[Bytes32] {
        &self.leaves
    }

    pub fn proof_by_index(&self, leaf_index: usize) -> Option<MmrInclusionProof> {
        if leaf_index >= self.leaves.len() {
            return None;
        }
        let mountains = mountain_layout(self.leaves.len());
        let (mountain_start, mountain_size) = mountains
            .iter()
            .copied()
            .find(|(start, size)| leaf_index >= *start && leaf_index < *start + *size)?;

        let peaks = mountain_peaks(&self.leaves, &mountains);
        let mountain_idx = mountains
            .iter()
            .position(|(start, size)| *start == mountain_start && *size == mountain_size)?;

        let local_offset = leaf_index - mountain_start;
        let local_siblings = local_merkle_path(
            &self.leaves[mountain_start..mountain_start + mountain_size],
            local_offset,
        );

        let left_peaks = peaks[..mountain_idx].to_vec();
        let right_peaks = peaks[mountain_idx + 1..].to_vec();

        Some(MmrInclusionProof {
            leaf_index: leaf_index as u64,
            leaf_count: self.leaves.len() as u64,
            leaf: self.leaves[leaf_index],
            mountain_start: mountain_start as u64,
            mountain_size: mountain_size as u64,
            local_siblings,
            left_peaks,
            right_peaks,
        })
    }

    pub fn proof_by_root(&self, root: Bytes32) -> Option<MmrInclusionProof> {
        let idx = self.leaves.iter().rposition(|leaf| *leaf == root)?;
        self.proof_by_index(idx)
    }
}

pub fn verify_mmr_inclusion_proof(expected_root: Bytes32, proof: &MmrInclusionProof) -> bool {
    let mountain_start = proof.mountain_start as usize;
    let mountain_size = proof.mountain_size as usize;
    let leaf_index = proof.leaf_index as usize;
    let leaf_count = proof.leaf_count as usize;
    if mountain_size == 0
        || !mountain_size.is_power_of_two()
        || mountain_start + mountain_size > leaf_count
        || leaf_index < mountain_start
        || leaf_index >= mountain_start + mountain_size
    {
        return false;
    }

    let mut acc = proof.leaf;
    let mut local_idx = leaf_index - mountain_start;
    for sibling in &proof.local_siblings {
        if (local_idx & 1) == 0 {
            acc = hash_nodes(&acc, sibling);
        } else {
            acc = hash_nodes(sibling, &acc);
        }
        local_idx >>= 1;
    }

    let mut peaks =
        Vec::with_capacity(proof.left_peaks.len() + 1usize + proof.right_peaks.len());
    peaks.extend_from_slice(&proof.left_peaks);
    peaks.push(acc);
    peaks.extend_from_slice(&proof.right_peaks);

    bag_peaks(&peaks, proof.leaf_count as u64) == expected_root
}

pub fn mmr_root_from_leaves(leaves: &[Bytes32]) -> Bytes32 {
    if leaves.is_empty() {
        return Bytes32::zero();
    }
    let mountains = mountain_layout(leaves.len());
    let peaks = mountain_peaks(leaves, &mountains);
    bag_peaks(&peaks, leaves.len() as u64)
}

fn mountain_layout(total_leaves: usize) -> Vec<(usize, usize)> {
    let mut layout = Vec::new();
    let mut remaining = total_leaves;
    let mut cursor = 0usize;
    while remaining > 0 {
        let size = largest_power_of_two_leq(remaining);
        layout.push((cursor, size));
        cursor += size;
        remaining -= size;
    }
    layout
}

fn mountain_peaks(leaves: &[Bytes32], mountains: &[(usize, usize)]) -> Vec<Bytes32> {
    mountains
        .iter()
        .map(|(start, size)| perfect_merkle_root(&leaves[*start..(*start + *size)]))
        .collect()
}

fn bag_peaks(peaks: &[Bytes32], leaf_count: u64) -> Bytes32 {
    if peaks.is_empty() {
        return Bytes32::zero();
    }
    let mut acc = peaks[0];
    for peak in &peaks[1..] {
        acc = hash_nodes(&acc, peak);
    }
    let mut len = [0u8; 32];
    len[..8].copy_from_slice(&leaf_count.to_le_bytes());
    let len_node = Bytes32::from(len);
    hash_nodes(&acc, &len_node)
}

fn perfect_merkle_root(leaves: &[Bytes32]) -> Bytes32 {
    debug_assert!(!leaves.is_empty());
    debug_assert!(leaves.len().is_power_of_two());
    if leaves.len() == 1 {
        return leaves[0];
    }
    let mut level: Vec<Bytes32> = leaves.to_vec();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len() / 2);
        for i in (0..level.len()).step_by(2) {
            next.push(hash_nodes(&level[i], &level[i + 1]));
        }
        level = next;
    }
    level[0]
}

fn local_merkle_path(leaves: &[Bytes32], leaf_index: usize) -> Vec<Bytes32> {
    debug_assert!(!leaves.is_empty());
    debug_assert!(leaves.len().is_power_of_two());
    let mut idx = leaf_index;
    let mut level: Vec<Bytes32> = leaves.to_vec();
    let mut siblings = Vec::new();
    while level.len() > 1 {
        let sibling_idx = if (idx & 1) == 0 { idx + 1 } else { idx - 1 };
        siblings.push(level[sibling_idx]);
        let mut next = Vec::with_capacity(level.len() / 2);
        for i in (0..level.len()).step_by(2) {
            next.push(hash_nodes(&level[i], &level[i + 1]));
        }
        idx >>= 1;
        level = next;
    }
    siblings
}

fn largest_power_of_two_leq(value: usize) -> usize {
    1usize << (usize::BITS - 1 - value.leading_zeros())
}

#[cfg(test)]
mod tests {
    use super::{FinalizedMmr, verify_mmr_inclusion_proof};
    use crate::types::bytes::Bytes32;

    fn root_from_u64(value: u64) -> Bytes32 {
        let mut out = [0u8; 32];
        out[0..8].copy_from_slice(&value.to_le_bytes());
        Bytes32::from(out)
    }

    #[test]
    fn mmr_proofs_roundtrip() {
        let mut mmr = FinalizedMmr::default();
        for i in 0..17u64 {
            mmr.append(root_from_u64(i + 1));
        }
        let root = mmr.root();
        for i in 0..17usize {
            let proof = mmr.proof_by_index(i).expect("proof");
            assert!(verify_mmr_inclusion_proof(root, &proof));
        }
    }
}
