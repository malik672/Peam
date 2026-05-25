use peam_consensus_types::containers::checkpoint::Checkpoint;
use peam_consensus_types::types::bytes::Bytes32;

#[inline]
pub fn short_root(root: &Bytes32) -> String {
    let bytes = root.as_array();
    format!(
        "{:02x}{:02x}{:02x}{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3]
    )
}

#[inline]
pub fn short_checkpoint(checkpoint: &Checkpoint) -> String {
    format!("{}:{}", checkpoint.slot.0.0, short_root(&checkpoint.root))
}

#[inline]
pub fn short_slot_root(slot: u64, root: &Bytes32) -> String {
    format!("{slot}:{}", short_root(root))
}

