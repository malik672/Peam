use crate::slot::Slot;
use crate::ssz::hash::hash_nodes;
use crate::ssz::{HashTreeRoot, SszDecode, SszEncode, SszFixedLen};
use crate::types::bytes::Bytes32;
use crate::types::container::Container;
use crate::unsafe_vec::write_bytes_at;

/// A finality or justification checkpoint: a `(root, slot)` pair identifying
/// a specific block in the canonical chain.
///
/// Checkpoints are used as the `source`, `target`, and `head` references in
/// [`AttestationData`], and as the `latest_justified` / `latest_finalized`
/// markers in [`State`].
///
/// # SSZ layout (fixed, 40 bytes)
///
/// | Byte range | Field  |
/// |------------|--------|
/// | 0 – 31     | `root` |
/// | 32 – 39    | `slot` |
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct Checkpoint {
    /// Block root of the checkpoint block.
    pub root: Bytes32,
    /// Slot of the checkpoint block.
    pub slot: Slot,
}

impl Container for Checkpoint {}

/// SSZ serialization for [`Checkpoint`] — fixed 40-byte encoding.
impl SszEncode for Checkpoint {
    fn encode_ssz(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(40);
        unsafe { out.set_len(40) };
        unsafe { write_bytes_at(&mut out, 0, self.root.as_ref()) };
        unsafe { write_bytes_at(&mut out, 32, &self.slot.0.0.to_le_bytes()) };
        out
    }
}

/// SSZ deserialization for [`Checkpoint`] — trusts that `bytes` is exactly 40 bytes.
impl SszDecode for Checkpoint {
    fn decode_ssz(bytes: &[u8]) -> Result<Self, String> {
        let root = Bytes32::from_slice(&bytes[0..32]);
        let slot = Slot::decode_ssz(&bytes[32..40])?;
        Ok(Checkpoint { root, slot })
    }
}

impl Checkpoint {
    /// Bounds-checked SSZ deserialization for untrusted input.
    ///
    /// Returns `Err` if `bytes.len() != 40`.
    pub fn decode_ssz_checked(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() != Self::fixed_len() {
            return Err(format!(
                "Checkpoint expects {} bytes, got {}",
                Self::fixed_len(),
                bytes.len()
            ));
        }
        Self::decode_ssz(bytes)
    }
}

/// Merkle hash-tree root for [`Checkpoint`].
///
/// `hash_tree_root = hash_nodes(root, slot_root)`
impl HashTreeRoot for Checkpoint {
    fn hash_tree_root(&self) -> [u8; 32] {
        let left = Bytes32::from(self.root.as_array());
        let right = Bytes32::from(self.slot.hash_tree_root());
        let root = hash_nodes(&left, &right);
        *root.as_ref()
    }
}

impl SszFixedLen for Checkpoint {
    fn fixed_len() -> usize {
        40
    }
}
