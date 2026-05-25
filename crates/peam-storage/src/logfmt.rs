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
pub fn short_opt_root(root: Option<Bytes32>) -> Option<String> {
    root.map(|root| short_root(&root))
}

#[inline]
pub fn short_opt_root_or_dash(root: Option<Bytes32>) -> String {
    short_opt_root(root).unwrap_or_else(|| "-".to_string())
}

#[allow(dead_code)]
#[inline]
pub fn short_checkpoint(checkpoint: &Checkpoint) -> String {
    format!("{}:{}", checkpoint.slot.0.0, short_root(&checkpoint.root))
}

#[inline]
pub fn short_slot_root(slot: u64, root: &Bytes32) -> String {
    format!("{slot}:{}", short_root(root))
}

#[cfg(test)]
mod tests {
    use super::{
        short_checkpoint, short_opt_root, short_opt_root_or_dash, short_root, short_slot_root,
    };
    use peam_consensus_types::containers::checkpoint::Checkpoint;
    use peam_consensus_types::slot::Slot;
    use peam_consensus_types::types::bytes::Bytes32;
    use peam_consensus_types::types::uint::Uint64;

    fn root(byte: u8) -> Bytes32 {
        Bytes32::from([byte; 32])
    }

    #[test]
    fn formats_roots_compactly() {
        assert_eq!(short_root(&root(0xab)), "abababab");
        assert_eq!(
            short_opt_root(Some(root(0xcd))).as_deref(),
            Some("cdcdcdcd")
        );
        assert_eq!(short_opt_root(None), None);
        assert_eq!(short_opt_root_or_dash(None), "-");
    }

    #[test]
    fn formats_checkpoint_and_slot_root_compactly() {
        let checkpoint = Checkpoint {
            slot: Slot(Uint64(42)),
            root: root(0x12),
        };
        assert_eq!(short_checkpoint(&checkpoint), "42:12121212");
        assert_eq!(short_slot_root(7, &root(0xef)), "7:efefefef");
    }
}
