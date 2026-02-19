use crate::ssz::{HashTreeRoot, SszDecode, SszEncode, SszFixedLen};
use crate::unsafe_vec::write_bytes_at;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct Uint64(pub u64);

impl SszEncode for Uint64 {
    fn encode_ssz(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(8);
        unsafe { out.set_len(8) };
        unsafe { write_bytes_at(&mut out, 0, &self.0.to_le_bytes()) };
        out
    }
}

impl SszDecode for Uint64 {
    fn decode_ssz(bytes: &[u8]) -> Result<Self, String> {
        let mut buf = [0u8; 8];
        buf.copy_from_slice(bytes);
        Ok(Uint64(u64::from_le_bytes(buf)))
    }
}

impl HashTreeRoot for Uint64 {
    #[inline]
    fn hash_tree_root(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[..8].copy_from_slice(&self.0.to_le_bytes());
        out
    }
}

impl SszFixedLen for Uint64 {
    fn fixed_len() -> usize {
        8
    }
}
