use crate::ssz::hash::{chunkify_fixed, hash_nodes, mix_in_length};
use crate::ssz::{HashTreeRoot, SszDecode, SszElement, SszEncode, SszFixedLen};
use crate::unsafe_vec::write_bytes_at;
pub use peam_ssz::types::bytes::Bytes32;

/// 32-byte fixed-size value. Used for block roots, state roots, and all
/// Merkle tree outputs. SSZ `hash_tree_root` returns the inner bytes directly
/// (identity — a single chunk is already its own root).
/// 52-byte fixed-size value. Holds a post-quantum (XMSS) public key.
/// SSZ hash_tree_root splits into two 32-byte chunks (left: bytes 0..32,
/// right: bytes 32..52 zero-padded) and hashes the pair.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct Bytes52([u8; 52]);

/// Variable-length byte list bounded by `LIMIT`. SSZ-encoded as raw bytes;
/// hash_tree_root chunkifies, merkleizes to `ceil(LIMIT/32)` leaves, then
/// mixes in the actual length.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct ByteList<const LIMIT: usize> {
    pub data: Vec<u8>,
}

/// 3112-byte fixed-size value. Holds a post-quantum (XMSS) signature.
/// SSZ hash_tree_root chunkifies into 98 chunks and merkleizes.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct Bytes3112([u8; 3112]);

impl Bytes52 {
    pub fn from_slice(bytes: &[u8]) -> Self {
        let mut out = [0u8; 52];
        out.copy_from_slice(&bytes[0..52]);
        Self(out)
    }

    pub fn as_array(&self) -> [u8; 52] {
        self.0
    }
}

impl<const LIMIT: usize> ByteList<LIMIT> {
    pub fn new(data: Vec<u8>) -> Result<Self, String> {
        if data.len() > LIMIT {
            return Err(format!(
                "ByteList length {} exceeds limit {}",
                data.len(),
                LIMIT
            ));
        }
        Ok(Self { data })
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }
}

impl Bytes3112 {
    pub const LEN: usize = 3112;

    pub fn zero() -> Self {
        Self([0u8; 3112])
    }

    #[inline]
    pub fn from_slice(bytes: &[u8]) -> Self {
        let mut out = [0u8; 3112];
        out.copy_from_slice(&bytes[0..3112]);
        Self(out)
    }

    pub fn as_array(&self) -> [u8; 3112] {
        self.0
    }
}

impl AsRef<[u8]> for Bytes52 {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8; 52]> for Bytes52 {
    fn as_ref(&self) -> &[u8; 52] {
        &self.0
    }
}

impl AsRef<[u8; 3112]> for Bytes3112 {
    fn as_ref(&self) -> &[u8; 3112] {
        &self.0
    }
}

impl AsRef<[u8]> for Bytes3112 {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<[u8; 3112]> for Bytes3112 {
    fn from(value: [u8; 3112]) -> Self {
        Self(value)
    }
}

impl<const LIMIT: usize> SszEncode for ByteList<LIMIT> {
    fn encode_ssz(&self) -> Vec<u8> {
        self.data.clone()
    }
}

impl<const LIMIT: usize> SszDecode for ByteList<LIMIT> {
    fn decode_ssz(bytes: &[u8]) -> Result<Self, String> {
        Ok(Self {
            data: bytes.to_vec(),
        })
    }
}

impl<const LIMIT: usize> ByteList<LIMIT> {
    pub fn decode_ssz_checked(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > LIMIT {
            return Err(format!(
                "ByteList length {} exceeds limit {}",
                bytes.len(),
                LIMIT
            ));
        }
        Self::decode_ssz(bytes)
    }
}

impl<const LIMIT: usize> HashTreeRoot for ByteList<LIMIT> {
    #[inline]
    fn hash_tree_root(&self) -> [u8; 32] {
        let chunks = chunkify_fixed(&self.data);
        let limit_chunks = (LIMIT + 31) / 32;
        let root = crate::ssz::hash::merkleize_with_limit(&chunks, limit_chunks)
            .unwrap_or_else(|_| Bytes32::zero());
        let mixed = mix_in_length(&root, self.data.len());
        *mixed.as_ref()
    }
}

impl<const LIMIT: usize> SszElement for ByteList<LIMIT> {}

impl SszEncode for Bytes3112 {
    fn encode_ssz(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(3112);
        unsafe { out.set_len(3112) };
        unsafe { write_bytes_at(&mut out, 0, &self.0) };
        out
    }
}

impl SszDecode for Bytes3112 {
    fn decode_ssz(bytes: &[u8]) -> Result<Self, String> {
        Ok(Bytes3112::from_slice(bytes))
    }
}

impl HashTreeRoot for Bytes3112 {
    fn hash_tree_root(&self) -> [u8; 32] {
        let chunks = chunkify_fixed(&self.0);
        let root = crate::ssz::hash::merkleize_with_limit(&chunks, chunks.len())
            .unwrap_or_else(|_| Bytes32::zero());
        *root.as_ref()
    }
}

impl SszFixedLen for Bytes3112 {
    fn fixed_len() -> usize {
        3112
    }
}

impl From<[u8; 52]> for Bytes52 {
    fn from(value: [u8; 52]) -> Self {
        Self(value)
    }
}

impl SszEncode for Bytes52 {
    fn encode_ssz(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(52);
        unsafe { out.set_len(52) };
        unsafe { write_bytes_at(&mut out, 0, &self.0) };
        out
    }
}

impl SszDecode for Bytes52 {
    fn decode_ssz(bytes: &[u8]) -> Result<Self, String> {
        Ok(Bytes52::from_slice(bytes))
    }
}

impl HashTreeRoot for Bytes52 {
    fn hash_tree_root(&self) -> [u8; 32] {
        let mut left = [0u8; 32];
        left.copy_from_slice(&self.0[0..32]);
        let mut right = [0u8; 32];
        right[..20].copy_from_slice(&self.0[32..52]);
        let root = hash_nodes(&Bytes32::from(left), &Bytes32::from(right));
        *root.as_ref()
    }
}

impl SszFixedLen for Bytes52 {
    fn fixed_len() -> usize {
        52
    }
}
