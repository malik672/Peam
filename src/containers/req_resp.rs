use crate::containers::block::SignedBlockWithAttestation;
use crate::ssz::hash::{merkleize_tree_root, merkleize_tree_root_3};
use crate::ssz::{HashTreeRoot, SszDecode, SszEncode, SszFixedLen};
use crate::types::bytes::Bytes32;
use crate::types::collections::SszList;
use crate::types::uint::Uint64;
use crate::unsafe_vec::write_bytes_at;

pub const MAX_BLOCKS_PER_REQUEST: usize = 1_024;
pub const MAX_BLOCKS_PER_ROOT_REQUEST: usize = 1_024;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct Status {
    pub fork_digest: Bytes32,
    pub finalized_root: Bytes32,
    pub finalized_epoch: Uint64,
    pub head_root: Bytes32,
    pub head_slot: Uint64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct Ping {
    pub seq_number: Uint64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct Pong {
    pub seq_number: Uint64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct BlocksByRangeRequest {
    pub start_slot: Uint64,
    pub count: Uint64,
    pub step: Uint64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlocksByRangeResponse {
    pub blocks: SszList<SignedBlockWithAttestation, MAX_BLOCKS_PER_REQUEST>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlocksByRootRequest {
    pub roots: SszList<Bytes32, MAX_BLOCKS_PER_ROOT_REQUEST>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlocksByRootResponse {
    pub blocks: SszList<SignedBlockWithAttestation, MAX_BLOCKS_PER_REQUEST>,
}

impl SszEncode for Status {
    fn encode_ssz(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + 32 + 8 + 32 + 8);
        unsafe { out.set_len(32 + 32 + 8 + 32 + 8) };
        unsafe { write_bytes_at(&mut out, 0, self.fork_digest.as_ref()) };
        unsafe { write_bytes_at(&mut out, 32, self.finalized_root.as_ref()) };
        unsafe { write_bytes_at(&mut out, 64, &self.finalized_epoch.0.to_le_bytes()) };
        unsafe { write_bytes_at(&mut out, 72, self.head_root.as_ref()) };
        unsafe { write_bytes_at(&mut out, 104, &self.head_slot.0.to_le_bytes()) };
        out
    }
}

impl SszDecode for Status {
    fn decode_ssz(bytes: &[u8]) -> Result<Self, String> {
        Ok(Self {
            fork_digest: Bytes32::from_slice(&bytes[0..32]),
            finalized_root: Bytes32::from_slice(&bytes[32..64]),
            finalized_epoch: Uint64::decode_ssz(&bytes[64..72])?,
            head_root: Bytes32::from_slice(&bytes[72..104]),
            head_slot: Uint64::decode_ssz(&bytes[104..112])?,
        })
    }
}

impl Status {
    pub fn decode_ssz_checked(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() != Self::fixed_len() {
            return Err(format!(
                "Status expects {} bytes, got {}",
                Self::fixed_len(),
                bytes.len()
            ));
        }
        Self::decode_ssz(bytes)
    }
}

impl HashTreeRoot for Status {
    fn hash_tree_root(&self) -> [u8; 32] {
        let field_roots = [
            self.fork_digest,
            self.finalized_root,
            Bytes32::from(self.finalized_epoch.hash_tree_root()),
            self.head_root,
            Bytes32::from(self.head_slot.hash_tree_root()),
        ];
        let root = merkleize_tree_root(&field_roots);
        *root.as_ref()
    }
}

impl SszFixedLen for Status {
    fn fixed_len() -> usize {
        112
    }
}

impl SszEncode for Ping {
    fn encode_ssz(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(8);
        unsafe { out.set_len(8) };
        unsafe { write_bytes_at(&mut out, 0, &self.seq_number.0.to_le_bytes()) };
        out
    }
}

impl SszDecode for Ping {
    fn decode_ssz(bytes: &[u8]) -> Result<Self, String> {
        Ok(Self {
            seq_number: Uint64::decode_ssz(bytes)?,
        })
    }
}

impl Ping {
    pub fn decode_ssz_checked(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() != Self::fixed_len() {
            return Err(format!(
                "Ping expects {} bytes, got {}",
                Self::fixed_len(),
                bytes.len()
            ));
        }
        Self::decode_ssz(bytes)
    }
}

impl HashTreeRoot for Ping {
    fn hash_tree_root(&self) -> [u8; 32] {
        self.seq_number.hash_tree_root()
    }
}

impl SszFixedLen for Ping {
    fn fixed_len() -> usize {
        8
    }
}

impl SszEncode for Pong {
    fn encode_ssz(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(8);
        unsafe { out.set_len(8) };
        unsafe { write_bytes_at(&mut out, 0, &self.seq_number.0.to_le_bytes()) };
        out
    }
}

impl SszDecode for Pong {
    fn decode_ssz(bytes: &[u8]) -> Result<Self, String> {
        Ok(Self {
            seq_number: Uint64::decode_ssz(bytes)?,
        })
    }
}

impl Pong {
    pub fn decode_ssz_checked(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() != Self::fixed_len() {
            return Err(format!(
                "Pong expects {} bytes, got {}",
                Self::fixed_len(),
                bytes.len()
            ));
        }
        Self::decode_ssz(bytes)
    }
}

impl HashTreeRoot for Pong {
    fn hash_tree_root(&self) -> [u8; 32] {
        self.seq_number.hash_tree_root()
    }
}

impl SszFixedLen for Pong {
    fn fixed_len() -> usize {
        8
    }
}

impl SszEncode for BlocksByRangeRequest {
    fn encode_ssz(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(24);
        unsafe { out.set_len(24) };
        unsafe { write_bytes_at(&mut out, 0, &self.start_slot.0.to_le_bytes()) };
        unsafe { write_bytes_at(&mut out, 8, &self.count.0.to_le_bytes()) };
        unsafe { write_bytes_at(&mut out, 16, &self.step.0.to_le_bytes()) };
        out
    }
}

impl SszDecode for BlocksByRangeRequest {
    fn decode_ssz(bytes: &[u8]) -> Result<Self, String> {
        Ok(Self {
            start_slot: Uint64::decode_ssz(&bytes[0..8])?,
            count: Uint64::decode_ssz(&bytes[8..16])?,
            step: Uint64::decode_ssz(&bytes[16..24])?,
        })
    }
}

impl BlocksByRangeRequest {
    pub fn decode_ssz_checked(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() != Self::fixed_len() {
            return Err(format!(
                "BlocksByRangeRequest expects {} bytes, got {}",
                Self::fixed_len(),
                bytes.len()
            ));
        }
        Self::decode_ssz(bytes)
    }
}

impl HashTreeRoot for BlocksByRangeRequest {
    fn hash_tree_root(&self) -> [u8; 32] {
        let field_roots = [
            Bytes32::from(self.start_slot.hash_tree_root()),
            Bytes32::from(self.count.hash_tree_root()),
            Bytes32::from(self.step.hash_tree_root()),
        ];
        let root = merkleize_tree_root_3(&field_roots);
        *root.as_ref()
    }
}

impl SszFixedLen for BlocksByRangeRequest {
    fn fixed_len() -> usize {
        24
    }
}

impl SszEncode for BlocksByRangeResponse {
    fn encode_ssz(&self) -> Vec<u8> {
        let body = self.blocks.encode_ssz();
        let mut out = Vec::with_capacity(4 + body.len());
        unsafe { out.set_len(4 + body.len()) };
        unsafe { write_bytes_at(&mut out, 0, &4u32.to_le_bytes()) };
        unsafe { write_bytes_at(&mut out, 4, &body) };
        out
    }
}

impl SszDecode for BlocksByRangeResponse {
    fn decode_ssz(bytes: &[u8]) -> Result<Self, String> {
        let mut buf = [0u8; 4];
        buf.copy_from_slice(&bytes[0..4]);
        let offset = u32::from_le_bytes(buf) as usize;
        Ok(Self {
            blocks: SszList::decode_ssz(&bytes[offset..])?,
        })
    }
}

impl BlocksByRangeResponse {
    pub fn decode_ssz_checked(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < 4 {
            return Err("BlocksByRangeResponse missing offset table".to_string());
        }
        let mut buf = [0u8; 4];
        buf.copy_from_slice(&bytes[0..4]);
        let offset = u32::from_le_bytes(buf) as usize;
        if offset != 4 || offset > bytes.len() {
            return Err("BlocksByRangeResponse offset is invalid".to_string());
        }
        Ok(Self {
            blocks: SszList::decode_ssz_checked(&bytes[offset..])?,
        })
    }
}

impl HashTreeRoot for BlocksByRangeResponse {
    fn hash_tree_root(&self) -> [u8; 32] {
        self.blocks.hash_tree_root()
    }
}

impl SszEncode for BlocksByRootRequest {
    fn encode_ssz(&self) -> Vec<u8> {
        let body = self.roots.encode_ssz();
        let mut out = Vec::with_capacity(4 + body.len());
        unsafe { out.set_len(4 + body.len()) };
        unsafe { write_bytes_at(&mut out, 0, &4u32.to_le_bytes()) };
        unsafe { write_bytes_at(&mut out, 4, &body) };
        out
    }
}

impl SszDecode for BlocksByRootRequest {
    fn decode_ssz(bytes: &[u8]) -> Result<Self, String> {
        let mut buf = [0u8; 4];
        buf.copy_from_slice(&bytes[0..4]);
        let offset = u32::from_le_bytes(buf) as usize;
        Ok(Self {
            roots: SszList::decode_ssz(&bytes[offset..])?,
        })
    }
}

impl BlocksByRootRequest {
    pub fn decode_ssz_checked(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < 4 {
            return Err("BlocksByRootRequest missing offset table".to_string());
        }
        let mut buf = [0u8; 4];
        buf.copy_from_slice(&bytes[0..4]);
        let offset = u32::from_le_bytes(buf) as usize;
        if offset != 4 || offset > bytes.len() {
            return Err("BlocksByRootRequest offset is invalid".to_string());
        }
        Ok(Self {
            roots: SszList::decode_ssz_checked(&bytes[offset..])?,
        })
    }
}

impl HashTreeRoot for BlocksByRootRequest {
    fn hash_tree_root(&self) -> [u8; 32] {
        self.roots.hash_tree_root()
    }
}

impl SszEncode for BlocksByRootResponse {
    fn encode_ssz(&self) -> Vec<u8> {
        let body = self.blocks.encode_ssz();
        let mut out = Vec::with_capacity(4 + body.len());
        unsafe { out.set_len(4 + body.len()) };
        unsafe { write_bytes_at(&mut out, 0, &4u32.to_le_bytes()) };
        unsafe { write_bytes_at(&mut out, 4, &body) };
        out
    }
}

impl SszDecode for BlocksByRootResponse {
    fn decode_ssz(bytes: &[u8]) -> Result<Self, String> {
        let mut buf = [0u8; 4];
        buf.copy_from_slice(&bytes[0..4]);
        let offset = u32::from_le_bytes(buf) as usize;
        Ok(Self {
            blocks: SszList::decode_ssz(&bytes[offset..])?,
        })
    }
}

impl BlocksByRootResponse {
    pub fn decode_ssz_checked(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < 4 {
            return Err("BlocksByRootResponse missing offset table".to_string());
        }
        let mut buf = [0u8; 4];
        buf.copy_from_slice(&bytes[0..4]);
        let offset = u32::from_le_bytes(buf) as usize;
        if offset != 4 || offset > bytes.len() {
            return Err("BlocksByRootResponse offset is invalid".to_string());
        }
        Ok(Self {
            blocks: SszList::decode_ssz_checked(&bytes[offset..])?,
        })
    }
}

impl HashTreeRoot for BlocksByRootResponse {
    fn hash_tree_root(&self) -> [u8; 32] {
        self.blocks.hash_tree_root()
    }
}
