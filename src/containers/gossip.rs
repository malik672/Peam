use peam_consensus_types::containers::attestation::{
    SignedAggregatedAttestation, SignedAttestation,
};
use peam_consensus_types::containers::block::{
    BlockHeader, SignedBlockWithAttestation, decode_signed_block_network,
    decode_signed_block_network_checked, encode_signed_block_network,
};
use peam_consensus_types::containers::validator::ValidatorIndex;
use peam_consensus_types::types::bytes::Bytes32;
use peam_consensus_types::types::uint::Uint64;
use crate::ssz::hash::hash_nodes;
use crate::ssz::{HashTreeRoot, SszDecode, SszEncode, SszFixedLen};
use crate::unsafe_vec::write_bytes_at;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GossipBlock {
    pub block: SignedBlockWithAttestation,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GossipBlockHeader {
    pub header: BlockHeader,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GossipAttestation {
    pub attestation: SignedAttestation,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GossipAggregatedAttestation {
    pub attestation: SignedAggregatedAttestation,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct VoluntaryExit {
    pub validator_index: ValidatorIndex,
    pub epoch: Uint64,
}

impl SszEncode for GossipBlock {
    fn encode_ssz(&self) -> Vec<u8> {
        encode_signed_block_network(&self.block)
    }
}

impl SszDecode for GossipBlock {
    fn decode_ssz(bytes: &[u8]) -> Result<Self, String> {
        Ok(Self {
            block: decode_signed_block_network(bytes)?,
        })
    }
}

impl GossipBlock {
    pub fn decode_ssz_checked(bytes: &[u8]) -> Result<Self, String> {
        Ok(Self {
            block: decode_signed_block_network_checked(bytes)?,
        })
    }
}

impl HashTreeRoot for GossipBlock {
    fn hash_tree_root(&self) -> [u8; 32] {
        self.block.hash_tree_root()
    }
}

impl SszEncode for GossipBlockHeader {
    fn encode_ssz(&self) -> Vec<u8> {
        self.header.encode_ssz()
    }
}

impl SszDecode for GossipBlockHeader {
    fn decode_ssz(bytes: &[u8]) -> Result<Self, String> {
        Ok(Self {
            header: BlockHeader::decode_ssz(bytes)?,
        })
    }
}

impl GossipBlockHeader {
    pub fn decode_ssz_checked(bytes: &[u8]) -> Result<Self, String> {
        Ok(Self {
            header: BlockHeader::decode_ssz_checked(bytes)?,
        })
    }
}

impl HashTreeRoot for GossipBlockHeader {
    fn hash_tree_root(&self) -> [u8; 32] {
        self.header.hash_tree_root()
    }
}

impl SszEncode for GossipAttestation {
    fn encode_ssz(&self) -> Vec<u8> {
        self.attestation.encode_ssz()
    }
}

impl SszDecode for GossipAttestation {
    fn decode_ssz(bytes: &[u8]) -> Result<Self, String> {
        Ok(Self {
            attestation: SignedAttestation::decode_ssz(bytes)?,
        })
    }
}

impl GossipAttestation {
    pub fn decode_ssz_checked(bytes: &[u8]) -> Result<Self, String> {
        Ok(Self {
            attestation: SignedAttestation::decode_ssz_checked(bytes)?,
        })
    }
}

impl HashTreeRoot for GossipAttestation {
    fn hash_tree_root(&self) -> [u8; 32] {
        self.attestation.hash_tree_root()
    }
}

impl SszEncode for GossipAggregatedAttestation {
    fn encode_ssz(&self) -> Vec<u8> {
        self.attestation.encode_ssz()
    }
}

impl SszDecode for GossipAggregatedAttestation {
    fn decode_ssz(bytes: &[u8]) -> Result<Self, String> {
        Ok(Self {
            attestation: SignedAggregatedAttestation::decode_ssz(bytes)?,
        })
    }
}

impl GossipAggregatedAttestation {
    pub fn decode_ssz_checked(bytes: &[u8]) -> Result<Self, String> {
        Ok(Self {
            attestation: SignedAggregatedAttestation::decode_ssz_checked(bytes)?,
        })
    }
}

impl HashTreeRoot for GossipAggregatedAttestation {
    fn hash_tree_root(&self) -> [u8; 32] {
        self.attestation.hash_tree_root()
    }
}

impl SszEncode for VoluntaryExit {
    fn encode_ssz(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(16);
        unsafe { out.set_len(16) };
        unsafe { write_bytes_at(&mut out, 0, &self.validator_index.0.0.to_le_bytes()) };
        unsafe { write_bytes_at(&mut out, 8, &self.epoch.0.to_le_bytes()) };
        out
    }
}

impl SszDecode for VoluntaryExit {
    fn decode_ssz(bytes: &[u8]) -> Result<Self, String> {
        Ok(Self {
            validator_index: ValidatorIndex::decode_ssz(&bytes[0..8])?,
            epoch: Uint64::decode_ssz(&bytes[8..16])?,
        })
    }
}

impl VoluntaryExit {
    pub fn decode_ssz_checked(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() != Self::fixed_len() {
            return Err(format!(
                "VoluntaryExit expects {} bytes, got {}",
                Self::fixed_len(),
                bytes.len()
            ));
        }
        Self::decode_ssz(bytes)
    }
}

impl HashTreeRoot for VoluntaryExit {
    fn hash_tree_root(&self) -> [u8; 32] {
        let left = Bytes32::from(self.validator_index.hash_tree_root());
        let right = Bytes32::from(self.epoch.hash_tree_root());
        let root = hash_nodes(&left, &right);
        *root.as_ref()
    }
}

impl SszFixedLen for VoluntaryExit {
    fn fixed_len() -> usize {
        16
    }
}
