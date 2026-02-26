use crate::containers::attestation::{AggregatedSignatureProof, Attestation};
use crate::containers::validator::ValidatorIndex;
use crate::slot::Slot;
use crate::ssz::hash::{hash_nodes, merkleize_tree_root};
use crate::ssz::{HashTreeRoot, SszDecode, SszElement, SszEncode, SszFixedLen};
use crate::types::bitlist::BitList;
use crate::types::bytes::{Bytes32, Bytes3112};
use crate::types::collections::SszList;
use crate::unsafe_vec::write_bytes_at;

pub const ATTESTATIONS_LIMIT: usize = 4_096;
pub type Attestations = SszList<Attestation, ATTESTATIONS_LIMIT>;
pub type AttestationSignatures = SszList<AggregatedSignatureProof, ATTESTATIONS_LIMIT>;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct BlockHeader {
    pub slot: Slot,
    pub proposer_index: ValidatorIndex,
    pub parent_root: Bytes32,
    pub state_root: Bytes32,
    pub body_root: Bytes32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlockBody {
    pub attestations: Attestations,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Block {
    pub slot: Slot,
    pub proposer_index: ValidatorIndex,
    pub parent_root: Bytes32,
    pub state_root: Bytes32,
    pub body: BlockBody,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlockWithAttestation {
    pub block: Block,
    /// Spec defines a single proposer attestation.
    pub proposer_attestation: Attestation,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlockSignatures {
    pub attestation_signatures: AttestationSignatures,
    pub proposer_signature: Bytes3112,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedBlockWithAttestation {
    pub message: BlockWithAttestation,
    pub signature: BlockSignatures,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlockWithSignatures {
    pub block: Block,
    pub signatures: AttestationSignatures,
}

impl SszElement for Block {}
impl SszElement for SignedBlockWithAttestation {}

impl SignedBlockWithAttestation {
    /// Basic structural checks for a signed block envelope.
    pub fn validate_basic(&self) -> Result<(), String> {
        let block = &self.message.block;
        let sig_count = self.signature.attestation_signatures.data.len();
        let att_count = block.body.attestations.data.len();
        if sig_count != att_count {
            return Err(format!(
                "attestation signatures count {} does not match attestations {}",
                sig_count, att_count
            ));
        }
        let proposer_attestation = &self.message.proposer_attestation;
        if proposer_attestation.data.slot != block.slot {
            return Err("proposer attestation slot does not match block slot".to_string());
        }
        let proposer_bit = single_set_bit(&proposer_attestation.aggregation_bits)
            .ok_or_else(|| "proposer attestation must have exactly one participant".to_string())?;
        if proposer_bit != block.proposer_index.0.0 as usize {
            return Err("proposer attestation does not match proposer index".to_string());
        }
        Ok(())
    }
}

fn single_set_bit(
    bits: &BitList<{ crate::containers::attestation::VALIDATOR_REGISTRY_LIMIT }>,
) -> Option<usize> {
    let mut found = None;
    let len = bits.len();
    //SIMDDDDDDDDDDDDDDDD
    for i in 0..len {
        let byte = i / 8;
        let bit = i % 8;
        if byte >= bits.data.len() {
            break;
        }
        if (bits.data[byte] & (1u8 << bit)) != 0 {
            if found.is_some() {
                return None;
            }
            found = Some(i);
        }
    }
    found
}

impl SszEncode for BlockHeader {
    fn encode_ssz(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(112);
        unsafe { out.set_len(112) };
        unsafe { write_bytes_at(&mut out, 0, &self.slot.0.0.to_le_bytes()) };
        unsafe { write_bytes_at(&mut out, 8, &self.proposer_index.0.0.to_le_bytes()) };
        unsafe { write_bytes_at(&mut out, 16, self.parent_root.as_ref()) };
        unsafe { write_bytes_at(&mut out, 48, self.state_root.as_ref()) };
        unsafe { write_bytes_at(&mut out, 80, self.body_root.as_ref()) };
        out
    }
}

impl SszDecode for BlockHeader {
    fn decode_ssz(bytes: &[u8]) -> Result<Self, String> {
        let slot = Slot::decode_ssz(&bytes[0..8])?;
        let proposer_index = ValidatorIndex::decode_ssz(&bytes[8..16])?;
        let parent_root = Bytes32::from_slice(&bytes[16..48]);
        let state_root = Bytes32::from_slice(&bytes[48..80]);
        let body_root = Bytes32::from_slice(&bytes[80..112]);
        Ok(Self {
            slot,
            proposer_index,
            parent_root,
            state_root,
            body_root,
        })
    }
}

impl BlockHeader {
    pub fn decode_ssz_checked(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() != Self::fixed_len() {
            return Err(format!(
                "BlockHeader expects {} bytes, got {}",
                Self::fixed_len(),
                bytes.len()
            ));
        }
        Self::decode_ssz(bytes)
    }
}

impl HashTreeRoot for BlockHeader {
    fn hash_tree_root(&self) -> [u8; 32] {
        let field_roots = [
            Bytes32::from(self.slot.hash_tree_root()),
            Bytes32::from(self.proposer_index.hash_tree_root()),
            self.parent_root,
            self.state_root,
            self.body_root,
        ];
        let root = merkleize_tree_root(&field_roots);
        *root.as_ref()
    }
}

impl SszFixedLen for BlockHeader {
    fn fixed_len() -> usize {
        112
    }
}

impl SszEncode for BlockBody {
    fn encode_ssz(&self) -> Vec<u8> {
        let fixed_len = 4;
        let attestations = self.attestations.encode_ssz();
        let mut fixed = Vec::with_capacity(fixed_len);
        let mut variable = Vec::with_capacity(attestations.len());

        let mut offsets = [0u32; 1];
        let offset = fixed_len;

        offsets[0] = offset as u32;
        unsafe { variable.set_len(attestations.len()) };
        unsafe { write_bytes_at(&mut variable, 0, &attestations) };

        unsafe { fixed.set_len(fixed_len) };
        unsafe { write_bytes_at(&mut fixed, 0, &offsets[0].to_le_bytes()) };
        fixed.extend_from_slice(&variable);
        fixed
    }
}

impl SszDecode for BlockBody {
    fn decode_ssz(bytes: &[u8]) -> Result<Self, String> {
        let mut buf = [0u8; 4];
        buf.copy_from_slice(&bytes[0..4]);
        let offset = u32::from_le_bytes(buf) as usize;
        let scope = bytes.len();

        let attestations = Attestations::decode_ssz(&bytes[offset..scope])?;
        Ok(Self { attestations })
    }
}

impl BlockBody {
    pub fn decode_ssz_checked(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < 4 {
            return Err("BlockBody missing offset table".to_string());
        }
        let mut buf = [0u8; 4];
        buf.copy_from_slice(&bytes[0..4]);
        let offset = u32::from_le_bytes(buf) as usize;
        if offset != 4 || offset > bytes.len() {
            return Err("BlockBody offset is invalid".to_string());
        }
        let attestations = Attestations::decode_ssz_checked(&bytes[offset..])?;
        Ok(Self { attestations })
    }
}

impl HashTreeRoot for BlockBody {
    fn hash_tree_root(&self) -> [u8; 32] {
        self.attestations.hash_tree_root()
    }
}

impl SszEncode for Block {
    fn encode_ssz(&self) -> Vec<u8> {
        let fixed_len = 8 + 8 + 32 + 32 + 4;
        let body = self.body.encode_ssz();
        let mut fixed = Vec::with_capacity(fixed_len);
        let mut variable = Vec::with_capacity(body.len());

        unsafe { fixed.set_len(fixed_len) };
        unsafe { write_bytes_at(&mut fixed, 0, &self.slot.0.0.to_le_bytes()) };
        unsafe { write_bytes_at(&mut fixed, 8, &self.proposer_index.0.0.to_le_bytes()) };
        unsafe { write_bytes_at(&mut fixed, 16, self.parent_root.as_ref()) };
        unsafe { write_bytes_at(&mut fixed, 48, self.state_root.as_ref()) };

        let mut offsets = [0u32; 1];
        let offset = fixed_len;

        offsets[0] = offset as u32;
        unsafe { variable.set_len(body.len()) };
        unsafe { write_bytes_at(&mut variable, 0, &body) };

        unsafe { write_bytes_at(&mut fixed, 80, &offsets[0].to_le_bytes()) };
        fixed.extend_from_slice(&variable);
        fixed
    }
}

impl SszDecode for Block {
    fn decode_ssz(bytes: &[u8]) -> Result<Self, String> {
        let slot = Slot::decode_ssz(&bytes[0..8])?;
        let proposer_index = ValidatorIndex::decode_ssz(&bytes[8..16])?;
        let parent_root = Bytes32::from_slice(&bytes[16..48]);
        let state_root = Bytes32::from_slice(&bytes[48..80]);
        let mut buf = [0u8; 4];
        buf.copy_from_slice(&bytes[80..84]);
        let offset = u32::from_le_bytes(buf) as usize;
        let body = BlockBody::decode_ssz(&bytes[offset..])?;
        Ok(Self {
            slot,
            proposer_index,
            parent_root,
            state_root,
            body,
        })
    }
}

impl Block {
    pub fn decode_ssz_checked(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < 8 + 8 + 32 + 32 + 4 {
            return Err("Block missing offset table".to_string());
        }
        let slot = Slot::decode_ssz(&bytes[0..8])?;
        let proposer_index = ValidatorIndex::decode_ssz(&bytes[8..16])?;
        let parent_root = Bytes32::from_slice(&bytes[16..48]);
        let state_root = Bytes32::from_slice(&bytes[48..80]);
        let mut buf = [0u8; 4];
        buf.copy_from_slice(&bytes[80..84]);
        let offset = u32::from_le_bytes(buf) as usize;
        if offset != 84 || offset > bytes.len() {
            return Err("Block offset is invalid".to_string());
        }
        let body = BlockBody::decode_ssz_checked(&bytes[offset..])?;
        Ok(Self {
            slot,
            proposer_index,
            parent_root,
            state_root,
            body,
        })
    }

    pub fn header(&self) -> BlockHeader {
        BlockHeader {
            slot: self.slot,
            proposer_index: self.proposer_index,
            parent_root: self.parent_root,
            state_root: self.state_root,
            body_root: Bytes32::from(self.body.hash_tree_root()),
        }
    }
}

impl HashTreeRoot for Block {
    fn hash_tree_root(&self) -> [u8; 32] {
        let field_roots = [
            Bytes32::from(self.slot.hash_tree_root()),
            Bytes32::from(self.proposer_index.hash_tree_root()),
            self.parent_root,
            self.state_root,
            Bytes32::from(self.body.hash_tree_root()),
        ];
        let root = merkleize_tree_root(&field_roots);
        *root.as_ref()
    }
}

impl SszEncode for BlockWithAttestation {
    fn encode_ssz(&self) -> Vec<u8> {
        let block = self.block.encode_ssz();
        let proposer = self.proposer_attestation.encode_ssz();
        let fixed_len = 8;
        let mut out = Vec::with_capacity(fixed_len + block.len() + proposer.len());
        unsafe { out.set_len(fixed_len + block.len() + proposer.len()) };
        let off_block = fixed_len as u32;
        let off_proposer = (fixed_len + block.len()) as u32;
        unsafe { write_bytes_at(&mut out, 0, &off_block.to_le_bytes()) };
        unsafe { write_bytes_at(&mut out, 4, &off_proposer.to_le_bytes()) };
        unsafe { write_bytes_at(&mut out, fixed_len, &block) };
        unsafe { write_bytes_at(&mut out, fixed_len + block.len(), &proposer) };
        out
    }
}

impl SszDecode for BlockWithAttestation {
    fn decode_ssz(bytes: &[u8]) -> Result<Self, String> {
        let mut buf = [0u8; 4];
        buf.copy_from_slice(&bytes[0..4]);
        let off_block = u32::from_le_bytes(buf) as usize;
        buf.copy_from_slice(&bytes[4..8]);
        let off_proposer = u32::from_le_bytes(buf) as usize;
        let block = Block::decode_ssz(&bytes[off_block..off_proposer])?;
        let proposer_attestation = Attestation::decode_ssz(&bytes[off_proposer..])?;
        Ok(Self {
            block,
            proposer_attestation,
        })
    }
}

impl BlockWithAttestation {
    pub fn decode_ssz_checked(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < 8 {
            return Err("BlockWithAttestation missing offset table".to_string());
        }
        let mut buf = [0u8; 4];
        buf.copy_from_slice(&bytes[0..4]);
        let off_block = u32::from_le_bytes(buf) as usize;
        buf.copy_from_slice(&bytes[4..8]);
        let off_proposer = u32::from_le_bytes(buf) as usize;
        if off_block != 8 || off_proposer < off_block || off_proposer > bytes.len() {
            return Err("BlockWithAttestation offsets are invalid".to_string());
        }
        let block = Block::decode_ssz_checked(&bytes[off_block..off_proposer])?;
        let proposer_attestation = Attestation::decode_ssz_checked(&bytes[off_proposer..])?;
        Ok(Self {
            block,
            proposer_attestation,
        })
    }
}

impl HashTreeRoot for BlockWithAttestation {
    fn hash_tree_root(&self) -> [u8; 32] {
        let block_root = Bytes32::from(self.block.hash_tree_root());
        let proposer_root = Bytes32::from(self.proposer_attestation.hash_tree_root());
        let root = hash_nodes(&block_root, &proposer_root);
        *root.as_ref()
    }
}

impl SszEncode for BlockSignatures {
    fn encode_ssz(&self) -> Vec<u8> {
        let sigs = self.attestation_signatures.encode_ssz();
        let fixed_len = 4 + Bytes3112::LEN;
        let mut out = Vec::with_capacity(fixed_len + sigs.len());
        unsafe { out.set_len(fixed_len + sigs.len()) };
        let off_sigs = fixed_len as u32;
        unsafe { write_bytes_at(&mut out, 0, &off_sigs.to_le_bytes()) };
        unsafe { write_bytes_at(&mut out, 4, self.proposer_signature.as_ref()) };
        unsafe { write_bytes_at(&mut out, fixed_len, &sigs) };
        out
    }
}

impl SszDecode for BlockSignatures {
    fn decode_ssz(bytes: &[u8]) -> Result<Self, String> {
        let mut buf = [0u8; 4];
        buf.copy_from_slice(&bytes[0..4]);
        let off_sigs = u32::from_le_bytes(buf) as usize;
        let proposer_signature = Bytes3112::from_slice(&bytes[4..(4 + Bytes3112::LEN)]);
        let attestation_signatures = AttestationSignatures::decode_ssz(&bytes[off_sigs..])?;
        Ok(Self {
            attestation_signatures,
            proposer_signature,
        })
    }
}

impl BlockSignatures {
    pub fn decode_ssz_checked(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < 4 + Bytes3112::LEN {
            return Err("BlockSignatures missing offset table".to_string());
        }
        let mut buf = [0u8; 4];
        buf.copy_from_slice(&bytes[0..4]);
        let off_sigs = u32::from_le_bytes(buf) as usize;
        if off_sigs != 4 + Bytes3112::LEN || off_sigs > bytes.len() {
            return Err("BlockSignatures offsets are invalid".to_string());
        }
        let proposer_signature = Bytes3112::from_slice(&bytes[4..(4 + Bytes3112::LEN)]);
        let attestation_signatures = AttestationSignatures::decode_ssz_checked(&bytes[off_sigs..])?;
        Ok(Self {
            attestation_signatures,
            proposer_signature,
        })
    }
}

impl HashTreeRoot for BlockSignatures {
    fn hash_tree_root(&self) -> [u8; 32] {
        let sigs_root = Bytes32::from(self.attestation_signatures.hash_tree_root());
        let proposer_root = Bytes32::from(self.proposer_signature.hash_tree_root());
        let root = hash_nodes(&sigs_root, &proposer_root);
        *root.as_ref()
    }
}

impl SszEncode for SignedBlockWithAttestation {
    fn encode_ssz(&self) -> Vec<u8> {
        let msg = self.message.encode_ssz();
        let sig = self.signature.encode_ssz();
        let fixed_len = 8;
        let mut out = Vec::with_capacity(fixed_len + msg.len() + sig.len());
        unsafe { out.set_len(fixed_len + msg.len() + sig.len()) };
        let off_msg = fixed_len as u32;
        let off_sig = (fixed_len + msg.len()) as u32;
        unsafe { write_bytes_at(&mut out, 0, &off_msg.to_le_bytes()) };
        unsafe { write_bytes_at(&mut out, 4, &off_sig.to_le_bytes()) };
        unsafe { write_bytes_at(&mut out, fixed_len, &msg) };
        unsafe { write_bytes_at(&mut out, fixed_len + msg.len(), &sig) };
        out
    }
}

impl SszDecode for SignedBlockWithAttestation {
    fn decode_ssz(bytes: &[u8]) -> Result<Self, String> {
        let mut buf = [0u8; 4];
        buf.copy_from_slice(&bytes[0..4]);
        let off_msg = u32::from_le_bytes(buf) as usize;
        buf.copy_from_slice(&bytes[4..8]);
        let off_sig = u32::from_le_bytes(buf) as usize;
        let message = BlockWithAttestation::decode_ssz(&bytes[off_msg..off_sig])?;
        let signature = BlockSignatures::decode_ssz(&bytes[off_sig..])?;
        Ok(Self { message, signature })
    }
}

impl SignedBlockWithAttestation {
    pub fn decode_ssz_checked(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < 8 {
            return Err("SignedBlockWithAttestation missing offset table".to_string());
        }
        let mut buf = [0u8; 4];
        buf.copy_from_slice(&bytes[0..4]);
        let off_msg = u32::from_le_bytes(buf) as usize;
        buf.copy_from_slice(&bytes[4..8]);
        let off_sig = u32::from_le_bytes(buf) as usize;
        if off_msg != 8 || off_sig < off_msg || off_sig > bytes.len() {
            return Err("SignedBlockWithAttestation offsets are invalid".to_string());
        }
        let message = BlockWithAttestation::decode_ssz_checked(&bytes[off_msg..off_sig])?;
        let signature = BlockSignatures::decode_ssz_checked(&bytes[off_sig..])?;
        Ok(Self { message, signature })
    }
}

impl HashTreeRoot for SignedBlockWithAttestation {
    fn hash_tree_root(&self) -> [u8; 32] {
        let msg_root = Bytes32::from(self.message.hash_tree_root());
        let sig_root = Bytes32::from(self.signature.hash_tree_root());
        let root = hash_nodes(&msg_root, &sig_root);
        *root.as_ref()
    }
}

impl SszEncode for BlockWithSignatures {
    fn encode_ssz(&self) -> Vec<u8> {
        let block = self.block.encode_ssz();
        let sigs = self.signatures.encode_ssz();
        let fixed_len = 8;
        let mut out = Vec::with_capacity(fixed_len + block.len() + sigs.len());
        unsafe { out.set_len(fixed_len + block.len() + sigs.len()) };
        let off_block = fixed_len as u32;
        let off_sigs = (fixed_len + block.len()) as u32;
        unsafe { write_bytes_at(&mut out, 0, &off_block.to_le_bytes()) };
        unsafe { write_bytes_at(&mut out, 4, &off_sigs.to_le_bytes()) };
        unsafe { write_bytes_at(&mut out, fixed_len, &block) };
        unsafe { write_bytes_at(&mut out, fixed_len + block.len(), &sigs) };
        out
    }
}

impl SszDecode for BlockWithSignatures {
    fn decode_ssz(bytes: &[u8]) -> Result<Self, String> {
        let mut buf = [0u8; 4];
        buf.copy_from_slice(&bytes[0..4]);
        let off_block = u32::from_le_bytes(buf) as usize;
        buf.copy_from_slice(&bytes[4..8]);
        let off_sigs = u32::from_le_bytes(buf) as usize;
        let block = Block::decode_ssz(&bytes[off_block..off_sigs])?;
        let signatures = AttestationSignatures::decode_ssz(&bytes[off_sigs..])?;
        Ok(Self { block, signatures })
    }
}

impl BlockWithSignatures {
    pub fn decode_ssz_checked(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < 8 {
            return Err("BlockWithSignatures missing offset table".to_string());
        }
        let mut buf = [0u8; 4];
        buf.copy_from_slice(&bytes[0..4]);
        let off_block = u32::from_le_bytes(buf) as usize;
        buf.copy_from_slice(&bytes[4..8]);
        let off_sigs = u32::from_le_bytes(buf) as usize;
        if off_block != 8 || off_sigs < off_block || off_sigs > bytes.len() {
            return Err("BlockWithSignatures offsets are invalid".to_string());
        }
        let block = Block::decode_ssz_checked(&bytes[off_block..off_sigs])?;
        let signatures = AttestationSignatures::decode_ssz_checked(&bytes[off_sigs..])?;
        Ok(Self { block, signatures })
    }
}

impl HashTreeRoot for BlockWithSignatures {
    fn hash_tree_root(&self) -> [u8; 32] {
        let block_root = Bytes32::from(self.block.hash_tree_root());
        let sigs_root = Bytes32::from(self.signatures.hash_tree_root());
        let root = hash_nodes(&block_root, &sigs_root);
        *root.as_ref()
    }
}
