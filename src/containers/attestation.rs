use crate::containers::checkpoint::Checkpoint;
use crate::slot::Slot;
use crate::ssz::hash::{hash_nodes, merkleize_tree_root_3};
use crate::ssz::{HashTreeRoot, SszDecode, SszEncode, SszElement, SszFixedLen};
use crate::types::bitlist::BitList;
use crate::types::bytes::{ByteList, Bytes3112, Bytes32};
use crate::types::uint::Uint64;
use crate::unsafe_vec::write_bytes_at;

pub const VALIDATOR_REGISTRY_LIMIT: usize = 4_096;
pub const SIGNATURE_BYTES: usize = 3_112;
pub const PROOF_MAX_BYTES: usize = 1_048_576;

/// Attestation content describing the validator's observed chain view.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttestationData {
    pub slot: Slot,
    pub head: Checkpoint,
    pub target: Checkpoint,
    pub source: Checkpoint,
}

/// Aggregated attestation consisting of participation bits and message.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Attestation {
    pub aggregation_bits: BitList<VALIDATOR_REGISTRY_LIMIT>,
    pub data: AttestationData,
}

pub type AggregatedAttestation = Attestation;

/// Validator attestation bundled with its signature.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedAttestation {
    pub validator_id: Uint64,
    pub message: AttestationData,
    pub signature: Bytes3112,
}

/// Aggregated signature proof bundled with participants.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AggregatedSignatureProof {
    pub participants: BitList<VALIDATOR_REGISTRY_LIMIT>,
    pub proof_data: ByteList<PROOF_MAX_BYTES>,
}

impl SszEncode for AttestationData {
    fn encode_ssz(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + 40 * 3);
        unsafe { out.set_len(8 + 40 * 3) };
        unsafe { write_bytes_at(&mut out, 0, &self.slot.0 .0.to_le_bytes()) };
        unsafe { write_bytes_at(&mut out, 8, &self.head.encode_ssz()) };
        unsafe { write_bytes_at(&mut out, 48, &self.target.encode_ssz()) };
        unsafe { write_bytes_at(&mut out, 88, &self.source.encode_ssz()) };
        out
    }
}

impl SszDecode for AttestationData {
    fn decode_ssz(bytes: &[u8]) -> Result<Self, String> {
        let slot = Slot::decode_ssz(&bytes[0..8])?;
        let head = Checkpoint::decode_ssz(&bytes[8..48])?;
        let target = Checkpoint::decode_ssz(&bytes[48..88])?;
        let source = Checkpoint::decode_ssz(&bytes[88..128])?;
        Ok(Self {
            slot,
            head,
            target,
            source,
        })
    }
}

impl AttestationData {
    pub fn decode_ssz_checked(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() != Self::fixed_len() {
            return Err(format!(
                "AttestationData expects {} bytes, got {}",
                Self::fixed_len(),
                bytes.len()
            ));
        }
        Self::decode_ssz(bytes)
    }
}

impl HashTreeRoot for AttestationData {
    fn hash_tree_root(&self) -> [u8; 32] {
        let slot_root = Bytes32::from(self.slot.hash_tree_root());
        let head_root = Bytes32::from(self.head.hash_tree_root());
        let target_root = Bytes32::from(self.target.hash_tree_root());
        let source_root = Bytes32::from(self.source.hash_tree_root());
        let root = merkleize_tree_root_3(&[slot_root, head_root, target_root]);
        let root = hash_nodes(&root, &source_root);
        *root.as_ref()
    }
}

impl SszFixedLen for AttestationData {
    fn fixed_len() -> usize {
        8 + 40 * 3
    }
}

impl SszEncode for Attestation {
    fn encode_ssz(&self) -> Vec<u8> {
        let data_bytes = self.data.encode_ssz();
        let bits = self.aggregation_bits.encode_ssz();
        let fixed_len = 4 + data_bytes.len();
        let mut out = Vec::with_capacity(fixed_len + bits.len());
        unsafe { out.set_len(fixed_len + bits.len()) };
        let offset = fixed_len as u32;
        unsafe { write_bytes_at(&mut out, 0, &offset.to_le_bytes()) };
        unsafe { write_bytes_at(&mut out, 4, &data_bytes) };
        unsafe { write_bytes_at(&mut out, fixed_len, &bits) };
        out
    }
}

impl SszDecode for Attestation {
    fn decode_ssz(bytes: &[u8]) -> Result<Self, String> {
        let mut buf = [0u8; 4];
        buf.copy_from_slice(&bytes[0..4]);
        let offset = u32::from_le_bytes(buf) as usize;
        let data = AttestationData::decode_ssz(&bytes[4..offset])?;
        let aggregation_bits = BitList::decode_ssz(&bytes[offset..])?;
        Ok(Self {
            aggregation_bits,
            data,
        })
    }
}

impl Attestation {
    pub fn decode_ssz_checked(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < 4 + AttestationData::fixed_len() {
            return Err("Attestation missing offset table".to_string());
        }
        Self::decode_ssz(bytes)
    }
}

impl HashTreeRoot for Attestation {
    fn hash_tree_root(&self) -> [u8; 32] {
        let bits_root = Bytes32::from(self.aggregation_bits.hash_tree_root());
        let data_root = Bytes32::from(self.data.hash_tree_root());
        let root = hash_nodes(&bits_root, &data_root);
        *root.as_ref()
    }
}

impl SszElement for Attestation {}

impl SszEncode for SignedAttestation {
    fn encode_ssz(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + 128 + SIGNATURE_BYTES);
        unsafe { out.set_len(8 + 128 + SIGNATURE_BYTES) };
        unsafe { write_bytes_at(&mut out, 0, &self.validator_id.0.to_le_bytes()) };
        let message = self.message.encode_ssz();
        unsafe { write_bytes_at(&mut out, 8, &message) };
        unsafe { write_bytes_at(&mut out, 136, self.signature.as_ref()) };
        out
    }
}

impl SszDecode for SignedAttestation {
    fn decode_ssz(bytes: &[u8]) -> Result<Self, String> {
        let validator_id = Uint64::decode_ssz(&bytes[0..8])?;
        let message = AttestationData::decode_ssz(&bytes[8..136])?;
        let signature = Bytes3112::from_slice(&bytes[136..(136 + SIGNATURE_BYTES)]);
        Ok(Self {
            validator_id,
            message,
            signature,
        })
    }
}

impl SignedAttestation {
    pub fn decode_ssz_checked(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() != Self::fixed_len() {
            return Err(format!(
                "SignedAttestation expects {} bytes, got {}",
                Self::fixed_len(),
                bytes.len()
            ));
        }
        Self::decode_ssz(bytes)
    }
}

impl HashTreeRoot for SignedAttestation {
    fn hash_tree_root(&self) -> [u8; 32] {
        let validator_root = Bytes32::from(self.validator_id.hash_tree_root());
        let message_root = Bytes32::from(self.message.hash_tree_root());
        let signature_root = Bytes32::from(self.signature.hash_tree_root());
        let root = merkleize_tree_root_3(&[validator_root, message_root, signature_root]);
        *root.as_ref()
    }
}

impl SszFixedLen for SignedAttestation {
    fn fixed_len() -> usize {
        8 + 128 + SIGNATURE_BYTES
    }
}


impl SszEncode for AggregatedSignatureProof {
    fn encode_ssz(&self) -> Vec<u8> {
        let bits = self.participants.encode_ssz();
        let proof = self.proof_data.encode_ssz();
        let fixed_len = 8;
        let mut out = Vec::with_capacity(fixed_len + bits.len() + proof.len());
        unsafe { out.set_len(fixed_len + bits.len() + proof.len()) };
        let off_bits = fixed_len as u32;
        let off_proof = (fixed_len + bits.len()) as u32;
        unsafe { write_bytes_at(&mut out, 0, &off_bits.to_le_bytes()) };
        unsafe { write_bytes_at(&mut out, 4, &off_proof.to_le_bytes()) };
        unsafe { write_bytes_at(&mut out, fixed_len, &bits) };
        unsafe { write_bytes_at(&mut out, fixed_len + bits.len(), &proof) };
        out
    }
}

impl SszDecode for AggregatedSignatureProof {
    fn decode_ssz(bytes: &[u8]) -> Result<Self, String> {
        let mut buf = [0u8; 4];
        buf.copy_from_slice(&bytes[0..4]);
        let off_bits = u32::from_le_bytes(buf) as usize;
        buf.copy_from_slice(&bytes[4..8]);
        let off_proof = u32::from_le_bytes(buf) as usize;
        let participants = BitList::decode_ssz(&bytes[off_bits..off_proof])?;
        let proof_data = ByteList::decode_ssz(&bytes[off_proof..])?;
        Ok(Self {
            participants,
            proof_data,
        })
    }
}

impl HashTreeRoot for AggregatedSignatureProof {
    fn hash_tree_root(&self) -> [u8; 32] {
        let bits_root = Bytes32::from(self.participants.hash_tree_root());
        let proof_root = Bytes32::from(self.proof_data.hash_tree_root());
        let root = hash_nodes(&bits_root, &proof_root);
        *root.as_ref()
    }
}

impl SszElement for AggregatedSignatureProof {}
