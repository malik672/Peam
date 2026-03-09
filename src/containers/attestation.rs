use crate::containers::checkpoint::Checkpoint;
use crate::slot::Slot;
use crate::ssz::hash::{hash_nodes, merkleize_tree_root_3};
use crate::ssz::{HashTreeRoot, SszDecode, SszElement, SszEncode, SszFixedLen};
use crate::types::bitlist::BitList;
use crate::types::bytes::{ByteList, Bytes32, Bytes3112};
use crate::types::uint::Uint64;
use crate::unsafe_vec::write_bytes_at;

/// Maximum number of validators tracked by aggregation bitfields.
pub const VALIDATOR_REGISTRY_LIMIT: usize = 4_096;
/// Number of attestation committees/subnets used by gossip validation.
pub const ATTESTATION_COMMITTEE_COUNT: u64 = 1;

/// Byte length of a post-quantum aggregate signature.
pub const SIGNATURE_BYTES: usize = 3_112;

/// Maximum byte length of a variable-length aggregated signature proof.
pub const PROOF_MAX_BYTES: usize = 1_048_576;

/// The message content of an attestation: the slot, head, target, and source checkpoints
/// that together describe the attesting validator's observed chain view.
///
/// # SSZ layout (fixed, 128 bytes)
///
/// | Byte range | Field    |
/// |------------|----------|
/// | 0 – 7      | `slot`   |
/// | 8 – 47     | `head`   |
/// | 48 – 87    | `target` |
/// | 88 – 127   | `source` |
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttestationData {
    /// Slot at which the attestation was created.
    pub slot: Slot,
    /// Validator's observed canonical head checkpoint.
    pub head: Checkpoint,
    /// Checkpoint the validator is voting to justify (target epoch boundary).
    pub target: Checkpoint,
    /// Most recently justified checkpoint the validator observed (source epoch boundary).
    pub source: Checkpoint,
}

/// Aggregated attestation: a set of validators (identified by `aggregation_bits`) all
/// attesting to the same [`AttestationData`].
///
/// The `aggregation_bits` bitfield has one bit per validator in the registry; bit `i`
/// is set when validator `i` contributed to this aggregate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Attestation {
    /// Bitfield of participating validators (one bit per validator index).
    pub aggregation_bits: BitList<VALIDATOR_REGISTRY_LIMIT>,
    /// The attested chain view shared by all participating validators.
    pub data: AttestationData,
}

/// Type alias clarifying that an [`Attestation`] carrying multiple participants is
/// an aggregated attestation.
pub type AggregatedAttestation = Attestation;

/// A single validator's attestation bundled with its post-quantum signature.
///
/// Used when a validator submits its own view before aggregation; the signature
/// covers `hash_tree_root(message)`.
///
/// # SSZ layout (fixed, 8 + 128 + `SIGNATURE_BYTES` bytes)
///
/// | Byte range                         | Field          |
/// |------------------------------------|----------------|
/// | 0 – 7                              | `validator_id` |
/// | 8 – 135                            | `message`      |
/// | 136 – 135 + `SIGNATURE_BYTES`      | `signature`    |
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedAttestation {
    /// Index of the signing validator in the registry.
    pub validator_id: Uint64,
    /// The attested chain view.
    pub message: AttestationData,
    /// Post-quantum signature over `hash_tree_root(message)`.
    pub signature: Bytes3112,
}

/// Aggregated attestation gossip payload carrying attestation data and a proof.
///
/// This matches the interop wire type used on the `/aggregation` gossipsub topic.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedAggregatedAttestation {
    /// Attested chain view shared by all participants.
    pub data: AttestationData,
    /// Aggregated signature proof and participant bitfield.
    pub proof: AggregatedSignatureProof,
}

/// An aggregated post-quantum signature proof together with the bitfield of
/// validators whose individual signatures were combined.
///
/// Paired with an [`Attestation`] inside a block body to allow signature
/// verification without re-transmitting the full message.
///
/// # SSZ layout (variable)
///
/// | Offset | Field          |
/// |--------|----------------|
/// | 0      | `participants` (offset, 4 B) |
/// | 4      | `proof_data`   (offset, 4 B) |
/// | …      | `participants` bytes         |
/// | …      | `proof_data`   bytes         |
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AggregatedSignatureProof {
    /// Bitfield of validators whose signatures were aggregated into `proof_data`.
    pub participants: BitList<VALIDATOR_REGISTRY_LIMIT>,
    /// Raw bytes of the aggregated post-quantum proof.
    pub proof_data: ByteList<PROOF_MAX_BYTES>,
}

/// SSZ serialization for [`AttestationData`] — 128-byte fixed encoding.
impl SszEncode for AttestationData {
    #[inline]
    fn encode_ssz(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + 40 * 3);
        unsafe { out.set_len(8 + 40 * 3) };
        unsafe { write_bytes_at(&mut out, 0, &self.slot.0.0.to_le_bytes()) };
        unsafe { write_bytes_at(&mut out, 8, &self.head.encode_ssz()) };
        unsafe { write_bytes_at(&mut out, 48, &self.target.encode_ssz()) };
        unsafe { write_bytes_at(&mut out, 88, &self.source.encode_ssz()) };
        out
    }
}

/// SSZ deserialization for [`AttestationData`] — trusts that `bytes` is exactly 128 bytes.
impl SszDecode for AttestationData {
    #[inline]
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
    /// Bounds-checked SSZ deserialization for untrusted input.
    ///
    /// Returns `Err` if `bytes.len() != 128`.
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

/// Merkle hash-tree root for [`AttestationData`].
///
/// Hashes all four fields and merklizes them as a balanced 4-leaf tree:
/// - Inner node of `[slot, head, target]` via `merkleize_tree_root_3`
/// - Final root = `hash_nodes(above, source_root)`
impl HashTreeRoot for AttestationData {
    fn hash_tree_root(&self) -> [u8; 32] {
        let slot_root = Bytes32::from(self.slot.hash_tree_root());
        let head_root = Bytes32::from(self.head.hash_tree_root());
        let target_root = Bytes32::from(self.target.hash_tree_root());
        let source_root = Bytes32::from(self.source.hash_tree_root());
        // Container root for 4 fields: hash(hash(slot, head), hash(target, source)).
        let left = hash_nodes(&slot_root, &head_root);
        let right = hash_nodes(&target_root, &source_root);
        let root = hash_nodes(&left, &right);
        *root.as_ref()
    }
}

impl SszFixedLen for AttestationData {
    fn fixed_len() -> usize {
        8 + 40 * 3
    }
}

/// SSZ serialization for [`Attestation`] — variable-length encoding.
///
/// Layout: `[offset: u32][data: 128 B][aggregation_bits: variable]`
/// The offset is a 4-byte little-endian pointer to where `aggregation_bits` starts
/// (always `4 + 128 = 132`).
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

/// SSZ deserialization for [`Attestation`] — trusts that the offset is valid.
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
    /// Bounds-checked SSZ deserialization for untrusted input.
    ///
    /// Returns `Err` if the total length is shorter than the minimum fixed section
    /// (`4 + AttestationData::fixed_len()`).
    pub fn decode_ssz_checked(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < 4 + AttestationData::fixed_len() {
            return Err("Attestation missing offset table".to_string());
        }
        Self::decode_ssz(bytes)
    }
}

/// Merkle hash-tree root for [`Attestation`].
///
/// `hash_tree_root = hash_nodes(aggregation_bits_root, data_root)`
impl HashTreeRoot for Attestation {
    fn hash_tree_root(&self) -> [u8; 32] {
        let bits_root = Bytes32::from(self.aggregation_bits.hash_tree_root());
        let data_root = Bytes32::from(self.data.hash_tree_root());
        let root = hash_nodes(&bits_root, &data_root);
        *root.as_ref()
    }
}

impl SszElement for Attestation {}

/// SSZ serialization for [`SignedAttestation`] — fixed-length encoding.
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

/// SSZ deserialization for [`SignedAttestation`] — trusts that `bytes` is the correct length.
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
    /// Bounds-checked SSZ deserialization for untrusted input.
    ///
    /// Returns `Err` if `bytes.len() != 8 + 128 + SIGNATURE_BYTES`.
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

/// Merkle hash-tree root for [`SignedAttestation`].
///
/// Merklizes all three fields as a balanced 3-leaf tree via `merkleize_tree_root_3`.
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

/// SSZ serialization for [`SignedAggregatedAttestation`] — variable-length.
///
/// Layout: `[data: 128 B][off_proof: u32][proof bytes]`
impl SszEncode for SignedAggregatedAttestation {
    fn encode_ssz(&self) -> Vec<u8> {
        let data_bytes = self.data.encode_ssz();
        let proof_bytes = self.proof.encode_ssz();
        let fixed_len = data_bytes.len() + 4;
        let mut out = Vec::with_capacity(fixed_len + proof_bytes.len());
        unsafe { out.set_len(fixed_len + proof_bytes.len()) };
        unsafe { write_bytes_at(&mut out, 0, &data_bytes) };
        unsafe {
            write_bytes_at(
                &mut out,
                data_bytes.len(),
                &(fixed_len as u32).to_le_bytes(),
            )
        };
        unsafe { write_bytes_at(&mut out, fixed_len, &proof_bytes) };
        out
    }
}

/// SSZ deserialization for [`SignedAggregatedAttestation`] — trusts offset validity.
impl SszDecode for SignedAggregatedAttestation {
    fn decode_ssz(bytes: &[u8]) -> Result<Self, String> {
        let data_len = AttestationData::fixed_len();
        let data = AttestationData::decode_ssz(&bytes[..data_len])?;
        let mut buf = [0u8; 4];
        buf.copy_from_slice(&bytes[data_len..(data_len + 4)]);
        let off_proof = u32::from_le_bytes(buf) as usize;
        let proof = AggregatedSignatureProof::decode_ssz(&bytes[off_proof..])?;
        Ok(Self { data, proof })
    }
}

impl SignedAggregatedAttestation {
    /// Bounds-checked SSZ deserialization for untrusted input.
    pub fn decode_ssz_checked(bytes: &[u8]) -> Result<Self, String> {
        let data_len = AttestationData::fixed_len();
        let min_len = data_len + 4;
        if bytes.len() < min_len {
            return Err(format!(
                "SignedAggregatedAttestation expects at least {min_len} bytes, got {}",
                bytes.len()
            ));
        }
        let mut buf = [0u8; 4];
        buf.copy_from_slice(&bytes[data_len..min_len]);
        let off_proof = u32::from_le_bytes(buf) as usize;
        if off_proof < min_len || off_proof > bytes.len() {
            return Err(format!(
                "SignedAggregatedAttestation invalid proof offset {off_proof} for length {}",
                bytes.len()
            ));
        }
        Self::decode_ssz(bytes)
    }
}

impl HashTreeRoot for SignedAggregatedAttestation {
    fn hash_tree_root(&self) -> [u8; 32] {
        let data_root = Bytes32::from(self.data.hash_tree_root());
        let proof_root = Bytes32::from(self.proof.hash_tree_root());
        let root = hash_nodes(&data_root, &proof_root);
        *root.as_ref()
    }
}

/// SSZ serialization for [`AggregatedSignatureProof`] — variable-length encoding.
///
/// Layout: `[off_participants: u32][off_proof: u32][participants bytes][proof bytes]`
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

/// SSZ deserialization for [`AggregatedSignatureProof`] — trusts that offsets are valid.
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

/// Merkle hash-tree root for [`AggregatedSignatureProof`].
///
/// `hash_tree_root = hash_nodes(participants_root, proof_data_root)`
impl HashTreeRoot for AggregatedSignatureProof {
    fn hash_tree_root(&self) -> [u8; 32] {
        let bits_root = Bytes32::from(self.participants.hash_tree_root());
        let proof_root = Bytes32::from(self.proof_data.hash_tree_root());
        let root = hash_nodes(&bits_root, &proof_root);
        *root.as_ref()
    }
}

impl SszElement for AggregatedSignatureProof {}
