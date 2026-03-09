use crate::containers::attestation::{
    AggregatedSignatureProof, Attestation, AttestationData, VALIDATOR_REGISTRY_LIMIT,
};
use crate::containers::validator::ValidatorIndex;
use crate::slot::Slot;
use crate::ssz::hash::{hash_nodes, merkleize_tree_root};
use crate::ssz::{HashTreeRoot, SszDecode, SszElement, SszEncode, SszFixedLen};
use crate::types::bitlist::BitList;
use crate::types::bytes::{Bytes32, Bytes3112};
use crate::types::collections::SszList;
use crate::unsafe_vec::write_bytes_at;

/// Maximum number of attestations that can appear in a single block body.
pub const ATTESTATIONS_LIMIT: usize = 4_096;

/// SSZ list of [`Attestation`]s included in a block body.
pub type Attestations = SszList<Attestation, ATTESTATIONS_LIMIT>;

/// SSZ list of [`AggregatedSignatureProof`]s, one per attestation in the block body.
/// Parallel index to [`Attestations`].
pub type AttestationSignatures = SszList<AggregatedSignatureProof, ATTESTATIONS_LIMIT>;

/// The compact header of a block: all fields except the body itself.
///
/// Used as the canonical identifier for a block (via `hash_tree_root`) and stored
/// in [`State::latest_block_header`] during and after a state transition.
///
/// `state_root` is zeroed while the transition is in-flight and written back once
/// the post-state root has been verified.
///
/// # SSZ layout (fixed, 112 bytes)
///
/// | Byte range | Field             |
/// |------------|-------------------|
/// | 0 – 7      | `slot`            |
/// | 8 – 15     | `proposer_index`  |
/// | 16 – 47    | `parent_root`     |
/// | 48 – 79    | `state_root`      |
/// | 80 – 111   | `body_root`       |
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct BlockHeader {
    /// Slot at which this block was proposed.
    pub slot: Slot,
    /// Validator index of the block proposer.
    pub proposer_index: ValidatorIndex,
    /// `hash_tree_root` of the parent block header.
    pub parent_root: Bytes32,
    /// `hash_tree_root` of the post-state; zero while the transition is in-flight.
    pub state_root: Bytes32,
    /// `hash_tree_root` of the [`BlockBody`].
    pub body_root: Bytes32,
}

/// The body of a block: the list of attestations included by the proposer.
///
/// `hash_tree_root(BlockBody)` equals `hash_tree_root(attestations)` directly,
/// since the body has only one field.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlockBody {
    /// Attestations included in this block, up to [`ATTESTATIONS_LIMIT`].
    pub attestations: Attestations,
}

/// A full block: header fields inlined together with the variable-length body.
///
/// The five header fields (`slot`, `proposer_index`, `parent_root`, `state_root`,
/// `body`) mirror [`BlockHeader`]; `body_root` is derived on demand via
/// [`Block::header`].
///
/// # SSZ layout (variable)
///
/// | Byte range | Field                    |
/// |------------|--------------------------|
/// | 0 – 7      | `slot`                   |
/// | 8 – 15     | `proposer_index`         |
/// | 16 – 47    | `parent_root`            |
/// | 48 – 79    | `state_root`             |
/// | 80 – 83    | `body` offset (4 B, LE)  |
/// | 84 – …     | `body` bytes             |
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Block {
    /// Slot at which this block was proposed.
    pub slot: Slot,
    /// Validator index of the block proposer.
    pub proposer_index: ValidatorIndex,
    /// `hash_tree_root` of the parent block header.
    pub parent_root: Bytes32,
    /// `hash_tree_root` of the post-state.
    pub state_root: Bytes32,
    /// Block body containing the attestations.
    pub body: BlockBody,
}

/// A [`Block`] paired with the proposer's own attestation.
///
/// The proposer attestation is submitted alongside the block so that the
/// proposer's vote is immediately visible to fork-choice without waiting
/// for a separate aggregate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlockWithAttestation {
    /// The proposed block.
    pub block: Block,
    /// The proposer's attestation, which must have exactly one participant
    /// matching `block.proposer_index`.
    pub proposer_attestation: Attestation,
}

/// Signature bundle for a [`BlockWithAttestation`].
///
/// Contains one [`AggregatedSignatureProof`] per attestation in the block body
/// (parallel to `block.body.attestations`) plus the proposer's individual
/// post-quantum signature.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlockSignatures {
    /// Aggregated proofs for each attestation in the block body.
    pub attestation_signatures: AttestationSignatures,
    /// Proposer's post-quantum signature over `hash_tree_root(proposer_attestation.data)`.
    pub proposer_signature: Bytes3112,
}

/// A fully signed block ready for import: message + signatures.
///
/// This is the top-level type exchanged over the network and passed to
/// [`State::process_signed_block`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedBlockWithAttestation {
    /// The block and proposer attestation.
    pub message: BlockWithAttestation,
    /// Cryptographic signatures covering the message.
    pub signature: BlockSignatures,
}

/// A [`Block`] paired with its full set of aggregated attestation signatures.
///
/// Used as an intermediate representation when signatures are attached to a
/// block separately from the proposer attestation (e.g. during gossip aggregation).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlockWithSignatures {
    /// The block.
    pub block: Block,
    /// Aggregated proofs, one per attestation in `block.body.attestations`.
    pub signatures: AttestationSignatures,
}

impl SszElement for Block {}
impl SszElement for SignedBlockWithAttestation {}

impl SignedBlockWithAttestation {
    /// Structural pre-checks before signature verification or state transition.
    ///
    /// Validates:
    /// - `attestation_signatures.len() == block.body.attestations.len()`
    /// - `proposer_attestation.data.slot == block.slot`
    /// - `proposer_attestation.aggregation_bits` has exactly one set bit
    /// - that bit's index equals `block.proposer_index`
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

/// Return the index of the single set bit in `bits`, or `None` if there are zero
/// or more than one set bits.
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

#[inline]
fn proposer_attestation_from_ream_parts(
    validator_id: u64,
    data: AttestationData,
) -> Result<Attestation, String> {
    let index = validator_id as usize;
    if index >= VALIDATOR_REGISTRY_LIMIT {
        return Err(format!(
            "proposer validator index {index} exceeds registry limit {VALIDATOR_REGISTRY_LIMIT}"
        ));
    }
    let bit_len = index + 1;
    let byte_len = bit_len.div_ceil(8);
    let mut bits = vec![0u8; byte_len];
    bits[index / 8] |= 1u8 << (index % 8);
    Ok(Attestation {
        aggregation_bits: BitList {
            data: bits,
            len: bit_len,
        },
        data,
    })
}

#[inline]
fn decode_ream_block_with_attestation(
    bytes: &[u8],
    checked: bool,
) -> Result<BlockWithAttestation, String> {
    // REAM devnet2 layout:
    // [off_block: u32][validator_id: u64][attestation_data: 128 bytes][block bytes]
    let proposer_fixed_len = 8 + AttestationData::fixed_len();
    let fixed_len = 4 + proposer_fixed_len;
    if bytes.len() < fixed_len {
        return Err("BlockWithAttestation (ream) missing fixed section".to_string());
    }
    let mut buf = [0u8; 4];
    buf.copy_from_slice(&bytes[0..4]);
    let off_block = u32::from_le_bytes(buf) as usize;
    if checked && (off_block != fixed_len || off_block > bytes.len()) {
        return Err("BlockWithAttestation (ream) offset is invalid".to_string());
    }
    if off_block < fixed_len || off_block > bytes.len() {
        return Err("BlockWithAttestation (ream) offset is out of bounds".to_string());
    }
    let validator_id = u64::from_le_bytes(
        bytes[4..12]
            .try_into()
            .map_err(|_| "BlockWithAttestation (ream) validator_id missing".to_string())?,
    );
    let attestation_data = if checked {
        AttestationData::decode_ssz_checked(&bytes[12..(12 + AttestationData::fixed_len())])?
    } else {
        AttestationData::decode_ssz(&bytes[12..(12 + AttestationData::fixed_len())])?
    };
    let proposer_attestation =
        proposer_attestation_from_ream_parts(validator_id, attestation_data)?;
    let block = if checked {
        Block::decode_ssz_checked(&bytes[off_block..])?
    } else {
        Block::decode_ssz(&bytes[off_block..])?
    };
    Ok(BlockWithAttestation {
        block,
        proposer_attestation,
    })
}

/// SSZ serialization for [`BlockHeader`] — fixed 112-byte encoding.
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

/// SSZ deserialization for [`BlockHeader`] — trusts that `bytes` is exactly 112 bytes.
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
    /// Bounds-checked SSZ deserialization for untrusted input.
    ///
    /// Returns `Err` if `bytes.len() != 112`.
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

/// Merkle hash-tree root for [`BlockHeader`].
///
/// Merklizes the five fields as a balanced 8-leaf tree (width=8) via
/// `merkleize_tree_root`: `[slot, proposer_index, parent_root, state_root, body_root]`.
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

/// SSZ serialization for [`BlockBody`] — variable-length encoding.
///
/// Layout: `[attestations_offset: u32][attestations bytes]`
/// The offset is always `4` (immediately after the single offset word).
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

/// SSZ deserialization for [`BlockBody`] — trusts that the offset is valid.
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
    /// Bounds-checked SSZ deserialization for untrusted input.
    ///
    /// Validates that total length is at least 4 bytes and that the offset
    /// equals `4` (the only valid value given a single variable field).
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

/// Merkle hash-tree root for [`BlockBody`].
///
/// Delegates directly to `attestations.hash_tree_root()` since the body has
/// only one field.
impl HashTreeRoot for BlockBody {
    fn hash_tree_root(&self) -> [u8; 32] {
        self.attestations.hash_tree_root()
    }
}

/// SSZ serialization for [`Block`] — variable-length encoding.
///
/// Layout: `[slot: 8][proposer_index: 8][parent_root: 32][state_root: 32]`
/// `[body_offset: 4][body bytes]`. The body offset is always `84`.
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

/// SSZ deserialization for [`Block`] — trusts that the body offset is valid.
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
    /// Bounds-checked SSZ deserialization for untrusted input.
    ///
    /// Validates that total length covers the fixed section (84 bytes) and
    /// that the body offset equals exactly `84`.
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

    /// Derive the [`BlockHeader`] for this block.
    ///
    /// Computes `body_root = hash_tree_root(body)` on the fly. The resulting
    /// header is what gets stored in [`State::latest_block_header`] and used
    /// as the canonical block identifier.
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

/// Merkle hash-tree root for [`Block`].
///
/// Merklizes the five logical fields as a balanced 8-leaf tree (width=8):
/// `[slot, proposer_index, parent_root, state_root, body_root]`.
/// `body_root` is computed inline as `hash_tree_root(body)`.
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

/// SSZ serialization for [`BlockWithAttestation`].
///
/// Interop canonical layout (Ream/EthLambda/Zeam):
/// `[off_block: u32][validator_id: u64][attestation_data: 128 B][block bytes]`.
///
/// We emit this format to preserve cross-client decode compatibility.
impl SszEncode for BlockWithAttestation {
    fn encode_ssz(&self) -> Vec<u8> {
        // Require exactly one proposer bit to derive validator_id for canonical wire format.
        let proposer_index = single_set_bit(&self.proposer_attestation.aggregation_bits)
            .expect("proposer attestation must have exactly one participant");
        let block = self.block.encode_ssz();
        let att_data = self.proposer_attestation.data.encode_ssz();
        let fixed_len = 4 + 8 + AttestationData::fixed_len();
        let mut out = Vec::with_capacity(fixed_len + block.len());
        unsafe { out.set_len(fixed_len + block.len()) };
        let off_block = fixed_len as u32;
        unsafe { write_bytes_at(&mut out, 0, &off_block.to_le_bytes()) };
        unsafe { write_bytes_at(&mut out, 4, &(proposer_index as u64).to_le_bytes()) };
        unsafe { write_bytes_at(&mut out, 12, &att_data) };
        unsafe { write_bytes_at(&mut out, fixed_len, &block) };
        out
    }
}

/// SSZ deserialization for [`BlockWithAttestation`] — trusts that offsets are valid.
impl SszDecode for BlockWithAttestation {
    fn decode_ssz(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < 8 {
            return Err("BlockWithAttestation missing offset table".to_string());
        }
        let mut buf = [0u8; 4];
        buf.copy_from_slice(&bytes[0..4]);
        let off_block = u32::from_le_bytes(buf) as usize;
        buf.copy_from_slice(&bytes[4..8]);
        let off_proposer = u32::from_le_bytes(buf) as usize;
        if off_block <= off_proposer && off_proposer <= bytes.len() {
            let block = Block::decode_ssz(&bytes[off_block..off_proposer])?;
            let proposer_attestation = Attestation::decode_ssz(&bytes[off_proposer..])?;
            return Ok(Self {
                block,
                proposer_attestation,
            });
        }
        decode_ream_block_with_attestation(bytes, false)
    }
}

impl BlockWithAttestation {
    /// Bounds-checked SSZ deserialization for untrusted input.
    ///
    /// Validates that total length is at least 8 bytes, `off_block == 8`,
    /// and `off_block <= off_proposer <= bytes.len()`.
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
            return decode_ream_block_with_attestation(bytes, true);
        }
        let block = Block::decode_ssz_checked(&bytes[off_block..off_proposer])?;
        let proposer_attestation = Attestation::decode_ssz_checked(&bytes[off_proposer..])?;
        Ok(Self {
            block,
            proposer_attestation,
        })
    }
}

/// Merkle hash-tree root for [`BlockWithAttestation`].
///
/// `hash_tree_root = hash_nodes(block_root, proposer_attestation_root)`
impl HashTreeRoot for BlockWithAttestation {
    fn hash_tree_root(&self) -> [u8; 32] {
        let block_root = Bytes32::from(self.block.hash_tree_root());
        let proposer_root = Bytes32::from(self.proposer_attestation.hash_tree_root());
        let root = hash_nodes(&block_root, &proposer_root);
        *root.as_ref()
    }
}

/// SSZ serialization for [`BlockSignatures`] — variable-length encoding.
///
/// Layout: `[off_sigs: u32][proposer_signature: SIGNATURE_BYTES][attestation_signatures bytes]`
/// The offset points past the fixed section (`4 + Bytes3112::LEN`).
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

/// SSZ deserialization for [`BlockSignatures`] — trusts that the offset is valid.
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
    /// Bounds-checked SSZ deserialization for untrusted input.
    ///
    /// Validates that total length covers the fixed section and that
    /// `off_sigs == 4 + Bytes3112::LEN`.
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

/// Merkle hash-tree root for [`BlockSignatures`].
///
/// `hash_tree_root = hash_nodes(attestation_signatures_root, proposer_signature_root)`
impl HashTreeRoot for BlockSignatures {
    fn hash_tree_root(&self) -> [u8; 32] {
        let sigs_root = Bytes32::from(self.attestation_signatures.hash_tree_root());
        let proposer_root = Bytes32::from(self.proposer_signature.hash_tree_root());
        let root = hash_nodes(&sigs_root, &proposer_root);
        *root.as_ref()
    }
}

/// SSZ serialization for [`SignedBlockWithAttestation`] — variable-length, two offsets.
///
/// Layout: `[off_msg: u32][off_sig: u32][message bytes][signature bytes]`
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

/// SSZ deserialization for [`SignedBlockWithAttestation`] — trusts that offsets are valid.
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
    /// Bounds-checked SSZ deserialization for untrusted input.
    ///
    /// Validates that total length is at least 8 bytes, `off_msg == 8`,
    /// and `off_msg <= off_sig <= bytes.len()`.
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

/// Merkle hash-tree root for [`SignedBlockWithAttestation`].
///
/// `hash_tree_root = hash_nodes(message_root, signature_root)`
impl HashTreeRoot for SignedBlockWithAttestation {
    fn hash_tree_root(&self) -> [u8; 32] {
        let msg_root = Bytes32::from(self.message.hash_tree_root());
        let sig_root = Bytes32::from(self.signature.hash_tree_root());
        let root = hash_nodes(&msg_root, &sig_root);
        *root.as_ref()
    }
}

/// SSZ serialization for [`BlockWithSignatures`] — variable-length, two offsets.
///
/// Layout: `[off_block: u32][off_sigs: u32][block bytes][signatures bytes]`
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

/// SSZ deserialization for [`BlockWithSignatures`] — trusts that offsets are valid.
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
    /// Bounds-checked SSZ deserialization for untrusted input.
    ///
    /// Validates that total length is at least 8 bytes, `off_block == 8`,
    /// and `off_block <= off_sigs <= bytes.len()`.
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

/// Merkle hash-tree root for [`BlockWithSignatures`].
///
/// `hash_tree_root = hash_nodes(block_root, signatures_root)`
impl HashTreeRoot for BlockWithSignatures {
    fn hash_tree_root(&self) -> [u8; 32] {
        let block_root = Bytes32::from(self.block.hash_tree_root());
        let sigs_root = Bytes32::from(self.signatures.hash_tree_root());
        let root = hash_nodes(&block_root, &sigs_root);
        *root.as_ref()
    }
}
