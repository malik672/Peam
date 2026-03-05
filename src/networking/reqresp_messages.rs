//! Typed req/resp protocol messages and their SSZ codecs.
//!
//! [`LeanSupportedProtocol`] enumerates all supported protocol IDs and
//! handles protocol-ID string parsing and construction.
//!
//! [`LeanRequestMessage`] and [`LeanResponseMessage`] are the typed envelopes
//! used above the raw byte layer; both implement SSZ encode/decode dispatched
//! by protocol variant.

use crate::containers::block::SignedBlockWithAttestation;
use crate::containers::checkpoint::Checkpoint;
use crate::containers::req_resp::{BlocksByRootRequest, BlocksByRootResponse, Status};
use crate::ssz::{SszEncode, SszFixedLen};
use crate::types::collections::SszList;

#[inline]
fn encode_lean_status_compat(status: &Status) -> Vec<u8> {
    // REAM lean status wire format:
    // struct Status { finalized: Checkpoint, head: Checkpoint } (80 bytes).
    let mut out = Vec::with_capacity(Checkpoint::fixed_len() * 2);
    out.extend_from_slice(
        &Checkpoint {
            root: status.finalized_root,
            slot: crate::slot::Slot(status.finalized_epoch),
        }
        .encode_ssz(),
    );
    out.extend_from_slice(
        &Checkpoint {
            root: status.head_root,
            slot: crate::slot::Slot(status.head_slot),
        }
        .encode_ssz(),
    );
    out
}

#[inline]
fn decode_lean_status_compat(data: &[u8]) -> Result<Status, String> {
    if data.len() == Status::fixed_len() {
        return Status::decode_ssz_checked(data);
    }
    let cp_len = Checkpoint::fixed_len();
    if data.len() != cp_len * 2 {
        return Err(format!(
            "unsupported status payload length: {} (expected {} or {})",
            data.len(),
            Status::fixed_len(),
            cp_len * 2
        ));
    }
    let finalized = Checkpoint::decode_ssz_checked(&data[0..cp_len])?;
    let head = Checkpoint::decode_ssz_checked(&data[cp_len..(cp_len * 2)])?;
    Ok(Status {
        fork_digest: crate::types::bytes::Bytes32::zero(),
        finalized_root: finalized.root,
        finalized_epoch: finalized.slot.0,
        head_root: head.root,
        head_slot: head.slot.0,
    })
}

#[inline]
fn decode_blocks_by_root_request_compat(data: &[u8]) -> Result<BlocksByRootRequest, String> {
    // Disambiguate by prefix when possible:
    // - peam historical wrapper starts with offset=4.
    // - REAM transparent list has no offset prefix.
    if data.len() >= 4 {
        let mut buf = [0u8; 4];
        buf.copy_from_slice(&data[..4]);
        let prefix = u32::from_le_bytes(buf) as usize;
        if prefix == 4
            && let Ok(req) = BlocksByRootRequest::decode_ssz_checked(data)
        {
            return Ok(req);
        }
    }
    let roots = SszList::decode_ssz_checked(data)?;
    Ok(BlocksByRootRequest { roots })
}

#[inline]
fn decode_blocks_by_root_response_compat(data: &[u8]) -> Result<BlocksByRootResponse, String> {
    // REAM sends one SignedBlockWithAttestation per chunk. Decode this first
    // to avoid permissive wrapper decoding from interpreting single-block bytes
    // as a malformed list.
    if let Ok(single) = SignedBlockWithAttestation::decode_ssz_checked(data) {
        let blocks =
            SszList::new(vec![single]).map_err(|err| format!("invalid block list: {err}"))?;
        return Ok(BlocksByRootResponse { blocks });
    }

    // Fallback for peam's historical wrapper form.
    if let Ok(resp) = BlocksByRootResponse::decode_ssz_checked(data) {
        return Ok(resp);
    }

    Err("unsupported BlocksByRoot response payload".to_string())
}

/// All req/resp protocols supported by the lean-Ethereum node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeanSupportedProtocol {
    /// `/leanconsensus/req/blocks_by_root/1/ssz_snappy`
    BlocksByRootV1,
    /// `/leanconsensus/req/status/1/ssz_snappy`
    StatusV1,
}

impl LeanSupportedProtocol {
    /// Returns the human-readable message name component of the protocol ID.
    pub fn message_name(&self) -> &'static str {
        match self {
            LeanSupportedProtocol::BlocksByRootV1 => "blocks_by_root",
            LeanSupportedProtocol::StatusV1 => "status",
        }
    }

    /// Returns the schema version string (`"1"` for all current protocols).
    pub fn schema_version(&self) -> &'static str {
        "1"
    }

    /// Constructs the full libp2p protocol ID string,
    /// e.g. `/leanconsensus/req/blocks_by_root/1/ssz_snappy`.
    pub fn protocol_id(&self) -> String {
        format!(
            "/leanconsensus/req/{}/{}/ssz_snappy",
            self.message_name(),
            self.schema_version()
        )
    }

    /// Parses a libp2p protocol ID string into a [`LeanSupportedProtocol`].
    ///
    /// Returns `None` if the string does not match the expected format or
    /// refers to an unknown protocol / unsupported version.
    pub fn parse_protocol_id(protocol: &str) -> Option<Self> {
        let parts: Vec<&str> = protocol.trim_start_matches('/').split('/').collect();
        let (name, version) = if parts.len() == 5
            && parts[0] == "leanconsensus"
            && parts[1] == "req"
            && parts[4] == "ssz_snappy"
        {
            (parts[2], parts[3])
        } else if parts.len() == 4 && parts[0] == "peam" && parts[1] == "reqresp" {
            // Legacy local format retained for backward compatibility.
            (parts[2], parts[3])
        } else {
            return None;
        };
        if version != "1" {
            return None;
        }
        match name {
            "blocks_by_root" => Some(LeanSupportedProtocol::BlocksByRootV1),
            "status" => Some(LeanSupportedProtocol::StatusV1),
            _ => None,
        }
    }
}

/// A typed inbound or outbound req/resp request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LeanRequestMessage {
    /// Peer status handshake.
    Status(Status),
    /// Request for blocks by their root hashes.
    BlocksByRoot(BlocksByRootRequest),
}

impl LeanRequestMessage {
    /// Returns the list of protocol ID strings this message can be sent over.
    pub fn supported_protocols(&self) -> Vec<String> {
        match self {
            LeanRequestMessage::Status(_) => {
                vec![LeanSupportedProtocol::StatusV1.protocol_id()]
            }
            LeanRequestMessage::BlocksByRoot(_) => {
                vec![LeanSupportedProtocol::BlocksByRootV1.protocol_id()]
            }
        }
    }

    /// Returns the maximum number of response chunks expected for this request.
    ///
    /// `Status` expects exactly 1 chunk; `BlocksByRoot` expects one per root.
    pub fn max_response_chunks(&self) -> u64 {
        match self {
            LeanRequestMessage::Status(_) => 1,
            LeanRequestMessage::BlocksByRoot(req) => req.roots.data.len() as u64,
        }
    }

    /// SSZ-encodes the inner message.
    pub fn encode_ssz(&self) -> Vec<u8> {
        match self {
            LeanRequestMessage::Status(status) => encode_lean_status_compat(status),
            // REAM-compatible transparent list payload.
            LeanRequestMessage::BlocksByRoot(req) => req.roots.encode_ssz(),
        }
    }

    /// SSZ-decodes bytes into the variant corresponding to `protocol`.
    ///
    /// # Errors
    ///
    /// Returns `Err` if decoding fails for the selected protocol.
    pub fn decode_ssz(protocol: LeanSupportedProtocol, data: &[u8]) -> Result<Self, String> {
        match protocol {
            LeanSupportedProtocol::StatusV1 => {
                Ok(LeanRequestMessage::Status(decode_lean_status_compat(data)?))
            }
            LeanSupportedProtocol::BlocksByRootV1 => Ok(LeanRequestMessage::BlocksByRoot(
                decode_blocks_by_root_request_compat(data)?,
            )),
        }
    }
}

/// A typed inbound or outbound req/resp response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LeanResponseMessage {
    /// Response to a status request.
    Status(Status),
    /// Response to a blocks-by-root request.
    BlocksByRoot(BlocksByRootResponse),
}

impl LeanResponseMessage {
    /// SSZ-encodes the inner message.
    pub fn encode_ssz(&self) -> Vec<u8> {
        match self {
            LeanResponseMessage::Status(status) => encode_lean_status_compat(status),
            LeanResponseMessage::BlocksByRoot(resp) => {
                if resp.blocks.data.len() == 1 {
                    // REAM-compatible chunk form.
                    return resp.blocks.data[0].encode_ssz();
                }
                resp.encode_ssz()
            }
        }
    }

    /// SSZ-decodes bytes into the variant corresponding to `protocol`.
    ///
    /// # Errors
    ///
    /// Returns `Err` if decoding fails for the selected protocol.
    pub fn decode_ssz(protocol: LeanSupportedProtocol, data: &[u8]) -> Result<Self, String> {
        match protocol {
            LeanSupportedProtocol::StatusV1 => Ok(LeanResponseMessage::Status(
                decode_lean_status_compat(data)?,
            )),
            LeanSupportedProtocol::BlocksByRootV1 => Ok(LeanResponseMessage::BlocksByRoot(
                decode_blocks_by_root_response_compat(data)?,
            )),
        }
    }
}
