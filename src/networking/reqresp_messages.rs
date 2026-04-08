//! Typed req/resp protocol messages and their SSZ codecs.
//!
//! [`LeanSupportedProtocol`] enumerates all supported protocol IDs and
//! handles protocol-ID string parsing and construction.
//!
//! [`LeanRequestMessage`] and [`LeanResponseMessage`] are the typed envelopes
//! used above the raw byte layer; both implement SSZ encode/decode dispatched
//! by protocol variant.

use crate::containers::block::SignedBlockWithAttestation;
use crate::containers::req_resp::{
    BlocksByRangeRequest, BlocksByRangeResponse, BlocksByRootRequest, BlocksByRootResponse, Status,
};
use crate::ssz::{SszDecode, SszEncode};
use crate::types::collections::SszList;

#[inline]
fn decode_blocks_by_root_request_compat(data: &[u8]) -> Result<BlocksByRootRequest, String> {
    if let Ok(req) = BlocksByRootRequest::decode_ssz(data) {
        return Ok(req);
    }
    let roots = SszList::decode_ssz(data)?;
    Ok(BlocksByRootRequest { roots })
}

#[inline]
fn decode_blocks_by_root_response_compat(
    data: &[u8],
) -> Result<SignedBlockWithAttestation, String> {
    if let Ok(single) = SignedBlockWithAttestation::decode_ssz(data) {
        return Ok(single);
    }
    if let Ok(resp) = BlocksByRootResponse::decode_ssz(data) {
        return resp
            .blocks
            .into_inner()
            .into_iter()
            .next()
            .ok_or_else(|| "empty BlocksByRoot response payload".to_string());
    }
    Err("unsupported BlocksByRoot response payload".to_string())
}

#[inline]
fn decode_blocks_by_range_response_compat(
    data: &[u8],
) -> Result<SignedBlockWithAttestation, String> {
    if let Ok(single) = SignedBlockWithAttestation::decode_ssz(data) {
        return Ok(single);
    }
    if let Ok(resp) = BlocksByRangeResponse::decode_ssz(data) {
        return resp
            .blocks
            .into_inner()
            .into_iter()
            .next()
            .ok_or_else(|| "empty BlocksByRange response payload".to_string());
    }
    Err("unsupported BlocksByRange response payload".to_string())
}

/// All req/resp protocols supported by the lean-Ethereum node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeanSupportedProtocol {
    /// `/leanconsensus/req/blocks_by_range/1/ssz_snappy`
    BlocksByRangeV1,
    /// `/leanconsensus/req/blocks_by_root/1/ssz_snappy`
    BlocksByRootV1,
    /// `/leanconsensus/req/status/1/ssz_snappy`
    StatusV1,
}

impl LeanSupportedProtocol {
    /// Returns the human-readable message name component of the protocol ID.
    pub fn message_name(&self) -> &'static str {
        match self {
            LeanSupportedProtocol::BlocksByRangeV1 => "blocks_by_range",
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
        } else {
            return None;
        };
        if version != "1" {
            return None;
        }
        match name {
            "blocks_by_range" => Some(LeanSupportedProtocol::BlocksByRangeV1),
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
    /// Request for blocks by slot range.
    BlocksByRange(BlocksByRangeRequest),
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
            LeanRequestMessage::BlocksByRange(_) => {
                vec![LeanSupportedProtocol::BlocksByRangeV1.protocol_id()]
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
            LeanRequestMessage::BlocksByRange(req) => req.count.0,
            LeanRequestMessage::BlocksByRoot(req) => req.roots.len() as u64,
        }
    }

    /// SSZ-encodes the inner message.
    pub fn encode_ssz(&self) -> Vec<u8> {
        match self {
            LeanRequestMessage::Status(status) => status.encode_ssz(),
            LeanRequestMessage::BlocksByRange(req) => req.encode_ssz(),
            LeanRequestMessage::BlocksByRoot(req) => req.encode_ssz(),
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
                Ok(LeanRequestMessage::Status(Status::decode_ssz(data)?))
            }
            LeanSupportedProtocol::BlocksByRangeV1 => Ok(LeanRequestMessage::BlocksByRange(
                BlocksByRangeRequest::decode_ssz(data)?,
            )),
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
    /// Response to a blocks-by-range request (one block per chunk).
    BlocksByRange(SignedBlockWithAttestation),
    /// Response to a blocks-by-root request (one block per chunk).
    BlocksByRoot(SignedBlockWithAttestation),
}

impl LeanResponseMessage {
    /// SSZ-encodes the inner message.
    pub fn encode_ssz(&self) -> Vec<u8> {
        match self {
            LeanResponseMessage::Status(status) => status.encode_ssz(),
            LeanResponseMessage::BlocksByRange(block) => block.encode_ssz(),
            LeanResponseMessage::BlocksByRoot(block) => block.encode_ssz(),
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
                Ok(LeanResponseMessage::Status(Status::decode_ssz(data)?))
            }
            LeanSupportedProtocol::BlocksByRangeV1 => Ok(LeanResponseMessage::BlocksByRange(
                decode_blocks_by_range_response_compat(data)?,
            )),
            LeanSupportedProtocol::BlocksByRootV1 => Ok(LeanResponseMessage::BlocksByRoot(
                decode_blocks_by_root_response_compat(data)?,
            )),
        }
    }
}
