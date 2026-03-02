//! Typed req/resp protocol messages and their SSZ codecs.
//!
//! [`LeanSupportedProtocol`] enumerates all supported protocol IDs and
//! handles protocol-ID string parsing and construction.
//!
//! [`LeanRequestMessage`] and [`LeanResponseMessage`] are the typed envelopes
//! used above the raw byte layer; both implement SSZ encode/decode dispatched
//! by protocol variant.

use crate::containers::req_resp::{BlocksByRootRequest, BlocksByRootResponse, Status};
use crate::ssz::SszEncode;

/// All req/resp protocols supported by the lean-Ethereum node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeanSupportedProtocol {
    /// `/peam/reqresp/blocks_by_root/1`
    BlocksByRootV1,
    /// `/peam/reqresp/status/1`
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
    /// e.g. `/peam/reqresp/blocks_by_root/1`.
    pub fn protocol_id(&self) -> String {
        format!(
            "/peam/reqresp/{}/{}",
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
        if parts.len() != 4 || parts[0] != "peam" || parts[1] != "reqresp" {
            return None;
        }
        let name = parts[2];
        let version = parts[3];
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
            LeanRequestMessage::Status(status) => status.encode_ssz(),
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
            LeanSupportedProtocol::StatusV1 => Ok(LeanRequestMessage::Status(
                Status::decode_ssz_checked(data)?,
            )),
            LeanSupportedProtocol::BlocksByRootV1 => Ok(LeanRequestMessage::BlocksByRoot(
                BlocksByRootRequest::decode_ssz_checked(data)?,
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
            LeanResponseMessage::Status(status) => status.encode_ssz(),
            LeanResponseMessage::BlocksByRoot(resp) => resp.encode_ssz(),
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
                Status::decode_ssz_checked(data)?,
            )),
            LeanSupportedProtocol::BlocksByRootV1 => Ok(LeanResponseMessage::BlocksByRoot(
                BlocksByRootResponse::decode_ssz_checked(data)?,
            )),
        }
    }
}
