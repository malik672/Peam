use crate::containers::req_resp::{BlocksByRootRequest, BlocksByRootResponse, Status};
use crate::ssz::SszEncode;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeanSupportedProtocol {
    BlocksByRootV1,
    StatusV1,
}

impl LeanSupportedProtocol {
    pub fn message_name(&self) -> &'static str {
        match self {
            LeanSupportedProtocol::BlocksByRootV1 => "blocks_by_root",
            LeanSupportedProtocol::StatusV1 => "status",
        }
    }

    pub fn schema_version(&self) -> &'static str {
        "1"
    }

    pub fn protocol_id(&self) -> String {
        format!(
            "/lean_eth/reqresp/{}/{}",
            self.message_name(),
            self.schema_version()
        )
    }

    pub fn parse_protocol_id(protocol: &str) -> Option<Self> {
        let parts: Vec<&str> = protocol.trim_start_matches('/').split('/').collect();
        if parts.len() != 4 || parts[0] != "lean_eth" || parts[1] != "reqresp" {
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LeanRequestMessage {
    Status(Status),
    BlocksByRoot(BlocksByRootRequest),
}

impl LeanRequestMessage {
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

    pub fn max_response_chunks(&self) -> u64 {
        match self {
            LeanRequestMessage::Status(_) => 1,
            LeanRequestMessage::BlocksByRoot(req) => req.roots.data.len() as u64,
        }
    }

    pub fn encode_ssz(&self) -> Vec<u8> {
        match self {
            LeanRequestMessage::Status(status) => status.encode_ssz(),
            LeanRequestMessage::BlocksByRoot(req) => req.encode_ssz(),
        }
    }

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LeanResponseMessage {
    Status(Status),
    BlocksByRoot(BlocksByRootResponse),
}

impl LeanResponseMessage {
    pub fn encode_ssz(&self) -> Vec<u8> {
        match self {
            LeanResponseMessage::Status(status) => status.encode_ssz(),
            LeanResponseMessage::BlocksByRoot(resp) => resp.encode_ssz(),
        }
    }

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
