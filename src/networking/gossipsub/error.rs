//! Gossipsub-specific error types.

/// Errors arising during gossipsub topic parsing or message decoding.
#[derive(Debug)]
pub enum GossipsubError {
    /// The topic string does not conform to the expected format.
    InvalidTopic(String),
    /// SSZ or other message decoding failed.
    Decode(String),
}

/// Converts a `String` error into a [`GossipsubError::Decode`].
impl From<String> for GossipsubError {
    fn from(value: String) -> Self {
        GossipsubError::Decode(value)
    }
}
