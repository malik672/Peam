#[derive(Debug)]
pub enum GossipsubError {
    InvalidTopic(String),
    Decode(String),
}

impl From<String> for GossipsubError {
    fn from(value: String) -> Self {
        GossipsubError::Decode(value)
    }
}
