use tokio::sync::broadcast;

#[derive(Debug, Clone)]
pub enum NetworkEvent {
    PeerConnected { peer_id: String },
    PeerDisconnected { peer_id: String },
    PeerBanned { peer_id: String, reason: String },
    GossipMessage { topic: String, payload: Vec<u8> },
    GossipValidated { topic: String, valid: bool },
    ReqRespRequest { peer_id: String, protocol: String, payload: Vec<u8> },
    ReqRespResponse { peer_id: String, protocol: String, payload: Vec<u8> },
    PeerScored { peer_id: String, score: i64 },
    RateLimited { peer_id: String, category: String },
}

#[derive(Clone)]
pub struct EventBus {
    sender: broadcast::Sender<NetworkEvent>,
}

impl EventBus {
    pub fn new(buffer: usize) -> Self {
        let (sender, _) = broadcast::channel(buffer);
        Self { sender }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<NetworkEvent> {
        self.sender.subscribe()
    }

    pub fn emit(&self, event: NetworkEvent) {
        let _ = self.sender.send(event);
    }
}
