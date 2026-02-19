use tokio::sync::mpsc;
use tracing::info;

use super::events::{EventBus, NetworkEvent};
use super::rate_limiter::RateLimiter;

#[derive(Clone)]
pub struct ReqResp {
    tx: mpsc::Sender<ReqRespMessage>,
    events: EventBus,
    limiter: RateLimiter,
}

#[derive(Debug)]
pub enum ReqRespMessage {
    Request {
        peer_id: String,
        protocol: String,
        payload: Vec<u8>,
    },
    Response {
        peer_id: String,
        protocol: String,
        payload: Vec<u8>,
    },
}

impl ReqResp {
    pub fn new(events: EventBus, buffer: usize) -> (Self, mpsc::Receiver<ReqRespMessage>) {
        let (tx, rx) = mpsc::channel(buffer);
        let limiter = RateLimiter::new(std::time::Duration::from_secs(1), 64);
        (Self { tx, events, limiter }, rx)
    }

    pub async fn send_request(&self, peer_id: String, protocol: String, payload: Vec<u8>) {
        if !self.limiter.allow("reqresp_out").await {
            self.events.emit(NetworkEvent::RateLimited {
                peer_id: "self".to_string(),
                category: "reqresp_out".to_string(),
            });
            return;
        }
        let msg = ReqRespMessage::Request {
            peer_id: peer_id.clone(),
            protocol: protocol.clone(),
            payload: payload.clone(),
        };
        let _ = self.tx.send(msg).await;
        info!("reqresp_request peer={peer_id} protocol={protocol}");
        self.events.emit(NetworkEvent::ReqRespRequest {
            peer_id,
            protocol,
            payload,
        });
    }

    pub async fn send_response(&self, peer_id: String, protocol: String, payload: Vec<u8>) {
        if !self.limiter.allow("reqresp_out").await {
            self.events.emit(NetworkEvent::RateLimited {
                peer_id: "self".to_string(),
                category: "reqresp_out".to_string(),
            });
            return;
        }
        let msg = ReqRespMessage::Response {
            peer_id: peer_id.clone(),
            protocol: protocol.clone(),
            payload: payload.clone(),
        };
        let _ = self.tx.send(msg).await;
        info!("reqresp_response peer={peer_id} protocol={protocol}");
        self.events.emit(NetworkEvent::ReqRespResponse {
            peer_id,
            protocol,
            payload,
        });
    }
}
