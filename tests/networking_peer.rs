use peam::networking::{NetworkEventBus, PeerManager};

#[tokio::test]
async fn peer_score_decay_and_ban() {
    let events = NetworkEventBus::new(16);
    let peers = PeerManager::new(events.clone());
    peers.connect("peer1".to_string()).await;
    peers.failed_response_from_peer("peer1").await;

    let banned = peers.decay_and_prune(1, -5).await;
    assert_eq!(banned, vec!["peer1".to_string()]);
    assert!(peers.score("peer1").await.is_none());
}

#[tokio::test]
async fn peer_score_success_and_failure() {
    let events = NetworkEventBus::new(16);
    let peers = PeerManager::new(events.clone());
    peers.connect("peer2".to_string()).await;
    let score = peers.successful_response_from_peer("peer2").await;
    assert_eq!(score, 10);
    let score = peers.failed_response_from_peer("peer2").await;
    assert_eq!(score, -10);
}
