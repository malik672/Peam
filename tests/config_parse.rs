use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

use lean_eth::app::load_node_settings;
use lean_eth::networking::GossipValidatorKind;

#[test]
fn parses_node_settings_from_text_config() {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    let path = std::env::temp_dir().join(format!("lean_eth_config_{stamp}.txt"));
    let config_text = r#"
# Example node config
genesis_time=42
discovery_interval_secs=7
score_decay_interval_secs=11
score_decay_amount=3
ban_threshold=-50
bootnodes=/ip4/1.2.3.4/tcp/30303/p2p/12D3KooWBootA,/ip4/5.6.7.8/tcp/30303/p2p/12D3KooWBootB
trusted_peers=/ip4/9.9.9.9/tcp/30303/p2p/12D3KooWTrustA
allowed_topics=lean_eth/gossip,lean_eth/blocks
topic_scores=lean_eth/gossip:2,lean_eth/blocks:-1
topic_validators=lean_eth/gossip=block,lean_eth/blocks=attestation
max_gossip_bytes=12345
max_reqresp_bytes=67890
storage_dir=node_store
"#;
    fs::write(&path, config_text).expect("write config");

    let (config, settings) = load_node_settings(&path).expect("parse config");
    assert_eq!(config.genesis_time.0, 42);
    assert_eq!(settings.discovery_interval_secs, 7);
    assert_eq!(settings.score_decay_interval_secs, 11);
    assert_eq!(settings.score_decay_amount, 3);
    assert_eq!(settings.ban_threshold, -50);
    assert_eq!(
        settings.bootnodes,
        vec![
            "/ip4/1.2.3.4/tcp/30303/p2p/12D3KooWBootA".to_string(),
            "/ip4/5.6.7.8/tcp/30303/p2p/12D3KooWBootB".to_string(),
        ]
    );
    assert_eq!(
        settings.trusted_peers,
        vec!["/ip4/9.9.9.9/tcp/30303/p2p/12D3KooWTrustA".to_string(),]
    );
    assert_eq!(
        settings.allowed_topics,
        vec!["lean_eth/gossip".to_string(), "lean_eth/blocks".to_string()]
    );
    assert_eq!(
        settings.topic_scores,
        vec![
            ("lean_eth/gossip".to_string(), 2),
            ("lean_eth/blocks".to_string(), -1),
        ]
    );
    assert_eq!(
        settings.topic_validators,
        vec![
            ("lean_eth/gossip".to_string(), GossipValidatorKind::Block),
            ("lean_eth/blocks".to_string(), GossipValidatorKind::Attestation),
        ]
    );
    assert_eq!(settings.max_gossip_bytes, 12345);
    assert_eq!(settings.max_reqresp_bytes, 67890);
    assert_eq!(settings.storage_dir, Some("node_store".to_string()));

    let _ = fs::remove_file(&path);
}
