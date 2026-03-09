use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

use peam::app::{NodeSettings, load_node_settings, resolve_metrics_identity};
use peam::networking::GossipValidatorKind;

#[test]
fn parses_node_settings_from_text_config() {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    let path = std::env::temp_dir().join(format!("peam_config_{stamp}.txt"));
    let config_text = r#"
# Example node config
genesis_time=42
discovery_interval_secs=7
score_decay_interval_secs=11
score_decay_amount=3
ban_threshold=-50
bootnodes=/ip4/1.2.3.4/tcp/30303/p2p/12D3KooWBootA,/ip4/5.6.7.8/tcp/30303/p2p/12D3KooWBootB
trusted_peers=/ip4/9.9.9.9/tcp/30303/p2p/12D3KooWTrustA
allowed_topics=peam/gossip,peam/blocks
topic_scores=peam/gossip:2,peam/blocks:-1
topic_validators=peam/gossip=block,peam/blocks=attestation
max_gossip_bytes=12345
max_reqresp_bytes=67890
allow_unverified_aggregate_proofs=true
validator_count=400
storage_dir=node_store
metrics=true
metrics_address=0.0.0.0
metrics_port=18080
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
        vec!["/peam/gossip".to_string(), "/peam/blocks".to_string()]
    );
    assert_eq!(
        settings.topic_scores,
        vec![
            ("/peam/gossip".to_string(), 2),
            ("/peam/blocks".to_string(), -1),
        ]
    );
    assert_eq!(
        settings.topic_validators,
        vec![
            ("/peam/gossip".to_string(), GossipValidatorKind::Block),
            ("/peam/blocks".to_string(), GossipValidatorKind::Attestation),
        ]
    );
    assert_eq!(settings.max_gossip_bytes, 12345);
    assert_eq!(settings.max_reqresp_bytes, 67890);
    assert!(settings.allow_unverified_aggregate_proofs);
    assert_eq!(settings.validator_count, 400);
    assert_eq!(settings.storage_dir, Some("node_store".to_string()));
    assert!(settings.metrics);
    assert_eq!(settings.metrics_address, "0.0.0.0".to_string());
    assert_eq!(settings.metrics_port, 18080);

    let _ = fs::remove_file(&path);
}

#[test]
fn resolves_metrics_identity_from_validators_yaml() {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("peam_metrics_identity_{stamp}"));
    fs::create_dir_all(&dir).expect("create temp dir");

    let config_path = dir.join("node.conf");
    fs::write(&config_path, "genesis_time=42\n").expect("write config");
    fs::write(&dir.join("validators.yaml"), "peam_0:\n- 0\nream_0:\n- 1\n")
        .expect("write validators");

    let settings = NodeSettings {
        metrics: true,
        metrics_address: "127.0.0.1".to_string(),
        metrics_port: 18080,
        discovery_interval_secs: 5,
        score_decay_interval_secs: 30,
        score_decay_amount: 1,
        ban_threshold: -100,
        listen_addr: "/ip4/0.0.0.0/udp/9000/quic-v1".to_string(),
        node_key_path: None,
        bootnodes: Vec::new(),
        trusted_peers: Vec::new(),
        allowed_topics: Vec::new(),
        topic_scores: Vec::new(),
        topic_validators: Vec::new(),
        max_gossip_bytes: 2_000_000,
        max_reqresp_bytes: 4_000_000,
        allow_unverified_aggregate_proofs: false,
        validator_count: 2,
        local_validator_index: 1,
        storage_dir: None,
        validator_config_path: None,
        metrics_node_name: None,
        metrics_client_name: None,
    };

    let (node_name, client_name) =
        resolve_metrics_identity(&config_path, &settings).expect("resolve identity");
    assert_eq!(node_name, "ream_0");
    assert_eq!(client_name, "ream");

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn resolves_metrics_identity_from_validator_config_when_needed() {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("peam_metrics_identity_cfg_{stamp}"));
    fs::create_dir_all(&dir).expect("create temp dir");

    let config_path = dir.join("node.conf");
    fs::write(&config_path, "genesis_time=42\n").expect("write config");
    fs::write(
        &dir.join("validator-config.yaml"),
        "validators:\n  - name: \"peam_0\"\n    privkey: \"0x01\"\n  - name: \"ethlambda_0\"\n    privkey: \"0x02\"\n",
    )
    .expect("write validator-config");

    let settings = NodeSettings {
        metrics: true,
        metrics_address: "127.0.0.1".to_string(),
        metrics_port: 18080,
        discovery_interval_secs: 5,
        score_decay_interval_secs: 30,
        score_decay_amount: 1,
        ban_threshold: -100,
        listen_addr: "/ip4/0.0.0.0/udp/9000/quic-v1".to_string(),
        node_key_path: None,
        bootnodes: Vec::new(),
        trusted_peers: Vec::new(),
        allowed_topics: Vec::new(),
        topic_scores: Vec::new(),
        topic_validators: Vec::new(),
        max_gossip_bytes: 2_000_000,
        max_reqresp_bytes: 4_000_000,
        allow_unverified_aggregate_proofs: false,
        validator_count: 2,
        local_validator_index: 1,
        storage_dir: None,
        validator_config_path: None,
        metrics_node_name: None,
        metrics_client_name: None,
    };

    let (node_name, client_name) =
        resolve_metrics_identity(&config_path, &settings).expect("resolve identity");
    assert_eq!(node_name, "ethlambda_0");
    assert_eq!(client_name, "ethlambda");

    let _ = fs::remove_dir_all(&dir);
}
