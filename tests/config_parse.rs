use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

use peam::app::{
    NodeSettings, load_node_settings, resolve_local_validator_index_for_node_name,
    resolve_metrics_identity, resolve_validator_startup_overrides,
};
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
http_api=false
bootnodes=/ip4/1.2.3.4/tcp/30303/p2p/12D3KooWBootA,/ip4/5.6.7.8/tcp/30303/p2p/12D3KooWBootB
trusted_peers=/ip4/9.9.9.9/tcp/30303/p2p/12D3KooWTrustA
allowed_topics=peam/gossip,peam/blocks
topic_scores=peam/gossip:2,peam/blocks:-1
topic_validators=peam/gossip=block,peam/blocks=attestation
max_gossip_bytes=12345
max_reqresp_bytes=67890
is_aggregator=true
attestation_committee_count=8
validator_count=400
storage_dir=node_store
metrics=true
metrics_address=0.0.0.0
metrics_port=18080
http_address=127.0.0.2
http_port=19090
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
    assert!(settings.is_aggregator);
    assert_eq!(settings.attestation_committee_count, 8);
    assert_eq!(settings.validator_count, 400);
    assert_eq!(settings.storage_dir, Some("node_store".to_string()));
    assert!(settings.metrics);
    assert_eq!(settings.metrics_address, "0.0.0.0".to_string());
    assert_eq!(settings.metrics_port, 18080);
    assert_eq!(settings.http_address, "127.0.0.2".to_string());
    assert_eq!(settings.http_port, 19090);
    assert!(!settings.http_api);

    let _ = fs::remove_file(&path);
}

#[test]
fn loads_bootnodes_from_nodes_yaml_file() {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("peam_nodes_yaml_{stamp}"));
    fs::create_dir_all(&dir).expect("create temp dir");

    let config_path = dir.join("node.conf");
    fs::write(&config_path, "genesis_time=42\nbootnodes_file=nodes.yaml\n").expect("write config");
    fs::write(
        dir.join("nodes.yaml"),
        "- enr:-IW4QGGifTt9ypyMtChDISUNX3z4z5iPdiEPOmBoILvnDuWIKbWVmKXxZERPnw0piQyaBNCENFEPoIi-vxsnsrBig9MBgmlkgnY0gmlwhH8AAAGEcXVpY4IjKYlzZWNwMjU2azGhAhMMnGF1rmIPQ9tWgqfkNmvsG-aIyc9EJU5JFo3Tegys\n",
    )
    .expect("write nodes yaml");

    let (_config, settings) = load_node_settings(&config_path).expect("parse config");
    assert_eq!(
        settings.bootnodes,
        vec![
            "/ip4/127.0.0.1/udp/9001/quic-v1/p2p/16Uiu2HAkvi2sxT75Bpq1c7yV2FjnSQJJ432d6jeshbmfdJss1i6f"
                .to_string()
        ]
    );

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn defaults_http_listener_to_metrics_listener_when_not_configured() {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    let path = std::env::temp_dir().join(format!("peam_http_default_{stamp}.txt"));
    let config_text = r#"
genesis_time=42
metrics=true
metrics_address=0.0.0.0
metrics_port=18080
"#;
    fs::write(&path, config_text).expect("write config");

    let (_config, settings) = load_node_settings(&path).expect("parse config");
    assert_eq!(settings.metrics_address, "0.0.0.0");
    assert_eq!(settings.metrics_port, 18080);
    assert_eq!(settings.http_address, "0.0.0.0");
    assert_eq!(settings.http_port, 18080);

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
    fs::write(dir.join("validators.yaml"), "peam_0:\n- 0\nream_0:\n- 1\n")
        .expect("write validators");

    let settings = NodeSettings {
        metrics: true,
        metrics_address: "127.0.0.1".to_string(),
        metrics_port: 18080,
        http_api: true,
        http_address: "127.0.0.1".to_string(),
        http_port: 18080,
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
        is_aggregator: false,
        attestation_committee_count: 1,
        validator_count: 2,
        local_validator_index: 1,
        storage_dir: None,
        validator_config_path: None,
        metrics_node_name: None,
        metrics_client_name: None,
        checkpoint_sync_url: None,
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
        dir.join("validator-config.yaml"),
        "validators:\n  - name: \"peam_0\"\n    privkey: \"0x01\"\n  - name: \"ethlambda_0\"\n    privkey: \"0x02\"\n",
    )
    .expect("write validator-config");

    let settings = NodeSettings {
        metrics: true,
        metrics_address: "127.0.0.1".to_string(),
        metrics_port: 18080,
        http_api: true,
        http_address: "127.0.0.1".to_string(),
        http_port: 18080,
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
        is_aggregator: false,
        attestation_committee_count: 1,
        validator_count: 2,
        local_validator_index: 1,
        storage_dir: None,
        validator_config_path: None,
        metrics_node_name: None,
        metrics_client_name: None,
        checkpoint_sync_url: None,
    };

    let (node_name, client_name) =
        resolve_metrics_identity(&config_path, &settings).expect("resolve identity");
    assert_eq!(node_name, "ethlambda_0");
    assert_eq!(client_name, "ethlambda");

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn validator_config_enr_fields_override_local_aggregator_flag() {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("peam_validator_cfg_override_{stamp}"));
    fs::create_dir_all(&dir).expect("create temp dir");

    let config_path = dir.join("node.conf");
    fs::write(
        &config_path,
        "genesis_time=42\nis_aggregator=false\nlocal_validator_index=0\nvalidator_config_path=validator-config.yaml\n",
    )
    .expect("write config");
    fs::write(
        dir.join("validator-config.yaml"),
        "validators:\n  - name: \"peam_0\"\n    privkey: \"0x01\"\n    enrFields:\n      is_aggregator: true\n",
    )
    .expect("write validator-config");

    let (_config, settings) = load_node_settings(&config_path).expect("parse config");
    assert!(settings.is_aggregator);

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn parses_genesis_yaml_as_config_with_default_node_settings() {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("peam_genesis_yaml_{stamp}"));
    fs::create_dir_all(&dir).expect("create temp dir");

    let config_path = dir.join("config.yaml");
    fs::write(
        &config_path,
        "GENESIS_TIME: 42\nGENESIS_VALIDATORS:\n  - attestation_pubkey: \"0xd1010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\"\n    proposal_pubkey: \"0xd2020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\"\n",
    )
    .expect("write genesis yaml");

    let (config, settings) = load_node_settings(&config_path).expect("parse genesis yaml");
    assert_eq!(config.genesis_time.0, 42);
    assert_eq!(settings.metrics_port, 8080);
    assert!(settings.http_api);
    assert_eq!(settings.http_address, "127.0.0.1");
    assert_eq!(settings.http_port, 8080);
    assert_eq!(settings.listen_addr, "/ip4/0.0.0.0/udp/9000/quic-v1");

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn rejects_legacy_single_pubkey_genesis_yaml() {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("peam_genesis_yaml_legacy_reject_{stamp}"));
    fs::create_dir_all(&dir).expect("create temp dir");

    let config_path = dir.join("config.yaml");
    fs::write(
        &config_path,
        "GENESIS_TIME: 42\nGENESIS_VALIDATORS:\n  - \"0xd1010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\"\n",
    )
    .expect("write legacy genesis yaml");

    let err = peam::app::build_genesis_from_config_yaml(&config_path).expect_err("legacy genesis must be rejected");
    assert!(err.contains("must be a mapping"), "{err}");

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn parses_structured_devnet4_genesis_yaml() {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("peam_genesis_yaml_devnet4_{stamp}"));
    fs::create_dir_all(&dir).expect("create temp dir");

    let config_path = dir.join("config.yaml");
    fs::write(
        &config_path,
        "GENESIS_TIME: 42\nGENESIS_VALIDATORS:\n  - attestation_pubkey: \"0xd1010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\"\n    proposal_pubkey: \"0xd2020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\"\n",
    )
    .expect("write genesis yaml");

    let (config, settings) = load_node_settings(&config_path).expect("parse genesis yaml");
    assert_eq!(config.genesis_time.0, 42);
    assert_eq!(settings.metrics_port, 8080);
    assert!(settings.http_api);

    let state = peam::app::build_genesis_from_config_yaml(&config_path).expect("build genesis");
    let validator = state.validators.get(0).expect("validator");
    assert_eq!(
        validator.attestation_pubkey,
        peam::types::bytes::Bytes52::from_slice(&[0xd1, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
    );
    assert_eq!(
        validator.proposal_pubkey,
        peam::types::bytes::Bytes52::from_slice(&[0xd2, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
    );

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn resolves_local_validator_index_from_node_name() {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("peam_node_id_lookup_{stamp}"));
    fs::create_dir_all(&dir).expect("create temp dir");

    let config_path = dir.join("node.conf");
    fs::write(&config_path, "genesis_time=42\n").expect("write config");
    fs::write(dir.join("validators.yaml"), "peam_0:\n- 0\npeer1_0:\n- 1\n")
        .expect("write validators");

    let settings = NodeSettings {
        metrics: false,
        metrics_address: "127.0.0.1".to_string(),
        metrics_port: 8080,
        http_api: true,
        http_address: "127.0.0.1".to_string(),
        http_port: 8080,
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
        is_aggregator: false,
        attestation_committee_count: 1,
        validator_count: 2,
        local_validator_index: 0,
        storage_dir: None,
        validator_config_path: None,
        metrics_node_name: None,
        metrics_client_name: None,
        checkpoint_sync_url: None,
    };

    let index = resolve_local_validator_index_for_node_name(&config_path, &settings, "peer1_0")
        .expect("resolve local validator index");
    assert_eq!(index, Some(1));

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn resolves_local_validator_index_from_custom_validators_path() {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("peam_custom_validators_{stamp}"));
    fs::create_dir_all(&dir).expect("create temp dir");

    let config_path = dir.join("node.conf");
    fs::write(&config_path, "genesis_time=42\n").expect("write config");
    let custom_validators = dir.join("custom-validators.yaml");
    fs::write(&custom_validators, "peer1_0:\n- 1\npeam_0:\n- 0\n").expect("write validators");

    let settings = load_node_settings(&config_path).expect("parse config").1;
    let (index, validator_keys_dir) = resolve_validator_startup_overrides(
        &config_path,
        &settings,
        Some("peer1_0"),
        None,
        Some(custom_validators.as_path()),
    )
    .expect("resolve startup overrides");
    assert_eq!(index, Some(1));
    assert_eq!(validator_keys_dir, dir.join("hash-sig-keys"));

    let _ = fs::remove_dir_all(&dir);
}
