use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use peam::app::{load_node_settings, resolve_validator_startup_overrides};

fn unique_temp_dir(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("unix time")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("peam_{label}_{}_{}", std::process::id(), nanos));
    fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

#[test]
fn startup_overrides_resolve_node_id_and_validator_keys_path() {
    let root = unique_temp_dir("startup_overrides");
    let config_path = root.join("node.conf");
    let custom_keys_dir = root.join("custom-hash-sig-keys");

    fs::write(
        &config_path,
        "genesis_time=42\nlocal_validator_index=0\nvalidator_config_path=validator-config.yaml\n",
    )
    .expect("write node config");
    fs::write(
        root.join("validators.yaml"),
        "peam_0:\n- 0\npeer1_0:\n- 1\n",
    )
    .expect("write validators.yaml");
    fs::create_dir_all(&custom_keys_dir).expect("create custom validator key dir");

    let (_, settings) = load_node_settings(&config_path).expect("load node settings");
    let (resolved_index, resolved_keys_dir) = resolve_validator_startup_overrides(
        &config_path,
        &settings,
        Some("peer1_0"),
        Some(&custom_keys_dir),
        None,
    )
    .expect("resolve startup overrides");

    assert_eq!(resolved_index, Some(1));
    assert_eq!(resolved_keys_dir, custom_keys_dir);

    let _ = fs::remove_dir_all(root);
}
