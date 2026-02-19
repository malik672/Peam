use std::fs;

use lean_eth::app::{build_genesis, load_config};
use lean_eth::containers::state::State;
use lean_eth::ssz::SszEncode;

fn write_temp_config(contents: &str) -> std::path::PathBuf {
    let mut path = std::env::temp_dir();
    let filename = format!("lean_eth_config_{}.txt", std::process::id());
    path.push(filename);
    fs::write(&path, contents).expect("write config");
    path
}

#[test]
fn e2e_config_to_genesis_roundtrip() {
    let path = write_temp_config("genesis_time=0\n");
    let config = load_config(&path).expect("load config");
    let state = build_genesis(config).expect("build genesis");
    let bytes = state.encode_ssz();
    let decoded = State::decode_ssz_checked(&bytes).expect("decode state");
    assert_eq!(decoded, state);
    let _ = fs::remove_file(path);
}
