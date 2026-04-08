#![allow(clippy::manual_is_multiple_of)]

use std::path::PathBuf;

use peam::containers::block::BlockBody;
use peam::containers::block::BlockHeader;
use peam::containers::checkpoint::Checkpoint;
use peam::containers::config::Config;
use peam::containers::validator::ValidatorIndex;
use peam::ssz::{SszDecode, SszEncode};
use peam::types::bytes::Bytes32;
use peam::types::uint::Uint64;

use serde_json::Value;

fn fixtures_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/ssz/devnet/consensus_containers")
}

fn load_fixture(path: &PathBuf) -> Value {
    let text = std::fs::read_to_string(path).expect("fixture file");
    let json: Value = serde_json::from_str(&text).expect("fixture json");
    json
}

fn first_fixture_entry(json: &Value) -> &Value {
    let obj = json.as_object().expect("fixture object");
    let (_, entry) = obj.iter().next().expect("fixture entry");
    entry
}

fn decode_hex(s: &str) -> Vec<u8> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    assert!(s.len() % 2 == 0, "hex string has odd length");
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        let hi = (bytes[i] as char).to_digit(16).expect("hex digit");
        let lo = (bytes[i + 1] as char).to_digit(16).expect("hex digit");
        out.push(((hi << 4) | lo) as u8);
        i += 2;
    }
    out
}

fn bytes32_from_hex(s: &str) -> Bytes32 {
    let bytes = decode_hex(s);
    Bytes32::from_slice(&bytes)
}

#[test]
fn lean_spec_config_zero_fixture() {
    let path = fixtures_root().join("test_config_zero.json");
    let json = load_fixture(&path);
    let entry = first_fixture_entry(&json);

    assert_eq!(entry["typeName"], "Config");
    let serialized = entry["serialized"].as_str().expect("serialized");
    let bytes = decode_hex(serialized);
    let decoded = Config::decode_ssz(&bytes).expect("decode config");
    let encoded = decoded.encode_ssz();
    assert_eq!(encoded, bytes);

    let genesis_time = entry["value"]["genesisTime"].as_u64().expect("genesisTime");
    assert_eq!(decoded.genesis_time, Uint64(genesis_time));
}

#[test]
fn lean_spec_config_typical_fixture() {
    let path = fixtures_root().join("test_config_typical.json");
    let json = load_fixture(&path);
    let entry = first_fixture_entry(&json);

    assert_eq!(entry["typeName"], "Config");
    let serialized = entry["serialized"].as_str().expect("serialized");
    let bytes = decode_hex(serialized);
    let decoded = Config::decode_ssz(&bytes).expect("decode config");
    let encoded = decoded.encode_ssz();
    assert_eq!(encoded, bytes);

    let genesis_time = entry["value"]["genesisTime"].as_u64().expect("genesisTime");
    assert_eq!(decoded.genesis_time, Uint64(genesis_time));
}

#[test]
fn lean_spec_checkpoint_zero_fixture() {
    let path = fixtures_root().join("test_checkpoint_zero.json");
    let json = load_fixture(&path);
    let entry = first_fixture_entry(&json);

    assert_eq!(entry["typeName"], "Checkpoint");
    let serialized = entry["serialized"].as_str().expect("serialized");
    let bytes = decode_hex(serialized);
    let decoded = Checkpoint::decode_ssz(&bytes).expect("decode checkpoint");
    let encoded = decoded.encode_ssz();
    assert_eq!(encoded, bytes);

    let root = entry["value"]["root"].as_str().expect("root");
    let slot = entry["value"]["slot"].as_u64().expect("slot");
    assert_eq!(decoded.root, bytes32_from_hex(root));
    assert_eq!(decoded.slot, peam::slot::Slot(Uint64(slot)));
}

#[test]
fn lean_spec_checkpoint_typical_fixture() {
    let path = fixtures_root().join("test_checkpoint_typical.json");
    let json = load_fixture(&path);
    let entry = first_fixture_entry(&json);

    assert_eq!(entry["typeName"], "Checkpoint");
    let serialized = entry["serialized"].as_str().expect("serialized");
    let bytes = decode_hex(serialized);
    let decoded = Checkpoint::decode_ssz(&bytes).expect("decode checkpoint");
    let encoded = decoded.encode_ssz();
    assert_eq!(encoded, bytes);

    let root = entry["value"]["root"].as_str().expect("root");
    let slot = entry["value"]["slot"].as_u64().expect("slot");
    assert_eq!(decoded.root, bytes32_from_hex(root));
    assert_eq!(decoded.slot, peam::slot::Slot(Uint64(slot)));
}

#[test]
fn lean_spec_block_header_zero_fixture() {
    let path = fixtures_root().join("test_block_header_zero.json");
    let json = load_fixture(&path);
    let entry = first_fixture_entry(&json);

    assert_eq!(entry["typeName"], "BlockHeader");
    let serialized = entry["serialized"].as_str().expect("serialized");
    let bytes = decode_hex(serialized);
    let decoded = BlockHeader::decode_ssz(&bytes).expect("decode block header");
    let encoded = decoded.encode_ssz();
    assert_eq!(encoded, bytes);

    let slot = entry["value"]["slot"].as_u64().expect("slot");
    let proposer = entry["value"]["proposerIndex"]
        .as_u64()
        .expect("proposerIndex");
    let parent_root = entry["value"]["parentRoot"].as_str().expect("parentRoot");
    let state_root = entry["value"]["stateRoot"].as_str().expect("stateRoot");
    let body_root = entry["value"]["bodyRoot"].as_str().expect("bodyRoot");

    assert_eq!(decoded.slot, peam::slot::Slot(Uint64(slot)));
    assert_eq!(decoded.proposer_index, ValidatorIndex(Uint64(proposer)));
    assert_eq!(decoded.parent_root, bytes32_from_hex(parent_root));
    assert_eq!(decoded.state_root, bytes32_from_hex(state_root));
    assert_eq!(decoded.body_root, bytes32_from_hex(body_root));
}

#[test]
fn lean_spec_block_header_typical_fixture() {
    let path = fixtures_root().join("test_block_header_typical.json");
    let json = load_fixture(&path);
    let entry = first_fixture_entry(&json);

    assert_eq!(entry["typeName"], "BlockHeader");
    let serialized = entry["serialized"].as_str().expect("serialized");
    let bytes = decode_hex(serialized);
    let decoded = BlockHeader::decode_ssz(&bytes).expect("decode block header");
    let encoded = decoded.encode_ssz();
    assert_eq!(encoded, bytes);

    let slot = entry["value"]["slot"].as_u64().expect("slot");
    let proposer = entry["value"]["proposerIndex"]
        .as_u64()
        .expect("proposerIndex");
    let parent_root = entry["value"]["parentRoot"].as_str().expect("parentRoot");
    let state_root = entry["value"]["stateRoot"].as_str().expect("stateRoot");
    let body_root = entry["value"]["bodyRoot"].as_str().expect("bodyRoot");

    assert_eq!(decoded.slot, peam::slot::Slot(Uint64(slot)));
    assert_eq!(decoded.proposer_index, ValidatorIndex(Uint64(proposer)));
    assert_eq!(decoded.parent_root, bytes32_from_hex(parent_root));
    assert_eq!(decoded.state_root, bytes32_from_hex(state_root));
    assert_eq!(decoded.body_root, bytes32_from_hex(body_root));
}

#[test]
fn lean_spec_block_body_empty_fixture() {
    let path = fixtures_root().join("test_block_body_empty.json");
    let json = load_fixture(&path);
    let entry = first_fixture_entry(&json);

    assert_eq!(entry["typeName"], "BlockBody");
    let serialized = entry["serialized"].as_str().expect("serialized");
    let bytes = decode_hex(serialized);
    let decoded = BlockBody::decode_ssz(&bytes).expect("decode block body");
    let encoded = decoded.encode_ssz();
    assert_eq!(encoded, bytes);
    assert!(decoded.attestations.is_empty());
}
