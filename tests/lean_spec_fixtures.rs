#![allow(clippy::manual_is_multiple_of)]

mod lean_spec;

use lean_spec::hex::bytes32_from_hex;
use lean_spec::ssz_runner::{
    decode_roundtrip, load_single_fixture_entry, local_consensus_container_fixture,
};
use peam::containers::block::BlockBody;
use peam::containers::block::BlockHeader;
use peam::containers::checkpoint::Checkpoint;
use peam::containers::config::Config;
use peam::containers::validator::ValidatorIndex;
use peam::types::uint::Uint64;

#[test]
fn lean_spec_config_zero_fixture() {
    let path = local_consensus_container_fixture("test_config_zero.json");
    let entry = load_single_fixture_entry(&path);
    let decoded: Config = decode_roundtrip(&entry, "Config");

    let genesis_time = entry["value"]["genesisTime"].as_u64().expect("genesisTime");
    assert_eq!(decoded.genesis_time, Uint64(genesis_time));
}

#[test]
fn lean_spec_config_typical_fixture() {
    let path = local_consensus_container_fixture("test_config_typical.json");
    let entry = load_single_fixture_entry(&path);
    let decoded: Config = decode_roundtrip(&entry, "Config");

    let genesis_time = entry["value"]["genesisTime"].as_u64().expect("genesisTime");
    assert_eq!(decoded.genesis_time, Uint64(genesis_time));
}

#[test]
fn lean_spec_checkpoint_zero_fixture() {
    let path = local_consensus_container_fixture("test_checkpoint_zero.json");
    let entry = load_single_fixture_entry(&path);
    let decoded: Checkpoint = decode_roundtrip(&entry, "Checkpoint");

    let root = entry["value"]["root"].as_str().expect("root");
    let slot = entry["value"]["slot"].as_u64().expect("slot");
    assert_eq!(decoded.root, bytes32_from_hex(root));
    assert_eq!(decoded.slot, peam::slot::Slot(Uint64(slot)));
}

#[test]
fn lean_spec_checkpoint_typical_fixture() {
    let path = local_consensus_container_fixture("test_checkpoint_typical.json");
    let entry = load_single_fixture_entry(&path);
    let decoded: Checkpoint = decode_roundtrip(&entry, "Checkpoint");

    let root = entry["value"]["root"].as_str().expect("root");
    let slot = entry["value"]["slot"].as_u64().expect("slot");
    assert_eq!(decoded.root, bytes32_from_hex(root));
    assert_eq!(decoded.slot, peam::slot::Slot(Uint64(slot)));
}

#[test]
fn lean_spec_block_header_zero_fixture() {
    let path = local_consensus_container_fixture("test_block_header_zero.json");
    let entry = load_single_fixture_entry(&path);
    let decoded: BlockHeader = decode_roundtrip(&entry, "BlockHeader");

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
    let path = local_consensus_container_fixture("test_block_header_typical.json");
    let entry = load_single_fixture_entry(&path);
    let decoded: BlockHeader = decode_roundtrip(&entry, "BlockHeader");

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
    let path = local_consensus_container_fixture("test_block_body_empty.json");
    let entry = load_single_fixture_entry(&path);
    let decoded: BlockBody = decode_roundtrip(&entry, "BlockBody");
    assert!(decoded.attestations.is_empty());
}
