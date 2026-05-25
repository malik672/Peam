use std::path::{Path, PathBuf};

use peam::ssz::{SszDecode, SszEncode};
use serde_json::Value;

use super::fixture_json::{first_fixture_entry, load_fixture_file};
use super::hex::decode_hex;

pub fn local_consensus_container_fixtures_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/ssz/devnet/consensus_containers")
}

pub fn local_consensus_container_fixture(name: &str) -> PathBuf {
    local_consensus_container_fixtures_root().join(name)
}

pub fn load_single_fixture_entry(path: &Path) -> Value {
    let json = load_fixture_file(path);
    let (_, entry) = first_fixture_entry(&json);
    entry.clone()
}

pub fn decode_roundtrip<T>(entry: &Value, expected_type: &str) -> T
where
    T: SszDecode + SszEncode,
{
    assert_eq!(entry["typeName"], expected_type);
    let serialized = entry["serialized"].as_str().expect("serialized");
    let bytes = decode_hex(serialized);
    let decoded = T::decode_ssz(&bytes).expect("decode fixture value");
    let encoded = decoded.encode_ssz();
    assert_eq!(encoded, bytes);
    decoded
}
