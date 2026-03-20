use std::fs;
use std::path::{Path, PathBuf};

use enr::{Enr, EnrPublicKey, k256::ecdsa::SigningKey as EnrSigningKey};
use libp2p::PeerId;
use libp2p::identity::secp256k1;
use serde::Deserialize;

use crate::containers::config::Config;
use crate::containers::state::{State, Validators};
use crate::containers::validator::{Validator, ValidatorIndex};
use crate::ssz::SszFixedLen;
use crate::types::bytes::Bytes52;
use crate::types::uint::Uint64;
use crate::unsafe_vec::write_at;

/// Default validator-set size used when config does not specify `validator_count`.
pub const DEFAULT_VALIDATOR_COUNT: usize = 5;
const DEFAULT_BLOCK_TOPIC: &str = "/leanconsensus/devnet3/blocks/ssz_snappy";
const DEFAULT_ATTESTATION_TOPIC: &str = "/leanconsensus/devnet3/attestation_0/ssz_snappy";
const DEFAULT_AGGREGATION_TOPIC: &str = "/leanconsensus/devnet3/aggregation/ssz_snappy";

#[inline]
fn canonicalize_topic(topic: &str) -> String {
    let topic = topic.trim();
    if topic.starts_with('/') {
        topic.to_string()
    } else {
        format!("/{topic}")
    }
}

#[inline]
fn default_allowed_topics() -> Vec<String> {
    vec![
        DEFAULT_BLOCK_TOPIC.to_string(),
        DEFAULT_ATTESTATION_TOPIC.to_string(),
        DEFAULT_AGGREGATION_TOPIC.to_string(),
    ]
}

#[inline]
fn default_topic_scores() -> Vec<(String, i64)> {
    vec![
        (DEFAULT_BLOCK_TOPIC.to_string(), 2),
        (DEFAULT_ATTESTATION_TOPIC.to_string(), 1),
        (DEFAULT_AGGREGATION_TOPIC.to_string(), 1),
    ]
}

#[inline]
fn default_topic_validators() -> Vec<(String, crate::networking::GossipValidatorKind)> {
    vec![
        (
            DEFAULT_BLOCK_TOPIC.to_string(),
            crate::networking::GossipValidatorKind::Block,
        ),
        (
            DEFAULT_ATTESTATION_TOPIC.to_string(),
            crate::networking::GossipValidatorKind::Attestation,
        ),
        (
            DEFAULT_AGGREGATION_TOPIC.to_string(),
            crate::networking::GossipValidatorKind::AggregatedAttestation,
        ),
    ]
}

#[inline]
fn resolve_validator_config_path(
    config_path: &Path,
    validator_config_path: Option<&str>,
) -> PathBuf {
    let config_dir = config_path.parent().unwrap_or_else(|| Path::new("."));
    validator_config_path
        .map(PathBuf::from)
        .map(|path| {
            if path.is_absolute() {
                path
            } else {
                config_dir.join(path)
            }
        })
        .unwrap_or_else(|| config_dir.join("validator-config.yaml"))
}

#[inline]
fn resolve_config_relative_path(config_path: &Path, value: &str) -> PathBuf {
    let candidate = PathBuf::from(value);
    if candidate.is_absolute() {
        candidate
    } else {
        config_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(candidate)
    }
}

#[inline]
fn decode_quic_port(raw: &[u8]) -> Option<u16> {
    let bytes: [u8; 2] = raw.try_into().ok()?;
    Some(u16::from_be_bytes(bytes))
}

pub fn load_bootnodes_from_enr_file(path: &Path) -> Result<Vec<String>, String> {
    let text = fs::read_to_string(path)
        .map_err(|err| format!("Failed to read bootnodes file {}: {err}", path.display()))?;
    let entries: serde_yaml::Value = serde_yaml::from_str(&text)
        .map_err(|err| format!("Failed to parse bootnodes file {}: {err}", path.display()))?;
    let sequence = entries.as_sequence().ok_or_else(|| {
        format!(
            "Failed to parse bootnodes file {}: expected a YAML sequence",
            path.display()
        )
    })?;

    let mut bootnodes = Vec::new();
    for (index, entry) in sequence.iter().enumerate() {
        let enr_text = match entry {
            serde_yaml::Value::String(value) => value.as_str(),
            serde_yaml::Value::Mapping(map) => map
                .get(serde_yaml::Value::String("enr".to_string()))
                .and_then(serde_yaml::Value::as_str)
                .ok_or_else(|| {
                    format!(
                        "Invalid bootnode entry {} in {}: expected `enr` string",
                        index + 1,
                        path.display()
                    )
                })?,
            _ => {
                return Err(format!(
                    "Invalid bootnode entry {} in {}: expected string or mapping",
                    index + 1,
                    path.display()
                ));
            }
        };
        let enr: Enr<EnrSigningKey> = enr_text.parse().map_err(|err| {
            format!(
                "Invalid ENR at {} entry {}: {err}",
                path.display(),
                index + 1
            )
        })?;

        let Some(ip) = enr.ip4() else {
            continue;
        };
        #[allow(deprecated)]
        let quic_port = enr
            .get("quic")
            .and_then(|value| decode_quic_port(value.as_ref()))
            .or_else(|| enr.udp4());
        let Some(quic_port) = quic_port else {
            continue;
        };

        let public_key = secp256k1::PublicKey::try_from_bytes(enr.public_key().encode().as_ref())
            .map_err(|err| {
            format!(
                "Invalid secp256k1 public key in {} entry {}: {err}",
                path.display(),
                index + 1
            )
        })?;
        let peer_id = PeerId::from_public_key(&public_key.into());
        bootnodes.push(format!("/ip4/{ip}/udp/{quic_port}/quic-v1/p2p/{peer_id}"));
    }

    Ok(bootnodes)
}

#[inline]
fn validator_config_entry(
    validator_config_path: &Path,
    local_validator_index: u64,
) -> Result<Option<ValidatorConfigEntry>, String> {
    if !validator_config_path.exists() {
        return Ok(None);
    }
    let raw = fs::read_to_string(validator_config_path)
        .map_err(|err| format!("Failed to read {}: {err}", validator_config_path.display()))?;
    let parsed: ValidatorConfig = serde_yaml::from_str(&raw)
        .map_err(|err| format!("Failed to parse {}: {err}", validator_config_path.display()))?;
    Ok(parsed
        .validators
        .into_iter()
        .nth(local_validator_index as usize))
}

#[inline]
fn resolve_validator_config_is_aggregator(
    config_path: &Path,
    validator_config_path: Option<&str>,
    local_validator_index: u64,
) -> Result<Option<bool>, String> {
    let validator_config_path = resolve_validator_config_path(config_path, validator_config_path);
    let Some(entry) = validator_config_entry(&validator_config_path, local_validator_index)? else {
        return Ok(None);
    };
    Ok(entry
        .enr_fields
        .and_then(|fields| fields.is_aggregator)
        .or(entry.is_aggregator))
}

#[inline]
fn local_validator_index_from_validators_yaml(
    validators_path: &Path,
    node_name: &str,
) -> Result<Option<u64>, String> {
    if !validators_path.exists() {
        return Ok(None);
    }
    let raw = fs::read_to_string(validators_path)
        .map_err(|err| format!("Failed to read {}: {err}", validators_path.display()))?;
    let by_node: std::collections::BTreeMap<String, Vec<u64>> = serde_yaml::from_str(&raw)
        .map_err(|err| format!("Failed to parse {}: {err}", validators_path.display()))?;
    Ok(by_node
        .get(node_name)
        .and_then(|indexes| indexes.first())
        .copied())
}

#[inline]
fn local_validator_index_from_validator_config(
    validator_config_path: &Path,
    node_name: &str,
) -> Result<Option<u64>, String> {
    if !validator_config_path.exists() {
        return Ok(None);
    }
    let raw = fs::read_to_string(validator_config_path)
        .map_err(|err| format!("Failed to read {}: {err}", validator_config_path.display()))?;
    let parsed: ValidatorConfig = serde_yaml::from_str(&raw)
        .map_err(|err| format!("Failed to parse {}: {err}", validator_config_path.display()))?;
    Ok(parsed
        .validators
        .iter()
        .position(|entry| entry.name == node_name)
        .map(|idx| idx as u64))
}

/// Runtime settings for a [`Node`], parsed from the config file.
///
/// All fields have defaults applied by [`load_node_settings`] when the
/// corresponding key is absent from the config.
///
/// # Defaults (when key is absent)
///
/// | Field                       | Default                                      |
/// |-----------------------------|----------------------------------------------|
/// | `metrics`                   | `false`                                      |
/// | `metrics_address`           | `"127.0.0.1"`                                |
/// | `metrics_port`              | `8080`                                       |
/// | `http_api`                  | `true`                                       |
/// | `http_address`              | `"127.0.0.1"`                                |
/// | `http_port`                 | `8080`                                       |
/// | `discovery_interval_secs`   | `5`                                          |
/// | `score_decay_interval_secs` | `30`                                         |
/// | `score_decay_amount`        | `1`                                          |
/// | `ban_threshold`             | `-100`                                       |
/// | `listen_addr`               | `"/ip4/0.0.0.0/udp/9000/quic-v1"`            |
/// | `node_key_path`             | `None` (ephemeral peer identity)             |
/// | `allowed_topics`            | block + attestation_0 + aggregation devnet3 topics |
/// | `topic_scores`              | block=2, attestation_0=1, aggregation=1      |
/// | `topic_validators`          | block + attestation_0 + aggregation validators |
/// | `max_gossip_bytes`          | `2_000_000`                                  |
/// | `max_reqresp_bytes`         | `4_000_000`                                  |
/// | `is_aggregator`            | `false`                                      |
/// | `attestation_committee_count` | `1`                                    |
/// | `validator_count`           | `5`                                          |
/// | `local_validator_index`     | `0`                                          |
/// | `storage_dir`               | `None` (resolved to `data_dir/store`)        |
/// | `validator_config_path`     | `None` (`<config_dir>/validator-config.yaml`)|
/// | `metrics_node_name`         | `None` (auto-resolve, fallback `"peam"`)     |
/// | `metrics_client_name`       | `None` (derived from node name)              |
/// | `checkpoint_sync_url`       | `None` (start from genesis/store)            |
#[derive(Clone, Debug)]
pub struct NodeSettings {
    /// Enable the Prometheus metrics HTTP server.
    pub metrics: bool,
    /// Bind address for the metrics server (e.g. `"127.0.0.1"`).
    pub metrics_address: String,
    /// TCP port for the metrics server.
    pub metrics_port: u16,
    /// Enable the leanSpec HTTP API endpoints (health, finalized state, etc).
    pub http_api: bool,
    /// Bind address for the leanSpec HTTP API server.
    pub http_address: String,
    /// TCP port for the leanSpec HTTP API server.
    pub http_port: u16,
    /// Interval in seconds between peer discovery rounds.
    pub discovery_interval_secs: u64,
    /// Interval in seconds between peer score decay ticks.
    pub score_decay_interval_secs: u64,
    /// Amount subtracted from a peer's score on each decay tick.
    pub score_decay_amount: i64,
    /// Score threshold below which a peer is banned.
    pub ban_threshold: i64,
    /// Multiaddr the libp2p swarm listens on.
    pub listen_addr: String,
    /// Optional path to secp256k1 private key used for libp2p identity.
    pub node_key_path: Option<String>,
    /// libp2p multiaddrs of bootstrap peers to dial on startup.
    pub bootnodes: Vec<String>,
    /// Peers that are always trusted regardless of score.
    pub trusted_peers: Vec<String>,
    /// Gossipsub topic strings this node will subscribe to.
    pub allowed_topics: Vec<String>,
    /// Per-topic score increments applied when a valid message is received.
    pub topic_scores: Vec<(String, i64)>,
    /// Per-topic gossip validator kind used to validate incoming messages.
    pub topic_validators: Vec<(String, crate::networking::GossipValidatorKind)>,
    /// Maximum byte size of a gossipsub message payload.
    pub max_gossip_bytes: usize,
    /// Maximum byte size of a request/response message.
    pub max_reqresp_bytes: usize,
    /// Whether this node performs attestation aggregation duties.
    pub is_aggregator: bool,
    /// Number of attestation subnets used for validator-to-subnet mapping.
    pub attestation_committee_count: u64,
    /// Number of validators used when building genesis.
    pub validator_count: usize,
    /// Local validator index used for runtime signing/proposing in devnet mode.
    pub local_validator_index: u64,
    /// Optional override for the block store directory.
    /// Relative paths are resolved against `data_dir`; `None` defaults to
    /// `data_dir/store`.
    pub storage_dir: Option<String>,
    /// Optional path to a `validator-config.yaml` file for cross-client
    /// node-name and aggregator-role resolution.
    ///
    /// Relative paths are resolved against the config file directory.
    pub validator_config_path: Option<String>,
    /// Optional metrics `lean_node_info{name=...}` override.
    pub metrics_node_name: Option<String>,
    /// Optional metrics `lean_connected_peers{client=...}` override.
    pub metrics_client_name: Option<String>,
    /// Optional HTTP URL of a checkpoint-sync provider.
    pub checkpoint_sync_url: Option<String>,
}

#[inline]
fn default_node_settings() -> NodeSettings {
    NodeSettings {
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
        allowed_topics: default_allowed_topics(),
        topic_scores: default_topic_scores(),
        topic_validators: default_topic_validators(),
        max_gossip_bytes: 2_000_000,
        max_reqresp_bytes: 4_000_000,
        is_aggregator: false,
        attestation_committee_count: 1,
        validator_count: DEFAULT_VALIDATOR_COUNT,
        local_validator_index: 0,
        storage_dir: None,
        validator_config_path: None,
        metrics_node_name: None,
        metrics_client_name: None,
        checkpoint_sync_url: None,
    }
}

/// Load only the chain [`Config`] from `path`.
///
/// Accepts two formats:
/// - **SSZ binary** — if `bytes.len() == Config::fixed_len()`, decoded directly
///   via [`Config::decode_ssz_checked`].
/// - **Key-value text** — lines of the form `key = value`; blank lines and
///   lines starting with `#` are ignored. The only recognized key is
///   `genesis_time` (parsed as `u64`).
///
/// # Errors
///
/// Returns `Err` if the file cannot be read, is not valid UTF-8 (text path),
/// contains a malformed line, or `genesis_time` is missing.
pub fn load_config(path: &Path) -> Result<Config, String> {
    let bytes =
        fs::read(path).map_err(|err| format!("Failed to read config {}: {err}", path.display()))?;

    if bytes.len() == Config::fixed_len() {
        return Config::decode_ssz_checked(&bytes);
    }

    let text =
        std::str::from_utf8(&bytes).map_err(|err| format!("Config is not valid UTF-8: {err}"))?;
    let mut genesis_time: Option<u64> = None;

    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| format!("Invalid config line: {line}"))?;
        let key = key.trim();
        let value = value.trim();
        if key == "genesis_time" {
            genesis_time = Some(
                value
                    .parse::<u64>()
                    .map_err(|err| format!("Invalid genesis_time {value}: {err}"))?,
            );
        }
    }

    let genesis_time = genesis_time.ok_or_else(|| "Config missing genesis_time".to_string())?;
    Ok(Config {
        genesis_time: Uint64(genesis_time),
    })
}

/// Load both the chain [`Config`] and [`NodeSettings`] from `path`.
///
/// Accepts the same two formats as [`load_config`]:
///
/// - **SSZ binary** — decoded as a bare [`Config`]; all [`NodeSettings`] fields
///   are set to their defaults, including devnet3 blocks/attestation-subnet/aggregation topics.
///
/// - **Key-value text** — parses all known keys (see [`NodeSettings`] field docs
///   for names). Multi-value keys (`bootnodes`, `trusted_peers`, `allowed_topics`)
///   are comma-separated. `topic_scores` uses `topic:score` pairs;
///   `topic_validators` uses `topic=kind` pairs where `kind` is one of
///   `block`, `block_header`, `attestation`, `aggregation`, `exit`
///   (unrecognized kinds map to `GossipValidatorKind::None`). If
///   `allowed_topics` is empty after parsing, the devnet3 defaults are
///   substituted. If `validator-config.yaml` contains `is_aggregator` metadata
///   for the local validator, it overrides the local config flag.
///
/// # Errors
///
/// Returns `Err` if the file cannot be read, is not valid UTF-8 (text path),
/// contains a malformed line, or `genesis_time` is missing.
pub fn load_node_settings(path: &Path) -> Result<(Config, NodeSettings), String> {
    let bytes =
        fs::read(path).map_err(|err| format!("Failed to read config {}: {err}", path.display()))?;

    if bytes.len() == Config::fixed_len() {
        let config = Config::decode_ssz_checked(&bytes)?;
        let settings = default_node_settings();
        return Ok((config, settings));
    }

    let text =
        std::str::from_utf8(&bytes).map_err(|err| format!("Config is not valid UTF-8: {err}"))?;
    if let Ok(doc) = serde_yaml::from_str::<serde_yaml::Value>(text)
        && let Some(genesis_time) = doc.get("GENESIS_TIME").and_then(|v| v.as_u64())
    {
        return Ok((
            Config {
                genesis_time: Uint64(genesis_time),
            },
            default_node_settings(),
        ));
    }
    let mut genesis_time: Option<u64> = None;
    let mut discovery_interval_secs: Option<u64> = None;
    let mut metrics: Option<bool> = None;
    let mut metrics_address: Option<String> = None;
    let mut metrics_port: Option<u16> = None;
    let mut http_api: Option<bool> = None;
    let mut http_address: Option<String> = None;
    let mut http_port: Option<u16> = None;
    let mut score_decay_interval_secs: Option<u64> = None;
    let mut score_decay_amount: Option<i64> = None;
    let mut ban_threshold: Option<i64> = None;
    let mut listen_addr: Option<String> = None;
    let mut node_key_path: Option<String> = None;
    let mut bootnodes: Vec<String> = Vec::new();
    let mut trusted_peers: Vec<String> = Vec::new();
    let mut allowed_topics: Vec<String> = Vec::new();
    let mut topic_scores: Vec<(String, i64)> = Vec::new();
    let mut topic_validators: Vec<(String, crate::networking::GossipValidatorKind)> = Vec::new();
    let mut max_gossip_bytes: Option<usize> = None;
    let mut max_reqresp_bytes: Option<usize> = None;
    let mut is_aggregator: Option<bool> = None;
    let mut attestation_committee_count: Option<u64> = None;
    let mut validator_count: Option<usize> = None;
    let mut local_validator_index: Option<u64> = None;
    let mut storage_dir: Option<String> = None;
    let mut validator_config_path: Option<String> = None;
    let mut metrics_node_name: Option<String> = None;
    let mut metrics_client_name: Option<String> = None;
    let mut checkpoint_sync_url: Option<String> = None;
    let mut bootnodes_file: Option<String> = None;

    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| format!("Invalid config line: {line}"))?;
        let key = key.trim();
        let value = value.trim();
        if key == "genesis_time" {
            genesis_time = Some(
                value
                    .parse::<u64>()
                    .map_err(|err| format!("Invalid genesis_time {value}: {err}"))?,
            );
        } else if key == "metrics" {
            metrics = Some(match value {
                "1" | "true" | "yes" | "on" => true,
                "0" | "false" | "no" | "off" => false,
                _ => return Err(format!("Invalid metrics {value}: expected true/false")),
            });
        } else if key == "metrics_address" {
            if !value.is_empty() {
                metrics_address = Some(value.to_string());
            }
        } else if key == "metrics_port" {
            metrics_port = Some(
                value
                    .parse::<u16>()
                    .map_err(|err| format!("Invalid metrics_port {value}: {err}"))?,
            );
        } else if key == "http_api" {
            http_api = Some(match value {
                "1" | "true" | "yes" | "on" => true,
                "0" | "false" | "no" | "off" => false,
                _ => return Err(format!("Invalid http_api {value}: expected true/false")),
            });
        } else if key == "http_address" {
            if !value.is_empty() {
                http_address = Some(value.to_string());
            }
        } else if key == "http_port" {
            http_port = Some(
                value
                    .parse::<u16>()
                    .map_err(|err| format!("Invalid http_port {value}: {err}"))?,
            );
        } else if key == "discovery_interval_secs" {
            discovery_interval_secs = Some(
                value
                    .parse::<u64>()
                    .map_err(|err| format!("Invalid discovery_interval_secs {value}: {err}"))?,
            );
        } else if key == "score_decay_interval_secs" {
            score_decay_interval_secs = Some(
                value
                    .parse::<u64>()
                    .map_err(|err| format!("Invalid score_decay_interval_secs {value}: {err}"))?,
            );
        } else if key == "score_decay_amount" {
            score_decay_amount = Some(
                value
                    .parse::<i64>()
                    .map_err(|err| format!("Invalid score_decay_amount {value}: {err}"))?,
            );
        } else if key == "ban_threshold" {
            ban_threshold = Some(
                value
                    .parse::<i64>()
                    .map_err(|err| format!("Invalid ban_threshold {value}: {err}"))?,
            );
        } else if key == "listen_addr" {
            if !value.is_empty() {
                listen_addr = Some(value.to_string());
            }
        } else if key == "node_key_path" {
            if !value.is_empty() {
                node_key_path = Some(value.to_string());
            }
        } else if key == "bootnodes" {
            bootnodes = value
                .split(',')
                .map(|entry| entry.trim())
                .filter(|entry| !entry.is_empty())
                .map(|entry| entry.to_string())
                .collect::<Vec<_>>();
        } else if key == "bootnodes_file" {
            if !value.is_empty() {
                bootnodes_file = Some(value.to_string());
            }
        } else if key == "trusted_peers" {
            trusted_peers = value
                .split(',')
                .map(|entry| entry.trim())
                .filter(|entry| !entry.is_empty())
                .map(|entry| entry.to_string())
                .collect::<Vec<_>>();
        } else if key == "allowed_topics" {
            allowed_topics = value
                .split(',')
                .map(|entry| entry.trim())
                .filter(|entry| !entry.is_empty())
                .map(canonicalize_topic)
                .collect::<Vec<_>>();
        } else if key == "topic_scores" {
            topic_scores = value
                .split(',')
                .filter_map(|entry| {
                    let (topic, score) = entry.trim().split_once(':')?;
                    let score = score.trim().parse::<i64>().ok()?;
                    Some((canonicalize_topic(topic), score))
                })
                .collect();
        } else if key == "topic_validators" {
            topic_validators = value
                .split(',')
                .filter_map(|entry| {
                    let (topic, kind) = entry.trim().split_once('=')?;
                    let kind = match kind.trim() {
                        "block" => crate::networking::GossipValidatorKind::Block,
                        "block_header" => crate::networking::GossipValidatorKind::BlockHeader,
                        "attestation" => crate::networking::GossipValidatorKind::Attestation,
                        "aggregation" | "aggregated_attestation" => {
                            crate::networking::GossipValidatorKind::AggregatedAttestation
                        }
                        "exit" => crate::networking::GossipValidatorKind::VoluntaryExit,
                        _ => crate::networking::GossipValidatorKind::None,
                    };
                    Some((canonicalize_topic(topic), kind))
                })
                .collect();
        } else if key == "max_gossip_bytes" {
            max_gossip_bytes = Some(
                value
                    .parse::<usize>()
                    .map_err(|err| format!("Invalid max_gossip_bytes {value}: {err}"))?,
            );
        } else if key == "max_reqresp_bytes" {
            max_reqresp_bytes = Some(
                value
                    .parse::<usize>()
                    .map_err(|err| format!("Invalid max_reqresp_bytes {value}: {err}"))?,
            );
        } else if key == "is_aggregator" {
            is_aggregator = Some(match value {
                "1" | "true" | "yes" | "on" => true,
                "0" | "false" | "no" | "off" => false,
                _ => {
                    return Err(format!(
                        "Invalid is_aggregator {value}: expected true/false"
                    ));
                }
            });
        } else if key == "attestation_committee_count" {
            let parsed = value
                .parse::<u64>()
                .map_err(|err| format!("Invalid attestation_committee_count {value}: {err}"))?;
            if parsed == 0 {
                return Err("Invalid attestation_committee_count 0: must be > 0".to_string());
            }
            attestation_committee_count = Some(parsed);
        } else if key == "validator_count" {
            let parsed = value
                .parse::<usize>()
                .map_err(|err| format!("Invalid validator_count {value}: {err}"))?;
            if parsed == 0 {
                return Err("Invalid validator_count 0: must be > 0".to_string());
            }
            validator_count = Some(parsed);
        } else if key == "local_validator_index" {
            local_validator_index = Some(
                value
                    .parse::<u64>()
                    .map_err(|err| format!("Invalid local_validator_index {value}: {err}"))?,
            );
        } else if key == "storage_dir" {
            if !value.is_empty() {
                storage_dir = Some(value.to_string());
            }
        } else if key == "validator_config_path" {
            if !value.is_empty() {
                validator_config_path = Some(value.to_string());
            }
        } else if key == "metrics_node_name" {
            if !value.is_empty() {
                metrics_node_name = Some(value.to_string());
            }
        } else if key == "metrics_client_name" {
            if !value.is_empty() {
                metrics_client_name = Some(value.to_string());
            }
        } else if key == "checkpoint_sync_url" {
            if !value.is_empty() {
                checkpoint_sync_url = Some(value.to_string());
            }
        }
    }

    let genesis_time = genesis_time.ok_or_else(|| "Config missing genesis_time".to_string())?;
    let config = Config {
        genesis_time: Uint64(genesis_time),
    };
    if let Some(path_value) = bootnodes_file.as_deref() {
        let resolved = resolve_config_relative_path(path, path_value);
        bootnodes.extend(load_bootnodes_from_enr_file(&resolved)?);
    }
    let resolved_metrics_address = metrics_address.unwrap_or_else(|| "127.0.0.1".to_string());
    let resolved_metrics_port = metrics_port.unwrap_or(8080);
    let resolved_http_address = http_address.unwrap_or_else(|| resolved_metrics_address.clone());
    let resolved_http_port = http_port.unwrap_or(resolved_metrics_port);
    let mut settings = if allowed_topics.is_empty() {
        NodeSettings {
            metrics: metrics.unwrap_or(false),
            metrics_address: resolved_metrics_address.clone(),
            metrics_port: resolved_metrics_port,
            http_api: http_api.unwrap_or(true),
            http_address: resolved_http_address.clone(),
            http_port: resolved_http_port,
            discovery_interval_secs: discovery_interval_secs.unwrap_or(5),
            score_decay_interval_secs: score_decay_interval_secs.unwrap_or(30),
            score_decay_amount: score_decay_amount.unwrap_or(1),
            ban_threshold: ban_threshold.unwrap_or(-100),
            listen_addr: listen_addr.unwrap_or_else(|| "/ip4/0.0.0.0/udp/9000/quic-v1".to_string()),
            node_key_path,
            bootnodes,
            trusted_peers,
            allowed_topics: default_allowed_topics(),
            topic_scores: default_topic_scores(),
            topic_validators: default_topic_validators(),
            max_gossip_bytes: max_gossip_bytes.unwrap_or(2_000_000),
            max_reqresp_bytes: max_reqresp_bytes.unwrap_or(4_000_000),
            is_aggregator: is_aggregator.unwrap_or(false),
            attestation_committee_count: attestation_committee_count.unwrap_or(1),
            validator_count: validator_count.unwrap_or(DEFAULT_VALIDATOR_COUNT),
            local_validator_index: local_validator_index.unwrap_or(0),
            storage_dir,
            validator_config_path,
            metrics_node_name,
            metrics_client_name,
            checkpoint_sync_url,
        }
    } else {
        NodeSettings {
            metrics: metrics.unwrap_or(false),
            metrics_address: resolved_metrics_address,
            metrics_port: resolved_metrics_port,
            http_api: http_api.unwrap_or(true),
            http_address: resolved_http_address,
            http_port: resolved_http_port,
            discovery_interval_secs: discovery_interval_secs.unwrap_or(5),
            score_decay_interval_secs: score_decay_interval_secs.unwrap_or(30),
            score_decay_amount: score_decay_amount.unwrap_or(1),
            ban_threshold: ban_threshold.unwrap_or(-100),
            listen_addr: listen_addr.unwrap_or_else(|| "/ip4/0.0.0.0/udp/9000/quic-v1".to_string()),
            node_key_path,
            bootnodes,
            trusted_peers,
            allowed_topics,
            topic_scores,
            topic_validators,
            max_gossip_bytes: max_gossip_bytes.unwrap_or(2_000_000),
            max_reqresp_bytes: max_reqresp_bytes.unwrap_or(4_000_000),
            is_aggregator: is_aggregator.unwrap_or(false),
            attestation_committee_count: attestation_committee_count.unwrap_or(1),
            validator_count: validator_count.unwrap_or(DEFAULT_VALIDATOR_COUNT),
            local_validator_index: local_validator_index.unwrap_or(0),
            storage_dir,
            validator_config_path,
            metrics_node_name,
            metrics_client_name,
            checkpoint_sync_url,
        }
    };
    if let Some(config_is_aggregator) = resolve_validator_config_is_aggregator(
        path,
        settings.validator_config_path.as_deref(),
        settings.local_validator_index,
    )? {
        settings.is_aggregator = config_is_aggregator;
    }
    Ok((config, settings))
}

#[derive(Deserialize)]
struct ValidatorConfig {
    validators: Vec<ValidatorConfigEntry>,
}

#[derive(Clone, Deserialize)]
struct ValidatorConfigEntry {
    name: String,
    #[serde(default)]
    is_aggregator: Option<bool>,
    #[serde(default, rename = "enrFields")]
    enr_fields: Option<ValidatorConfigEnrFields>,
}

#[derive(Clone, Deserialize)]
struct ValidatorConfigEnrFields {
    #[serde(default)]
    is_aggregator: Option<bool>,
}

#[inline]
fn derive_client_name(node_name: &str) -> String {
    node_name
        .split_once('_')
        .map(|(prefix, _)| prefix)
        .or_else(|| node_name.split_once('-').map(|(prefix, _)| prefix))
        .filter(|prefix| !prefix.is_empty())
        .unwrap_or(node_name)
        .to_string()
}

#[inline]
fn node_name_from_validators_yaml(
    validators_path: &Path,
    local_validator_index: u64,
) -> Result<Option<String>, String> {
    if !validators_path.exists() {
        return Ok(None);
    }
    let raw = fs::read_to_string(validators_path)
        .map_err(|err| format!("Failed to read {}: {err}", validators_path.display()))?;
    let by_node: std::collections::BTreeMap<String, Vec<u64>> = serde_yaml::from_str(&raw)
        .map_err(|err| format!("Failed to parse {}: {err}", validators_path.display()))?;
    Ok(by_node.into_iter().find_map(|(name, indexes)| {
        if indexes.contains(&local_validator_index) {
            Some(name)
        } else {
            None
        }
    }))
}

#[inline]
fn node_name_from_validator_config(
    validator_config_path: &Path,
    local_validator_index: u64,
) -> Result<Option<String>, String> {
    Ok(
        validator_config_entry(validator_config_path, local_validator_index)?
            .map(|entry| entry.name),
    )
}

pub fn resolve_local_validator_index_for_node_name(
    config_path: &Path,
    settings: &NodeSettings,
    node_name: &str,
) -> Result<Option<u64>, String> {
    let config_dir = config_path.parent().unwrap_or_else(|| Path::new("."));
    let validators_path = config_dir.join("validators.yaml");
    if let Some(index) = local_validator_index_from_validators_yaml(&validators_path, node_name)? {
        return Ok(Some(index));
    }
    let validator_config_path =
        resolve_validator_config_path(config_path, settings.validator_config_path.as_deref());
    local_validator_index_from_validator_config(&validator_config_path, node_name)
}

pub fn resolve_validator_startup_overrides(
    config_path: &Path,
    settings: &NodeSettings,
    node_id: Option<&str>,
    validator_keys_path: Option<&Path>,
    validators_path: Option<&Path>,
) -> Result<(Option<u64>, PathBuf), String> {
    let validators_path = validators_path.map(Path::to_path_buf).unwrap_or_else(|| {
        config_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join("validators.yaml")
    });
    let local_validator_index = match node_id {
        Some(node_name) => {
            if let Some(index) =
                local_validator_index_from_validators_yaml(&validators_path, node_name)?
            {
                Some(index)
            } else {
                resolve_local_validator_index_for_node_name(config_path, settings, node_name)?
            }
        }
        None => None,
    };
    let config_dir = config_path.parent().unwrap_or_else(|| Path::new("."));
    let validator_keys_dir = validator_keys_path
        .map(Path::to_path_buf)
        .unwrap_or_else(|| config_dir.join("hash-sig-keys"));
    Ok((local_validator_index, validator_keys_dir))
}

/// Resolve metrics labels (`node_name`, `client_name`) for this node.
///
/// Priority:
/// 1. Explicit config overrides (`metrics_node_name`, `metrics_client_name`)
/// 2. `validators.yaml` lookup by `local_validator_index`
/// 3. `validator-config.yaml` nth-entry lookup
/// 4. Fallback to `"peam"` and derived client name
pub fn resolve_metrics_identity(
    config_path: &Path,
    settings: &NodeSettings,
) -> Result<(String, String), String> {
    let explicit_node_name = settings
        .metrics_node_name
        .as_ref()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(ToOwned::to_owned);

    let node_name = if let Some(name) = explicit_node_name {
        name
    } else {
        let config_dir = config_path.parent().unwrap_or_else(|| Path::new("."));
        let validators_path = config_dir.join("validators.yaml");
        if let Some(name) =
            node_name_from_validators_yaml(&validators_path, settings.local_validator_index)?
        {
            name
        } else {
            let validator_config_path = resolve_validator_config_path(
                config_path,
                settings.validator_config_path.as_deref(),
            );
            node_name_from_validator_config(&validator_config_path, settings.local_validator_index)?
                .unwrap_or_else(|| "peam".to_string())
        }
    };

    let client_name = settings
        .metrics_client_name
        .as_ref()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| derive_client_name(&node_name));

    Ok((node_name, client_name))
}

/// Construct a genesis [`State`] from the given chain [`Config`].
///
/// Builds a genesis state using the default validator count.
#[inline]
pub fn build_genesis(config: Config) -> Result<State, String> {
    build_genesis_with_validator_count(config, DEFAULT_VALIDATOR_COUNT)
}

/// Builds a genesis state using `validator_count` deterministic validators.
#[inline]
pub fn build_genesis_with_validator_count(
    config: Config,
    validator_count: usize,
) -> Result<State, String> {
    if validator_count == 0 {
        return Err("validator_count must be > 0".to_string());
    }
    let validators = build_devnet_validators(validator_count);
    Ok(State::generate_genesis(config.genesis_time, validators))
}

/// Builds a genesis state from a lean-spec `config.yaml` file.
///
/// Parses `GENESIS_TIME` and `GENESIS_VALIDATORS` (hex-encoded 52-byte pubkeys)
/// from the YAML config. This is the canonical genesis used by all clients.
pub fn build_genesis_from_config_yaml(path: &Path) -> Result<State, String> {
    build_genesis_from_config_yaml_with_override(path, None)
}

pub fn build_genesis_from_config_yaml_with_override(
    path: &Path,
    genesis_time_override: Option<u64>,
) -> Result<State, String> {
    let raw = fs::read_to_string(path)
        .map_err(|err| format!("failed to read {}: {err}", path.display()))?;
    let doc: serde_yaml::Value = serde_yaml::from_str(&raw)
        .map_err(|err| format!("failed to parse {}: {err}", path.display()))?;
    let genesis_time = genesis_time_override.unwrap_or_else(|| {
        doc.get("GENESIS_TIME")
            .and_then(|v| v.as_u64())
            .unwrap_or_default()
    });
    if genesis_time == 0 {
        return Err(format!("missing GENESIS_TIME in {}", path.display()));
    }
    let validators_yaml = doc
        .get("GENESIS_VALIDATORS")
        .and_then(|v| v.as_sequence())
        .ok_or_else(|| format!("missing GENESIS_VALIDATORS in {}", path.display()))?;
    if validators_yaml.is_empty() {
        return Err(format!("GENESIS_VALIDATORS is empty in {}", path.display()));
    }
    let mut validators = Vec::with_capacity(validators_yaml.len());
    for (i, entry) in validators_yaml.iter().enumerate() {
        let hex_str = entry
            .as_str()
            .ok_or_else(|| format!("GENESIS_VALIDATORS[{i}] is not a string"))?;
        let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);
        let pk_bytes: Vec<u8> = (0..hex_str.len())
            .step_by(2)
            .map(|j| {
                u8::from_str_radix(&hex_str[j..j + 2], 16)
                    .map_err(|err| format!("GENESIS_VALIDATORS[{i}] bad hex: {err}"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        if pk_bytes.len() != 52 {
            return Err(format!(
                "GENESIS_VALIDATORS[{i}] expected 52 bytes, got {}",
                pk_bytes.len()
            ));
        }
        validators.push(Validator {
            pubkey: Bytes52::from_slice(&pk_bytes),
            index: ValidatorIndex(Uint64(i as u64)),
            balance: Uint64(0),
        });
    }
    let validators = Validators::new(validators).expect("genesis validator set");
    Ok(State::generate_genesis(Uint64(genesis_time), validators))
}

#[inline]
fn build_devnet_validators(validator_count: usize) -> Validators {
    let mut validators = Vec::with_capacity(validator_count);
    // SAFETY:
    // - capacity is pre-allocated to `validator_count`.
    // - each slot in [0, validator_count) is written exactly once below.
    unsafe { validators.set_len(validator_count) };
    for i in 0..validator_count {
        let mut pubkey = [0u8; 52];
        // Deterministic placeholder key material for local devnet topology.
        pubkey[0] = 0xD1;
        pubkey[1] = i as u8;
        // SAFETY: `i < validator_count`, so index is in-bounds of initialized len.
        unsafe {
            write_at(
                &mut validators,
                i,
                Validator {
                    pubkey: Bytes52::from(pubkey),
                    index: ValidatorIndex(Uint64(i as u64)),
                    balance: Uint64(0),
                },
            )
        };
    }
    Validators::new(validators).expect("devnet validator set")
}
