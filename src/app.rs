use std::fs;
use std::path::Path;

use crate::containers::config::Config;
use crate::containers::state::{State, Validators};
use crate::containers::validator::{Validator, ValidatorIndex};
use crate::ssz::SszFixedLen;
use crate::types::bytes::Bytes52;
use crate::types::uint::Uint64;
use crate::unsafe_vec::write_at;

/// Default validator-set size used when config does not specify `validator_count`.
pub const DEFAULT_VALIDATOR_COUNT: usize = 5;

#[inline]
fn canonicalize_topic(topic: &str) -> String {
    let topic = topic.trim();
    if topic.starts_with('/') {
        topic.to_string()
    } else {
        format!("/{topic}")
    }
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
/// | `discovery_interval_secs`   | `5`                                          |
/// | `score_decay_interval_secs` | `30`                                         |
/// | `score_decay_amount`        | `1`                                          |
/// | `ban_threshold`             | `-100`                                       |
/// | `allowed_topics`            | block + attestation devnet2 topics           |
/// | `topic_scores`              | block=2, attestation=1                       |
/// | `topic_validators`          | block + attestation validators               |
/// | `max_gossip_bytes`          | `2_000_000`                                  |
/// | `max_reqresp_bytes`         | `4_000_000`                                  |
/// | `validator_count`           | `5`                                          |
/// | `local_validator_index`     | `0`                                          |
/// | `storage_dir`               | `None` (resolved to `data_dir/store`)        |
#[derive(Clone, Debug)]
pub struct NodeSettings {
    /// Enable the Prometheus metrics HTTP server.
    pub metrics: bool,
    /// Bind address for the metrics server (e.g. `"127.0.0.1"`).
    pub metrics_address: String,
    /// TCP port for the metrics server.
    pub metrics_port: u16,
    /// Interval in seconds between peer discovery rounds.
    pub discovery_interval_secs: u64,
    /// Interval in seconds between peer score decay ticks.
    pub score_decay_interval_secs: u64,
    /// Amount subtracted from a peer's score on each decay tick.
    pub score_decay_amount: i64,
    /// Score threshold below which a peer is banned.
    pub ban_threshold: i64,
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
    /// Number of validators used when building genesis.
    pub validator_count: usize,
    /// Local validator index used for runtime signing/proposing in devnet mode.
    pub local_validator_index: u64,
    /// Optional override for the block store directory.
    /// Relative paths are resolved against `data_dir`; `None` defaults to
    /// `data_dir/store`.
    pub storage_dir: Option<String>,
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
///   are set to their defaults, including the devnet2 block and attestation topics.
///
/// - **Key-value text** — parses all known keys (see [`NodeSettings`] field docs
///   for names). Multi-value keys (`bootnodes`, `trusted_peers`, `allowed_topics`)
///   are comma-separated. `topic_scores` uses `topic:score` pairs;
///   `topic_validators` uses `topic=kind` pairs where `kind` is one of
///   `block`, `block_header`, `attestation`, `exit` (unrecognized kinds map to
///   `GossipValidatorKind::None`). If `allowed_topics` is empty after parsing,
///   the devnet2 defaults are substituted.
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
        let settings = NodeSettings {
            metrics: false,
            metrics_address: "127.0.0.1".to_string(),
            metrics_port: 8080,
            discovery_interval_secs: 5,
            score_decay_interval_secs: 30,
            score_decay_amount: 1,
            ban_threshold: -100,
            bootnodes: Vec::new(),
            trusted_peers: Vec::new(),
            allowed_topics: vec![
                "/leanconsensus/devnet2/block/ssz_snappy".to_string(),
                "/leanconsensus/devnet2/attestation/ssz_snappy".to_string(),
            ],
            topic_scores: vec![
                ("/leanconsensus/devnet2/block/ssz_snappy".to_string(), 2),
                (
                    "/leanconsensus/devnet2/attestation/ssz_snappy".to_string(),
                    1,
                ),
            ],
            topic_validators: vec![
                (
                    "/leanconsensus/devnet2/block/ssz_snappy".to_string(),
                    crate::networking::GossipValidatorKind::Block,
                ),
                (
                    "/leanconsensus/devnet2/attestation/ssz_snappy".to_string(),
                    crate::networking::GossipValidatorKind::Attestation,
                ),
            ],
            max_gossip_bytes: 2_000_000,
            max_reqresp_bytes: 4_000_000,
            validator_count: DEFAULT_VALIDATOR_COUNT,
            local_validator_index: 0,
            storage_dir: None,
        };
        return Ok((config, settings));
    }

    let text =
        std::str::from_utf8(&bytes).map_err(|err| format!("Config is not valid UTF-8: {err}"))?;
    let mut genesis_time: Option<u64> = None;
    let mut discovery_interval_secs: Option<u64> = None;
    let mut metrics: Option<bool> = None;
    let mut metrics_address: Option<String> = None;
    let mut metrics_port: Option<u16> = None;
    let mut score_decay_interval_secs: Option<u64> = None;
    let mut score_decay_amount: Option<i64> = None;
    let mut ban_threshold: Option<i64> = None;
    let mut bootnodes: Vec<String> = Vec::new();
    let mut trusted_peers: Vec<String> = Vec::new();
    let mut allowed_topics: Vec<String> = Vec::new();
    let mut topic_scores: Vec<(String, i64)> = Vec::new();
    let mut topic_validators: Vec<(String, crate::networking::GossipValidatorKind)> = Vec::new();
    let mut max_gossip_bytes: Option<usize> = None;
    let mut max_reqresp_bytes: Option<usize> = None;
    let mut validator_count: Option<usize> = None;
    let mut local_validator_index: Option<u64> = None;
    let mut storage_dir: Option<String> = None;

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
        } else if key == "bootnodes" {
            bootnodes = value
                .split(',')
                .map(|entry| entry.trim())
                .filter(|entry| !entry.is_empty())
                .map(|entry| entry.to_string())
                .collect::<Vec<_>>();
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
        }
    }

    let genesis_time = genesis_time.ok_or_else(|| "Config missing genesis_time".to_string())?;
    let config = Config {
        genesis_time: Uint64(genesis_time),
    };
    let settings = if allowed_topics.is_empty() {
        NodeSettings {
            metrics: metrics.unwrap_or(false),
            metrics_address: metrics_address.unwrap_or_else(|| "127.0.0.1".to_string()),
            metrics_port: metrics_port.unwrap_or(8080),
            discovery_interval_secs: discovery_interval_secs.unwrap_or(5),
            score_decay_interval_secs: score_decay_interval_secs.unwrap_or(30),
            score_decay_amount: score_decay_amount.unwrap_or(1),
            ban_threshold: ban_threshold.unwrap_or(-100),
            bootnodes,
            trusted_peers,
            allowed_topics: vec![
                "/leanconsensus/devnet2/block/ssz_snappy".to_string(),
                "/leanconsensus/devnet2/attestation/ssz_snappy".to_string(),
            ],
            topic_scores: vec![
                ("/leanconsensus/devnet2/block/ssz_snappy".to_string(), 2),
                (
                    "/leanconsensus/devnet2/attestation/ssz_snappy".to_string(),
                    1,
                ),
            ],
            topic_validators: vec![
                (
                    "/leanconsensus/devnet2/block/ssz_snappy".to_string(),
                    crate::networking::GossipValidatorKind::Block,
                ),
                (
                    "/leanconsensus/devnet2/attestation/ssz_snappy".to_string(),
                    crate::networking::GossipValidatorKind::Attestation,
                ),
            ],
            max_gossip_bytes: max_gossip_bytes.unwrap_or(2_000_000),
            max_reqresp_bytes: max_reqresp_bytes.unwrap_or(4_000_000),
            validator_count: validator_count.unwrap_or(DEFAULT_VALIDATOR_COUNT),
            local_validator_index: local_validator_index.unwrap_or(0),
            storage_dir,
        }
    } else {
        NodeSettings {
            metrics: metrics.unwrap_or(false),
            metrics_address: metrics_address.unwrap_or_else(|| "127.0.0.1".to_string()),
            metrics_port: metrics_port.unwrap_or(8080),
            discovery_interval_secs: discovery_interval_secs.unwrap_or(5),
            score_decay_interval_secs: score_decay_interval_secs.unwrap_or(30),
            score_decay_amount: score_decay_amount.unwrap_or(1),
            ban_threshold: ban_threshold.unwrap_or(-100),
            bootnodes,
            trusted_peers,
            allowed_topics,
            topic_scores,
            topic_validators,
            max_gossip_bytes: max_gossip_bytes.unwrap_or(2_000_000),
            max_reqresp_bytes: max_reqresp_bytes.unwrap_or(4_000_000),
            validator_count: validator_count.unwrap_or(DEFAULT_VALIDATOR_COUNT),
            local_validator_index: local_validator_index.unwrap_or(0),
            storage_dir,
        }
    };
    Ok((config, settings))
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
