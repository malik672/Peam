use std::fs;
use std::path::Path;

use crate::containers::config::Config;
use crate::containers::state::{State, Validators};
use crate::ssz::SszFixedLen;
use crate::types::uint::Uint64;

#[derive(Clone, Debug)]
pub struct NodeSettings {
    pub discovery_interval_secs: u64,
    pub score_decay_interval_secs: u64,
    pub score_decay_amount: i64,
    pub ban_threshold: i64,
    pub bootnodes: Vec<String>,
    pub trusted_peers: Vec<String>,
    pub allowed_topics: Vec<String>,
    pub topic_scores: Vec<(String, i64)>,
    pub topic_validators: Vec<(String, crate::networking::GossipValidatorKind)>,
    pub max_gossip_bytes: usize,
    pub max_reqresp_bytes: usize,
}

pub fn load_config(path: &Path) -> Result<Config, String> {
    let bytes = fs::read(path)
        .map_err(|err| format!("Failed to read config {}: {err}", path.display()))?;

    if bytes.len() == Config::fixed_len() {
        return Config::decode_ssz_checked(&bytes);
    }

    let text = std::str::from_utf8(&bytes)
        .map_err(|err| format!("Config is not valid UTF-8: {err}"))?;
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

    let genesis_time =
        genesis_time.ok_or_else(|| "Config missing genesis_time".to_string())?;
    Ok(Config {
        genesis_time: Uint64(genesis_time),
    })
}

pub fn load_node_settings(path: &Path) -> Result<(Config, NodeSettings), String> {
    let bytes = fs::read(path)
        .map_err(|err| format!("Failed to read config {}: {err}", path.display()))?;

    if bytes.len() == Config::fixed_len() {
        let config = Config::decode_ssz_checked(&bytes)?;
        let settings = NodeSettings {
            discovery_interval_secs: 5,
            score_decay_interval_secs: 30,
            score_decay_amount: 1,
            ban_threshold: -100,
            bootnodes: Vec::new(),
            trusted_peers: Vec::new(),
            allowed_topics: vec![
                "leanconsensus/devnet2/block/ssz_snappy".to_string(),
                "leanconsensus/devnet2/attestation/ssz_snappy".to_string(),
            ],
            topic_scores: vec![
                ("leanconsensus/devnet2/block/ssz_snappy".to_string(), 2),
                ("leanconsensus/devnet2/attestation/ssz_snappy".to_string(), 1),
            ],
            topic_validators: vec![
                (
                    "leanconsensus/devnet2/block/ssz_snappy".to_string(),
                    crate::networking::GossipValidatorKind::Block,
                ),
                (
                    "leanconsensus/devnet2/attestation/ssz_snappy".to_string(),
                    crate::networking::GossipValidatorKind::Attestation,
                ),
            ],
            max_gossip_bytes: 2_000_000,
            max_reqresp_bytes: 4_000_000,
        };
        return Ok((config, settings));
    }

    let text = std::str::from_utf8(&bytes)
        .map_err(|err| format!("Config is not valid UTF-8: {err}"))?;
    let mut genesis_time: Option<u64> = None;
    let mut discovery_interval_secs: Option<u64> = None;
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
                .map(|entry| entry.to_string())
                .collect::<Vec<_>>();
        } else if key == "topic_scores" {
            topic_scores = value
                .split(',')
                .filter_map(|entry| {
                    let (topic, score) = entry.trim().split_once(':')?;
                    let score = score.trim().parse::<i64>().ok()?;
                    Some((topic.trim().to_string(), score))
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
                    Some((topic.trim().to_string(), kind))
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
        }
    }

    let genesis_time =
        genesis_time.ok_or_else(|| "Config missing genesis_time".to_string())?;
    let config = Config {
        genesis_time: Uint64(genesis_time),
    };
    let settings = if allowed_topics.is_empty() {
        NodeSettings {
            discovery_interval_secs: discovery_interval_secs.unwrap_or(5),
            score_decay_interval_secs: score_decay_interval_secs.unwrap_or(30),
            score_decay_amount: score_decay_amount.unwrap_or(1),
            ban_threshold: ban_threshold.unwrap_or(-100),
            bootnodes,
            trusted_peers,
            allowed_topics: vec![
                "leanconsensus/devnet2/block/ssz_snappy".to_string(),
                "leanconsensus/devnet2/attestation/ssz_snappy".to_string(),
            ],
            topic_scores: vec![
                ("leanconsensus/devnet2/block/ssz_snappy".to_string(), 2),
                ("leanconsensus/devnet2/attestation/ssz_snappy".to_string(), 1),
            ],
            topic_validators: vec![
                (
                    "leanconsensus/devnet2/block/ssz_snappy".to_string(),
                    crate::networking::GossipValidatorKind::Block,
                ),
                (
                    "leanconsensus/devnet2/attestation/ssz_snappy".to_string(),
                    crate::networking::GossipValidatorKind::Attestation,
                ),
            ],
            max_gossip_bytes: max_gossip_bytes.unwrap_or(2_000_000),
            max_reqresp_bytes: max_reqresp_bytes.unwrap_or(4_000_000),
        }
    } else {
        NodeSettings {
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
        }
    };
    Ok((config, settings))
}

pub fn build_genesis(config: Config) -> Result<State, String> {
    let validators = Validators::new(vec![])?;
    Ok(State::generate_genesis(config.genesis_time, validators))
}
