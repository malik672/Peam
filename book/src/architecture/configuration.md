# Configuration

Configuration is loaded from a plain-text key=value file. It controls genesis time, networking, gossip topics, and storage.

## Text config format

```text
genesis_time=42
discovery_interval_secs=5
score_decay_interval_secs=30
score_decay_amount=1
ban_threshold=-100
bootnodes=/ip4/1.2.3.4/tcp/30303/p2p/12D3KooWBootA
trusted_peers=/ip4/5.6.7.8/tcp/30303/p2p/12D3KooWTrustA
allowed_topics=leanconsensus/devnet2/block/ssz_snappy,leanconsensus/devnet2/attestation/ssz_snappy
topic_scores=leanconsensus/devnet2/block/ssz_snappy:2,leanconsensus/devnet2/attestation/ssz_snappy:1
topic_validators=leanconsensus/devnet2/block/ssz_snappy=block,leanconsensus/devnet2/attestation/ssz_snappy=attestation
max_gossip_bytes=2000000
max_reqresp_bytes=4000000
storage_dir=store
```

## SSZ config

`Config` is a minimal SSZ-encoded struct containing a single `genesis_time: Uint64`. It is 8 bytes fixed-length and supports `HashTreeRoot`.

```rust
pub struct Config {
    pub genesis_time: Uint64,
}
```

The node accepts either SSZ config bytes or the text format above. SSZ config can be generated with `--genesis-time <u64>` and piped to storage or passed directly.

## Key fields

| Field | Type | Description |
|-------|------|-------------|
| `genesis_time` | `u64` | Unix timestamp of the genesis slot |
| `discovery_interval_secs` | `u64` | How often to run peer discovery |
| `score_decay_interval_secs` | `u64` | Peer score decay frequency |
| `score_decay_amount` | `i64` | Score units subtracted per decay tick |
| `ban_threshold` | `i64` | Score at which a peer is banned |
| `bootnodes` | `multiaddr` list | Initial peers for discovery |
| `trusted_peers` | `multiaddr` list | Peers exempt from score-based banning |
| `allowed_topics` | string list | Gossip topics the node subscribes to |
| `topic_scores` | `topic:score` pairs | Per-topic score weights |
| `topic_validators` | `topic=kind` pairs | Maps topics to validators (`block`, `attestation`) |
| `max_gossip_bytes` | `u64` | Max size of a single gossip message |
| `max_reqresp_bytes` | `u64` | Max size of a req/resp payload |
| `storage_dir` | path | Storage root relative to `--data-dir` |
