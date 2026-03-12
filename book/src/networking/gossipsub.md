# Gossipsub

`lean_eth` uses libp2p gossipsub for block and attestation broadcast. The gossip sub-module lives in `src/networking/gossipsub/`.

## Topics

Topics follow the pattern `leanconsensus/<network>/<object>/<encoding>`, e.g.:

```
leanconsensus/devnet3/blocks/ssz_snappy
leanconsensus/devnet3/attestation_0/ssz_snappy
leanconsensus/devnet3/aggregation/ssz_snappy
```

Topics are configured via `allowed_topics` in the config file. Each topic can be assigned a score weight via `topic_scores` and a validator kind via `topic_validators`.

## Message types

`LeanGossipsubMessage` is the decoded inbound gossip envelope:

```rust
pub enum LeanGossipsubMessage {
    Block(GossipBlock),
    AttestationSubnet { subnet_id: u64, attestation: GossipAttestation },
    AggregatedAttestation(GossipAggregatedAttestation),
}
```

Raw bytes are decoded from SSZ (snappy-compressed on the wire) to these typed variants before validation.

## Validation pipeline

Inbound messages pass through a multi-stage validation pipeline before being relayed or accepted:

1. **Size check** — reject if payload exceeds `max_gossip_bytes`.
2. **Rate limiting** — per-peer and per-topic token-bucket limits.
3. **Well-formedness** — SSZ decode must succeed.
4. **Topic validation** — topic must be in `allowed_topics`.
5. **Content validation** — dispatched to the registered `GossipSignatureVerifier` for the topic:
   - `block` topics: structural checks (proof count, proposer slot, participant count) + optional PQ signature verification.
   - `attestation` topics: participant index range and bit consistency.
   - `aggregation` topics: aggregate participant/proof structure plus optional PQ signature verification.
6. **Fork-choice integration** — accepted blocks are passed to `ForkChoiceStore`.

## Gossip verifiers

| Verifier | Description |
|----------|-------------|
| `NoopGossipVerifier` | Accepts everything — used in tests |
| `SimpleGossipVerifier` | Structural checks only |
| `GossipSignatureVerifier` | Full structural + PQ signature verification |

The active verifier is set per-topic in `topic_validators`. `verifier_from_validators` constructs the verifier map from the config.

## Outbound publishing

```rust
networking.gossip.publish(topic, payload).await?;
```

The `Gossip` handle wraps a tokio channel to the gossipsub swarm. Publishing is non-blocking from the caller's perspective.

## Rate limiting

`RateLimiter` implements a token-bucket per (peer, topic) pair. Peers that exceed the limit have their messages dropped and their score penalized.
