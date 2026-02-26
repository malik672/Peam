# Networking Overview

The networking stack is built on **libp2p** and runs as a set of background tokio tasks wired together through a shared event bus.

## Tasks

| Task | Description |
|------|-------------|
| `p2p_task` | Drives the libp2p swarm event loop |
| `gossip_task` | Inbound gossip pipeline with per-peer and per-topic rate limiting |
| `reqresp_task` | Inbound req/resp pipeline with per-peer rate limiting and scoring |
| `score_decay_task` | Periodic peer score decay and ban pruning |
| `discovery_task` | Periodic seed dialing |

## The `Networking` struct

```rust
pub struct Networking {
    pub events: EventBus,      // broadcast bus — subscribe to observe network events
    pub peers: PeerManager,    // peer registry and scorer
    pub gossip: Gossip,        // outbound gossip publisher
    pub reqresp: ReqResp,      // outbound req/resp sender
    pub discovery: Discovery,  // discovery state
    // task handles (abort on shutdown)
}
```

All sub-systems communicate through typed channels. The `EventBus` is a tokio broadcast channel that any subscriber can clone.

## Transport

- **TCP + DNS** for standard p2p connectivity.
- **QUIC** for low-latency paths.
- **Noise + Yamux** for encryption and multiplexing.
- **mDNS** for local-network peer discovery.
- **Identify + Ping** protocols for peer metadata exchange and keep-alive.

## Libp2p protocols used

| Protocol | Purpose |
|----------|---------|
| `gossipsub` | Block and attestation broadcast |
| `request-response` | Status, block-by-root, block-by-range |
| `identify` | Exchange peer info (agent version, listen addrs) |
| `ping` | Connection liveness check |
| `mdns` | Local peer discovery |
| `kad` / `discv5` | Wide-area peer discovery (in progress) |

## Starting the stack

```rust
let networking = Networking::start_with_config(config, event_bus, handlers).await?;
```
