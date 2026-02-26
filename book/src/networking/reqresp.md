# Req/Resp

The request-response protocol enables point-to-point queries between peers — primarily for block sync and status exchange.

## Protocols

Supported protocol IDs are defined in `LeanSupportedProtocol`:

| Protocol | Direction | Description |
|----------|-----------|-------------|
| Status | bidirectional | Exchange head/finalized/justified roots |
| BlockByRoot | client → server | Fetch a single block by its hash tree root |
| BlockByRange | client → server | Fetch a contiguous range of blocks by slot |

## Message types

```rust
pub enum LeanRequestMessage {
    Status { head: Bytes32, finalized: Bytes32, justified: Bytes32 },
    BlockByRoot(Bytes32),
    BlockByRange { start_slot: u64, count: u64 },
}

pub enum LeanResponseMessage {
    Status { head: Bytes32, finalized: Bytes32, justified: Bytes32 },
    Block(SignedBlockWithAttestation),
    // ...
}
```

## Handlers

Inbound requests are dispatched to a `ReqRespHandler`:

```rust
pub trait ReqRespHandler {
    fn handle(&self, request: LeanRequestMessage) -> LeanResponseMessage;
}
```

| Handler | Description |
|---------|-------------|
| `NoopReqRespHandler` | Returns empty responses — used in tests |
| `StoreReqRespHandler` | Serves blocks and status from a `Store` reference |

`StoreReqRespHandler` is what the node uses at runtime: it reads from the `FileStore` to answer `BlockByRoot` and `BlockByRange` queries.

## Rate limiting

The req/resp task applies per-peer rate limiting (separate from gossip limits). Peers that exceed the configured rate have requests dropped and receive a score penalty.

## Size limit

Responses are bounded by `max_reqresp_bytes` from the config. Oversized payloads are rejected at both the send and receive side.
