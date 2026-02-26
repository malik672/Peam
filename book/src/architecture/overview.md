# Architecture Overview

`lean_eth` is structured as a layered stack where each layer has a clear boundary and a single responsibility.

```
┌─────────────────────────────────────────┐
│              CLI / main.rs              │  argument parsing, tokio runtime
├─────────────────────────────────────────┤
│                Node                     │  async event loop, slot timer
├──────────────┬──────────────────────────┤
│  Networking  │  Fork Choice + State     │  gossipsub, req/resp / consensus
├──────────────┴──────────────────────────┤
│                Storage                  │  MemoryStore or FileStore
├─────────────────────────────────────────┤
│           SSZ / Types / Crypto          │  encode, hash, verify
└─────────────────────────────────────────┘
```

## Data Flow

1. **Networking** receives a gossip message or a req/resp response.
2. The message is validated (well-formedness, topic rules, signature checks).
3. Valid blocks are passed to **Fork Choice** which updates the head.
4. Accepted blocks and resulting states are written to **Storage**.
5. The **Slot timer** fires each epoch boundary and drives finalization bookkeeping.

## Module Map

| Module | File(s) | Purpose |
|--------|---------|---------|
| `app` | `app.rs` | Config loading, genesis state construction |
| `node` | `node.rs` | Async runtime, channel wiring, slot loop |
| `slot` | `slot.rs` | Slot number arithmetic and timing |
| `containers` | `containers/` | `Block`, `State`, `Attestation`, `Config`, … |
| `ssz` | `ssz/` | `SszEncode`, `SszDecode`, `HashTreeRoot`, merkleization |
| `types` | `types/` | `Bytes32`, `BitList`, `SszList`, `SszVector`, `Uint64` |
| `storage` | `storage/` | `Store` trait, `MemoryStore`, `FileStore` |
| `networking` | `networking/` | libp2p swarm, gossipsub, req/resp, discovery, peers |
| `fork_choice` | `fork_choice.rs` | GHOST fork-choice store |
| `crypto` | `crypto/` | PQ signature verification stub |
| `unsafe_vec` | `unsafe_vec.rs` | Unsafe fixed-size write helpers |
