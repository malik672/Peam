# Node & Runtime

The node is the top-level coordinator. It wires together networking, storage, fork choice, and the slot timer into a single async event loop running on tokio.

## Node struct

```rust
pub struct Node {
    config: Config,
    state: Arc<RwLock<State>>,
    store: Arc<RwLock<FileStore>>,
    fork_choice: Arc<RwLock<Option<ForkChoiceStore>>>,
    networking: Option<Networking>,
    settings: NodeSettings,
    shutdown_tx: Option<oneshot::Sender<()>>,
    shutdown_rx: oneshot::Receiver<()>,
    // ...
}
```

- `state` and `store` are wrapped in `Arc<RwLock<_>>` so they can be shared across async tasks and the networking layer.
- `fork_choice` starts as `None` and is initialized on the first valid block.
- `shutdown_tx` / `shutdown_rx` form a oneshot channel used for clean shutdown (e.g., Ctrl-C).

## Startup sequence

1. Parse CLI args (`--config`, `--data-dir`).
2. Load `Config` and `NodeSettings` from the config file.
3. Open (or create) a `FileStore` at `<data-dir>/store`.
4. Load or build genesis `State`.
5. Start the `Networking` stack (libp2p swarm).
6. Enter the async event loop.

## Gossip event handling

Incoming gossip is dispatched to `handle_gossip_event`, which:

1. Decodes the raw bytes into a `LeanGossipsubMessage` (`Block` or `Attestation`).
2. For blocks: acquires write locks on `state` and `store`, calls `store.put_signed_block`, then updates fork choice.
3. For attestations: validates the validator index and delegates to fork choice.

The fork choice store is lazily initialized from the first accepted block.

## CLI

```
lean_eth --config <path>
lean_eth --genesis-time <u64>
lean_eth --run --config <path> --data-dir <path>
```

- `--config` alone: print the parsed config.
- `--genesis-time` alone: build a genesis state and print its hash tree root.
- `--run`: start the full node.
