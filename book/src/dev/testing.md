# Building & Testing

## Build

```bash
cargo build
```

The build requires stable Rust (edition 2024). No nightly features are used.

`build.rs` generates `ZERO_HASHES` (64-level precomputed SHA-256 zero tree) at compile time and writes it to `$OUT_DIR/zero_hashes.rs`.

## Tests

```bash
cargo test
```

All tests pass without any external dependencies (no running node, no network).

### Integration test files

| Test file | Coverage |
|-----------|----------|
| `bitlist_ssz.rs` | BitList SSZ encode/decode roundtrip |
| `block_envelopes.rs` | Block blob envelope encode/decode |
| `config_parse.rs` | Config text and SSZ parsing |
| `fork_choice_store.rs` | ForkChoiceStore block import and head update |
| `gossip_containers.rs` | Gossip message decode |
| `lean_spec_container_placeholders.rs` | Attestation/aggregation spec parity |
| `lean_spec_fixtures.rs` | Spec fixture roundtrips |
| `networking_wire.rs` | Wire message encode/decode |
| `node_gossip_integration.rs` | End-to-end gossip → storage integration |
| `pq_negative.rs` | PQ invalid-material rejection |
| `ream_networking_ports.rs` | Real-socket networking smoke tests (ignored by default) |
| `req_resp.rs` | Req/resp protocol encode/decode |
| `slot_logic.rs` | Slot arithmetic and justification window |
| `ssz_collections.rs` | SszList / SszVector roundtrips |
| `ssz_containers.rs` | All container SSZ roundtrips |
| `state_logic.rs` | State transition correctness |
| `prune_perf_regression.rs` | Prune performance regression guard |

### Networking tests (require real sockets)

These are `#[ignore]` by default:

```bash
cargo test --test ream_networking_ports -- --ignored
```

Set `LEAN_ETH_REQUIRE_MDNS=1` to make the mDNS discovery test fail hard on timeout.

### PQ tests

```bash
cargo test --test pq_negative
```

## Fixtures

Test fixtures live in `tests/fixtures/`. They are SSZ-encoded objects used for spec parity tests.
