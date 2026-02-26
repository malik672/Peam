# Containers

`src/containers/` holds the beacon-chain data structures. Every container implements `SszEncode`, `SszDecode`, and `HashTreeRoot`.

## Block types

```
SignedBlockWithAttestation
  └── message: BlockWithAttestation
  │     ├── block: Block
  │     │     ├── slot: Slot
  │     │     ├── proposer_index: ValidatorIndex
  │     │     ├── parent_root: Bytes32
  │     │     ├── state_root: Bytes32
  │     │     └── body: BlockBody { attestations: SszList<Attestation, 4096> }
  │     └── proposer_attestation: Attestation
  └── signature: BlockSignatures
        ├── attestation_signatures: SszList<AggregatedSignatureProof, 4096>
        └── proposer_signature: Bytes3112
```

- `BlockHeader` is the fixed-size header (slot, proposer_index, parent_root, state_root, body_root) — 112 bytes SSZ.
- `Block` contains a full `BlockBody` with the attestation list.
- `SignedBlockWithAttestation` is the wire type: block + proposer attestation + all PQ signatures.

## State

```
State (208 bytes fixed + variable)
  ├── config: Config          (genesis_time)
  ├── slot: Slot
  ├── latest_block_header: BlockHeader
  ├── latest_justified: Checkpoint
  ├── latest_finalized: Checkpoint
  ├── historical_block_hashes: SszList<Bytes32, 262144>
  ├── justified_slots: SszList<Bytes32, 262144>
  ├── validators: SszList<Validator, 4096>
  ├── balances: SszList<Uint64, 4096>
  ├── justifications_roots: SszList<Bytes32, 262144>
  └── justifications_validators: SszList<BitList, 1073741824>
```

SSZ layout — fixed section (208 bytes):

| Byte range | Size | Field |
|------------|------|-------|
| 0 – 7      | 8 B  | `config.genesis_time` |
| 8 – 15     | 8 B  | `slot` |
| 16 – 127   | 112 B| `latest_block_header` |
| 128 – 167  | 40 B | `latest_justified` |
| 168 – 207  | 40 B | `latest_finalized` |
| 208 – 231  | 24 B | variable-field offsets (6 × 4 B, LE) |

## Checkpoint

```rust
pub struct Checkpoint {
    pub slot: Slot,
    pub root: Bytes32,
}
```

40 bytes fixed. Used for `latest_justified` and `latest_finalized` in `State`.

## Validator

Each active validator record stores its public key (compressed `Bytes52`) plus participation metadata indexed by epoch. Validators are stored in `State::validators` as a `SszList<Validator, 4096>`.

## Attestation

```rust
pub struct Attestation {
    pub validator_id: ValidatorIndex,
    pub slot: Slot,
    pub block_root: Bytes32,
    // ...
}
```

Attestations appear in both `BlockBody` (included by proposer) and in gossip messages (forwarded individually).

## Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `HISTORICAL_ROOTS_LIMIT` | 262 144 | Max historical block hashes |
| `VALIDATOR_REGISTRY_LIMIT` | 4 096 | Max validators |
| `ATTESTATIONS_LIMIT` | 4 096 | Max attestations per block |
| `JUSTIFICATION_VALIDATORS_LIMIT` | 1 073 741 824 | Max justification validator bits |
