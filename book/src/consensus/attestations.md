# Attestations

Attestations are the primary voting mechanism. Each attestation records a validator's view of the chain head at a given slot.

## Types

```rust
pub struct Attestation {
    pub validator_id: ValidatorIndex,
    pub slot: Slot,
    pub block_root: Bytes32,
    // aggregation_bits, source, target (planned)
}

pub struct AggregatedSignatureProof {
    pub participants: Vec<ValidatorIndex>,
    pub signature: Bytes3112,  // PQ aggregate signature
}
```

`BlockBody` carries up to 4096 attestations per block, each paired with an `AggregatedSignatureProof`.

## Lifecycle

```
Validator signs attestation
    → Gossiped on attestation topic
    → Received by other nodes
    → Validated (well-formedness, timing, signature)
    → Recorded in ForkChoiceStore::latest_votes
    → Included in next block's body by proposer
    → Verified during state transition
    → Applied to justification/finalization accounting
```

## Validation rules (current)

**Gossip stage:**
- Validator index must be `< VALIDATOR_REGISTRY_LIMIT`.
- Aggregation bits must be internally consistent.
- PQ aggregate proof participants must match the aggregation bitfield.

**State-transition stage:**
- Proof count equals block attestation count.
- Proposer attestation slot equals block slot.
- Proposer attestation has exactly one participant matching `block.proposer_index`.
- Aggregate proof participants match attestation aggregation bits exactly.
- All participant indices are in range.

**Planned:**
- Source/target/head root cross-referencing against local chain view.
- Slot timing window enforcement (gossip stage).
- Aggregate signature cryptographic verification (requires PQ multisig).
- Block-building aggregate selection (overlap-aware set-cover heuristic).

## Justification accounting

Accepted attestations update `state.justifications_validators` — a per-slot bitfield tracking which validators have voted for each justification window slot. When the bitfield reaches supermajority, the corresponding checkpoint is advanced.

The aggregated vote data feeds into `ForkChoiceStore::latest_votes` for the head-selection algorithm.
