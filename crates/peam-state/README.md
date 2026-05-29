# peam-state

State transition logic for `Peam`.

This crate owns the consensus state engine:

- `State`
- slot processing
- attestation processing
- signed block processing
- generic verifier and transition metrics traits

It depends on `peam-consensus-types` for the protocol model layer and on
`peam-ssz` for SSZ/hash-tree-root support.

## What belongs here

- state transition rules
- state-local helper logic
- generic interfaces needed to process blocks without binding directly to the
  root crate's PQ implementation

## What does not belong here

- concrete PQ verifier glue
- storage backends
- fork choice
- networking/runtime orchestration

The root `peam` crate supplies the concrete PQ-backed processing glue on top of
this generic state engine.
