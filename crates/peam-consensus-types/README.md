# peam-consensus-types

Protocol-facing Lean consensus types for `Peam`.

This crate holds the SSZ-shaped model layer used by the rest of the workspace:

- consensus containers such as blocks, attestations, checkpoints, config, and validators
- slot/time model
- primitive Lean/SSZ-oriented wrapper types
- re-exports of the `peam-ssz` traits and hashing helpers used by those types

## What belongs here

- data structures
- SSZ encode/decode and hash-tree-root implementations
- small type-level helpers closely tied to consensus objects

## What does not belong here

- state transition logic
- fork choice
- storage policy
- node/runtime orchestration
- networking task logic

This crate is the lowest Lean-specific layer in the `Peam` workspace and is
intended to stay boring, stable, and easy to reuse.
