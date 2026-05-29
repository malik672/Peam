# peam-fork-choice

Fork-choice engine for `Peam`.

This crate contains the in-memory fork-choice store and the logic around:

- vote tracking
- head selection
- justified/finalized checkpoint tracking
- safe-target computation
- pruning/reorg bookkeeping

It depends on:

- `peam-consensus-types` for Lean protocol data types
- `peam-state` for the state view needed by fork choice

## What belongs here

- fork-choice state
- fork-choice transitions and queries
- helper logic directly tied to head selection and checkpoint movement

## What does not belong here

- persistent storage
- networking gossip queues
- node lifecycle / runtime tasks

This crate is meant to be the reusable in-memory fork-choice layer, with the
root `peam` crate coordinating when and how it is updated.
