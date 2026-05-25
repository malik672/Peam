# peam-state Extraction Notes

This is the next meaningful crate boundary after `peam-consensus-types`.

## Goal

Move the consensus state engine out of the top-level `peam` crate into:

```text
crates/peam-state/
```

while keeping the current runtime/storage/networking behavior intact.

## What belongs in `peam-state`

- `State`
- state transition logic
- attestation processing
- slot processing
- `SignatureVerifier`
- `NoopSignatureVerifier`
- `PqSignatureVerifier` or an extracted verifier hook, depending on how much crypto we want in the crate
- `TransitionMetricsSink`
- `NoopTransitionMetricsSink`

## Current blockers / coupling to reduce

### 1. Metrics coupling

This was the first blocker.

`State` used to depend directly on `MetricsRegistry` through
`process_signed_block_with_metrics(...)`.

That coupling has now been reduced:

- `TransitionMetricsSink` lives in the state layer
- `MetricsRegistry` implements that trait in the app crate
- `State::process_signed_block_with_metrics(...)` now accepts any `TransitionMetricsSink`

This keeps the API shape familiar while removing the direct dependency from the
state layer to the metrics layer.

### 2. Crypto coupling

`PqSignatureVerifier` currently uses `crate::crypto::pq`.

This is the next real design choice:

1. keep PQ verifier code inside `peam-state`
2. extract a tiny shared crypto adapter crate
3. move only `State` + generic verifier traits first, and keep concrete PQ verifier glue in `peam`

Option 3 is the safest incremental move if we want the smallest first extraction.

### 3. Logging helpers

`State` currently uses `crate::logfmt::*`.

These helpers are small, so we should either:

1. copy the handful of formatting helpers into `peam-state`, or
2. replace the dependency with slightly more local formatting inside the crate

This is low risk.

### 4. SSZ and low-level helpers

`State` depends on:

- `peam-consensus-types`
- `peam_ssz`
- `unsafe_vec`

`peam_ssz` is already a clean dependency.

For `unsafe_vec`, either:

1. copy the tiny helper into `peam-state`, or
2. expose a tiny shared helper module inside the crate

This is not a serious blocker.

## Recommended extraction order

1. keep shrinking state-layer dependencies on app-only code
2. decide whether `PqSignatureVerifier` moves with the crate or stays as app glue
3. create `crates/peam-state`
4. move:
   - `src/containers/state.rs`
   - `src/containers/state_metrics.rs`
5. leave a root compatibility shim at `src/containers/state.rs`
6. migrate callers to `peam_state::...`
7. only then decide whether `containers::gossip` or storage traits want their own crate

## Success condition

The extraction is worth it if:

- runtime code imports `peam_state::State` directly
- the state layer no longer depends on the top-level app crate
- tests still run without needing broad rewrites
- `fork_choice` becomes the next obvious crate boundary instead of another mixed layer
