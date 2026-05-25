# Pre-Hive Spec Confidence Bar

This document defines the minimum confidence bar we want before spending real
time on Hive-style black-box interop.

The point is not "full spec parity". The point is making Hive failures useful.
If Peam is weak on local conformance, Hive becomes noisy and hard to debug.

## Goal

Before serious Hive work, Peam should have:

1. A deterministic local conformance harness for the core logic layers.
2. A documented way to point that harness at shared `leanSpec` fixture output.
3. CI coverage for the deterministic harness targets.
4. A small, explicit checklist of what is still missing so we do not pretend
   the harness means "full spec parity".
5. At least one minimal black-box API smoke test that treats Peam like a node.
6. A real-binary startup/API smoke that exercises `peam --run` with checked-in
   validator key material instead of only in-process server spawning.

## Required Surfaces

### 1. SSZ

- Keep fixture-backed SSZ roundtrip coverage green.
- Preserve the existing local container fixtures.
- Continue treating SSZ as the lowest-friction correctness gate.

### 2. Fork Choice

- Keep local scenario coverage for:
  - voted branch selection
  - descendant preference
  - safe target progression
  - vote-shift reorgs
  - finalized-history pruning
- Keep the runner able to discover shared `leanSpec` fixture output roots.
- Be explicit that the current runner is still a Peam-oriented compatibility
  harness, not a full parser for `ForkChoiceTest` output.

### 3. State Transition

- Keep local scenario coverage for:
  - first block after genesis
  - linear chain progression
  - slot gaps
  - large slot numbers
  - invalid proposer
  - invalid parent root
- Keep the runner able to discover shared `leanSpec` fixture output roots.
- Be explicit that the current runner is still a Peam-oriented compatibility
  harness, not a full parser for `StateTransitionTest` output.

### 4. Fixture Discovery / Workflow

- Accept either:
  - `.../leanSpec/fixtures`
  - `.../leanSpec/fixtures/consensus`
  - repo-local `tests/fixtures/lean_spec`
- Keep a one-command script for running the harness.
- Document how to generate shared fixtures from `leanSpec`.

### 5. CI

- Keep the deterministic harness targets in CI:
  - `lean_spec_fixtures`
  - `lean_spec_fork_choice`
  - `lean_spec_state_transition`

### 6. Minimal Black-Box API Surface

- Smoke the leanSpec-facing HTTP aliases:
  - `/lean/v0/health`
  - `/lean/v0/states/finalized`
  - `/lean/v0/checkpoints/justified`
  - `/lean/v0/fork_choice`
- Keep the smoke test deterministic and local.
- Check both initialized and uninitialized fork-choice behavior.
- Use it as the bridge between fixture-driven correctness and future Hive work.
- Keep the real `peam --run` smoke on checked-in validator key fixtures so it
  stays fast enough to be part of the normal confidence suite.

## Not Yet the Bar

Even after the items above are complete, this still does **not** mean:

- full upstream `leanSpec` fixture-schema support
- full API conformance
- full Hive readiness
- complete networking / sync / req-resp interop coverage

Those remain follow-on work.

## One-Shot Deliverables In This Pass

This implementation pass should:

1. Land this document.
2. Make fixture discovery understand real `leanSpec` output roots better.
3. Tighten the harness docs and scripts around actual `leanSpec` fixture
   generation paths.
4. Add a single "pre-Hive confidence" script that runs the harness and the
   most relevant deterministic correctness tests together.
5. Add a minimal black-box HTTP API smoke test.
6. Keep all of the above green under `cargo test`.

## Current Real-Binary Smoke

Peam now includes a real-binary HTTP smoke probe in the normal suite:

- `lean_spec_http_api_external_process_smoke`
- `lean_spec_http_api_external_process_restart_smoke`

That probe launches `peam --run` against a checked-in one-validator split
hash-sig fixture and verifies the leanSpec-facing HTTP surface from outside the
process.

The restart variant reuses the same data directory across two launches so the
suite also checks that Peam can restore a sane node-facing view from an
existing store.

## Next Step After This Pass

Once this bar is in place, the next good move is:

1. teach the runners more of the upstream generated fixture schema, or
2. add a minimal black-box API/Hive-style smoke layer on top.
