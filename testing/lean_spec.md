# leanSpec Harness

Peam now has a small fixture-driven conformance harness for three families:

- `ssz`
- `fork_choice`
- `state_transition`

The harness is intentionally split into:

- shared helpers in `tests/lean_spec/`
- top-level test targets:
  - `tests/lean_spec_fixtures.rs`
  - `tests/lean_spec_fork_choice.rs`
  - `tests/lean_spec_state_transition.rs`
- local checked-in fixtures in `tests/fixtures/lean_spec/`

There is also a minimal black-box API smoke target:

- `tests/lean_spec_http_api.rs`

That file now contains two layers:

- deterministic in-process HTTP smokes
- a real external-process probe for the `peam --run` binary using a checked-in
  split validator key fixture
- a tiny lifecycle-style restart probe that reuses the same data directory

## How fixture discovery works

The harness checks fixture roots in this order:

1. `LEAN_SPECTEST_FIXTURES`
2. `../leanSpec/fixtures`
3. `../leanSpec/fixtures/consensus`
4. `./leanSpec/fixtures`
5. `./leanSpec/fixtures/consensus`
6. `./vendor/leanSpec/fixtures`
7. `./vendor/leanSpec/fixtures/consensus`
8. `./tests/fixtures/lean_spec`

That means the harness works in two modes:

- **repo-local mode** using the checked-in JSON fixtures in Peam
- **shared-fixture mode** when you have a `leanSpec` checkout available

For `fork_choice` and `state_transition`, Peam now understands two fixture shapes:

- the local Peam scenario schema used by the checked-in JSONs
- a narrow generated-envelope compatibility subset that matches the outer shape
  of `leanSpec`'s `fork_choice_test` / `state_transition_test` output

The generated-envelope support is intentionally partial. It is there to help us
grow toward shared fixtures without pretending we already parse every upstream field.

Today that compatibility layer covers:

- generated `state_transition_test` envelopes for:
  - simple linear block sequences
  - expected exception cases
- generated `fork_choice_test` envelopes for:
  - block steps
  - gossip-attestation steps
  - basic store checks (`head`, justified/finalized slot, safe target)

## Run locally

Use the helper script:

```bash
./scripts/test_lean_spec.sh
```

Or point it at a shared fixture checkout:

```bash
./scripts/test_lean_spec.sh /absolute/path/to/leanSpec/fixtures
```

You can also export the environment variable directly:

```bash
LEAN_SPECTEST_FIXTURES=/absolute/path/to/leanSpec/fixtures \
  cargo test --test lean_spec_fixtures --test lean_spec_fork_choice --test lean_spec_state_transition
```

The harness also accepts a root that already points at `fixtures/consensus`.

## Generating shared fixtures from leanSpec

From a nearby `leanSpec` checkout, generate consensus fixtures with:

```bash
cd /absolute/path/to/leanSpec
uv run fill --clean --fork=devnet --output fixtures
```

That produces files under:

```text
fixtures/consensus/ssz/...
fixtures/consensus/fork_choice/...
fixtures/consensus/state_transition/...
```

Then point Peam at either:

- `/absolute/path/to/leanSpec/fixtures`
- `/absolute/path/to/leanSpec/fixtures/consensus`

## Pre-Hive confidence

For the current minimum bar before serious Hive work, see:

- `testing/impl.md`

There is also a one-shot confidence script:

```bash
./scripts/test_pre_hive_confidence.sh
```

Or with shared fixtures:

```bash
./scripts/test_pre_hive_confidence.sh /absolute/path/to/leanSpec/fixtures
```

That script runs:

- the three fixture-backed harness targets
- the minimal black-box API smoke target
- the deterministic fork-choice and state-logic regression tests

That includes the real external-process startup probe now that the startup path
uses checked-in validator key material and completes in a reasonable amount of
time for the suite.

## Current local fixture coverage

### Fork choice

- head updates on new block
- voted branch wins
- descendant chain wins
- safe target after supermajority
- vote-shift reorg
- finalized-history pruning / checkpoint progression

### State transition

- first block after genesis
- linear chain
- blocks with gaps
- large slot number
- invalid proposer
- invalid parent root

## What still belongs elsewhere

The harness does not replace every unit test.

Keep unit tests for:

- direct aggregation mechanics
- justified-slots window behavior
- low-level attestation/state invariants
- PQ/signature-specific behavior

Use the fixture harness for:

- parity-style scenarios
- multi-step behavioral flows
- cross-checking Peam against shared fixture semantics

Use the API smoke test for:

- proving the leanSpec-facing endpoints behave like a node surface
- catching route / response regressions before we reach for Hive
- checking both initialized and uninitialized fork-choice behavior
- checking that a cold boot and a restart on the same store both expose a sane
  node surface from outside the process

If you want to rerun just the real binary startup probe, run:

```bash
cargo test --test lean_spec_http_api lean_spec_http_api_external_process_smoke -- --nocapture
```

If you want the first tiny lifecycle-style black-box scenario specifically, run:

```bash
cargo test --test lean_spec_http_api lean_spec_http_api_external_process_restart_smoke -- --nocapture
```
