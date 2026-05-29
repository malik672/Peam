# leanSpec Harness Checklist

This document is a concrete implementation checklist for turning Peam's existing
leanSpec parity work into a real fixture-driven conformance harness.

The goal is not to copy another client wholesale. The goal is to give Peam one
structured way to:

- discover shared leanSpec fixtures
- run them against Peam code
- report pass/fail clearly
- grow coverage over time without scattering parity work across ad hoc tests

## What Peam already has

Peam is not starting from zero.

- SSZ fixture tests: `tests/lean_spec_fixtures.rs`
- parity placeholders: `tests/lean_spec_container_placeholders.rs`
- local fixture files: `tests/fixtures/ssz/devnet/...`
- fork choice tests: `tests/fork_choice_store.rs`
- leanSpec-style HTTP/API behavior in the node path

What is missing is a first-class fixture harness like the other clients have.

## Reference patterns to copy

Use these as implementation references, not as templates to mirror line-for-line.

- Ream:
  - `testing/lean-spec-tests/tests/tests.rs`
  - `testing/lean-spec-tests/src/...`
- Ethlambda:
  - `crates/blockchain/tests/forkchoice_spectests.rs`
  - `crates/blockchain/state_transition/tests/stf_spectests.rs`
- nlean:
  - `tests/Lean.SpecTests/FixtureDiscovery.cs`
  - `tests/Lean.SpecTests/...`

## Scope for the first serious milestone

Only cover these fixture families first:

1. `ssz`
2. `fork_choice`
3. `state_transition`

Do not start with:

- `sync`
- `api_endpoint`
- `justifiability`
- `verify_signatures`

Those can come later after the harness shape is stable.

## File-by-file implementation checklist

### 1. Create `tests/lean_spec/mod.rs`

Purpose:

- central namespace for the harness modules
- keeps shared helpers out of one-off test files

Initial contents:

```rust
pub mod fixture_discovery;
pub mod fixture_json;
pub mod hex;
pub mod ssz_runner;
pub mod fork_choice_runner;
pub mod state_transition_runner;
```

Notes:

- It is fine if `fork_choice_runner` and `state_transition_runner` start as
  stubs while the SSZ harness is being moved over.

### 2. Create `tests/lean_spec/fixture_discovery.rs`

Purpose:

- locate the fixture root directory
- support `LEAN_SPECTEST_FIXTURES`
- enumerate fixture files by family

Copy the discovery shape from:

- `nlean/tests/Lean.SpecTests/FixtureDiscovery.cs`

Functions to implement:

- `pub fn fixtures_root() -> Option<PathBuf>`
- `pub fn discover_fixture_files(kind: &str) -> Vec<PathBuf>`

Search order:

1. `LEAN_SPECTEST_FIXTURES`
2. `../leanSpec/fixtures/consensus`
3. `./leanSpec/fixtures/consensus`
4. `./vendor/leanSpec/fixtures/consensus`
5. fallback local Peam fixtures where relevant

Behavior:

- if no fixture root exists, tests should skip cleanly with a useful message
- file enumeration should recurse and sort deterministically

### 3. Create `tests/lean_spec/fixture_json.rs`

Purpose:

- parse the outer leanSpec JSON fixture shape once
- avoid repeating `serde_json::Value` boilerplate in every test file

Move shared logic out of `tests/lean_spec_fixtures.rs`, especially helpers like:

- `load_fixture`
- `first_fixture_entry`

Functions to implement:

- `pub fn load_fixture_file(path: &Path) -> Value`
- `pub fn fixture_entries(json: &Value) -> Vec<(&str, &Value)>`
- `pub fn first_fixture_entry(json: &Value) -> (&str, &Value)`

If the structure grows, introduce typed fixture wrappers later. Do not start by
over-designing this.

### 4. Create `tests/lean_spec/hex.rs`

Purpose:

- one shared place for hex/bytes helpers

Move the following helpers from `tests/lean_spec_fixtures.rs`:

- `decode_hex`
- `bytes32_from_hex`

Potential helpers:

- `pub fn decode_hex(s: &str) -> Vec<u8>`
- `pub fn bytes32_from_hex(s: &str) -> Bytes32`
- `pub fn expect_hex_field(value: &Value, key: &str) -> Vec<u8>`

This is a small file, but it keeps later runners much cleaner.

### 5. Create `tests/lean_spec/ssz_runner.rs`

Purpose:

- turn the current SSZ fixture tests into a real harnessed runner

Start by porting the existing logic from:

- `tests/lean_spec_fixtures.rs`

First supported fixture types:

- `Config`
- `Checkpoint`
- `BlockHeader`
- `BlockBody`

Initial responsibility:

- load a fixture entry
- decode SSZ bytes into the target type
- re-encode and assert round-trip equality
- assert a few key semantic fields where it is cheap and valuable

Suggested public API:

```rust
pub fn run_ssz_fixture_file(path: &Path)
pub fn run_ssz_fixture_entry(test_id: &str, entry: &Value)
```

Do not attempt to support every SSZ container immediately. Grow by fixture type.

### 6. Rewrite `tests/lean_spec_fixtures.rs` as a thin test entrypoint

Current state:

- this file contains the implementation details directly

Target state:

- discover SSZ fixture files
- iterate entries
- call into `lean_spec::ssz_runner`

This file should become the top-level test surface for SSZ fixture conformance,
not the place where all the parsing and decoding logic lives.

### 7. Create `tests/lean_spec/fork_choice_runner.rs`

Purpose:

- execute fixture-driven fork choice scenarios against Peam

This is the most important non-SSZ addition.

Reference files:

- `ream/testing/lean-spec-tests/tests/tests.rs`
- `ethlambda/crates/blockchain/tests/forkchoice_spectests.rs`

First version should support only the core loop:

- initialize store/state
- apply ticks
- apply blocks
- apply attestations
- assert expected head/checkpoint outcomes

Suggested split:

- JSON parsing helpers in this file at first
- move typed fixture structs into their own module only if the file gets too big

Suggested public API:

```rust
pub async fn run_fork_choice_fixture_file(path: &Path)
pub async fn run_fork_choice_fixture_entry(test_id: &str, entry: &Value)
```

Minimum useful coverage:

- head selection
- checkpoint alignment
- basic attestation influence on fork choice

### 8. Add `tests/lean_spec_fork_choice.rs`

Purpose:

- top-level async test entrypoint for fork choice fixtures

Behavior:

- discover `fork_choice` JSON files
- skip cleanly if fixtures are unavailable
- run each file/entry through `fork_choice_runner`
- print enough context to make failures debuggable

This should follow the general "find files, loop, summarize" shape used by Ream.

### 9. Create `tests/lean_spec/state_transition_runner.rs`

Purpose:

- run fixture-driven state transition checks against Peam's state machinery

Reference:

- `ethlambda/crates/blockchain/state_transition/tests/stf_spectests.rs`

Initial target:

- slots/ticks
- block processing
- state root / header invariants where the fixture format expects them

Suggested public API:

```rust
pub fn run_state_transition_fixture_file(path: &Path)
pub fn run_state_transition_fixture_entry(test_id: &str, entry: &Value)
```

Do not take on signatures or sync semantics in this first pass.

### 10. Add `tests/lean_spec_state_transition.rs`

Purpose:

- top-level test entrypoint for state transition fixtures

Behavior:

- discover fixture files
- skip cleanly if absent
- call into `state_transition_runner`

### 11. Reduce `tests/lean_spec_container_placeholders.rs`

Current state:

- this is a useful scratchpad for parity ideas, but not a substitute for a real
  conformance suite

After the new harness exists:

- keep any genuinely useful unit tests
- delete or rewrite placeholder-only coverage
- move all "leanSpec parity" claims into the real fixture harness

Rule of thumb:

- unit-level invariants stay
- fixture-driven parity checks move

### 12. Add one command for running the harness locally

Minimum target:

```bash
LEAN_SPECTEST_FIXTURES=/path/to/leanSpec/fixtures/consensus cargo test lean_spec
```

Nice follow-up:

- `scripts/test_lean_spec.sh`
or
- a `Makefile` target

Do not block the harness on having a fancy wrapper.

### 13. Add one CI gate after SSZ + fork choice are green

First CI gate should be deliberately narrow:

- SSZ fixture tests
- fork choice fixture tests

State transition can follow once it is stable enough.

The point of the first gate is to start treating fixture conformance as part of
the client's correctness surface, not as optional local experimentation.

## Recommended implementation order

Build in this order:

1. `tests/lean_spec/fixture_discovery.rs`
2. `tests/lean_spec/fixture_json.rs`
3. `tests/lean_spec/hex.rs`
4. `tests/lean_spec/ssz_runner.rs`
5. rewrite `tests/lean_spec_fixtures.rs`
6. `tests/lean_spec/fork_choice_runner.rs`
7. `tests/lean_spec_fork_choice.rs`
8. `tests/lean_spec/state_transition_runner.rs`
9. `tests/lean_spec_state_transition.rs`
10. reduce `tests/lean_spec_container_placeholders.rs`
11. add CI

## Day 1 / Day 2 / Day 3 version

### Day 1

- add `mod.rs`
- add `fixture_discovery.rs`
- add `fixture_json.rs`
- add `hex.rs`
- move current SSZ fixture logic into `ssz_runner.rs`
- keep the old SSZ tests green

### Day 2

- make `tests/lean_spec_fixtures.rs` a thin entrypoint
- add `fork_choice_runner.rs`
- wire `tests/lean_spec_fork_choice.rs`
- get a first narrow subset of fork-choice fixtures running

### Day 3

- add `state_transition_runner.rs`
- wire `tests/lean_spec_state_transition.rs`
- trim placeholder tests
- add the first CI gate

## Success criteria for the first milestone

The first milestone is successful if all of the following are true:

- Peam can locate a shared leanSpec fixture directory automatically
- SSZ fixtures run through a reusable harness instead of one-off tests
- at least one real fork-choice fixture family runs end-to-end
- missing fixtures cause clean skips, not confusing failures
- the structure makes it obvious where to add new fixture families later

## What not to do

Avoid these traps:

- do not start with all fixture families at once
- do not bury harness logic back into one-off test files
- do not block progress on perfect typed JSON models for every fixture schema
- do not try to solve signatures, sync, and API endpoint conformance in the
  first milestone

The right move is to get one durable harness shape in place, then grow it.
