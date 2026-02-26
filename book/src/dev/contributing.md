# Contributing

## Getting started

```bash
git clone <repo>
cd lean_eth
cargo build
cargo test
```

All tests must pass before submitting a PR.

## Code style

- Rust stable, edition 2024. No nightly features.
- No `unwrap` / `expect` in library code — return `Result<_, String>`.
- Keep `unsafe` blocks small and document the safety invariant with a comment.
- Pre-allocate output buffers when size is known ahead of time (see `rules.md`).
- No `#[allow(clippy::...)]` in new code unless truly necessary.

## Performance rules

From `rules.md`:

1. If output length is known ahead of time, pre-allocate once and write by index.
2. Avoid incremental `push` in fixed-size writes.
3. For `Vec<u8>` fixed-size writes, use `unsafe_vec::write_at` with explicit safety comments.
4. Keep this policy for serialization paths (`storage`, `ssz`, wire encoding) unless profiling proves otherwise.

## Testing

Every new feature should have at least one integration test in `tests/`. Storage changes need a test in `tests/storage_skeleton.rs` or a new file. Networking changes need a test in `tests/networking_wire.rs` or `tests/node_gossip_integration.rs`.

For performance-sensitive code, add a benchmark in `benches/` and record a baseline in the PR description.

## Pull requests

- Run `cargo test` and `cargo clippy` before opening a PR.
- Reference the relevant section of `CHANGELOG.md` or add a new entry under `## Unreleased`.
- Keep PRs focused — one logical change per PR.

## Release notes

Tracked in `CHANGELOG.md`. Format: `## Unreleased` → `## vX.Y.Z` on release.

## License

By contributing you agree that your contributions are dual-licensed under MIT or Apache-2.0, as described in `LICENSE` and `LICENSE-APACHE`.
