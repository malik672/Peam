# SSZ & Merkleization

`lean_eth` ships its own SSZ implementation tuned for minimal allocations and cache-friendly access patterns.

## Traits

| Trait | Purpose |
|-------|---------|
| `SszEncode` | `fn encode_ssz(&self) -> Vec<u8>` |
| `SszDecode` | `fn decode_ssz(bytes: &[u8]) -> Result<Self, String>` |
| `SszFixedLen` | `fn fixed_len() -> usize` — for fixed-size containers |
| `HashTreeRoot` | `fn hash_tree_root(&self) -> [u8; 32]` |

Every data structure that crosses a wire or gets stored implements all four.

## Encoding convention

Fixed-size fields are written with pre-allocated buffers and `unsafe_vec::write_at` to avoid bounds checks inside hot encode paths:

```rust
let mut out = Vec::with_capacity(N);
unsafe { out.set_len(N) };
unsafe { write_bytes_at(&mut out, 0, &field.to_le_bytes()) };
```

Variable-size fields use offset tables as per the SSZ spec.

## Merkleization

Located in `ssz/hash.rs`. Three key functions:

### `chunkify_fixed(data: &[u8]) -> Vec<Bytes32>`

Splits a byte slice into 32-byte chunks, zero-padding the last chunk. Empty input yields `[Bytes32::zero()]`.

### `merkleize(chunks: &[Bytes32]) -> Bytes32`

Builds a binary Merkle tree over `chunks` and returns the root. Internally calls `merkleize_with_limit`.

### `hash_nodes(left: &Bytes32, right: &Bytes32) -> Bytes32`

SHA-256 hash of the concatenation of two 32-byte nodes — the primitive tree operation.

## Zero hashes

Zero hashes up to depth 64 are generated at compile time by `build.rs` and embedded as a static array:

```rust
pub static ZERO_HASHES: [[u8; 32]; 65] = [...];
```

This avoids runtime computation of the empty subtree hashes used in Merkle padding.

## Performance notes

- `merkleize_unsafe` is an alternative implementation that avoids some bounds checks in the inner loop.
- `chunkify_fixed` uses `unsafe { out.set_len(chunk_count) }` + direct index writes instead of `push`.
- See `benches/merkleize_loop.rs` and `benches/chunkify_fixed.rs` for benchmark targets.
