# Types

`src/types/` provides the primitive types used throughout the codebase.

## Bytes types

| Type | Size | Description |
|------|------|-------------|
| `Bytes32` | 32 bytes | General-purpose hash / root type |
| `Bytes52` | 52 bytes | PQ public key |
| `Bytes3112` | 3112 bytes | PQ signature |

`Bytes32` is the most pervasive type — every block root, state root, and fork-choice key is a `Bytes32`.

```rust
let root = Bytes32::zero();            // all-zero sentinel
let root = Bytes32::from([0xAB; 32]);  // from array
let slice = root.as_slice();           // &[u8]
let arr   = root.as_array();          // &[u8; 32]
```

## Integers

`Uint64` wraps `u64` and implements `SszEncode`, `SszDecode`, and `HashTreeRoot`. Little-endian encoding is used throughout (SSZ spec).

## BitList

`BitList` is a variable-length bitfield. It is used for attestation aggregation bits.

- Backed by `Vec<u8>` with a length (in bits) tracked separately.
- Implements SSZ encode/decode including the length-delimiting sentinel bit.
- Supports set/get by bit index and participant iteration.

## Collections

| Type | Description |
|------|-------------|
| `SszList<T, N>` | Variable-length list bounded to `N` elements |
| `SszVector<T, N>` | Fixed-length vector of exactly `N` elements |

Both implement `SszEncode`, `SszDecode`, and `HashTreeRoot`. The `HashTreeRoot` for lists mixes in the length as a chunk alongside the Merkle root of elements (per the SSZ spec).

## unsafe_vec

`src/unsafe_vec.rs` provides helpers for writing into pre-allocated `Vec<u8>` buffers without redundant bounds checks:

```rust
// Write a T at byte offset `at` in `buf`.
unsafe fn write_at<T>(buf: &mut Vec<T>, at: usize, value: T)

// Write raw bytes at byte offset `at`.
unsafe fn write_bytes_at(buf: &mut Vec<u8>, at: usize, bytes: &[u8])
```

These are used in SSZ encode paths where the output size is computed ahead of time. The safety contract is that the caller must ensure `buf.len() >= at + size_of::<T>()`.
