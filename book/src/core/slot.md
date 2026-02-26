# Slot Logic

`src/slot.rs` defines the `Slot` type and the justification-window arithmetic.

## Slot type

`Slot` is a newtype wrapper around `Uint64`. It implements full SSZ traits (encode, decode, fixed-len, hash-tree-root) and the standard ordering traits (`Ord`, `PartialOrd`).

```rust
pub struct Slot(pub Uint64);
```

SSZ encoding is 8 bytes, little-endian.

## Justification window

Two functions control which slots are eligible for justification relative to the current finalized slot.

### `justified_index_after(candidate, finalized) -> Option<u64>`

Returns the slot's index in the justification window (`candidate - finalized - 1`), or `None` if the candidate is at or before the finalized slot.

### `is_justifiable_after(candidate, finalized) -> Result<bool, String>`

Determines whether a slot is within the justification eligibility window using a number-theoretic rule:

A slot at distance `d = candidate - finalized` from the finalized slot is justifiable if any of the following hold:

- `d <= 5` (first few slots are always eligible)
- `d` is a perfect square
- `4d + 1` is a perfect odd square (i.e., `4d + 1 = k²` for some odd `k`)

The last two conditions together cover a sparse but growing set of distances beyond the initial window, implementing a log-scale justification thinning policy.

The integer square root is computed with a plain bit-by-bit algorithm (`isqrt_u64`) that runs in O(log n) without floating point.
