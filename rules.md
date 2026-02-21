# Performance Rules

1. If output length is known ahead of time, pre-allocate once and write by index.
2. Avoid incremental `push` in fixed-size writes.
3. For `Vec<u8>` fixed-size writes, use `unsafe_vec::write_at` with explicit safety comments.
4. Keep this policy for serialization paths (`storage`, `ssz`, wire encoding) unless profiling proves otherwise.
