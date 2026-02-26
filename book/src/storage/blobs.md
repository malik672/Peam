# Blob Format

All objects stored in `canonical.redb` are wrapped in a versioned blob envelope before being written. The envelope provides integrity checking and allows future format migrations.

## Envelope layout

```
┌──────────────┬─────────┬──────┬──────────────┬───────────────┬─────────┐
│ LEANSTRG (8B)│ ver (1B)│ kind │  length (4B) │ SHA-256 (32B) │ payload │
│  magic bytes │  = 0x01 │ (1B) │   LE u32     │   checksum    │  (SSZ)  │
└──────────────┴─────────┴──────┴──────────────┴───────────────┴─────────┘
```

Total header size: **46 bytes** (`8 + 1 + 1 + 4 + 32`).

## Fields

| Field | Size | Value |
|-------|------|-------|
| Magic | 8 B | `LEANSTRG` (ASCII) |
| Version | 1 B | `0x01` |
| Kind | 1 B | `0x01` = state, `0x02` = block, `0x03` = signed block |
| Length | 4 B | LE u32, payload byte count |
| Checksum | 32 B | SHA-256 of payload |
| Payload | N B | SSZ-encoded object |

## Decode validation

`decode_blob(expected_kind, bytes)` checks, in order:

1. Magic prefix matches `LEANSTRG`.
2. Version byte is `0x01`.
3. Kind byte matches `expected_kind`.
4. Total length equals `46 + payload_len`.
5. SHA-256 of payload matches stored checksum.

Returns `None` on any mismatch. Returns `Some(payload)` on success.

## Backward compatibility

If the first 8 bytes are **not** `LEANSTRG`, the raw bytes are returned as-is. This allows loading of pre-envelope raw-SSZ blobs written by earlier versions of the node.

## Encoding

`encode_blob(kind, payload)` builds the envelope in a single pre-allocated `Vec`:

```rust
let mut out = Vec::with_capacity(8 + 1 + 1 + 4 + 32 + payload.len());
out.extend_from_slice(BLOB_MAGIC);   // "LEANSTRG"
out.push(BLOB_VERSION);              // 0x01
out.push(kind);
out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
out.extend_from_slice(&Sha256::digest(payload));
out.extend_from_slice(payload);
```

## redb tables

The following `redb` tables are used inside `canonical.redb`:

| Table | Key type | Value type | Contents |
|-------|----------|------------|----------|
| `canonical_state_blob` | `&[u8]` (root) | `&[u8]` (blob) | State blobs |
| `canonical_block_blob` | `&[u8]` (root) | `&[u8]` (blob) | Block blobs |
| `canonical_signed_block_blob` | `&[u8]` (root) | `&[u8]` (blob) | Signed-block blobs |
| `canonical_state_slot` | `u64` (slot) | `&[u8]` (root) | Slot → state root index |
| `canonical_block_slot` | `u64` (slot) | `&[u8]` (root) | Slot → block root index |
| `canonical_meta` | `&str` | `&[u8]` (root) | `head`, `finalized`, `justified` |
