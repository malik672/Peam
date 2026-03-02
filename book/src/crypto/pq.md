# PQ Signatures

`lean_eth` has post-quantum signatures enabled by default on master.

## Signature scheme

The scheme is instantiated via `leansig`:

```
XMSS + Poseidon hashing
  lifetime: 2^32 signatures
  dimension: 64
  base: 8
  mode: hashing-optimized
```

Public keys are 52 bytes (`Bytes52`). Signatures are 3112 bytes (`Bytes3112`).

## API

```rust
// Decode a 52-byte public key
pub fn public_key_from_bytes(bytes: &Bytes52) -> Result<LeanSigPublicKey, String>

// Decode a 3112-byte signature
pub fn signature_from_bytes(bytes: &Bytes3112) -> Result<LeanSigSignature, String>

// Verify a single proposer signature
pub fn verify_signature(
    public_key: &Bytes52,
    epoch: u32,
    message: &[u8; 32],
    signature: &Bytes3112,
) -> Result<(), String>

// Verify an aggregated multisig proof
pub fn verify_aggregate_signature(
    public_keys: &[Bytes52],
    message: &[u8; 32],
    aggregate_signature_bytes: &[u8],
    epoch: u32,
) -> Result<(), String>
```

## Dependency

`leansig` is fetched from `https://github.com/leanEthereum/leanSig.git` at a pinned rev. The `fiat-shamir` transitive dependency is vendored in the repository under `fiat-shamir/`.

## Negative tests

```bash
cargo test --test pq_negative
```

Tests verify that:
- `verify_signature` with invalid key/signature returns a decode or verification error.
- `verify_aggregate_signature` rejects malformed aggregate proof bytes.
