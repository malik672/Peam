# Changelog

## Unreleased

### Networking
- Added ignored real-socket smoke tests for:
  - two-node connectivity
  - status req/resp roundtrip
  - mDNS discovery (`ream_mdns_discovery_smoke`)
- Hardened gossip validation to reject blocks where aggregated proof participants do not match attestation aggregation bits.

### State / Consensus
- Enforced participants-vs-aggregation-bits consistency in signed block processing (structural and PQ verifier paths).
- Extended state tests with an explicit negative case for mismatched attestation proof participants.

### Spec / Parity
- Ported aggregation parity checks in `tests/lean_spec_container_placeholders.rs`:
  - attestation aggregation behavior
  - state aggregation behavior

### Docs
- Added explicit validation-rule documentation in README.
- Updated implementation plan progress and remaining final-stretch items.
