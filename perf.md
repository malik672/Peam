# Performance Notes

## Startup Cost (FileStore::open)

`FileStore::open()` currently pays a one-time startup cost:
- opens `canonical.redb`
- loads full `state_by_slot` and `block_by_slot` indexes into memory
- loads fork-choice metadata

This is expected to happen once per process start.  
The `storage_open/*cold*` Criterion benchmarks intentionally include this startup work in every iteration, so they are not steady-state read latency numbers.

## Practical Interpretation

If cold benchmark regresses but steady-state read/write is stable or better, that usually means startup work increased, not runtime path cost.

## Justification Votes Representation

Current vote-root count is small, so a linear `Vec` scan is acceptable in practice today.
However, this may not hold as scenarios scale.

Tradeoff:
- `Vec` only: deterministic order and no re-sort cost on encode, but O(n) lookup/update per attestation by `target.root`.
- Hash map only: fast lookup/update, but requires sorting for deterministic encode order.

Recommended structure for scale:
- Ordered storage for deterministic encoding (`Vec<Bytes32>` + parallel `Vec<JustificationVotes>`).
- Fast index map for updates (`RapidHashMap<Bytes32, usize>`).

This keeps deterministic serialization while avoiding per-attestation linear scans as root count grows.

## Historical Root Map Rebuild

Current behavior:
- `process_attestations` rebuilds `historical_root_slots` from `historical_block_hashes.data` on every call.
- This is correct but adds repeated O(n) map construction cost as history grows.

Recommended optimization:
- Keep consensus source-of-truth as `historical_block_hashes` (do not replace with DB lookups in transition logic).
- Add an in-memory cached `root -> latest_slot` map and update it incrementally when headers are imported / history shifts.
- Rebuild only on initialization or explicit recovery paths.

This preserves deterministic state-transition semantics while removing avoidable per-call rebuild overhead.

## Justification Pruning Hot Path (Implemented)

Recent change in `process_attestations` finalization pruning:
- Kept strict invariant: error if any pending justification root is missing from `root -> slot` mapping.
- Reduced lookup work from two map lookups per root to one by folding the invariant check into a single `retain` pass.

Why this is faster:
- Previous flow: scan roots for missing mapping, then scan again to retain.
- Current flow: one scan does both.

Effect:
- Same correctness behavior.
- Lower per-finalization CPU overhead, especially when pending justification roots are large.

## Sync/Storage Perf Changes With High Confidence (Implemented)

### Strong In-Flight Dedup by Block Root

Implemented behavior:
- never schedule duplicate `BlocksByRoot` requests for the same root while one is already pending.

Why this is a high-confidence perf win:
- removes redundant outbound req/resp traffic for identical roots,
- removes duplicate decode/validation work for identical responses,
- reduces lock/contention churn in sync bookkeeping.

### Full Pruning: Index + Blob GC

Implemented behavior:
- prune now deletes unreferenced canonical state/block/signed-block blobs in `canonical.redb`
  after index pruning.

Why this is a high-confidence perf win:
- reduces long-run DB size and table scan pressure,
- improves cache locality and lowers read amplification over time,
- stabilizes disk usage and I/O behavior on long-running nodes.

## Candidates Requiring Bench Validation (Not Auto-Enabled)

The items below are likely helpful in many environments, but not guaranteed improvements in all
network conditions. They should be A/B tested before enabling by default.

1. Adaptive sync timeout by gap-to-head  
Reason not guaranteed: too-short near-head timeout can increase retry churn on slow/loaded peers.

2. Hedged backfill requests near head  
Reason not guaranteed: can reduce tail latency but increases network and CPU load (duplicate work).

3. Latency-weighted peer selection  
Reason not guaranteed: EWMA can overfit transient latency spikes and choose suboptimal peers.

4. Failed-peer exclusion + exponential retry  
Reason not guaranteed: temporary peer failures may self-heal quickly; exclusion can delay recovery
in small peer sets.

5. Queue-based pending-block cascade (DAG + DB pending refs)  
Reason not guaranteed: can improve robustness at scale but adds complexity and extra bookkeeping
overhead in normal conditions.

6. Bounded memory buffers for attestation/signature staging  
Reason not guaranteed: protects memory under burst, but dropping overflow can hurt liveness/finality.
