use std::fmt::Write as FmtWrite;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tracing::{info, warn};

use crate::containers::state::State;
use crate::fork_choice::ForkChoiceStore;
use crate::networking::peer_manager::PeerManager;
use crate::ssz::SszEncode;
use crate::storage::{FileStore, Store};
use crate::unsafe_vec::{write_at, write_bytes_at};

enum HttpRoute {
    Metrics,
    Health,
    FinalizedState,
    JustifiedCheckpoint,
    ForkChoice,
    NotFound,
}

// ---------------------------------------------------------------------------
// AtomicCounter
// ---------------------------------------------------------------------------

/// Lock-free monotonic counter backed by `AtomicU64`.
pub struct AtomicCounter(AtomicU64);

impl AtomicCounter {
    pub const fn new() -> Self {
        Self(AtomicU64::new(0))
    }

    #[inline]
    pub fn inc(&self) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn add(&self, n: u64) {
        self.0.fetch_add(n, Ordering::Relaxed);
    }

    #[inline]
    pub fn get(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

impl Default for AtomicCounter {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// AtomicHistogram
// ---------------------------------------------------------------------------

/// Bucket upper bounds in nanoseconds for PQ signing / attestation verification.
pub static BUCKETS_SIG: &[u64] = &[
    5_000_000,     // 0.005s
    10_000_000,    // 0.01s
    25_000_000,    // 0.025s
    50_000_000,    // 0.05s
    100_000_000,   // 0.1s
    1_000_000_000, // 1s
];

/// Bucket upper bounds in nanoseconds for aggregate signature operations.
pub static BUCKETS_AGG: &[u64] = &[
    100_000_000,   // 0.1s
    250_000_000,   // 0.25s
    500_000_000,   // 0.5s
    750_000_000,   // 0.75s
    1_000_000_000, // 1s
    1_250_000_000, // 1.25s
    1_500_000_000, // 1.5s
    2_000_000_000, // 2s
    4_000_000_000, // 4s
];

/// Bucket upper bounds in nanoseconds for fork choice block processing.
pub static BUCKETS_FC_BLOCK: &[u64] = &[
    5_000_000,     // 0.005s
    10_000_000,    // 0.01s
    25_000_000,    // 0.025s
    50_000_000,    // 0.05s
    100_000_000,   // 0.1s
    1_000_000_000, // 1s
    1_250_000_000, // 1.25s
    1_500_000_000, // 1.5s
    2_000_000_000, // 2s
    4_000_000_000, // 4s
];

/// Bucket upper bounds in nanoseconds for full state transition.
pub static BUCKETS_STATE_TRANSITION: &[u64] = &[
    250_000_000,   // 0.25s
    500_000_000,   // 0.5s
    750_000_000,   // 0.75s
    1_000_000_000, // 1s
    1_250_000_000, // 1.25s
    1_500_000_000, // 1.5s
    2_000_000_000, // 2s
    2_500_000_000, // 2.5s
    3_000_000_000, // 3s
    4_000_000_000, // 4s
];

/// Bucket upper bounds (plain u64, not nanoseconds) for reorg depth.
pub static BUCKETS_REORG_DEPTH: &[u64] = &[1, 2, 3, 5, 7, 10, 20, 30, 50, 100];

/// Bucket upper bounds in nanoseconds for committee aggregation.
pub static BUCKETS_COMMITTEE_AGG: &[u64] = &[
    5_000_000,     // 0.005s
    10_000_000,    // 0.01s
    25_000_000,    // 0.025s
    50_000_000,    // 0.05s
    100_000_000,   // 0.1s
    250_000_000,   // 0.25s
    500_000_000,   // 0.5s
    750_000_000,   // 0.75s
    1_000_000_000, // 1s
];

/// Lock-free histogram with fixed bucket boundaries.
///
/// Each bucket counts observations whose value is ≤ the bucket boundary.
/// An implicit `+Inf` bucket is always appended.
pub struct AtomicHistogram {
    boundaries: &'static [u64],
    /// One counter per boundary + one for +Inf.
    buckets: Box<[AtomicU64]>,
    count: AtomicU64,
    sum: AtomicU64,
}

impl AtomicHistogram {
    pub fn new(boundaries: &'static [u64]) -> Self {
        let len = boundaries.len() + 1; // +1 for +Inf
        let mut buckets = Vec::with_capacity(len);
        for _ in 0..len {
            buckets.push(AtomicU64::new(0));
        }
        Self {
            boundaries,
            buckets: buckets.into_boxed_slice(),
            count: AtomicU64::new(0),
            sum: AtomicU64::new(0),
        }
    }

    /// Record a value in nanoseconds (or plain u64 for non-time histograms).
    #[inline]
    pub fn observe(&self, value: u64) {
        self.count.fetch_add(1, Ordering::Relaxed);
        self.sum.fetch_add(value, Ordering::Relaxed);
        for (i, &bound) in self.boundaries.iter().enumerate() {
            if value <= bound {
                self.buckets[i].fetch_add(1, Ordering::Relaxed);
            }
        }
        // +Inf bucket always gets incremented
        self.buckets[self.boundaries.len()].fetch_add(1, Ordering::Relaxed);
    }

    /// Record the elapsed time since `start` in nanoseconds.
    #[inline]
    pub fn observe_duration(&self, start: Instant) {
        let ns = start.elapsed().as_nanos() as u64;
        self.observe(ns);
    }

    /// Render in Prometheus text exposition format.
    ///
    /// `name` is the metric base name (e.g. `lean_pq_attestation_signing_time`).
    /// `help` is the HELP line text.
    /// If `nanos_to_secs` is true, the sum and bucket boundaries are rendered
    /// as seconds (divide by 1e9). Otherwise they are rendered as-is.
    pub fn render(&self, name: &str, help: &str, nanos_to_secs: bool) -> String {
        let mut out = String::with_capacity(512);
        let _ = writeln!(out, "# HELP {name} {help}");
        let _ = writeln!(out, "# TYPE {name} histogram");

        for (i, &bound) in self.boundaries.iter().enumerate() {
            let cumulative = self.buckets[i].load(Ordering::Relaxed);
            let le = if nanos_to_secs {
                format!("{:.6}", bound as f64 / 1_000_000_000.0)
            } else {
                format!("{bound}")
            };
            let _ = writeln!(out, "{name}_bucket{{le=\"{le}\"}} {cumulative}");
        }
        let inf_count = self.buckets[self.boundaries.len()].load(Ordering::Relaxed);
        let _ = writeln!(out, "{name}_bucket{{le=\"+Inf\"}} {inf_count}");

        let sum_val = self.sum.load(Ordering::Relaxed);
        let sum_display = if nanos_to_secs {
            format!("{:.6}", sum_val as f64 / 1_000_000_000.0)
        } else {
            format!("{sum_val}")
        };
        let _ = writeln!(out, "{name}_sum {sum_display}");
        let _ = writeln!(out, "{name}_count {}", self.count.load(Ordering::Relaxed));
        out
    }

    pub fn count(&self) -> u64 {
        self.count.load(Ordering::Relaxed)
    }

    pub fn sum(&self) -> u64 {
        self.sum.load(Ordering::Relaxed)
    }
}

// ---------------------------------------------------------------------------
// MetricsRegistry
// ---------------------------------------------------------------------------

/// All spec-defined metrics for a lean Ethereum consensus client.
///
/// Passed as `Arc<MetricsRegistry>` to all tasks; fields are lock-free.
pub struct MetricsRegistry {
    // -- Node info --
    pub start_time_seconds: u64,

    // -- PQ individual signatures --
    pub pq_attestation_signatures_total: AtomicCounter,
    pub pq_attestation_signatures_valid_total: AtomicCounter,
    pub pq_attestation_signatures_invalid_total: AtomicCounter,
    pub pq_proposer_signatures_total: AtomicCounter,
    pub pq_proposer_signatures_valid_total: AtomicCounter,
    pub pq_proposer_signatures_invalid_total: AtomicCounter,
    pub pq_attestation_signing_time: AtomicHistogram,
    pub pq_proposer_signing_time: AtomicHistogram,
    pub pq_attestation_verification_time: AtomicHistogram,

    // -- PQ aggregate signatures --
    pub pq_aggregated_signatures_total: AtomicCounter,
    pub pq_aggregated_signatures_valid_total: AtomicCounter,
    pub pq_aggregated_signatures_invalid_total: AtomicCounter,
    pub pq_attestations_in_aggregated_signatures_total: AtomicCounter,
    pub pq_aggregated_signing_time: AtomicHistogram,
    pub pq_aggregated_verification_time: AtomicHistogram,

    // -- Fork choice --
    pub fc_attestations_valid_total: AtomicCounter,
    pub fc_attestations_invalid_total: AtomicCounter,
    pub fc_block_processing_time: AtomicHistogram,
    pub fc_attestation_validation_time: AtomicHistogram,
    pub fc_reorg_depth: AtomicHistogram,
    pub fc_committee_aggregation_time: AtomicHistogram,

    // -- State transition --
    pub finalizations_success_total: AtomicCounter,
    pub finalizations_error_total: AtomicCounter,
    pub slots_processed_total: AtomicCounter,
    pub attestations_processed_total: AtomicCounter,
    pub state_transition_time: AtomicHistogram,
    pub state_transition_slots_processing_time: AtomicHistogram,
    pub state_transition_block_processing_time: AtomicHistogram,
    pub state_transition_attestations_processing_time: AtomicHistogram,
    pub block_import_end_to_end_time: AtomicHistogram,

    // -- Validator --
    pub is_aggregator: AtomicBool,
    pub attestation_committee_subnet: AtomicU64,
    pub attestation_committee_count: AtomicU64,

    // -- Network peer connections --
    pub peer_connection_inbound: AtomicCounter,
    pub peer_connection_outbound: AtomicCounter,
    pub peer_disconnection_inbound: AtomicCounter,
    pub peer_disconnection_outbound: AtomicCounter,
}

impl MetricsRegistry {
    pub fn new() -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        Self {
            start_time_seconds: now,

            pq_attestation_signatures_total: AtomicCounter::new(),
            pq_attestation_signatures_valid_total: AtomicCounter::new(),
            pq_attestation_signatures_invalid_total: AtomicCounter::new(),
            pq_proposer_signatures_total: AtomicCounter::new(),
            pq_proposer_signatures_valid_total: AtomicCounter::new(),
            pq_proposer_signatures_invalid_total: AtomicCounter::new(),
            pq_attestation_signing_time: AtomicHistogram::new(BUCKETS_SIG),
            pq_proposer_signing_time: AtomicHistogram::new(BUCKETS_SIG),
            pq_attestation_verification_time: AtomicHistogram::new(BUCKETS_SIG),

            pq_aggregated_signatures_total: AtomicCounter::new(),
            pq_aggregated_signatures_valid_total: AtomicCounter::new(),
            pq_aggregated_signatures_invalid_total: AtomicCounter::new(),
            pq_attestations_in_aggregated_signatures_total: AtomicCounter::new(),
            pq_aggregated_signing_time: AtomicHistogram::new(BUCKETS_AGG),
            pq_aggregated_verification_time: AtomicHistogram::new(BUCKETS_AGG),

            fc_attestations_valid_total: AtomicCounter::new(),
            fc_attestations_invalid_total: AtomicCounter::new(),
            fc_block_processing_time: AtomicHistogram::new(BUCKETS_FC_BLOCK),
            fc_attestation_validation_time: AtomicHistogram::new(BUCKETS_SIG),
            fc_reorg_depth: AtomicHistogram::new(BUCKETS_REORG_DEPTH),
            fc_committee_aggregation_time: AtomicHistogram::new(BUCKETS_COMMITTEE_AGG),

            finalizations_success_total: AtomicCounter::new(),
            finalizations_error_total: AtomicCounter::new(),
            slots_processed_total: AtomicCounter::new(),
            attestations_processed_total: AtomicCounter::new(),
            state_transition_time: AtomicHistogram::new(BUCKETS_STATE_TRANSITION),
            state_transition_slots_processing_time: AtomicHistogram::new(BUCKETS_SIG),
            state_transition_block_processing_time: AtomicHistogram::new(BUCKETS_SIG),
            state_transition_attestations_processing_time: AtomicHistogram::new(BUCKETS_SIG),
            block_import_end_to_end_time: AtomicHistogram::new(BUCKETS_STATE_TRANSITION),

            is_aggregator: AtomicBool::new(false),
            attestation_committee_subnet: AtomicU64::new(0),
            attestation_committee_count: AtomicU64::new(0),

            peer_connection_inbound: AtomicCounter::new(),
            peer_connection_outbound: AtomicCounter::new(),
            peer_disconnection_inbound: AtomicCounter::new(),
            peer_disconnection_outbound: AtomicCounter::new(),
        }
    }
}

impl Default for MetricsRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Metrics server
// ---------------------------------------------------------------------------

#[inline]
pub fn spawn_http_server(
    state: Arc<RwLock<State>>,
    store: Arc<RwLock<FileStore>>,
    fork_choice: Arc<RwLock<Option<ForkChoiceStore>>>,
    peers: Option<PeerManager>,
    is_syncing: Arc<AtomicBool>,
    sync_target_slot: Arc<AtomicU64>,
    sync_pending_depth: Arc<AtomicU64>,
    registry: Arc<MetricsRegistry>,
    node_name: String,
    client_name: String,
    bind_addr: String,
    enable_metrics: bool,
    enable_http_api: bool,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let listener = match TcpListener::bind(&bind_addr).await {
            Ok(listener) => listener,
            Err(err) => {
                warn!("http bind failed on {}: {}", bind_addr, err);
                return;
            }
        };
        let listener_label = match (enable_metrics, enable_http_api) {
            (true, true) => "metrics/http",
            (true, false) => "metrics",
            (false, true) => "http api",
            (false, false) => "disabled",
        };
        info!("{listener_label} listening on {}", bind_addr);
        let mut finalized_state_cache: Option<(crate::types::bytes::Bytes32, Vec<u8>)> = None;

        loop {
            let (mut stream, _peer) = match listener.accept().await {
                Ok(v) => v,
                Err(err) => {
                    warn!("metrics accept failed: {}", err);
                    continue;
                }
            };

            let mut request_buf = [0u8; 2048];
            let request_len = match stream.read(&mut request_buf).await {
                Ok(n) => n,
                Err(err) => {
                    warn!("metrics read failed: {}", err);
                    continue;
                }
            };
            if request_len == 0 {
                continue;
            }
            let route = classify_http_route(&request_buf[..request_len]);

            let response = match route {
                HttpRoute::Metrics => {
                    if !enable_metrics {
                        http_response_bytes(
                            "404 Not Found",
                            "text/plain; charset=utf-8",
                            b"metrics disabled\n".to_vec(),
                        )
                    } else {
                        let body = {
                            let state_guard = state.read().expect("state lock");
                            let store_guard = store.read().expect("store lock");
                            let fc_guard = fork_choice.read().expect("fork choice lock");
                            let peer_count = peers.as_ref().map(|p| p.peer_count()).unwrap_or(0);
                            let syncing = is_syncing.load(Ordering::Relaxed);
                            let sync_target = sync_target_slot.load(Ordering::Relaxed);
                            let sync_depth = sync_pending_depth.load(Ordering::Relaxed);
                            render_metrics(
                                &state_guard,
                                &store_guard,
                                &fc_guard,
                                peer_count,
                                syncing,
                                sync_target,
                                sync_depth,
                                &registry,
                                &node_name,
                                &client_name,
                            )
                            .into_bytes()
                        };
                        http_response_bytes("200 OK", "text/plain; version=0.0.4", body)
                    }
                }
                HttpRoute::Health => {
                    if !enable_http_api {
                        http_response_bytes(
                            "404 Not Found",
                            "text/plain; charset=utf-8",
                            b"http api disabled\n".to_vec(),
                        )
                    } else {
                        http_response_bytes("200 OK", "text/plain; charset=utf-8", b"ok\n".to_vec())
                    }
                }
                HttpRoute::FinalizedState => {
                    if !enable_http_api {
                        http_response_bytes(
                            "404 Not Found",
                            "text/plain; charset=utf-8",
                            b"http api disabled\n".to_vec(),
                        )
                    } else {
                        let finalized_state = {
                            let state_guard = state.read().expect("state lock");
                            let store_guard = store.read().expect("store lock");
                            latest_finalized_state_ssz(
                                &state_guard,
                                &store_guard,
                                &mut finalized_state_cache,
                            )
                        };
                        match finalized_state {
                            Some(bytes) => {
                                http_response_bytes("200 OK", "application/octet-stream", bytes)
                            }
                            None => http_response_bytes(
                                "404 Not Found",
                                "text/plain; charset=utf-8",
                                b"finalized state not found\n".to_vec(),
                            ),
                        }
                    }
                }
                HttpRoute::JustifiedCheckpoint => {
                    if !enable_http_api {
                        http_response_bytes(
                            "404 Not Found",
                            "text/plain; charset=utf-8",
                            b"http api disabled\n".to_vec(),
                        )
                    } else {
                        let maybe_checkpoint = {
                            let fc_guard = fork_choice.read().expect("fork choice lock");
                            fc_guard.as_ref().map(|fc| fc.latest_justified())
                        };
                        match maybe_checkpoint {
                            Some(checkpoint) => http_response_bytes(
                                "200 OK",
                                "application/json; charset=utf-8",
                                checkpoint_json(checkpoint.slot.0.0, checkpoint.root),
                            ),
                            None => http_response_bytes(
                                "503 Service Unavailable",
                                "text/plain; charset=utf-8",
                                b"store not initialized\n".to_vec(),
                            ),
                        }
                    }
                }
                HttpRoute::ForkChoice => {
                    if !enable_http_api {
                        http_response_bytes(
                            "404 Not Found",
                            "text/plain; charset=utf-8",
                            b"http api disabled\n".to_vec(),
                        )
                    } else {
                        let fork_choice_snapshot = {
                            let fc_guard = fork_choice.read().expect("fork choice lock");
                            fc_guard.as_ref().map(fork_choice_json)
                        };
                        match fork_choice_snapshot {
                            Some(body) => http_response_bytes(
                                "200 OK",
                                "application/json; charset=utf-8",
                                body,
                            ),
                            None => http_response_bytes(
                                "503 Service Unavailable",
                                "text/plain; charset=utf-8",
                                b"store not initialized\n".to_vec(),
                            ),
                        }
                    }
                }
                HttpRoute::NotFound => http_response_bytes(
                    "404 Not Found",
                    "text/plain; charset=utf-8",
                    b"not found\n".to_vec(),
                ),
            };

            if let Err(err) = stream.write_all(&response).await {
                warn!("metrics write failed: {}", err);
            }
            let _ = stream.shutdown().await;
        }
    })
}

#[inline]
fn classify_http_route(request: &[u8]) -> HttpRoute {
    let line_end = request
        .iter()
        .position(|b| *b == b'\n')
        .unwrap_or(request.len());
    let mut line = &request[..line_end];
    if line.last() == Some(&b'\r') {
        line = &line[..line.len().saturating_sub(1)];
    }
    if !line.starts_with(b"GET ") {
        return HttpRoute::NotFound;
    }
    let path_start = 4usize;
    if path_start >= line.len() {
        return HttpRoute::NotFound;
    }
    let Some(path_rel_end) = line[path_start..].iter().position(|b| *b == b' ') else {
        return HttpRoute::NotFound;
    };
    let mut path = &line[path_start..path_start + path_rel_end];
    if let Some(query_start) = path.iter().position(|b| *b == b'?') {
        path = &path[..query_start];
    }
    match path {
        b"/" | b"/metrics" => HttpRoute::Metrics,
        b"/health" | b"/v0/health" | b"/lean/health" | b"/lean/v0/health" => HttpRoute::Health,
        b"/states/finalized"
        | b"/v0/states/finalized"
        | b"/lean/states/finalized"
        | b"/lean/v0/states/finalized" => HttpRoute::FinalizedState,
        b"/v0/checkpoints/justified"
        | b"/checkpoints/justified"
        | b"/lean/checkpoints/justified"
        | b"/lean/v0/checkpoints/justified" => HttpRoute::JustifiedCheckpoint,
        b"/fork_choice" | b"/v0/fork_choice" | b"/lean/fork_choice" | b"/lean/v0/fork_choice" => {
            HttpRoute::ForkChoice
        }
        _ => HttpRoute::NotFound,
    }
}

#[cfg(test)]
mod route_tests {
    use super::{HttpRoute, classify_http_route};

    fn route_for(path: &str) -> HttpRoute {
        let request = format!("GET {path} HTTP/1.1\r\nHost: localhost\r\n\r\n");
        classify_http_route(request.as_bytes())
    }

    #[test]
    fn accepts_v0_route_aliases() {
        assert!(matches!(route_for("/v0/health"), HttpRoute::Health));
        assert!(matches!(
            route_for("/v0/states/finalized"),
            HttpRoute::FinalizedState
        ));
        assert!(matches!(
            route_for("/v0/checkpoints/justified"),
            HttpRoute::JustifiedCheckpoint
        ));
        assert!(matches!(
            route_for("/v0/fork_choice"),
            HttpRoute::ForkChoice
        ));
    }
}

#[inline]
fn http_response_bytes(status: &str, content_type: &str, body: Vec<u8>) -> Vec<u8> {
    let mut response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    response.extend_from_slice(&body);
    response
}

#[inline]
fn latest_finalized_state_ssz(
    state: &State,
    store: &FileStore,
    cache: &mut Option<(crate::types::bytes::Bytes32, Vec<u8>)>,
) -> Option<Vec<u8>> {
    let store_finalized = store.finalized();
    if let Some(root) = store_finalized {
        if let Some((cached_root, cached_bytes)) = cache.as_ref()
            && *cached_root == root
        {
            return Some(cached_bytes.clone());
        }
        if let Some(finalized_state) = store.get_state(&root) {
            let bytes = finalized_state.encode_ssz();
            *cache = Some((root, bytes.clone()));
            return Some(bytes);
        }
        return None;
    }
    // Before any finalized root has been persisted, serve the live in-memory snapshot.
    *cache = None;
    Some(state.encode_ssz())
}

#[inline]
fn checkpoint_json(slot: u64, root: crate::types::bytes::Bytes32) -> Vec<u8> {
    const PREFIX: &[u8] = b"{\"slot\":";
    const MID: &[u8] = b",\"root\":\"0x";
    const SUFFIX: &[u8] = b"\"}\n";
    const HEX: &[u8; 16] = b"0123456789abcdef";

    let slot_bytes = slot.to_string().into_bytes();
    let root_bytes: &[u8] = root.as_ref();
    let total_len =
        PREFIX.len() + slot_bytes.len() + MID.len() + (root_bytes.len() * 2) + SUFFIX.len();

    let mut out = Vec::with_capacity(total_len);
    unsafe { out.set_len(total_len) };

    let mut cursor = 0usize;
    unsafe { write_bytes_at(&mut out, cursor, PREFIX) };
    cursor += PREFIX.len();
    unsafe { write_bytes_at(&mut out, cursor, &slot_bytes) };
    cursor += slot_bytes.len();
    unsafe { write_bytes_at(&mut out, cursor, MID) };
    cursor += MID.len();

    for &b in root_bytes {
        unsafe { write_at(&mut out, cursor, HEX[(b >> 4) as usize]) };
        unsafe { write_at(&mut out, cursor + 1, HEX[(b & 0x0f) as usize]) };
        cursor += 2;
    }

    unsafe { write_bytes_at(&mut out, cursor, SUFFIX) };
    out
}

#[inline]
fn fork_choice_json(store: &ForkChoiceStore) -> Vec<u8> {
    let finalized = store.latest_finalized();
    let justified = store.latest_justified();
    let head = store.head();
    let safe_target = store.safe_target();
    let validator_count = store.head_validator_count();
    let finalized_slot = finalized.slot.0.0;

    let mut out = String::new();
    out.push('{');

    out.push_str("\"nodes\":[");
    let mut first = true;
    for node in store
        .node_snapshots()
        .into_iter()
        .filter(|n| n.slot >= finalized_slot)
    {
        if !first {
            out.push(',');
        }
        first = false;
        out.push('{');
        out.push_str("\"root\":\"0x");
        push_hex(&mut out, node.root.as_ref());
        out.push_str("\",\"slot\":");
        let _ = write!(&mut out, "{}", node.slot);
        out.push_str(",\"parent_root\":\"0x");
        push_hex(&mut out, node.parent_root.as_ref());
        out.push_str("\",\"proposer_index\":");
        let _ = write!(&mut out, "{}", node.proposer_index);
        out.push_str(",\"weight\":");
        let _ = write!(&mut out, "{}", node.weight);
        out.push('}');
    }
    out.push(']');

    out.push_str(",\"head\":\"0x");
    push_hex(&mut out, head.as_ref());
    out.push('"');

    out.push_str(",\"justified\":{");
    out.push_str("\"slot\":");
    let _ = write!(&mut out, "{}", justified.slot.0.0);
    out.push_str(",\"root\":\"0x");
    push_hex(&mut out, justified.root.as_ref());
    out.push_str("\"}");

    out.push_str(",\"finalized\":{");
    out.push_str("\"slot\":");
    let _ = write!(&mut out, "{}", finalized.slot.0.0);
    out.push_str(",\"root\":\"0x");
    push_hex(&mut out, finalized.root.as_ref());
    out.push_str("\"}");

    out.push_str(",\"safe_target\":\"0x");
    push_hex(&mut out, safe_target.as_ref());
    out.push('"');

    out.push_str(",\"validator_count\":");
    let _ = write!(&mut out, "{}", validator_count);

    out.push('}');
    out.into_bytes()
}

#[inline]
fn push_hex(out: &mut String, bytes: &[u8]) {
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

#[inline]
fn write_gauge_metric(out: &mut String, name: &str, value: impl std::fmt::Display) {
    let _ = writeln!(out, "# TYPE {name} gauge");
    let _ = writeln!(out, "{name} {value}");
}

#[inline]
fn write_counter_metric(out: &mut String, name: &str, value: impl std::fmt::Display) {
    let _ = writeln!(out, "# TYPE {name} counter");
    let _ = writeln!(out, "{name} {value}");
}

#[inline]
fn write_counter_metric_labeled(out: &mut String, name: &str, labels: &str, value: u64) {
    let _ = writeln!(out, "{name}{{{labels}}} {value}");
}

#[inline]
fn escape_label_value(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

#[cfg(all(
    any(target_os = "linux", target_os = "macos"),
    not(target_env = "msvc")
))]
fn write_jemalloc_metrics(out: &mut String) {
    use tikv_jemalloc_ctl::{epoch, stats};

    if epoch::advance().is_err() {
        return;
    }

    if let Ok(value) = stats::allocated::read() {
        write_gauge_metric(out, "lean_jemalloc_bytes_allocated", value);
    }
    if let Ok(value) = stats::active::read() {
        write_gauge_metric(out, "lean_jemalloc_bytes_active", value);
    }
    if let Ok(value) = stats::metadata::read() {
        write_gauge_metric(out, "lean_jemalloc_bytes_metadata", value);
    }
    if let Ok(value) = stats::resident::read() {
        write_gauge_metric(out, "lean_jemalloc_bytes_resident", value);
    }
    if let Ok(value) = stats::mapped::read() {
        write_gauge_metric(out, "lean_jemalloc_bytes_mapped", value);
    }
    if let Ok(value) = stats::retained::read() {
        write_gauge_metric(out, "lean_jemalloc_bytes_retained", value);
    }
}

#[cfg(not(all(
    any(target_os = "linux", target_os = "macos"),
    not(target_env = "msvc")
)))]
fn write_jemalloc_metrics(_out: &mut String) {}

fn render_metrics(
    state: &State,
    store: &FileStore,
    fork_choice: &Option<ForkChoiceStore>,
    peer_count: usize,
    syncing: bool,
    sync_target_slot: u64,
    sync_pending_depth: u64,
    registry: &MetricsRegistry,
    node_name: &str,
    client_name: &str,
) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let store_head_slot = store
        .head()
        .and_then(|root| store.get_block(&root))
        .map(|block| block.slot.0.0)
        .unwrap_or(state.slot.0.0);

    let fc_head_slot = fork_choice.as_ref().map(|fc| fc.head_slot()).unwrap_or(0);
    let fc_justified_slot = fork_choice
        .as_ref()
        .map(|fc| fc.latest_justified().slot.0.0)
        .unwrap_or(0);
    let fc_finalized_slot = fork_choice
        .as_ref()
        .map(|fc| fc.latest_finalized().slot.0.0)
        .unwrap_or(0);
    let fc_previous_justified_slot = fork_choice
        .as_ref()
        .map(|fc| fc.previous_justified().slot.0.0)
        .unwrap_or(0);
    let fc_active_validators = fork_choice
        .as_ref()
        .map(|fc| fc.validator_count())
        .unwrap_or(0);
    let reorgs_total = fork_choice
        .as_ref()
        .map(|fc| fc.reorgs_total())
        .unwrap_or(0u64);
    let safe_target_slot = fork_choice
        .as_ref()
        .map(|fc| fc.safe_target_slot())
        .unwrap_or(0);
    let gossip_signatures = fork_choice
        .as_ref()
        .map(|fc| fc.gossip_signatures_count())
        .unwrap_or(0);
    let latest_votes = fork_choice
        .as_ref()
        .map(|fc| fc.latest_votes_count())
        .unwrap_or(0);

    let head_slot = store_head_slot.max(fc_head_slot);
    let justified_slot = state.latest_justified.slot.0.0.max(fc_justified_slot);
    let finalized_slot = state.latest_finalized.slot.0.0.max(fc_finalized_slot);
    let previous_justified_slot = if fc_previous_justified_slot > 0 {
        fc_previous_justified_slot
    } else {
        state.latest_justified.slot.0.0
    };
    let active_validators = state.validators.data.len().max(fc_active_validators);
    let is_agg = if registry.is_aggregator.load(Ordering::Relaxed) {
        1
    } else {
        0
    };
    let attestation_subnet = registry
        .attestation_committee_subnet
        .load(Ordering::Relaxed);
    let attestation_subnet_count = registry.attestation_committee_count.load(Ordering::Relaxed);

    let mut out = String::with_capacity(8192);

    // -- Node info --
    let _ = writeln!(out, "# HELP lean_node_info Client implementation metadata.");
    let _ = writeln!(out, "# TYPE lean_node_info gauge");
    let node_name = escape_label_value(node_name);
    let client_name = escape_label_value(client_name);
    let _ = writeln!(
        out,
        "lean_node_info{{name=\"{}\",version=\"{}\"}} 1",
        node_name,
        env!("CARGO_PKG_VERSION")
    );
    write_gauge_metric(
        &mut out,
        "lean_node_start_time_seconds",
        registry.start_time_seconds,
    );
    write_gauge_metric(&mut out, "lean_node_time_seconds", now);

    // -- Beacon chain gauges --
    write_gauge_metric(&mut out, "lean_current_slot", state.slot.0.0);
    write_gauge_metric(&mut out, "lean_head_slot", head_slot);
    // Alias for clients/dashboards that use non-latest names.
    write_gauge_metric(&mut out, "lean_justified_slot", justified_slot);
    // Alias for clients/dashboards that use non-latest names.
    write_gauge_metric(&mut out, "lean_finalized_slot", finalized_slot);
    write_gauge_metric(&mut out, "lean_latest_justified_slot", justified_slot);
    write_gauge_metric(&mut out, "lean_latest_finalized_slot", finalized_slot);
    write_gauge_metric(
        &mut out,
        "lean_previous_justified_slot",
        previous_justified_slot,
    );
    write_gauge_metric(&mut out, "lean_safe_target_slot", safe_target_slot);
    write_gauge_metric(&mut out, "lean_validators_count", active_validators);
    write_counter_metric(&mut out, "lean_fork_choice_reorgs_total", reorgs_total);
    write_gauge_metric(&mut out, "lean_processed_deposits_total", 0);

    // -- Fork choice vote counts --
    write_gauge_metric(&mut out, "lean_gossip_signatures", gossip_signatures);
    write_gauge_metric(
        &mut out,
        "lean_latest_known_aggregated_payloads",
        latest_votes,
    );
    write_gauge_metric(
        &mut out,
        "lean_latest_new_aggregated_payloads",
        gossip_signatures,
    );

    // -- Validator --
    write_gauge_metric(&mut out, "lean_is_aggregator", is_agg);
    write_gauge_metric(
        &mut out,
        "lean_attestation_committee_subnet",
        attestation_subnet,
    );
    write_gauge_metric(
        &mut out,
        "lean_attestation_committee_count",
        attestation_subnet_count,
    );

    // -- Network --
    write_gauge_metric(&mut out, "lean_connected_peers", peer_count);
    let _ = writeln!(
        out,
        "lean_connected_peers{{client=\"{}\"}} {peer_count}",
        client_name
    );
    let _ = writeln!(out, "# TYPE lean_peer_connection_events_total counter");
    write_counter_metric_labeled(
        &mut out,
        "lean_peer_connection_events_total",
        "direction=\"inbound\",result=\"success\"",
        registry.peer_connection_inbound.get(),
    );
    write_counter_metric_labeled(
        &mut out,
        "lean_peer_connection_events_total",
        "direction=\"outbound\",result=\"success\"",
        registry.peer_connection_outbound.get(),
    );
    write_counter_metric_labeled(
        &mut out,
        "lean_peer_connection_events_total",
        "direction=\"inbound\",result=\"timeout\"",
        0,
    );
    write_counter_metric_labeled(
        &mut out,
        "lean_peer_connection_events_total",
        "direction=\"outbound\",result=\"timeout\"",
        0,
    );
    write_counter_metric_labeled(
        &mut out,
        "lean_peer_connection_events_total",
        "direction=\"inbound\",result=\"error\"",
        0,
    );
    write_counter_metric_labeled(
        &mut out,
        "lean_peer_connection_events_total",
        "direction=\"outbound\",result=\"error\"",
        0,
    );

    let _ = writeln!(out, "# TYPE lean_peer_disconnection_events_total counter");
    write_counter_metric_labeled(
        &mut out,
        "lean_peer_disconnection_events_total",
        "direction=\"inbound\",reason=\"remote_close\"",
        registry.peer_disconnection_inbound.get(),
    );
    write_counter_metric_labeled(
        &mut out,
        "lean_peer_disconnection_events_total",
        "direction=\"outbound\",reason=\"local_close\"",
        registry.peer_disconnection_outbound.get(),
    );
    write_counter_metric_labeled(
        &mut out,
        "lean_peer_disconnection_events_total",
        "direction=\"inbound\",reason=\"timeout\"",
        0,
    );
    write_counter_metric_labeled(
        &mut out,
        "lean_peer_disconnection_events_total",
        "direction=\"outbound\",reason=\"timeout\"",
        0,
    );
    write_counter_metric_labeled(
        &mut out,
        "lean_peer_disconnection_events_total",
        "direction=\"inbound\",reason=\"error\"",
        0,
    );
    write_counter_metric_labeled(
        &mut out,
        "lean_peer_disconnection_events_total",
        "direction=\"outbound\",reason=\"error\"",
        0,
    );

    // -- Sync --
    write_gauge_metric(&mut out, "lean_syncing", if syncing { 1 } else { 0 });
    write_gauge_metric(&mut out, "lean_sync_target_slot", sync_target_slot);
    write_gauge_metric(&mut out, "lean_sync_pending_depth", sync_pending_depth);

    // -- Storage --
    write_gauge_metric(
        &mut out,
        "lean_storage_canonical_state_rows",
        store.canonical_state_rows(),
    );
    write_gauge_metric(
        &mut out,
        "lean_storage_canonical_block_rows",
        store.canonical_block_rows(),
    );
    write_gauge_metric(
        &mut out,
        "lean_storage_pending_block_rows",
        store.pending_block_rows(),
    );
    write_jemalloc_metrics(&mut out);

    // -- PQ individual signature counters --
    write_counter_metric(
        &mut out,
        "lean_pq_sig_attestation_signatures_total",
        registry.pq_attestation_signatures_total.get(),
    );
    write_counter_metric(
        &mut out,
        "lean_pq_sig_attestation_signatures_valid_total",
        registry.pq_attestation_signatures_valid_total.get(),
    );
    write_counter_metric(
        &mut out,
        "lean_pq_sig_attestation_signatures_invalid_total",
        registry.pq_attestation_signatures_invalid_total.get(),
    );
    write_counter_metric(
        &mut out,
        "lean_pq_proposer_signatures_total",
        registry.pq_proposer_signatures_total.get(),
    );
    write_counter_metric(
        &mut out,
        "lean_pq_proposer_signatures_valid_total",
        registry.pq_proposer_signatures_valid_total.get(),
    );
    write_counter_metric(
        &mut out,
        "lean_pq_proposer_signatures_invalid_total",
        registry.pq_proposer_signatures_invalid_total.get(),
    );

    // -- PQ aggregate signature counters --
    write_counter_metric(
        &mut out,
        "lean_pq_sig_aggregated_signatures_total",
        registry.pq_aggregated_signatures_total.get(),
    );
    write_counter_metric(
        &mut out,
        "lean_pq_sig_aggregated_signatures_valid_total",
        registry.pq_aggregated_signatures_valid_total.get(),
    );
    write_counter_metric(
        &mut out,
        "lean_pq_sig_aggregated_signatures_invalid_total",
        registry.pq_aggregated_signatures_invalid_total.get(),
    );
    write_counter_metric(
        &mut out,
        "lean_pq_sig_attestations_in_aggregated_signatures_total",
        registry
            .pq_attestations_in_aggregated_signatures_total
            .get(),
    );

    // -- Fork choice counters --
    write_counter_metric(
        &mut out,
        "lean_attestations_valid_total",
        registry.fc_attestations_valid_total.get(),
    );
    write_counter_metric(
        &mut out,
        "lean_attestations_invalid_total",
        registry.fc_attestations_invalid_total.get(),
    );

    // -- State transition counters --
    let _ = writeln!(out, "# TYPE lean_finalizations_total counter");
    write_counter_metric_labeled(
        &mut out,
        "lean_finalizations_total",
        "result=\"success\"",
        registry.finalizations_success_total.get(),
    );
    write_counter_metric_labeled(
        &mut out,
        "lean_finalizations_total",
        "result=\"error\"",
        registry.finalizations_error_total.get(),
    );
    write_counter_metric(
        &mut out,
        "lean_state_transition_slots_processed_total",
        registry.slots_processed_total.get(),
    );
    write_counter_metric(
        &mut out,
        "lean_state_transition_attestations_processed_total",
        registry.attestations_processed_total.get(),
    );

    // -- PQ individual signature histograms --
    out.push_str(&registry.pq_attestation_signing_time.render(
        "lean_pq_sig_attestation_signing_time_seconds",
        "Time to produce a PQ attestation signature.",
        true,
    ));
    out.push_str(&registry.pq_proposer_signing_time.render(
        "lean_pq_sig_proposer_signing_time_seconds",
        "Time to produce a PQ proposer signature.",
        true,
    ));
    out.push_str(&registry.pq_proposer_signing_time.render(
        "lean_pq_proposer_signing_time",
        "Time to produce a PQ proposer signature.",
        true,
    ));
    out.push_str(&registry.pq_attestation_verification_time.render(
        "lean_pq_sig_attestation_verification_time_seconds",
        "Time to verify a PQ attestation signature.",
        true,
    ));

    // -- PQ aggregate histograms --
    out.push_str(&registry.pq_aggregated_signing_time.render(
        "lean_pq_sig_aggregated_signatures_building_time_seconds",
        "Time to build an aggregate PQ signature.",
        true,
    ));
    out.push_str(&registry.pq_aggregated_verification_time.render(
        "lean_pq_sig_aggregated_signatures_verification_time_seconds",
        "Time to verify an aggregate PQ signature.",
        true,
    ));

    // -- Fork choice histograms --
    out.push_str(&registry.fc_block_processing_time.render(
        "lean_fork_choice_block_processing_time_seconds",
        "Time for fork choice to process a block.",
        true,
    ));
    out.push_str(&registry.fc_attestation_validation_time.render(
        "lean_attestation_validation_time_seconds",
        "Time for fork choice attestation validation.",
        true,
    ));
    out.push_str(&registry.fc_reorg_depth.render(
        "lean_fork_choice_reorg_depth",
        "Depth of chain reorganizations.",
        false,
    ));
    out.push_str(&registry.fc_committee_aggregation_time.render(
        "lean_committee_signatures_aggregation_time_seconds",
        "Time for committee aggregation.",
        true,
    ));

    // -- State transition histograms --
    out.push_str(&registry.state_transition_time.render(
        "lean_state_transition_time_seconds",
        "Total state transition time.",
        true,
    ));
    out.push_str(&registry.state_transition_slots_processing_time.render(
        "lean_state_transition_slots_processing_time_seconds",
        "Time to process slots in state transition.",
        true,
    ));
    out.push_str(&registry.state_transition_block_processing_time.render(
        "lean_state_transition_block_processing_time_seconds",
        "Time to process block in state transition.",
        true,
    ));
    out.push_str(
        &registry
            .state_transition_attestations_processing_time
            .render(
                "lean_state_transition_attestations_processing_time_seconds",
                "Time to process attestations in state transition.",
                true,
            ),
    );
    out.push_str(&registry.block_import_end_to_end_time.render(
        "lean_block_import_end_to_end_time",
        "End-to-end time to import a signed block.",
        true,
    ));

    out
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn atomic_counter_inc_and_get() {
        let c = AtomicCounter::new();
        assert_eq!(c.get(), 0);
        c.inc();
        assert_eq!(c.get(), 1);
        c.add(5);
        assert_eq!(c.get(), 6);
    }

    #[test]
    fn atomic_histogram_observe_and_render() {
        let boundaries: &'static [u64] = &[10, 50, 100];
        let h = AtomicHistogram::new(boundaries);
        h.observe(5);
        h.observe(25);
        h.observe(75);
        h.observe(200);

        assert_eq!(h.count(), 4);
        assert_eq!(h.sum(), 305);

        let rendered = h.render("test_metric", "A test histogram.", false);
        assert!(rendered.contains("# HELP test_metric A test histogram."));
        assert!(rendered.contains("# TYPE test_metric histogram"));
        assert!(rendered.contains("test_metric_bucket{le=\"10\"} 1"));
        assert!(rendered.contains("test_metric_bucket{le=\"50\"} 2"));
        assert!(rendered.contains("test_metric_bucket{le=\"100\"} 3"));
        assert!(rendered.contains("test_metric_bucket{le=\"+Inf\"} 4"));
        assert!(rendered.contains("test_metric_sum 305"));
        assert!(rendered.contains("test_metric_count 4"));
    }

    #[test]
    fn atomic_histogram_nanos_to_secs_render() {
        let h = AtomicHistogram::new(BUCKETS_SIG);
        h.observe(7_000_000); // 0.007s — falls in 0.01 bucket
        let rendered = h.render("lean_pq_signing", "PQ signing time.", true);
        assert!(rendered.contains("le=\"0.005000\""));
        assert!(rendered.contains("le=\"0.010000\""));
        assert!(rendered.contains("lean_pq_signing_sum"));
        assert!(rendered.contains("lean_pq_signing_count 1"));
    }

    #[test]
    fn metrics_registry_creates() {
        let r = MetricsRegistry::new();
        assert!(r.start_time_seconds > 0);
        assert_eq!(r.pq_attestation_signatures_total.get(), 0);
        assert_eq!(r.fc_attestations_valid_total.get(), 0);
        r.pq_attestation_signatures_total.inc();
        assert_eq!(r.pq_attestation_signatures_total.get(), 1);
    }
}
