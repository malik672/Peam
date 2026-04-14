mod gossip;
mod head;
mod sync;
mod tasks;

pub use gossip::handle_gossip_event;
pub use head::proposal_head_from_pending;

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tracing::{info, warn};

use crate::app::{
    NodeSettings, build_genesis_from_config_yaml_with_override, build_genesis_with_validator_count,
    load_node_settings, resolve_metrics_identity, resolve_validator_startup_overrides,
};
use crate::checkpoint_sync::{
    build_anchor_block, build_anchor_signed_block, fetch_checkpoint_state, verify_checkpoint_state,
};
use crate::containers::attestation::Attestation;
use crate::containers::attestation::SignedAttestation;
use crate::containers::checkpoint::Checkpoint;
use crate::containers::config::Config;
use crate::containers::state::State;
use crate::fork_choice::ForkChoiceStore;
use crate::metrics::{MetricsRegistry, spawn_http_server};
use crate::networking::{
    Networking, NetworkingConfig, StateGossipContext, StoreReqRespHandler, verifier_from_validators,
};
use crate::ssz::HashTreeRoot;
use crate::storage::{FileStore, Store};
use crate::types::bytes::Bytes32;

use self::sync::spawn_status_sync_task;
use tasks::{
    DevnetValidatorKeyCache, PendingBlockAttestation, build_devnet_pq_validator_keys,
    build_devnet_pq_validator_keys_from_hash_sig_dir, filter_keys_against_genesis,
    spawn_attestation_aggregation_task, spawn_block_production_task,
    spawn_consensus_lifecycle_task, spawn_signed_attestation_task, spawn_strict_slot_clock,
};

const PEAM_ASCII_BANNER: &str = r#"
 ____  _____    _    __  __
|  _ \| ____|  / \  |  \/  |
| |_) |  _|   / _ \ | |\/| |
|  __/| |___ / ___ \| |  | |
|_|   |_____/_/   \_\_|  |_|
"#;

fn normalize_genesis_anchor_roots(state: &mut State, anchor_root: Bytes32) {
    if state.slot.0.0 != 0 {
        return;
    }
    if state.latest_justified.slot.0.0 == 0 && state.latest_justified.root == Bytes32::zero() {
        state.latest_justified.root = anchor_root;
    }
    if state.latest_finalized.slot.0.0 == 0 && state.latest_finalized.root == Bytes32::zero() {
        state.latest_finalized.root = anchor_root;
    }
}

fn seed_anchor_store_and_fork_choice(
    store: &mut FileStore,
    state: &mut State,
) -> Result<ForkChoiceStore, String> {
    let anchor_block = build_anchor_block(state);
    let anchor_root = Bytes32::from(anchor_block.hash_tree_root());
    normalize_genesis_anchor_roots(state, anchor_root);
    let signed_anchor = build_anchor_signed_block(state, &anchor_block)?;
    store.put_anchor_signed_block(anchor_root, &signed_anchor, state)?;
    store.set_head(anchor_root);
    store.set_finalized_checkpoint(Checkpoint {
        root: anchor_root,
        slot: anchor_block.slot,
    });
    store.set_justified(anchor_root);
    let mut fc = ForkChoiceStore::new(signed_anchor, state.clone())?;
    fc.override_checkpoint_roots(anchor_root);
    Ok(fc)
}

/// Filesystem paths used to initialize a [`Node`].
#[derive(Clone, Debug)]
pub struct NodeConfig {
    /// Path to the TOML/JSON node configuration file.
    pub config_path: PathBuf,
    /// Root directory for all node data (store, keys, etc.).
    pub data_dir: PathBuf,
    /// Optional CLI override for checkpoint sync URL.
    pub checkpoint_sync_url: Option<String>,
    /// Optional CLI override for libp2p listen address.
    pub listen_addr: Option<String>,
    /// Optional CLI override for bootnodes.
    pub bootnodes: Option<Vec<String>>,
    /// Optional CLI override for the metrics port.
    pub metrics_port: Option<u16>,
    /// Optional CLI override for the HTTP API port.
    pub api_port: Option<u16>,
    /// Optional CLI override for libp2p node key path.
    pub node_key_path: Option<PathBuf>,
    /// Optional CLI override for validator assignments file.
    pub validators_path: Option<PathBuf>,
    /// Optional CLI override for aggregator mode.
    pub is_aggregator: Option<bool>,
    /// Optional CLI override for attestation committee count.
    pub attestation_committee_count: Option<u64>,
    /// Optional CLI override for validator key directory.
    pub validator_keys_path: Option<PathBuf>,
    /// Optional CLI override for node identifier / validator assignment.
    pub node_id: Option<String>,
    /// Optional CLI override for genesis time.
    pub genesis_time_override: Option<u64>,
}

/// The top-level beacon node: owns consensus state, block storage,
/// fork-choice, and the networking stack.
///
/// # Lifecycle
///
/// 1. [`Node::load`] — reads config, builds genesis state, opens the store,
///    allocates shared state behind `Arc<RwLock<_>>`.
/// 2. [`Node::run`] — starts networking, spawns the gossip-event loop and
///    optional metrics server, then blocks until `ctrl-c` or
///    [`Node::shutdown`] is called.
/// 3. [`Node::shutdown`] — sends a signal through `shutdown_tx` to unblock
///    `run`, which then tears down the networking stack and metrics task.
pub struct Node {
    /// Chain-level configuration (genesis time, etc.).
    config: Config,
    /// Shared mutable consensus state — updated on every block import.
    state: Arc<RwLock<State>>,
    /// Disk-backed block store — persists signed blocks and state snapshots.
    store: Arc<RwLock<FileStore>>,
    /// Fork-choice store — initialized from the local anchor once available.
    fork_choice: Arc<RwLock<Option<ForkChoiceStore>>>,
    /// Attestations received since the last proposal head query.
    pending_attestations: Arc<RwLock<Vec<Attestation>>>,
    /// Individual signed attestations awaiting aggregation (aggregator-only).
    pending_individual_attestations: Arc<RwLock<Vec<SignedAttestation>>>,
    /// Aggregated attestations staged by lifecycle for block production.
    pending_block_attestations: Arc<RwLock<Vec<PendingBlockAttestation>>>,
    /// Root data directory for this node instance.
    data_dir: PathBuf,
    /// Resolved path to the block store directory.
    store_dir: PathBuf,
    /// Active libp2p networking stack; `None` until `run` is called.
    networking: Option<Networking>,
    /// Runtime settings loaded from the config file.
    settings: NodeSettings,
    /// Sender half of the shutdown oneshot; consumed by [`Node::shutdown`].
    shutdown_tx: Option<oneshot::Sender<()>>,
    /// Receiver half of the shutdown oneshot; awaited in [`Node::run`].
    shutdown_rx: oneshot::Receiver<()>,
    /// Handle to the optional Prometheus metrics server task.
    metrics_task: Option<JoinHandle<()>>,
    /// Handle to the optional leanSpec HTTP API server task.
    http_api_task: Option<JoinHandle<()>>,
    /// Handle to the fork-choice lifecycle interval task.
    lifecycle_task: Option<JoinHandle<()>>,
    /// Handle to the local signed-attestation publishing task.
    signing_task: Option<JoinHandle<()>>,
    /// Handle to the local block-production task.
    block_task: Option<JoinHandle<()>>,
    /// Handle to the local aggregation publishing task.
    aggregation_task: Option<JoinHandle<()>>,
    /// Handle to the status/backfill sync task.
    sync_task: Option<JoinHandle<()>>,
    /// Handle to the deferred attestation-gossip retry task.
    deferred_gossip_task: Option<JoinHandle<()>>,
    /// True while the node is actively catching up from peers.
    is_syncing: Arc<AtomicBool>,
    /// Peer-reported head slot currently targeted by the sync loop.
    sync_target_slot: Arc<AtomicU64>,
    /// Number of backfill blocks buffered before import.
    sync_pending_depth: Arc<AtomicU64>,
    /// Shared metrics registry for all spec-defined Prometheus metrics.
    metrics: Arc<MetricsRegistry>,
    /// Validator key cache (loaded from hash-sig files when available, otherwise deterministic devnet).
    devnet_validator_keys: DevnetValidatorKeyCache,
    /// Human-readable source of validator keys for startup logs.
    validator_key_source: String,
    /// Resolved `lean_node_info{name=...}` label.
    metrics_node_name: String,
    /// Resolved `lean_connected_peers{client=...}` label.
    metrics_client_name: String,
}

impl Node {
    /// Load a node from disk, building genesis state and opening the block store.
    ///
    /// Reads `node_config.config_path` to obtain [`Config`] and [`NodeSettings`],
    /// constructs a genesis [`State`], resolves the store directory (relative paths
    /// are joined against `data_dir`), and opens or creates the [`FileStore`].
    ///
    /// Fork-choice starts as `None` and is initialized on the first imported block.
    ///
    /// # Errors
    ///
    /// Returns `Err` if config loading, genesis construction, or store opening fails.
    pub fn load(node_config: NodeConfig) -> Result<Self, String> {
        let (mut config, mut settings) = load_node_settings(&node_config.config_path)?;
        if let Some(url) = node_config.checkpoint_sync_url {
            settings.checkpoint_sync_url = Some(url);
        }
        if let Some(listen_addr) = node_config.listen_addr {
            settings.listen_addr = listen_addr;
        }
        if let Some(bootnodes) = node_config.bootnodes {
            settings.bootnodes = bootnodes;
        }
        if let Some(metrics_port) = node_config.metrics_port {
            if metrics_port == 0 {
                settings.metrics = false;
                settings.metrics_port = 0;
            } else {
                settings.metrics = true;
                settings.metrics_port = metrics_port;
            }
        }
        if let Some(api_port) = node_config.api_port {
            if api_port == 0 {
                settings.http_api = false;
                settings.http_port = 0;
            } else {
                settings.http_api = true;
                settings.http_port = api_port;
            }
        }
        if let Some(node_key_path) = node_config.node_key_path {
            settings.node_key_path = Some(node_key_path.to_string_lossy().into_owned());
        }
        if let Some(attestation_committee_count) = node_config.attestation_committee_count {
            settings.attestation_committee_count = attestation_committee_count;
        }
        if let Some(is_aggregator) = node_config.is_aggregator {
            settings.is_aggregator = is_aggregator;
        }
        let (resolved_local_validator_index, hash_sig_keys_dir_override) =
            resolve_validator_startup_overrides(
                &node_config.config_path,
                &settings,
                node_config.node_id.as_deref(),
                node_config.validator_keys_path.as_deref(),
                node_config.validators_path.as_deref(),
            )?;
        if let Some(node_id) = node_config.node_id.as_ref() {
            settings.metrics_node_name = Some(node_id.clone());
            if let Some(index) = resolved_local_validator_index {
                settings.local_validator_index = index;
            } else {
                warn!(
                    node_id,
                    configured_local_validator_index = settings.local_validator_index,
                    "node-id override did not resolve a validator assignment; keeping configured local_validator_index"
                );
            }
        }
        if let Some(genesis_time_override) = node_config.genesis_time_override {
            config.genesis_time = crate::types::uint::Uint64(genesis_time_override);
        }
        crate::containers::attestation::set_attestation_committee_count(
            settings.attestation_committee_count,
        );
        if settings.is_aggregator {
            crate::crypto::pq::setup_aggregate_prover();
        }
        tracing::info!(
            validator_count = settings.validator_count,
            local_validator_index = settings.local_validator_index,
            is_aggregator = settings.is_aggregator,
            listen_addr = %settings.listen_addr,
            bootnodes = settings.bootnodes.len(),
            checkpoint_sync = settings.checkpoint_sync_url.is_some(),
            "peam startup: settings applied"
        );
        let fallback_config_dir = node_config
            .config_path
            .parent()
            .unwrap_or_else(|| Path::new("."));
        let config_dir = settings
            .validator_config_path
            .as_ref()
            .map(|path| {
                let path = Path::new(path);
                if path.is_absolute() {
                    path.to_path_buf()
                } else {
                    fallback_config_dir.join(path)
                }
            })
            .and_then(|path| path.parent().map(|parent| parent.to_path_buf()))
            .unwrap_or_else(|| fallback_config_dir.to_path_buf());
        let genesis_config_yaml = config_dir.join("config.yaml");
        let expected_genesis_state = if genesis_config_yaml.is_file() {
            tracing::info!(
                path = %genesis_config_yaml.display(),
                "peam startup: loading genesis from config.yaml"
            );
            build_genesis_from_config_yaml_with_override(
                &genesis_config_yaml,
                node_config.genesis_time_override,
            )?
        } else {
            build_genesis_with_validator_count(config.clone(), settings.validator_count)?
        };
        let hash_sig_keys_dir = hash_sig_keys_dir_override;
        let (devnet_validator_keys, validator_key_source) = if hash_sig_keys_dir.is_dir() {
            match build_devnet_pq_validator_keys_from_hash_sig_dir(
                &hash_sig_keys_dir,
                expected_genesis_state.validators.len(),
            ) {
                Ok(keys) => (
                    keys,
                    format!("hash_sig_keys:{}", hash_sig_keys_dir.display()),
                ),
                Err(err) => {
                    warn!(
                        "failed to load validator keys from {}: {}; falling back to deterministic devnet keys",
                        hash_sig_keys_dir.display(),
                        err
                    );
                    (
                        build_devnet_pq_validator_keys(
                            expected_genesis_state.validators.len(),
                        ),
                        "deterministic_devnet".to_string(),
                    )
                }
            }
        } else {
            (
                build_devnet_pq_validator_keys(expected_genesis_state.validators.len()),
                "deterministic_devnet".to_string(),
            )
        };
        tracing::info!(
            source = %validator_key_source,
            "peam startup: validator keys loaded"
        );
        let loaded_keys = devnet_validator_keys.iter().filter(|k| k.is_some()).count();
        tracing::info!(
            loaded_keys,
            total = devnet_validator_keys.len(),
            "peam startup: validator key cache"
        );
        let devnet_validator_keys =
            filter_keys_against_genesis(&expected_genesis_state, devnet_validator_keys);
        if let Some(first) = expected_genesis_state.validators.first() {
            tracing::info!(
                first_validator_pubkey = ?first.attestation_pubkey,
                "peam startup: first validator pubkey"
            );
        }
        let local_validator_index = settings.local_validator_index as usize;
        let Some(expected) = expected_genesis_state
            .validators
            .get(local_validator_index)
        else {
            return Err(format!(
                "local_validator_index {} out of range for {} genesis validators",
                settings.local_validator_index,
                expected_genesis_state.validators.len()
            ));
        };
        let Some(Some(local_key)) = devnet_validator_keys.get(local_validator_index) else {
            return Err(format!(
                "local validator key missing after filtering against genesis (source: {}); \
ensure hash-sig-keys are available or use matching derivation for validator {}",
                validator_key_source, settings.local_validator_index
            ));
        };
        if local_key.attestation_pubkey != expected.attestation_pubkey {
            return Err(format!(
                "local validator pubkey mismatch after filtering (source: {}); \
expected {:?}, got {:?}",
                validator_key_source, expected.attestation_pubkey, local_key.attestation_pubkey
            ));
        }
        let (metrics_node_name, metrics_client_name) =
            resolve_metrics_identity(&node_config.config_path, &settings).unwrap_or_else(|err| {
                warn!(
                    "failed to resolve metrics identity from config: {}; falling back to peam",
                    err
                );
                ("peam".to_string(), "peam".to_string())
            });
        let store_dir = settings
            .storage_dir
            .as_ref()
            .map(PathBuf::from)
            .map(|dir| {
                if dir.is_absolute() {
                    dir
                } else {
                    node_config.data_dir.join(dir)
                }
            })
            .unwrap_or_else(|| node_config.data_dir.join("store"));
        let store = Arc::new(RwLock::new(FileStore::open(&store_dir)?));
        let mut initial_state = expected_genesis_state;
        let mut initial_fork_choice: Option<ForkChoiceStore> = None;
        let store_is_empty = {
            let guard = store.read().expect("store lock");
            guard.canonical_state_rows() == 0
                && guard.canonical_block_rows() == 0
                && guard.pending_block_rows() == 0
                && guard.head().is_none()
        };
        if let Some(url) = settings.checkpoint_sync_url.as_ref() {
            let store_has_data = {
                let guard = store.read().expect("store lock");
                guard.canonical_state_rows() > 0
                    || guard.canonical_block_rows() > 0
                    || guard.pending_block_rows() > 0
                    || guard.head().is_some()
            };
            if store_has_data {
                warn!(
                    checkpoint_sync_url = url,
                    "checkpoint sync requested on non-empty store; overwriting anchor metadata"
                );
            }
            let mut checkpoint_state = fetch_checkpoint_state(url)?;
            verify_checkpoint_state(&checkpoint_state, &initial_state)?;
            if checkpoint_state.latest_block_header.state_root == Bytes32::zero() {
                let mut tmp = checkpoint_state.clone();
                tmp.latest_block_header.state_root = Bytes32::zero();
                let computed_root = Bytes32::from(tmp.hash_tree_root());
                checkpoint_state.latest_block_header.state_root = computed_root;
            }
            {
                let mut guard = store.write().expect("store lock");
                match seed_anchor_store_and_fork_choice(&mut guard, &mut checkpoint_state) {
                    Ok(fc) => initial_fork_choice = Some(fc),
                    Err(err) => {
                        return Err(format!("checkpoint sync fork choice init failed: {err}"));
                    }
                }
            }
            let state_root = checkpoint_state.latest_block_header.state_root;
            let anchor_root = Bytes32::from(build_anchor_block(&checkpoint_state).hash_tree_root());
            tracing::info!(
                checkpoint_sync_url = url,
                checkpoint_slot = checkpoint_state.slot.0.0,
                checkpoint_state_root = ?state_root,
                checkpoint_block_root = ?anchor_root,
                "checkpoint sync applied"
            );
            initial_state = checkpoint_state;
        } else if store_is_empty {
            let mut guard = store.write().expect("store lock");
            match seed_anchor_store_and_fork_choice(&mut guard, &mut initial_state) {
                Ok(fc) => initial_fork_choice = Some(fc),
                Err(err) => return Err(format!("genesis anchor init failed: {err}")),
            }
        }
        let state = Arc::new(RwLock::new(initial_state));
        let fork_choice = Arc::new(RwLock::new(initial_fork_choice));
        let pending_attestations = Arc::new(RwLock::new(Vec::new()));
        let pending_individual_attestations = Arc::new(RwLock::new(Vec::new()));
        let pending_block_attestations = Arc::new(RwLock::new(Vec::new()));
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let metrics = Arc::new(MetricsRegistry::new());
        Ok(Self {
            config,
            state,
            store,
            fork_choice,
            pending_attestations,
            pending_individual_attestations,
            pending_block_attestations,
            data_dir: node_config.data_dir,
            store_dir,
            networking: None,
            settings,
            shutdown_tx: Some(shutdown_tx),
            shutdown_rx,
            metrics_task: None,
            http_api_task: None,
            lifecycle_task: None,
            signing_task: None,
            block_task: None,
            aggregation_task: None,
            sync_task: None,
            deferred_gossip_task: None,
            is_syncing: Arc::new(AtomicBool::new(false)),
            sync_target_slot: Arc::new(AtomicU64::new(0)),
            sync_pending_depth: Arc::new(AtomicU64::new(0)),
            metrics,
            devnet_validator_keys,
            validator_key_source,
            metrics_node_name,
            metrics_client_name,
        })
    }

    /// Start the node and run until shutdown.
    ///
    /// Steps:
    /// 1. Logs startup info (data dir, store dir, genesis time, state root).
    /// 2. Builds [`NetworkingConfig`] from [`NodeSettings`] and starts the
    ///    libp2p stack via [`Networking::start_with_config`].
    /// 3. Dials all configured bootnodes.
    /// 4. Spawns a Tokio task that receives [`NetworkEvent::GossipMessage`]
    ///    events and dispatches them to [`handle_gossip_event`].
    /// 5. Optionally spawns the HTTP API / metrics server.
    /// 6. Waits for either `ctrl-c` or a [`Node::shutdown`] signal.
    /// 7. Gracefully shuts down networking and aborts the metrics task.
    ///
    /// # Errors
    ///
    /// Returns `Err` if any setup step fails (currently infallible after `load`).
    pub async fn run(mut self) -> Result<(), String> {
        let version = format!(
            "peam/v{}/{arch}-{os}",
            env!("CARGO_PKG_VERSION"),
            arch = std::env::consts::ARCH,
            os = std::env::consts::OS
        );
        info!(version = %version, "Starting peam");
        info!(
            node_key = %self
                .settings
                .node_key_path
                .as_deref()
                .unwrap_or("<ephemeral>"),
            "Using libp2p node key"
        );
        info!(
            genesis_time = self.config.genesis_time.0,
            validator_count = self.settings.validator_count,
            "Loaded genesis configuration"
        );
        info!(
            node_id = %self.metrics_node_name,
            index = self.settings.local_validator_index,
            secret_key_source = %self.validator_key_source,
            "Loading validator secret key"
        );
        info!(
            node_id = %self.metrics_node_name,
            count = usize::from(
                self.devnet_validator_keys
                    .get(self.settings.local_validator_index as usize)
                    .is_some_and(|entry| entry.is_some())
            ),
            "Loaded validator secret keys"
        );
        info!("\n{PEAM_ASCII_BANNER}");
        let state_root = self.state.read().expect("state lock").hash_tree_root();
        info!(
            node_id = %self.metrics_node_name,
            data_dir = %self.data_dir_display(),
            store_dir = %self.store_dir_display(),
            genesis_time = self.config.genesis_time.0,
            state_root = ?state_root,
            sync_mode = "blocks_by_root_backfill",
            streaming_sync = false,
            checkpoint_sync = self.settings.checkpoint_sync_url.is_some(),
            http_api = self.settings.http_api,
            metrics = self.settings.metrics,
            metrics_address = %self.settings.metrics_address,
            metrics_port = self.settings.metrics_port,
            http_address = %self.settings.http_address,
            http_port = self.settings.http_port,
            "node startup summary"
        );

        // Default to PQ verification for gossip signatures when validator keys exist.
        let signature_verifier = {
            let state_guard = self.state.read().expect("state lock");
            verifier_from_validators(state_guard.validators.as_slice())
        };
        let reqresp_handler = Arc::new(StoreReqRespHandler::new(
            self.state.clone(),
            self.store.clone(),
        ));
        let slot_clock = spawn_strict_slot_clock(self.config.genesis_time.0);
        let gossip_context = Arc::new(StateGossipContext::with_slot_clock_and_store(
            self.state.clone(),
            slot_clock,
            self.store.clone(),
        ));

        let committee_count = self.settings.attestation_committee_count.max(1);
        let local_subnet = self.settings.local_validator_index % committee_count;
        let (allowed_topics, topic_scores, topic_validators) = filter_topics_for_role(
            &self.settings.allowed_topics,
            &self.settings.topic_scores,
            &self.settings.topic_validators,
            self.settings.is_aggregator,
            local_subnet,
        );
        tracing::info!(
            is_aggregator = self.settings.is_aggregator,
            local_subnet,
            configured_topics = ?self.settings.allowed_topics,
            active_topics = ?allowed_topics,
            "peam networking topics resolved"
        );
        let net_config = NetworkingConfig {
            discovery_interval_secs: self.settings.discovery_interval_secs,
            score_decay_interval_secs: self.settings.score_decay_interval_secs,
            score_decay_amount: self.settings.score_decay_amount,
            ban_threshold: self.settings.ban_threshold,
            bootnodes: self.settings.bootnodes.clone(),
            trusted_peers: self.settings.trusted_peers.clone(),
            listen_addr: self.settings.listen_addr.clone(),
            node_key_path: self.settings.node_key_path.clone(),
            allowed_topics,
            topic_scores,
            topic_validators,
            signature_verifier,
            reqresp_handler,
            gossip_context,
            max_gossip_bytes: self.settings.max_gossip_bytes,
            max_reqresp_bytes: self.settings.max_reqresp_bytes,
        };
        self.networking = Some(Networking::start_with_config(net_config.clone()));
        if let Some(networking) = &self.networking {
            for peer in &net_config.bootnodes {
                networking.add_seed_peer(peer.clone()).await;
            }
        }

        if let Some(networking) = &self.networking {
            let mut rx = networking.events.subscribe();
            let state = self.state.clone();
            let store = self.store.clone();
            let fork_choice = self.fork_choice.clone();
            let pending_attestations = self.pending_attestations.clone();
            let pending_individual_attestations = self.pending_individual_attestations.clone();
            let pending_block_attestations = self.pending_block_attestations.clone();
            let is_aggregator = self.settings.is_aggregator;
            let metrics = self.metrics.clone();
            let deferred_gossip = Arc::new(RwLock::new(Vec::new()));
            let deferred_gossip_rx = deferred_gossip.clone();
            tokio::spawn(async move {
                loop {
                    let event = match rx.recv().await {
                        Ok(event) => event,
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                            warn!("network events channel lagged, skipped {n} events");
                            continue;
                        }
                        Err(err) => {
                            warn!("network events channel closed err={err}");
                            return;
                        }
                    };
                    match event {
                        crate::networking::NetworkEvent::GossipMessage { topic, payload } => {
                            handle_gossip_event(
                                &topic,
                                &payload,
                                &state,
                                &store,
                                &fork_choice,
                                &pending_attestations,
                                &pending_individual_attestations,
                                &pending_block_attestations,
                                is_aggregator,
                                &metrics,
                            );
                        }
                        crate::networking::NetworkEvent::GossipDeferredUnknownRoots {
                            topic,
                            payload,
                        } => {
                            gossip::queue_deferred_unknown_root_gossip(
                                &deferred_gossip_rx,
                                topic,
                                payload,
                            );
                        }
                        _ => {}
                    }
                }
            });

            let sync_rx = networking.events.subscribe();
            self.sync_task = Some(spawn_status_sync_task(
                networking.p2p_sender(),
                networking.peers.clone(),
                sync_rx,
                self.state.clone(),
                self.store.clone(),
                self.fork_choice.clone(),
                self.pending_attestations.clone(),
                self.is_syncing.clone(),
                self.sync_target_slot.clone(),
                self.sync_pending_depth.clone(),
                self.metrics.clone(),
            ));
            self.deferred_gossip_task = Some(gossip::spawn_deferred_gossip_retry_task(
                self.state.clone(),
                self.store.clone(),
                self.fork_choice.clone(),
                self.pending_attestations.clone(),
                self.pending_individual_attestations.clone(),
                self.pending_block_attestations.clone(),
                deferred_gossip,
                net_config.gossip_context.clone(),
                self.settings.is_aggregator,
                self.metrics.clone(),
            ));
        }

        if let Some(networking) = &self.networking {
            let committee_count = self.settings.attestation_committee_count.max(1);
            let local_subnet = self.settings.local_validator_index % committee_count;
            self.metrics
                .is_aggregator
                .store(self.settings.is_aggregator, Ordering::Relaxed);
            self.metrics
                .attestation_committee_count
                .store(committee_count, Ordering::Relaxed);
            self.metrics
                .attestation_committee_subnet
                .store(local_subnet, Ordering::Relaxed);

            let maybe_block_topic = select_block_topic(&net_config.allowed_topics);
            if let Some(block_topic) = maybe_block_topic.clone() {
                self.block_task = spawn_block_production_task(
                    self.config.genesis_time.0,
                    self.settings.local_validator_index as usize,
                    block_topic,
                    networking.p2p_sender(),
                    self.is_syncing.clone(),
                    self.state.clone(),
                    self.store.clone(),
                    self.fork_choice.clone(),
                    self.pending_block_attestations.clone(),
                    self.devnet_validator_keys.clone(),
                    self.metrics.clone(),
                );
            } else {
                warn!("no block topic configured; local block production disabled");
            }

            let maybe_att_topic = select_attestation_topic(
                &self.settings.allowed_topics,
                self.settings.local_validator_index,
                committee_count,
            );
            if let Some(attestation_topic) = maybe_att_topic {
                self.signing_task = spawn_signed_attestation_task(
                    self.config.genesis_time.0,
                    self.settings.local_validator_index as usize,
                    attestation_topic,
                    networking.p2p_sender(),
                    self.is_syncing.clone(),
                    self.state.clone(),
                    self.fork_choice.clone(),
                    self.pending_attestations.clone(),
                    self.pending_individual_attestations.clone(),
                    self.devnet_validator_keys.clone(),
                    self.metrics.clone(),
                    self.settings.is_aggregator,
                );
            } else {
                warn!("no attestation topic configured; local signing task disabled");
            }

            if self.settings.is_aggregator {
                if let Some(aggregation_topic) =
                    select_aggregation_topic(&net_config.allowed_topics)
                {
                    self.aggregation_task = spawn_attestation_aggregation_task(
                        self.config.genesis_time.0,
                        aggregation_topic,
                        networking.p2p_sender(),
                        self.pending_individual_attestations.clone(),
                        self.pending_attestations.clone(),
                        self.pending_block_attestations.clone(),
                        self.devnet_validator_keys.clone(),
                        self.settings.local_validator_index as usize,
                        committee_count,
                        self.metrics.clone(),
                    );
                } else {
                    warn!("no aggregation topic configured; aggregator task disabled");
                }
            }
        }

        self.lifecycle_task = Some(spawn_consensus_lifecycle_task(
            self.config.genesis_time.0,
            self.fork_choice.clone(),
            self.pending_attestations.clone(),
            self.metrics.clone(),
        ));

        let shared_http_bind = self.settings.metrics
            && self.settings.http_api
            && self.settings.metrics_port != 0
            && self.settings.http_port != 0
            && self.settings.metrics_address == self.settings.http_address
            && self.settings.metrics_port == self.settings.http_port;
        if shared_http_bind {
            let bind = format!(
                "{}:{}",
                self.settings.metrics_address, self.settings.metrics_port
            );
            self.metrics_task = Some(spawn_http_server(
                self.state.clone(),
                self.store.clone(),
                self.fork_choice.clone(),
                self.networking.as_ref().map(|n| n.peers.clone()),
                self.is_syncing.clone(),
                self.sync_target_slot.clone(),
                self.sync_pending_depth.clone(),
                self.metrics.clone(),
                self.metrics_node_name.clone(),
                self.metrics_client_name.clone(),
                bind,
                self.settings.metrics,
                self.settings.http_api,
            ));
        } else {
            if self.settings.metrics && self.settings.metrics_port != 0 {
                let bind = format!(
                    "{}:{}",
                    self.settings.metrics_address, self.settings.metrics_port
                );
                self.metrics_task = Some(spawn_http_server(
                    self.state.clone(),
                    self.store.clone(),
                    self.fork_choice.clone(),
                    self.networking.as_ref().map(|n| n.peers.clone()),
                    self.is_syncing.clone(),
                    self.sync_target_slot.clone(),
                    self.sync_pending_depth.clone(),
                    self.metrics.clone(),
                    self.metrics_node_name.clone(),
                    self.metrics_client_name.clone(),
                    bind,
                    true,
                    false,
                ));
            }
            if self.settings.http_api && self.settings.http_port != 0 {
                let bind = format!("{}:{}", self.settings.http_address, self.settings.http_port);
                self.http_api_task = Some(spawn_http_server(
                    self.state.clone(),
                    self.store.clone(),
                    self.fork_choice.clone(),
                    self.networking.as_ref().map(|n| n.peers.clone()),
                    self.is_syncing.clone(),
                    self.sync_target_slot.clone(),
                    self.sync_pending_depth.clone(),
                    self.metrics.clone(),
                    self.metrics_node_name.clone(),
                    self.metrics_client_name.clone(),
                    bind,
                    false,
                    true,
                ));
            }
        }

        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                warn!("ctrl-c received");
            }
            _ = &mut self.shutdown_rx => {
                info!("shutdown requested");
            }
        }

        if let Some(networking) = self.networking.take() {
            networking.shutdown().await;
        }
        if let Some(task) = self.metrics_task.take() {
            task.abort();
        }
        if let Some(task) = self.http_api_task.take() {
            task.abort();
        }
        if let Some(task) = self.lifecycle_task.take() {
            task.abort();
        }
        if let Some(task) = self.signing_task.take() {
            task.abort();
        }
        if let Some(task) = self.block_task.take() {
            task.abort();
        }
        if let Some(task) = self.aggregation_task.take() {
            task.abort();
        }
        if let Some(task) = self.sync_task.take() {
            task.abort();
        }
        if let Some(task) = self.deferred_gossip_task.take() {
            task.abort();
        }
        info!("node stopped");
        Ok(())
    }

    /// Signal the node to stop.
    ///
    /// Sends on the internal shutdown oneshot, unblocking the `select!` in
    /// [`Node::run`]. No-op if called more than once (the sender is consumed
    /// on first call).
    pub fn shutdown(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
    }

    /// Display-friendly representation of `data_dir`.
    fn data_dir_display(&self) -> String {
        self.data_dir.display().to_string()
    }

    /// Display-friendly representation of `store_dir`.
    fn store_dir_display(&self) -> String {
        self.store_dir.display().to_string()
    }
}

#[inline]
fn select_attestation_topic(
    allowed_topics: &[String],
    local_validator_index: u64,
    committee_count: u64,
) -> Option<String> {
    let subnet = if committee_count <= 1 {
        0
    } else {
        local_validator_index % committee_count
    };
    allowed_topics
        .iter()
        .find(|topic| topic.contains(&format!("/attestation_{subnet}/")))
        .cloned()
}

#[inline]
fn select_aggregation_topic(allowed_topics: &[String]) -> Option<String> {
    allowed_topics
        .iter()
        .find(|topic| topic.contains("/aggregation/"))
        .cloned()
}

#[inline]
fn select_block_topic(allowed_topics: &[String]) -> Option<String> {
    allowed_topics
        .iter()
        .find(|topic| topic.contains("/block/"))
        .cloned()
}

#[inline]
fn filter_topics_for_role(
    allowed_topics: &[String],
    topic_scores: &[(String, i64)],
    topic_validators: &[(String, crate::networking::GossipValidatorKind)],
    is_aggregator: bool,
    local_attestation_subnet: u64,
) -> (
    Vec<String>,
    Vec<(String, i64)>,
    Vec<(String, crate::networking::GossipValidatorKind)>,
) {
    if is_aggregator {
        return (
            allowed_topics.to_vec(),
            topic_scores.to_vec(),
            topic_validators.to_vec(),
        );
    }
    let local_attestation_fragment = format!("/attestation_{local_attestation_subnet}/");
    let should_keep = |topic: &str| {
        !topic.contains("/attestation_") || topic.contains(&local_attestation_fragment)
    };
    let allowed = allowed_topics
        .iter()
        .filter(|topic| should_keep(topic))
        .cloned()
        .collect::<Vec<_>>();
    let scores = topic_scores
        .iter()
        .filter(|(topic, _)| should_keep(topic))
        .cloned()
        .collect::<Vec<_>>();
    let validators = topic_validators
        .iter()
        .filter(|(topic, _)| should_keep(topic))
        .cloned()
        .collect::<Vec<_>>();
    (allowed, scores, validators)
}
