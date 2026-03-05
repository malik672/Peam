mod gossip;
mod head;
mod tasks;

pub use gossip::handle_gossip_event;
pub use head::proposal_head_from_pending;

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64};
use std::sync::{Arc, RwLock};

use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tracing::{info, warn};

use crate::app::{NodeSettings, build_genesis_with_validator_count, load_node_settings};
use crate::containers::attestation::Attestation;
use crate::containers::config::Config;
use crate::containers::state::State;
use crate::fork_choice::ForkChoiceStore;
use crate::metrics::{MetricsRegistry, spawn_metrics_server};
use crate::networking::{Networking, NetworkingConfig, StateGossipContext, StoreReqRespHandler};
use crate::ssz::HashTreeRoot;
use crate::storage::FileStore;

use tasks::{
    apply_devnet_pq_validator_pubkeys, spawn_block_production_task, spawn_consensus_lifecycle_task,
    spawn_signed_attestation_task, spawn_status_sync_task, spawn_strict_slot_clock,
};

/// Filesystem paths used to initialize a [`Node`].
#[derive(Clone, Debug)]
pub struct NodeConfig {
    /// Path to the TOML/JSON node configuration file.
    pub config_path: PathBuf,
    /// Root directory for all node data (store, keys, etc.).
    pub data_dir: PathBuf,
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
    /// Fork-choice store — `None` until the first valid block is imported.
    fork_choice: Arc<RwLock<Option<ForkChoiceStore>>>,
    /// Attestations received since the last proposal head query.
    pending_attestations: Arc<RwLock<Vec<Attestation>>>,
    /// Aggregated attestations staged by lifecycle for block production.
    pending_block_attestations: Arc<RwLock<Vec<Attestation>>>,
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
    /// Handle to the fork-choice lifecycle interval task.
    lifecycle_task: Option<JoinHandle<()>>,
    /// Handle to the local signed-attestation publishing task.
    signing_task: Option<JoinHandle<()>>,
    /// Handle to the local block-production task.
    block_task: Option<JoinHandle<()>>,
    /// Handle to the status/backfill sync task.
    sync_task: Option<JoinHandle<()>>,
    /// True while the node is actively catching up from peers.
    is_syncing: Arc<AtomicBool>,
    /// Peer-reported head slot currently targeted by the sync loop.
    sync_target_slot: Arc<AtomicU64>,
    /// Number of backfill blocks buffered before import.
    sync_pending_depth: Arc<AtomicU64>,
    /// Shared metrics registry for all spec-defined Prometheus metrics.
    metrics: Arc<MetricsRegistry>,
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
        let (config, settings) = load_node_settings(&node_config.config_path)?;
        let mut genesis_state =
            build_genesis_with_validator_count(config.clone(), settings.validator_count)?;
        apply_devnet_pq_validator_pubkeys(&mut genesis_state);
        let state = Arc::new(RwLock::new(genesis_state));
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
        let fork_choice = Arc::new(RwLock::new(None));
        let pending_attestations = Arc::new(RwLock::new(Vec::new()));
        let pending_block_attestations = Arc::new(RwLock::new(Vec::new()));
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let metrics = Arc::new(MetricsRegistry::new());
        Ok(Self {
            config,
            state,
            store,
            fork_choice,
            pending_attestations,
            pending_block_attestations,
            data_dir: node_config.data_dir,
            store_dir,
            networking: None,
            settings,
            shutdown_tx: Some(shutdown_tx),
            shutdown_rx,
            metrics_task: None,
            lifecycle_task: None,
            signing_task: None,
            block_task: None,
            sync_task: None,
            is_syncing: Arc::new(AtomicBool::new(false)),
            sync_target_slot: Arc::new(AtomicU64::new(0)),
            sync_pending_depth: Arc::new(AtomicU64::new(0)),
            metrics,
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
    /// 5. Optionally spawns a Prometheus metrics server.
    /// 6. Waits for either `ctrl-c` or a [`Node::shutdown`] signal.
    /// 7. Gracefully shuts down networking and aborts the metrics task.
    ///
    /// # Errors
    ///
    /// Returns `Err` if any setup step fails (currently infallible after `load`).
    pub async fn run(mut self) -> Result<(), String> {
        info!("node starting");
        info!("data_dir={}", self.data_dir_display());
        info!("store_dir={}", self.store_dir_display());
        info!("genesis_time={}", self.config.genesis_time.0);
        let state_root = self.state.read().expect("state lock").hash_tree_root();
        info!("state_root={:?}", state_root);

        // Devnet interop default: do structural/context validation for gossip,
        // then enforce structure again at block import.
        let signature_verifier = Arc::new(crate::networking::NoopGossipVerifier);
        let reqresp_handler = Arc::new(StoreReqRespHandler::new(
            self.state.clone(),
            self.store.clone(),
        ));
        let slot_clock = spawn_strict_slot_clock(self.config.genesis_time.0);
        let gossip_context = Arc::new(StateGossipContext::with_slot_clock(
            self.state.clone(),
            slot_clock,
        ));

        let net_config = NetworkingConfig {
            discovery_interval_secs: self.settings.discovery_interval_secs,
            score_decay_interval_secs: self.settings.score_decay_interval_secs,
            score_decay_amount: self.settings.score_decay_amount,
            ban_threshold: self.settings.ban_threshold,
            bootnodes: self.settings.bootnodes.clone(),
            trusted_peers: self.settings.trusted_peers.clone(),
            listen_addr: "/ip4/0.0.0.0/udp/9000/quic-v1".to_string(),
            allowed_topics: self.settings.allowed_topics.clone(),
            topic_scores: self.settings.topic_scores.clone(),
            topic_validators: self.settings.topic_validators.clone(),
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
            let metrics = self.metrics.clone();
            tokio::spawn(async move {
                loop {
                    let Ok(event) = rx.recv().await else { continue };
                    if let crate::networking::NetworkEvent::GossipMessage { topic, payload } = event
                    {
                        handle_gossip_event(
                            &topic,
                            &payload,
                            &state,
                            &store,
                            &fork_choice,
                            &pending_attestations,
                            &metrics,
                        );
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
                self.is_syncing.clone(),
                self.sync_target_slot.clone(),
                self.sync_pending_depth.clone(),
                self.metrics.clone(),
            ));
        }

        if let Some(networking) = &self.networking {
            let maybe_block_topic = self
                .settings
                .allowed_topics
                .iter()
                .find(|topic| topic.contains("block"))
                .cloned();
            if let Some(block_topic) = maybe_block_topic {
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
                    self.metrics.clone(),
                );
            } else {
                warn!("no block topic configured; local block production disabled");
            }

            let maybe_att_topic = self
                .settings
                .allowed_topics
                .iter()
                .find(|topic| topic.contains("attestation"))
                .cloned();
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
                    self.metrics.clone(),
                );
            } else {
                warn!("no attestation topic configured; local signing task disabled");
            }
        }

        self.lifecycle_task = Some(spawn_consensus_lifecycle_task(
            self.config.genesis_time.0,
            self.fork_choice.clone(),
            self.pending_attestations.clone(),
            self.pending_block_attestations.clone(),
            self.metrics.clone(),
        ));

        if self.settings.metrics {
            let bind = format!(
                "{}:{}",
                self.settings.metrics_address, self.settings.metrics_port
            );
            self.metrics_task = Some(spawn_metrics_server(
                self.state.clone(),
                self.store.clone(),
                self.fork_choice.clone(),
                self.networking.as_ref().map(|n| n.peers.clone()),
                self.is_syncing.clone(),
                self.sync_target_slot.clone(),
                self.sync_pending_depth.clone(),
                self.metrics.clone(),
                bind,
            ));
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
        if let Some(task) = self.lifecycle_task.take() {
            task.abort();
        }
        if let Some(task) = self.signing_task.take() {
            task.abort();
        }
        if let Some(task) = self.block_task.take() {
            task.abort();
        }
        if let Some(task) = self.sync_task.take() {
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
