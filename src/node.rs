use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tokio::time::MissedTickBehavior;
use tracing::{info, warn};

use crate::app::{NodeSettings, build_genesis, load_node_settings};
use crate::containers::attestation::{Attestation, VALIDATOR_REGISTRY_LIMIT};
use crate::containers::config::Config;
use crate::containers::state::State;
use crate::fork_choice::ForkChoiceStore;
use crate::metrics::spawn_metrics_server;
use crate::networking::gossipsub::lean::message::LeanGossipsubMessage;
use crate::networking::{
    Networking, NetworkingConfig, StateGossipContext, StoreReqRespHandler, verifier_from_validators,
};
use crate::slot::{
    ACCEPTANCE_INTERVAL_INDEX, INTERVALS_PER_SLOT, SAFE_TARGET_INTERVAL_INDEX, SLOT_DURATION_SECS,
    interval_index_from_unix_millis, next_slot_boundary_delay, slot_index_from_unix_millis,
    unix_now_millis,
};
use crate::ssz::HashTreeRoot;
use crate::storage::{FileStore, Store};
use crate::types::bitlist::BitList;
use crate::types::bytes::Bytes32;
use libp2p::gossipsub::TopicHash;
use std::sync::{Arc, RwLock};

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
}

/// Drain all pending attestations into the fork-choice store and return the
/// current proposal head root.
///
/// Takes a write lock on `pending_attestations`, drains the buffer, then takes
/// a write lock on `fork_choice` and calls
/// [`ForkChoiceStore::get_proposal_head_with_pending`].
///
/// Returns `None` if fork-choice has not yet been initialized (i.e. no block
/// has been imported yet).
pub fn proposal_head_from_pending(
    fork_choice: &Arc<RwLock<Option<ForkChoiceStore>>>,
    pending_attestations: &Arc<RwLock<Vec<Attestation>>>,
) -> Option<Bytes32> {
    let drained = {
        let mut pending = pending_attestations
            .write()
            .expect("pending attestations lock");
        pending.drain(..).collect::<Vec<_>>()
    };
    let aggregated = aggregate_attestations(drained);
    let mut fc = fork_choice.write().expect("fork choice lock");
    let fc = fc.as_mut()?;
    Some(fc.get_proposal_head_with_pending(aggregated.iter()))
}

/// Merge attestations with identical `AttestationData` using bitwise OR over
/// participant sets, then order by descending participant count.
fn aggregate_attestations(attestations: Vec<Attestation>) -> Vec<Attestation> {
    let mut grouped: HashMap<[u8; 32], Attestation> = HashMap::new();
    for attestation in attestations {
        let key = attestation.data.hash_tree_root();
        if let Some(existing) = grouped.get_mut(&key) {
            merge_aggregation_bits(
                &mut existing.aggregation_bits,
                &attestation.aggregation_bits,
            );
        } else {
            grouped.insert(key, attestation);
        }
    }
    let mut out = grouped.into_values().collect::<Vec<_>>();
    out.sort_by(|a, b| {
        participant_count(&b.aggregation_bits).cmp(&participant_count(&a.aggregation_bits))
    });
    out
}

#[inline]
fn participant_count(
    bits: &BitList<{ crate::containers::attestation::VALIDATOR_REGISTRY_LIMIT }>,
) -> usize {
    let mut count = 0usize;
    let len = bits.len();
    for i in 0..len {
        let byte = i / 8;
        let bit = i % 8;
        if byte >= bits.data.len() {
            break;
        }
        if (bits.data[byte] & (1u8 << bit)) != 0 {
            count += 1;
        }
    }
    count
}

fn merge_aggregation_bits(
    dst: &mut BitList<{ crate::containers::attestation::VALIDATOR_REGISTRY_LIMIT }>,
    src: &BitList<{ crate::containers::attestation::VALIDATOR_REGISTRY_LIMIT }>,
) {
    let target_len = dst.len.max(src.len);
    let target_bytes = target_len.div_ceil(8);
    if dst.data.len() < target_bytes {
        dst.data.resize(target_bytes, 0);
    }
    for i in 0..src.data.len() {
        if i < dst.data.len() {
            dst.data[i] |= src.data[i];
        }
    }
    dst.len = target_len;
}

#[inline]
fn spawn_strict_slot_clock(genesis_time_secs: u64) -> Arc<AtomicU64> {
    let now = unix_now_millis().unwrap_or(0);
    let initial_slot = slot_index_from_unix_millis(genesis_time_secs, now);
    let delay = next_slot_boundary_delay(genesis_time_secs, now);
    let slot_clock = Arc::new(AtomicU64::new(initial_slot));
    let slot_clock_task = Arc::clone(&slot_clock);
    tokio::spawn(async move {
        let start = tokio::time::Instant::now() + delay;
        let mut ticker = tokio::time::interval_at(start, Duration::from_secs(SLOT_DURATION_SECS));
        ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
        loop {
            ticker.tick().await;
            let Some(now_millis) = unix_now_millis() else {
                continue;
            };
            let slot = slot_index_from_unix_millis(genesis_time_secs, now_millis);
            slot_clock_task.store(slot, Ordering::Relaxed);
        }
    });
    slot_clock
}

#[inline]
fn spawn_consensus_lifecycle_task(
    genesis_time_secs: u64,
    fork_choice: Arc<RwLock<Option<ForkChoiceStore>>>,
    pending_attestations: Arc<RwLock<Vec<Attestation>>>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let interval_millis = ((SLOT_DURATION_SECS * 1_000) / INTERVALS_PER_SLOT).max(1);
        let mut ticker = tokio::time::interval(Duration::from_millis(interval_millis));
        ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
        loop {
            ticker.tick().await;
            let Some(now_millis) = unix_now_millis() else {
                continue;
            };
            let interval = interval_index_from_unix_millis(genesis_time_secs, now_millis);
            let drained = {
                let mut pending = pending_attestations
                    .write()
                    .expect("pending attestations lock");
                pending.drain(..).collect::<Vec<_>>()
            };
            let aggregated = aggregate_attestations(drained);
            let mut fc_guard = fork_choice.write().expect("fork choice lock");
            let Some(fc) = fc_guard.as_mut() else {
                continue;
            };
            for attestation in &aggregated {
                fc.on_attestation(attestation);
            }
            if interval == SAFE_TARGET_INTERVAL_INDEX {
                fc.update_safe_target();
            }
            if interval == ACCEPTANCE_INTERVAL_INDEX {
                fc.accept_new_votes();
            }
        }
    })
}

/// Decode and dispatch a single gossipsub message, updating shared state.
///
/// Deserializes `payload` according to `topic` into a [`LeanGossipsubMessage`],
/// then branches on the message type:
///
/// - **Block** — acquires write locks on `state` and `store`, imports the block
///   via `Store::put_signed_block`, then either initializes fork-choice (if not
///   yet set) or calls `ForkChoiceStore::on_block`. Silently ignored on
///   decode or import failure.
///
/// - **Attestation / AttestationSubnet** — reconstructs a single-validator
///   [`Attestation`] from the `SignedAttestation`, bounds-checks the validator
///   index, and appends it to `pending_attestations`. A separate lifecycle task
///   promotes these votes into fork-choice at interval boundaries.
///   Silently ignored if the validator index is out of range or the bitlist
///   construction fails.
pub fn handle_gossip_event<S: Store + Send + Sync + 'static>(
    topic: &str,
    payload: &[u8],
    state: &Arc<RwLock<State>>,
    store: &Arc<RwLock<S>>,
    fork_choice: &Arc<RwLock<Option<ForkChoiceStore>>>,
    pending_attestations: &Arc<RwLock<Vec<Attestation>>>,
) {
    let topic_hash = TopicHash::from_raw(topic.to_string());
    let msg = match LeanGossipsubMessage::decode(&topic_hash, payload) {
        Ok(msg) => msg,
        Err(_) => return,
    };
    match msg {
        LeanGossipsubMessage::Block(block) => {
            let signed = block.block.clone();
            let root = Bytes32::from(signed.message.block.hash_tree_root());
            let mut state_guard = state.write().expect("state lock");
            let mut store_guard = store.write().expect("store lock");
            if store_guard
                .put_signed_block(root, signed.clone(), &mut state_guard)
                .is_ok()
            {
                let mut fc = fork_choice.write().expect("fork choice lock");
                if fc.is_none() {
                    if let Ok(new_fc) = ForkChoiceStore::new(signed.clone(), state_guard.clone()) {
                        *fc = Some(new_fc);
                    }
                } else if let Some(fc) = fc.as_mut() {
                    let _ = fc.on_block(signed.clone(), state_guard.clone());
                }
            }
        }
        LeanGossipsubMessage::Attestation(att) => {
            let att = &att.attestation;
            let idx = att.validator_id.0 as usize;
            if idx >= VALIDATOR_REGISTRY_LIMIT {
                return;
            }
            let mut bits = vec![false; idx + 1];
            bits[idx] = true;
            if let Ok(bitlist) = BitList::new(bits) {
                let aggregated = Attestation {
                    aggregation_bits: bitlist,
                    data: att.message.clone(),
                };
                pending_attestations
                    .write()
                    .expect("pending attestations lock")
                    .push(aggregated.clone());
            }
        }
        LeanGossipsubMessage::AttestationSubnet { attestation, .. } => {
            let att = &attestation.attestation;
            let idx = att.validator_id.0 as usize;
            if idx >= VALIDATOR_REGISTRY_LIMIT {
                return;
            }
            let mut bits = vec![false; idx + 1];
            bits[idx] = true;
            if let Ok(bitlist) = BitList::new(bits) {
                let aggregated = Attestation {
                    aggregation_bits: bitlist,
                    data: att.message.clone(),
                };
                pending_attestations
                    .write()
                    .expect("pending attestations lock")
                    .push(aggregated.clone());
            }
        }
    }
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
        let state = Arc::new(RwLock::new(build_genesis(config.clone())?));
        let store_dir = settings
            .storage_dir
            .as_ref()
            .map(|dir| PathBuf::from(dir))
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
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        Ok(Self {
            config,
            state,
            store,
            fork_choice,
            pending_attestations,
            data_dir: node_config.data_dir,
            store_dir,
            networking: None,
            settings,
            shutdown_tx: Some(shutdown_tx),
            shutdown_rx,
            metrics_task: None,
            lifecycle_task: None,
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

        let signature_verifier = {
            let state = self.state.read().expect("state lock");
            verifier_from_validators(&state.validators.data)
        };
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
                        );
                    }
                }
            });
        }

        self.lifecycle_task = Some(spawn_consensus_lifecycle_task(
            self.config.genesis_time.0,
            self.fork_choice.clone(),
            self.pending_attestations.clone(),
        ));

        if self.settings.metrics {
            let bind = format!(
                "{}:{}",
                self.settings.metrics_address, self.settings.metrics_port
            );
            self.metrics_task = Some(spawn_metrics_server(
                self.state.clone(),
                self.store.clone(),
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
