use std::path::PathBuf;

use tokio::task::JoinHandle;
use tokio::sync::oneshot;
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
use crate::ssz::HashTreeRoot;
use crate::storage::{FileStore, Store};
use crate::types::bitlist::BitList;
use crate::types::bytes::Bytes32;
use libp2p::gossipsub::TopicHash;
use std::sync::{Arc, RwLock};

#[derive(Clone, Debug)]
pub struct NodeConfig {
    pub config_path: PathBuf,
    pub data_dir: PathBuf,
}

pub struct Node {
    config: Config,
    state: Arc<RwLock<State>>,
    store: Arc<RwLock<FileStore>>,
    fork_choice: Arc<RwLock<Option<ForkChoiceStore>>>,
    data_dir: PathBuf,
    store_dir: PathBuf,
    networking: Option<Networking>,
    settings: NodeSettings,
    shutdown_tx: Option<oneshot::Sender<()>>,
    shutdown_rx: oneshot::Receiver<()>,
    metrics_task: Option<JoinHandle<()>>,
}

pub fn handle_gossip_event<S: Store + Send + Sync + 'static>(
    topic: &str,
    payload: &[u8],
    state: &Arc<RwLock<State>>,
    store: &Arc<RwLock<S>>,
    fork_choice: &Arc<RwLock<Option<ForkChoiceStore>>>,
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
                let mut fc = fork_choice.write().expect("fork choice lock");
                if let Some(fc) = fc.as_mut() {
                    fc.on_attestation(&aggregated);
                }
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
                let mut fc = fork_choice.write().expect("fork choice lock");
                if let Some(fc) = fc.as_mut() {
                    fc.on_attestation(&aggregated);
                }
            }
        }
    }
}

impl Node {
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
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        Ok(Self {
            config,
            state,
            store,
            fork_choice,
            data_dir: node_config.data_dir,
            store_dir,
            networking: None,
            settings,
            shutdown_tx: Some(shutdown_tx),
            shutdown_rx,
            metrics_task: None,
        })
    }

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
        let gossip_context = Arc::new(StateGossipContext::new(self.state.clone()));

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
            tokio::spawn(async move {
                loop {
                    let Ok(event) = rx.recv().await else { continue };
                    if let crate::networking::NetworkEvent::GossipMessage { topic, payload } = event
                    {
                        handle_gossip_event(&topic, &payload, &state, &store, &fork_choice);
                    }
                }
            });
        }

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
        info!("node stopped");
        Ok(())
    }

    pub fn shutdown(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
    }

    fn data_dir_display(&self) -> String {
        self.data_dir.display().to_string()
    }

    fn store_dir_display(&self) -> String {
        self.store_dir.display().to_string()
    }
}
