use std::path::PathBuf;

use tokio::sync::oneshot;
use tracing::{info, warn};

use crate::app::{build_genesis, load_node_settings, NodeSettings};
use crate::containers::config::Config;
use crate::containers::state::State;
use crate::networking::{
    Networking, NetworkingConfig, StoreReqRespHandler, StateGossipContext,
    verifier_from_validators,
};
use crate::storage::MemoryStore;
use crate::ssz::HashTreeRoot;
use std::sync::{Arc, RwLock};

#[derive(Clone, Debug)]
pub struct NodeConfig {
    pub config_path: PathBuf,
    pub data_dir: PathBuf,
}

pub struct Node {
    config: Config,
    state: Arc<RwLock<State>>,
    store: Arc<RwLock<MemoryStore>>,
    data_dir: PathBuf,
    networking: Option<Networking>,
    settings: NodeSettings,
    shutdown_tx: Option<oneshot::Sender<()>>,
    shutdown_rx: oneshot::Receiver<()>,
}

impl Node {
    pub fn load(node_config: NodeConfig) -> Result<Self, String> {
        let (config, settings) = load_node_settings(&node_config.config_path)?;
        let state = Arc::new(RwLock::new(build_genesis(config.clone())?));
        let store = Arc::new(RwLock::new(MemoryStore::new()));
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        Ok(Self {
            config,
            state,
            store,
            data_dir: node_config.data_dir,
            networking: None,
            settings,
            shutdown_tx: Some(shutdown_tx),
            shutdown_rx,
        })
    }

    pub async fn run(mut self) -> Result<(), String> {
        info!("node starting");
        info!("data_dir={}", self.data_dir_display());
        info!("genesis_time={}", self.config.genesis_time.0);
        let state_root = self
            .state
            .read()
            .expect("state lock")
            .hash_tree_root();
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
}
