use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tracing::{info, warn};

use crate::containers::state::State;
use crate::fork_choice::ForkChoiceStore;
use crate::networking::peer_manager::PeerManager;
use crate::storage::FileStore;

#[inline]
pub fn spawn_metrics_server(
    state: Arc<RwLock<State>>,
    store: Arc<RwLock<FileStore>>,
    fork_choice: Arc<RwLock<Option<ForkChoiceStore>>>,
    peers: Option<PeerManager>,
    bind_addr: String,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let listener = match TcpListener::bind(&bind_addr).await {
            Ok(listener) => listener,
            Err(err) => {
                warn!("metrics bind failed on {}: {}", bind_addr, err);
                return;
            }
        };
        info!("metrics listening on {}", bind_addr);

        loop {
            let (mut stream, _peer) = match listener.accept().await {
                Ok(v) => v,
                Err(err) => {
                    warn!("metrics accept failed: {}", err);
                    continue;
                }
            };

            let body = {
                let state_guard = state.read().expect("state lock");
                let store_guard = store.read().expect("store lock");
                let fc_guard = fork_choice.read().expect("fork choice lock");
                let peer_count = peers.as_ref().map(|p| p.peer_count()).unwrap_or(0);
                render_metrics(&state_guard, &store_guard, &fc_guard, peer_count)
            };

            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );

            if let Err(err) = stream.write_all(response.as_bytes()).await {
                warn!("metrics write failed: {}", err);
            }
            let _ = stream.shutdown().await;
        }
    })
}

fn render_metrics(
    state: &State,
    store: &FileStore,
    fork_choice: &Option<ForkChoiceStore>,
    peer_count: usize,
) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let (
        head_slot,
        justified_slot,
        finalized_slot,
        previous_justified_slot,
        active_validators,
        reorgs_total,
    ) = match fork_choice {
        Some(fc) => (
            fc.head_slot(),
            fc.latest_justified().slot.0.0,
            fc.latest_finalized().slot.0.0,
            fc.previous_justified().slot.0.0,
            fc.validator_count(),
            fc.reorgs_total(),
        ),
        None => (
            state.slot.0.0,
            state.latest_justified.slot.0.0,
            state.latest_finalized.slot.0.0,
            state.latest_justified.slot.0.0,
            state.validators.data.len(),
            0u64,
        ),
    };

    format!(
        "# TYPE lean_node_time_seconds gauge\nlean_node_time_seconds {now}\n\
         # TYPE lean_state_slot gauge\nlean_state_slot {}\n\
         # TYPE lean_head_slot gauge\nlean_head_slot {head_slot}\n\
         # TYPE lean_justified_slot gauge\nlean_justified_slot {justified_slot}\n\
         # TYPE lean_finalized_slot gauge\nlean_finalized_slot {finalized_slot}\n\
         # TYPE lean_previous_justified_slot gauge\nlean_previous_justified_slot {previous_justified_slot}\n\
         # TYPE lean_current_active_validators gauge\nlean_current_active_validators {active_validators}\n\
         # TYPE lean_reorgs_total counter\nlean_reorgs_total {reorgs_total}\n\
         # TYPE lean_processed_deposits_total gauge\nlean_processed_deposits_total 0\n\
         # TYPE libp2p_peers gauge\nlibp2p_peers {peer_count}\n\
         # TYPE lean_storage_canonical_state_rows gauge\nlean_storage_canonical_state_rows {}\n\
         # TYPE lean_storage_canonical_block_rows gauge\nlean_storage_canonical_block_rows {}\n\
         # TYPE lean_storage_pending_block_rows gauge\nlean_storage_pending_block_rows {}\n",
        state.slot.0.0,
        store.canonical_state_rows(),
        store.canonical_block_rows(),
        store.pending_block_rows(),
    )
}
