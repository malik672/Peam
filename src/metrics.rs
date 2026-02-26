use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tracing::{info, warn};

use crate::containers::state::State;
use crate::storage::FileStore;

pub fn spawn_metrics_server(
    state: Arc<RwLock<State>>,
    store: Arc<RwLock<FileStore>>,
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
                render_metrics(&state_guard, &store_guard)
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

fn render_metrics(state: &State, store: &FileStore) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    format!(
        "# TYPE lean_node_time_seconds gauge\nlean_node_time_seconds {now}\n\
# TYPE lean_state_slot gauge\nlean_state_slot {}\n\
# TYPE lean_latest_justified_slot gauge\nlean_latest_justified_slot {}\n\
# TYPE lean_latest_finalized_slot gauge\nlean_latest_finalized_slot {}\n\
# TYPE lean_storage_canonical_state_rows gauge\nlean_storage_canonical_state_rows {}\n\
# TYPE lean_storage_canonical_block_rows gauge\nlean_storage_canonical_block_rows {}\n\
# TYPE lean_storage_pending_block_rows gauge\nlean_storage_pending_block_rows {}\n",
        state.slot.0.0,
        state.latest_justified.slot.0.0,
        state.latest_finalized.slot.0.0,
        store.canonical_state_rows(),
        store.canonical_block_rows(),
        store.pending_block_rows(),
    )
}
