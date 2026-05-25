use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::RwLock;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use peam::containers::attestation::{Attestation, AttestationData};
use peam::containers::block::{
    Block, BlockBody, BlockSignatures, BlockWithAttestation, SignedBlockWithAttestation,
};
use peam::containers::checkpoint::Checkpoint;
use peam::containers::state::{State, Validators};
use peam::containers::validator::{Validator, ValidatorIndex};
use peam::fork_choice::ForkChoiceStore;
use peam::metrics::{MetricsRegistry, spawn_http_server};
use peam::slot::Slot;
use peam::ssz::{HashTreeRoot, SszEncode};
use peam::storage::FileStore;
use peam::types::bitlist::BitList;
use peam::types::bytes::{Bytes32, Bytes52, Bytes3112};
use peam::types::collections::SszList;
use peam::types::uint::Uint64;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lean_spec_http_api_smoke() {
    let (temp_dir, bind_addr, server_task, anchor_state, anchor_root) =
        start_test_http_server(true).await;

    let health = http_get(&bind_addr, "/lean/v0/health").await;
    assert!(health.starts_with("HTTP/1.1 200 OK"), "{health}");
    assert!(health.ends_with("ok\n"), "{health}");

    let health_alias = http_get(&bind_addr, "/v0/health").await;
    assert!(
        health_alias.starts_with("HTTP/1.1 200 OK"),
        "{health_alias}"
    );

    let finalized_state = http_get_bytes(&bind_addr, "/lean/v0/states/finalized").await;
    let (status_line, body) = split_http_response(&finalized_state);
    assert_eq!(status_line, "HTTP/1.1 200 OK");
    assert_eq!(body, anchor_state.encode_ssz());

    let justified = http_get(&bind_addr, "/lean/v0/checkpoints/justified").await;
    assert!(justified.starts_with("HTTP/1.1 200 OK"), "{justified}");
    assert!(
        justified.contains("\"slot\":0"),
        "expected justified slot 0 in response: {justified}"
    );
    assert!(
        justified.contains(&format!(
            "\"root\":\"0x{}\"",
            hex_bytes(anchor_root.as_ref())
        )),
        "expected justified root in response: {justified}"
    );

    let fork_choice = http_get(&bind_addr, "/lean/v0/fork_choice").await;
    assert!(fork_choice.starts_with("HTTP/1.1 200 OK"), "{fork_choice}");
    assert!(
        fork_choice.contains(&format!(
            "\"head\":\"0x{}\"",
            hex_bytes(anchor_root.as_ref())
        )),
        "expected head root in response: {fork_choice}"
    );
    assert!(
        fork_choice.contains("\"validator_count\":2"),
        "expected validator count in response: {fork_choice}"
    );

    let missing = http_get(&bind_addr, "/lean/v0/does-not-exist").await;
    assert!(missing.starts_with("HTTP/1.1 404 Not Found"), "{missing}");

    shutdown_test_http_server(temp_dir, server_task).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lean_spec_http_api_uninitialized_fork_choice_smoke() {
    let (temp_dir, bind_addr, server_task, anchor_state, _anchor_root) =
        start_test_http_server(false).await;

    let health = http_get(&bind_addr, "/health").await;
    assert!(health.starts_with("HTTP/1.1 200 OK"), "{health}");

    let finalized_state = http_get_bytes(&bind_addr, "/v0/states/finalized").await;
    let (status_line, body) = split_http_response(&finalized_state);
    assert_eq!(status_line, "HTTP/1.1 200 OK");
    assert_eq!(body, anchor_state.encode_ssz());

    let justified = http_get(&bind_addr, "/v0/checkpoints/justified").await;
    assert!(
        justified.starts_with("HTTP/1.1 503 Service Unavailable"),
        "{justified}"
    );

    let fork_choice = http_get(&bind_addr, "/v0/fork_choice").await;
    assert!(
        fork_choice.starts_with("HTTP/1.1 503 Service Unavailable"),
        "{fork_choice}"
    );

    shutdown_test_http_server(temp_dir, server_task).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lean_spec_http_api_external_process_smoke() {
    let server = start_external_peam_http_server().await;

    assert_external_http_surface(&server.bind_addr).await;

    shutdown_external_peam_http_server(server).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lean_spec_http_api_external_process_restart_smoke() {
    let temp_dir = unique_temp_dir("peam-http-api-external-restart");
    std::fs::create_dir_all(&temp_dir).expect("create restart temp dir");

    let first_server = start_external_peam_http_server_in_dir(temp_dir.clone()).await;
    let first_snapshot = assert_external_http_surface(&first_server.bind_addr).await;
    shutdown_external_peam_http_server_preserve_data(first_server).await;

    let second_server = start_external_peam_http_server_in_dir(temp_dir.clone()).await;
    let second_snapshot = assert_external_http_surface(&second_server.bind_addr).await;
    assert_eq!(
        first_snapshot, second_snapshot,
        "expected black-box HTTP surface to stay stable across restart"
    );
    shutdown_external_peam_http_server(second_server).await;
}

fn build_validators(count: usize) -> Validators {
    let validators = (0..count)
        .map(|index| {
            let seed = (index as u8).wrapping_add(1);
            Validator {
                attestation_pubkey: Bytes52::from([seed; 52]),
                proposal_pubkey: Bytes52::from([seed; 52]),
                index: ValidatorIndex(Uint64(index as u64)),
                balance: Uint64(0),
            }
        })
        .collect::<Vec<_>>();
    Validators::new(validators).expect("validators")
}

fn build_signed_block(
    base_state: &State,
    slot: u64,
    include_attestation: bool,
) -> (SignedBlockWithAttestation, State, Bytes32) {
    let validator_count = base_state.validators.len() as u64;
    let proposer = if validator_count == 0 {
        0
    } else {
        slot % validator_count
    };
    let mut temp = base_state.clone();
    temp.process_slots(Slot(Uint64(slot)))
        .expect("process slots");
    let parent_root = Bytes32::from(temp.latest_block_header.hash_tree_root());
    let attestations = if include_attestation {
        let att = Attestation {
            aggregation_bits: BitList::new(vec![true]).expect("participants"),
            data: AttestationData {
                slot: Slot(Uint64(slot)),
                head: Checkpoint {
                    root: parent_root,
                    slot: Slot(Uint64(slot)),
                },
                target: Checkpoint {
                    root: parent_root,
                    slot: Slot(Uint64(slot)),
                },
                source: Checkpoint {
                    root: Bytes32::zero(),
                    slot: Slot(Uint64(0)),
                },
            },
        };
        SszList::new(vec![att]).expect("attestations")
    } else {
        SszList::new(vec![]).expect("attestations")
    };
    let body = BlockBody { attestations };
    let mut block = Block {
        slot: Slot(Uint64(slot)),
        proposer_index: ValidatorIndex(Uint64(proposer)),
        parent_root,
        state_root: Bytes32::zero(),
        body,
    };
    let mut post = base_state.clone();
    post.process_slots(block.slot).expect("process slots");
    let header = block.header();
    post.process_block_header(header).expect("process header");
    post.process_block_body(&block.body, header.body_root)
        .expect("process body");
    block.state_root = Bytes32::from(post.hash_tree_root());
    post.latest_block_header.state_root = block.state_root;

    let proposer_attestation = Attestation {
        aggregation_bits: BitList::new({
            let mut bits = vec![false; proposer as usize + 1];
            bits[proposer as usize] = true;
            bits
        })
        .expect("participants"),
        data: AttestationData {
            slot: block.slot,
            head: Checkpoint {
                root: parent_root,
                slot: Slot(Uint64(slot)),
            },
            target: Checkpoint {
                root: Bytes32::zero(),
                slot: Slot(Uint64(slot)),
            },
            source: Checkpoint {
                root: Bytes32::zero(),
                slot: Slot(Uint64(0)),
            },
        },
    };
    let message = BlockWithAttestation {
        block,
        proposer_attestation,
    };
    let signature = BlockSignatures {
        attestation_signatures: SszList::new(vec![]).expect("attestation sigs"),
        proposer_signature: Bytes3112::zero(),
    };
    let root = Bytes32::from(message.block.hash_tree_root());
    (
        SignedBlockWithAttestation { message, signature },
        post,
        root,
    )
}

fn available_bind_addr() -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
    let addr = listener.local_addr().expect("local addr");
    drop(listener);
    addr.to_string()
}

fn available_tcp_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral tcp");
    let port = listener.local_addr().expect("local addr").port();
    drop(listener);
    port
}

fn available_udp_port() -> u16 {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind ephemeral udp");
    let port = socket.local_addr().expect("local addr").port();
    drop(socket);
    port
}

fn unique_temp_dir(prefix: &str) -> PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("{prefix}-{nanos}-{counter}"))
}

async fn start_test_http_server(
    with_fork_choice: bool,
) -> (PathBuf, String, tokio::task::JoinHandle<()>, State, Bytes32) {
    let temp_dir = unique_temp_dir("peam-http-api");
    std::fs::create_dir_all(&temp_dir).expect("create temp dir");
    let store = Arc::new(RwLock::new(
        FileStore::open(&temp_dir).expect("open file store"),
    ));

    let validators = build_validators(2);
    let genesis_state = State::generate_genesis(Uint64(0), validators);
    let (anchor_block, anchor_state, anchor_root) = build_signed_block(&genesis_state, 1, false);
    let fork_choice = if with_fork_choice {
        Some(ForkChoiceStore::new(anchor_block, anchor_state.clone()).expect("fork choice"))
    } else {
        None
    };
    let state = Arc::new(RwLock::new(anchor_state.clone()));

    let bind_addr = available_bind_addr();
    let server_task = spawn_http_server(
        state,
        store,
        Arc::new(RwLock::new(fork_choice)),
        None,
        Arc::new(AtomicBool::new(false)),
        Arc::new(AtomicU64::new(0)),
        Arc::new(AtomicU64::new(0)),
        Arc::new(MetricsRegistry::default()),
        "peam-test".to_string(),
        "peam".to_string(),
        bind_addr.clone(),
        false,
        true,
    );

    tokio::time::sleep(Duration::from_millis(50)).await;

    (temp_dir, bind_addr, server_task, anchor_state, anchor_root)
}

struct ExternalPeamServer {
    temp_dir: PathBuf,
    bind_addr: String,
    config_path: PathBuf,
    child: Option<Child>,
}

#[derive(Debug, PartialEq, Eq)]
struct ExternalHttpSnapshot {
    finalized_state: Vec<u8>,
    justified_response: String,
    fork_choice_response: String,
}

async fn start_external_peam_http_server() -> ExternalPeamServer {
    let temp_dir = unique_temp_dir("peam-http-api-external");
    std::fs::create_dir_all(&temp_dir).expect("create external temp dir");
    start_external_peam_http_server_in_dir(temp_dir).await
}

async fn start_external_peam_http_server_in_dir(temp_dir: PathBuf) -> ExternalPeamServer {
    let config_path = temp_dir.join("smoke-config.txt");
    if !config_path.is_file() {
        std::fs::write(
            &config_path,
            "genesis_time=0\nvalidator_count=1\nlocal_validator_index=0\nmetrics=false\nhttp_api=true\n",
        )
        .expect("write smoke config");
    }
    let validator_keys_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/http_smoke/hash-sig-keys");

    let api_port = available_tcp_port();
    let listen_port = available_udp_port();
    let bind_addr = format!("127.0.0.1:{api_port}");
    let listen_addr = format!("/ip4/127.0.0.1/udp/{listen_port}/quic-v1");
    let peam_bin = std::env::var_os("CARGO_BIN_EXE_peam").expect("peam test binary path");

    let child = Command::new(peam_bin)
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .arg("--run")
        .arg("--config")
        .arg(&config_path)
        .arg("--data-dir")
        .arg(&temp_dir)
        .arg("--validator-keys")
        .arg(&validator_keys_dir)
        .arg("--listen")
        .arg(&listen_addr)
        .arg("--api-port")
        .arg(api_port.to_string())
        .arg("--metrics-port")
        .arg("0")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn peam binary");

    let mut server = ExternalPeamServer {
        temp_dir,
        bind_addr,
        config_path,
        child: Some(child),
    };

    wait_for_external_http_ready(&mut server)
        .await
        .unwrap_or_else(|message| panic!("{message}"));

    server
}

async fn shutdown_test_http_server(temp_dir: PathBuf, server_task: tokio::task::JoinHandle<()>) {
    server_task.abort();
    let _ = server_task.await;
    std::fs::remove_dir_all(temp_dir).expect("cleanup temp dir");
}

async fn shutdown_external_peam_http_server(mut server: ExternalPeamServer) {
    if let Some(mut child) = server.child.take() {
        let _ = child.kill();
        let _ = child.wait();
    }
    std::fs::remove_dir_all(server.temp_dir).expect("cleanup external temp dir");
}

async fn shutdown_external_peam_http_server_preserve_data(mut server: ExternalPeamServer) {
    if let Some(mut child) = server.child.take() {
        let _ = child.kill();
        let _ = child.wait();
    }
    assert!(
        server.config_path.is_file(),
        "expected smoke config to remain present for restart"
    );
}

async fn http_get(bind_addr: &str, path: &str) -> String {
    String::from_utf8(http_get_bytes(bind_addr, path).await).expect("utf8 response")
}

async fn http_get_bytes(bind_addr: &str, path: &str) -> Vec<u8> {
    let mut stream = TcpStream::connect(bind_addr)
        .await
        .expect("connect http server");
    let request = format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    stream
        .write_all(request.as_bytes())
        .await
        .expect("write request");
    let mut bytes = Vec::new();
    stream.read_to_end(&mut bytes).await.expect("read response");
    bytes
}

async fn assert_external_http_surface(bind_addr: &str) -> ExternalHttpSnapshot {
    let health = http_get(bind_addr, "/lean/v0/health").await;
    assert!(health.starts_with("HTTP/1.1 200 OK"), "{health}");
    assert!(health.ends_with("ok\n"), "{health}");

    let health_alias = http_get(bind_addr, "/v0/health").await;
    assert!(
        health_alias.starts_with("HTTP/1.1 200 OK"),
        "{health_alias}"
    );

    let fork_choice = http_get(bind_addr, "/lean/v0/fork_choice").await;
    assert!(fork_choice.starts_with("HTTP/1.1 200 OK"), "{fork_choice}");
    assert!(
        fork_choice.contains("\"validator_count\""),
        "expected validator count in response: {fork_choice}"
    );
    assert!(
        fork_choice.contains("\"head\":"),
        "expected head root in response: {fork_choice}"
    );

    let justified = http_get(bind_addr, "/lean/v0/checkpoints/justified").await;
    assert!(justified.starts_with("HTTP/1.1 200 OK"), "{justified}");
    assert!(
        justified.contains("\"slot\":"),
        "expected justified checkpoint payload: {justified}"
    );

    let finalized_state = http_get_bytes(bind_addr, "/lean/v0/states/finalized").await;
    let (status_line, body) = split_http_response(&finalized_state);
    assert_eq!(status_line, "HTTP/1.1 200 OK");
    assert!(
        !body.is_empty(),
        "expected finalized state bytes from external process endpoint"
    );

    ExternalHttpSnapshot {
        finalized_state: body,
        justified_response: justified,
        fork_choice_response: fork_choice,
    }
}

fn split_http_response(bytes: &[u8]) -> (&str, Vec<u8>) {
    let marker = b"\r\n\r\n";
    let split = bytes
        .windows(marker.len())
        .position(|window| window == marker)
        .expect("http body separator");
    let headers = std::str::from_utf8(&bytes[..split]).expect("utf8 headers");
    let status_line = headers.lines().next().expect("status line");
    (status_line, bytes[split + marker.len()..].to_vec())
}

fn hex_bytes(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}

async fn wait_for_external_http_ready(server: &mut ExternalPeamServer) -> Result<(), String> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    let mut last_error = String::new();
    while tokio::time::Instant::now() < deadline {
        let child = server
            .child
            .as_mut()
            .expect("external peam child available while waiting for health");
        if let Some(status) = child.try_wait().map_err(|err| err.to_string())? {
            return Err(external_process_failure(
                server,
                format!("peam exited early with status {status}"),
            )
            .await);
        }

        match http_get_bytes_result(&server.bind_addr, "/lean/v0/states/finalized").await {
            Ok(finalized_state) => {
                let (status_line, body) = split_http_response(&finalized_state);
                if status_line != "HTTP/1.1 200 OK" {
                    last_error = format!(
                        "finalized endpoint not ready yet: {}",
                        String::from_utf8_lossy(&finalized_state)
                    );
                } else if body.is_empty() {
                    last_error = "finalized endpoint returned empty body".to_string();
                } else {
                    match http_get_bytes_result(&server.bind_addr, "/lean/v0/fork_choice").await {
                        Ok(fork_choice_response) => {
                            let (fork_choice_status, _) =
                                split_http_response(&fork_choice_response);
                            if fork_choice_status == "HTTP/1.1 200 OK" {
                                return Ok(());
                            }
                            last_error = format!(
                                "fork_choice endpoint not ready yet: {}",
                                String::from_utf8_lossy(&fork_choice_response)
                            );
                        }
                        Err(err) => {
                            last_error = format!("fork_choice request failed: {err}");
                        }
                    }
                }
            }
            Err(err) => {
                last_error = format!("finalized request failed: {err}");
            }
        }

        if last_error.is_empty() {
            match TcpStream::connect(&server.bind_addr).await {
                Ok(mut stream) => {
                    let request = b"GET /lean/v0/health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
                    if let Err(err) = stream.write_all(request).await {
                        last_error = format!("write request failed: {err}");
                    } else {
                        let mut bytes = Vec::new();
                        match stream.read_to_end(&mut bytes).await {
                            Ok(_) => {
                                let response = String::from_utf8_lossy(&bytes);
                                if response.starts_with("HTTP/1.1 200 OK") {
                                    return Ok(());
                                }
                                last_error = format!("unexpected health response: {response}");
                            }
                            Err(err) => {
                                last_error = format!("read response failed: {err}");
                            }
                        }
                    }
                }
                Err(err) => {
                    last_error = err.to_string();
                }
            }
        }

        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    Err(external_process_failure(
        server,
        format!(
            "timed out waiting for peam HTTP surface on {}; last error: {}",
            server.bind_addr, last_error
        ),
    )
    .await)
}

async fn http_get_bytes_result(bind_addr: &str, path: &str) -> Result<Vec<u8>, String> {
    match TcpStream::connect(bind_addr).await {
        Ok(mut stream) => {
            let request =
                format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
            stream
                .write_all(request.as_bytes())
                .await
                .map_err(|err| format!("write request failed: {err}"))?;
            let mut bytes = Vec::new();
            stream
                .read_to_end(&mut bytes)
                .await
                .map_err(|err| format!("read response failed: {err}"))?;
            Ok(bytes)
        }
        Err(err) => Err(err.to_string()),
    }
}

async fn external_process_failure(server: &mut ExternalPeamServer, context: String) -> String {
    let output = if let Some(mut child) = server.child.take() {
        let _ = child.kill();
        child.wait_with_output().ok()
    } else {
        None
    };
    let _ = std::fs::remove_dir_all(&server.temp_dir);
    match output {
        Some(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            format!("{context}\nstdout:\n{stdout}\nstderr:\n{stderr}")
        }
        None => context,
    }
}
