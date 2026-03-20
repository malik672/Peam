use std::env;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use peam::app::{build_genesis, build_genesis_from_config_yaml_with_override, load_config};
use peam::containers::config::Config;
use peam::node::{Node, NodeConfig};
use peam::ssz::HashTreeRoot;
use peam::types::uint::Uint64;

#[cfg(all(
    any(target_os = "linux", target_os = "macos"),
    not(target_env = "msvc")
))]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

fn print_usage() {
    eprintln!("Usage:");
    eprintln!("  peam --config <path>");
    eprintln!("  peam --genesis <path>");
    eprintln!("  peam --genesis-time <u64>");
    eprintln!("  peam --run --config <path> --data-dir <path> [options]");
    eprintln!("Options:");
    eprintln!("  --genesis <path>              leanSpec-style alias for genesis/config path");
    eprintln!("  --checkpoint-sync-url <url>   Fetch finalized state for checkpoint sync");
    eprintln!("  --listen <multiaddr>          Override listen address");
    eprintln!("  --bootnode <multiaddr>        Add a bootnode (repeatable)");
    eprintln!("  --validator-keys <path>       Override validator key directory");
    eprintln!("  --node-id <name>              Override node identifier / validator assignment");
    eprintln!("  --api-port <port>             Override HTTP API port");
    eprintln!("  --genesis-time-now            Override genesis time to current unix time");
    eprintln!("  --is-aggregator               Enable aggregator mode");
    eprintln!("  -v, --verbose                 Enable debug logging");
    eprintln!("  --no-color                    Disable ANSI colors in logs");
}

fn to_hex(bytes: &[u8]) -> String {
    use std::fmt::Write;

    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(&mut out, "{b:02x}");
    }
    out
}

#[tokio::main]
async fn main() {
    let mut args = env::args().skip(1);
    let mut config_path: Option<PathBuf> = None;
    let mut genesis_time: Option<u64> = None;
    let mut data_dir: Option<PathBuf> = None;
    let mut checkpoint_sync_url: Option<String> = None;
    let mut listen_addr: Option<String> = None;
    let mut bootnodes: Vec<String> = Vec::new();
    let mut validator_keys_path: Option<PathBuf> = None;
    let mut node_id: Option<String> = None;
    let mut api_port: Option<u16> = None;
    let mut is_aggregator = false;
    let mut verbose = false;
    let mut no_color = false;
    let mut genesis_time_now = false;
    let mut run_node = false;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--config" | "--genesis" => {
                let path = args.next().unwrap_or_default();
                if path.is_empty() {
                    eprintln!("Missing value for {arg}");
                    print_usage();
                    std::process::exit(2);
                }
                config_path = Some(PathBuf::from(path));
            }
            "--genesis-time" => {
                let value = args.next().unwrap_or_default();
                if value.is_empty() {
                    eprintln!("Missing value for --genesis-time");
                    print_usage();
                    std::process::exit(2);
                }
                let parsed = value.parse::<u64>().unwrap_or_else(|err| {
                    eprintln!("Invalid genesis time {value}: {err}");
                    std::process::exit(2);
                });
                genesis_time = Some(parsed);
            }
            "--data-dir" => {
                let value = args.next().unwrap_or_default();
                if value.is_empty() {
                    eprintln!("Missing value for --data-dir");
                    print_usage();
                    std::process::exit(2);
                }
                data_dir = Some(PathBuf::from(value));
            }
            "--checkpoint-sync-url" => {
                let value = args.next().unwrap_or_default();
                if value.is_empty() {
                    eprintln!("Missing value for --checkpoint-sync-url");
                    print_usage();
                    std::process::exit(2);
                }
                checkpoint_sync_url = Some(value);
            }
            "--listen" => {
                let value = args.next().unwrap_or_default();
                if value.is_empty() {
                    eprintln!("Missing value for --listen");
                    print_usage();
                    std::process::exit(2);
                }
                listen_addr = Some(value);
            }
            "--bootnode" => {
                let value = args.next().unwrap_or_default();
                if value.is_empty() {
                    eprintln!("Missing value for --bootnode");
                    print_usage();
                    std::process::exit(2);
                }
                bootnodes.push(value);
            }
            "--validator-keys" => {
                let value = args.next().unwrap_or_default();
                if value.is_empty() {
                    eprintln!("Missing value for --validator-keys");
                    print_usage();
                    std::process::exit(2);
                }
                validator_keys_path = Some(PathBuf::from(value));
            }
            "--node-id" => {
                let value = args.next().unwrap_or_default();
                if value.is_empty() {
                    eprintln!("Missing value for --node-id");
                    print_usage();
                    std::process::exit(2);
                }
                node_id = Some(value);
            }
            "--api-port" => {
                let value = args.next().unwrap_or_default();
                if value.is_empty() {
                    eprintln!("Missing value for --api-port");
                    print_usage();
                    std::process::exit(2);
                }
                api_port = Some(value.parse::<u16>().unwrap_or_else(|err| {
                    eprintln!("Invalid api port {value}: {err}");
                    std::process::exit(2);
                }));
            }
            "--is-aggregator" => {
                is_aggregator = true;
            }
            "--genesis-time-now" => {
                genesis_time_now = true;
            }
            "-v" | "--verbose" => {
                verbose = true;
            }
            "--no-color" => {
                no_color = true;
            }
            "--run" => {
                run_node = true;
            }
            "--help" | "-h" => {
                print_usage();
                return;
            }
            other => {
                eprintln!("Unknown argument: {other}");
                print_usage();
                std::process::exit(2);
            }
        }
    }

    let default_level = if verbose {
        tracing::Level::DEBUG
    } else {
        tracing::Level::INFO
    };
    let mut filter = tracing_subscriber::EnvFilter::builder()
        .with_default_directive(default_level.into())
        .from_env_lossy();
    for directive in [
        "rec_aggregation::xmss_aggregate=off",
        "packed_pcs_commit=off",
        "sub_protocols::generic_logup=off",
        "air::prove=off",
    ] {
        filter = filter.add_directive(directive.parse().expect("valid log directive"));
    }

    let _ = tracing_subscriber::fmt()
        .with_ansi(!no_color)
        .with_env_filter(filter)
        .try_init();

    let genesis_time_override = if genesis_time_now {
        Some(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("unix time")
                .as_secs(),
        )
    } else {
        None
    };

    if run_node {
        let config_path = config_path.unwrap_or_else(|| {
            eprintln!("Missing --config/--genesis for --run");
            print_usage();
            std::process::exit(2);
        });
        let data_dir = data_dir.unwrap_or_else(|| {
            eprintln!("Missing --data-dir for --run");
            print_usage();
            std::process::exit(2);
        });
        let node = match Node::load(NodeConfig {
            config_path,
            data_dir,
            checkpoint_sync_url,
            listen_addr,
            bootnodes: (!bootnodes.is_empty()).then_some(bootnodes),
            api_port,
            is_aggregator: is_aggregator.then_some(true),
            validator_keys_path,
            node_id,
            genesis_time_override,
        }) {
            Ok(node) => node,
            Err(err) => {
                eprintln!("{err}");
                std::process::exit(1);
            }
        };
        if let Err(err) = node.run().await {
            eprintln!("{err}");
            std::process::exit(1);
        }
        return;
    }

    if checkpoint_sync_url.is_some()
        || listen_addr.is_some()
        || !bootnodes.is_empty()
        || validator_keys_path.is_some()
        || node_id.is_some()
        || api_port.is_some()
        || is_aggregator
        || genesis_time_now
    {
        eprintln!("runtime override flags require --run");
        print_usage();
        std::process::exit(2);
    }

    let config = if let Some(path) = config_path {
        match load_config(&path) {
            Ok(mut cfg) => {
                if let Some(override_secs) = genesis_time_override {
                    cfg.genesis_time = Uint64(override_secs);
                }
                cfg
            }
            Err(err) => {
                if path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.eq_ignore_ascii_case("config.yaml"))
                {
                    let state = match build_genesis_from_config_yaml_with_override(
                        &path,
                        genesis_time_override,
                    ) {
                        Ok(state) => state,
                        Err(genesis_err) => {
                            eprintln!("{err}");
                            eprintln!("{genesis_err}");
                            std::process::exit(1);
                        }
                    };
                    let root = state.hash_tree_root();
                    println!("genesis_root={}", to_hex(&root));
                    return;
                }
                eprintln!("{err}");
                std::process::exit(1);
            }
        }
    } else if let Some(genesis_time) = genesis_time {
        Config {
            genesis_time: Uint64(genesis_time),
        }
    } else {
        print_usage();
        std::process::exit(2);
    };

    let state = match build_genesis(config) {
        Ok(state) => state,
        Err(err) => {
            eprintln!("{err}");
            std::process::exit(1);
        }
    };

    let root = state.hash_tree_root();
    println!("genesis_root={}", to_hex(&root));
}
