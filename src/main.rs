use std::env;
use std::path::PathBuf;

use peam::app::{build_genesis, load_config};
use peam::containers::config::Config;
use peam::node::{Node, NodeConfig};
use peam::ssz::HashTreeRoot;
use peam::types::uint::Uint64;

#[cfg(all(any(target_os = "linux", target_os = "macos"), not(target_env = "msvc")))]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

fn print_usage() {
    eprintln!("Usage:");
    eprintln!("  peam --config <path>");
    eprintln!("  peam --genesis-time <u64>");
    eprintln!("  peam --run --config <path> --data-dir <path>");
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
    let mut filter = tracing_subscriber::EnvFilter::builder()
        .with_default_directive(tracing::Level::INFO.into())
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
        .with_env_filter(filter)
        .try_init();

    let mut args = env::args().skip(1);
    let mut config_path: Option<PathBuf> = None;
    let mut genesis_time: Option<u64> = None;
    let mut data_dir: Option<PathBuf> = None;
    let mut run_node = false;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--config" => {
                let path = args.next().unwrap_or_default();
                if path.is_empty() {
                    eprintln!("Missing value for --config");
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

    if run_node {
        let config_path = config_path.unwrap_or_else(|| {
            eprintln!("Missing --config for --run");
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

    let config = if let Some(path) = config_path {
        match load_config(&path) {
            Ok(cfg) => cfg,
            Err(err) => {
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
