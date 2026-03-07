use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use leansig::serialization::Serializable;
use peam::crypto::pq::key_gen_for_devnet_validator;

const DEFAULT_VALIDATORS: usize = 3;
const DEFAULT_NODE_MAP: &str = "peam_0:0,peer1_0:1,peer2_0:2";

#[derive(Clone)]
struct ValidatorMaterial {
    pubkey_hex_no_prefix: String,
    privkey_file: String,
}

fn print_usage() {
    eprintln!("Usage:");
    eprintln!(
        "  devnet2_registry_gen --out <dir> --genesis-time <u64> [--validators <usize>] [--node-map <name:i,name:j,...>]"
    );
    eprintln!();
    eprintln!("Example:");
    eprintln!(
        "  devnet2_registry_gen --out /tmp/devnet --genesis-time 1772472000 --validators 3 --node-map peam_0:0,peer1_0:1,peer2_0:2"
    );
}

fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write;

    let mut out = String::with_capacity(bytes.len() * 2 + 2);
    out.push_str("0x");
    for b in bytes {
        let _ = write!(&mut out, "{b:02x}");
    }
    out
}

fn ensure_dir(path: &Path) -> Result<(), String> {
    fs::create_dir_all(path).map_err(|err| format!("failed to create {}: {err}", path.display()))
}

fn parse_node_map(raw: &str) -> Result<BTreeMap<String, Vec<usize>>, String> {
    let mut map: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    for pair in raw.split(',').filter(|s| !s.trim().is_empty()) {
        let (name, idx_raw) = pair
            .split_once(':')
            .ok_or_else(|| format!("invalid node-map entry: {pair}"))?;
        let name = name.trim();
        if name.is_empty() {
            return Err(format!("invalid node name in node-map entry: {pair}"));
        }
        let idx = idx_raw
            .trim()
            .parse::<usize>()
            .map_err(|err| format!("invalid index in node-map entry {pair}: {err}"))?;
        map.entry(name.to_string()).or_default().push(idx);
    }
    Ok(map)
}

fn main() {
    let mut args = env::args().skip(1);
    let mut out_dir: Option<PathBuf> = None;
    let mut genesis_time: Option<u64> = None;
    let mut validator_count = DEFAULT_VALIDATORS;
    let mut node_map_raw = DEFAULT_NODE_MAP.to_string();

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--out" => {
                let value = args.next().unwrap_or_default();
                if value.is_empty() {
                    eprintln!("Missing value for --out");
                    print_usage();
                    std::process::exit(2);
                }
                out_dir = Some(PathBuf::from(value));
            }
            "--genesis-time" => {
                let value = args.next().unwrap_or_default();
                if value.is_empty() {
                    eprintln!("Missing value for --genesis-time");
                    print_usage();
                    std::process::exit(2);
                }
                let parsed = value.parse::<u64>().unwrap_or_else(|err| {
                    eprintln!("Invalid --genesis-time {value}: {err}");
                    std::process::exit(2);
                });
                genesis_time = Some(parsed);
            }
            "--validators" => {
                let value = args.next().unwrap_or_default();
                if value.is_empty() {
                    eprintln!("Missing value for --validators");
                    print_usage();
                    std::process::exit(2);
                }
                validator_count = value.parse::<usize>().unwrap_or_else(|err| {
                    eprintln!("Invalid --validators {value}: {err}");
                    std::process::exit(2);
                });
                if validator_count == 0 {
                    eprintln!("--validators must be > 0");
                    std::process::exit(2);
                }
            }
            "--node-map" => {
                let value = args.next().unwrap_or_default();
                if value.is_empty() {
                    eprintln!("Missing value for --node-map");
                    print_usage();
                    std::process::exit(2);
                }
                node_map_raw = value;
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

    let out_dir = out_dir.unwrap_or_else(|| {
        eprintln!("Missing required --out");
        print_usage();
        std::process::exit(2);
    });
    let genesis_time = genesis_time.unwrap_or_else(|| {
        eprintln!("Missing required --genesis-time");
        print_usage();
        std::process::exit(2);
    });

    let node_map = parse_node_map(&node_map_raw).unwrap_or_else(|err| {
        eprintln!("Invalid --node-map: {err}");
        std::process::exit(2);
    });

    for (node, indexes) in &node_map {
        if indexes.is_empty() {
            eprintln!("node-map has empty validator list for node {node}");
            std::process::exit(2);
        }
        for idx in indexes {
            if *idx >= validator_count {
                eprintln!(
                    "node-map index {idx} out of range for --validators {}",
                    validator_count
                );
                std::process::exit(2);
            }
        }
    }

    let hash_sig_dir = out_dir.join("hash-sig-keys");
    ensure_dir(&hash_sig_dir).unwrap_or_else(|err| {
        eprintln!("{err}");
        std::process::exit(1);
    });

    let mut pubkeys = Vec::with_capacity(validator_count);
    let mut validator_material = Vec::with_capacity(validator_count);
    let mut manifest_lines = Vec::with_capacity(validator_count * 3 + 8);
    manifest_lines.push("key_scheme: SIGTopLevelTargetSumLifetime32Dim64Base8".to_string());
    manifest_lines.push("hash_function: Poseidon2".to_string());
    manifest_lines.push("encoding: TargetSum".to_string());
    manifest_lines.push("lifetime: 4294967296".to_string());
    manifest_lines.push("log_num_active_epochs: 18".to_string());
    manifest_lines.push("num_active_epochs: 262144".to_string());
    manifest_lines.push(format!("num_validators: {validator_count}"));
    manifest_lines.push("validators:".to_string());

    for idx in 0..validator_count {
        let (pubkey, secret_key) = key_gen_for_devnet_validator(idx).unwrap_or_else(|err| {
            eprintln!("failed to derive validator {idx}: {err}");
            std::process::exit(1);
        });

        let pubkey_hex = hex_encode(pubkey.as_ref());
        pubkeys.push(pubkey_hex.clone());

        let sk_bytes = secret_key.to_bytes();
        let sk_filename = format!("validator_{idx}_sk.ssz");
        let sk_path = hash_sig_dir.join(&sk_filename);
        fs::write(&sk_path, &sk_bytes).unwrap_or_else(|err| {
            eprintln!("failed writing {}: {err}", sk_path.display());
            std::process::exit(1);
        });

        let pk_bytes = pubkey.as_array();
        let pk_filename = format!("validator_{idx}_pk.ssz");
        let pk_path = hash_sig_dir.join(&pk_filename);
        fs::write(&pk_path, &pk_bytes).unwrap_or_else(|err| {
            eprintln!("failed writing {}: {err}", pk_path.display());
            std::process::exit(1);
        });

        validator_material.push(ValidatorMaterial {
            pubkey_hex_no_prefix: pubkey_hex.trim_start_matches("0x").to_string(),
            privkey_file: sk_filename.clone(),
        });

        manifest_lines.push(format!("- index: {idx}"));
        manifest_lines.push(format!("  pubkey_hex: {pubkey_hex}"));
        manifest_lines.push(format!("  privkey_file: {sk_filename}"));
    }

    let manifest_path = hash_sig_dir.join("validator-keys-manifest.yaml");
    fs::write(&manifest_path, manifest_lines.join("\n") + "\n").unwrap_or_else(|err| {
        eprintln!("failed writing {}: {err}", manifest_path.display());
        std::process::exit(1);
    });

    let mut config_lines = Vec::with_capacity(pubkeys.len() + 3);
    config_lines.push(format!("GENESIS_TIME: {genesis_time}"));
    config_lines.push(format!("NUM_VALIDATORS: {validator_count}"));
    config_lines.push("GENESIS_VALIDATORS:".to_string());
    for pk in &pubkeys {
        config_lines.push(format!("- {pk}"));
    }
    let config_path = out_dir.join("config.yaml");
    fs::write(&config_path, config_lines.join("\n") + "\n").unwrap_or_else(|err| {
        eprintln!("failed writing {}: {err}", config_path.display());
        std::process::exit(1);
    });

    let mut validators_lines = Vec::new();
    for (node, indexes) in &node_map {
        let mut indexes = indexes.clone();
        indexes.sort_unstable();
        validators_lines.push(format!("{node}:"));
        for idx in indexes {
            validators_lines.push(format!("- {idx}"));
        }
    }
    let validators_path = out_dir.join("validators.yaml");
    fs::write(&validators_path, validators_lines.join("\n") + "\n").unwrap_or_else(|err| {
        eprintln!("failed writing {}: {err}", validators_path.display());
        std::process::exit(1);
    });

    let mut annotated_lines = Vec::new();
    for (node, indexes) in &node_map {
        let mut indexes = indexes.clone();
        indexes.sort_unstable();
        annotated_lines.push(format!("{node}:"));
        for idx in indexes {
            let material = validator_material.get(idx).unwrap_or_else(|| {
                eprintln!("validator index {idx} missing material");
                std::process::exit(1);
            });
            annotated_lines.push(format!("  - index: {idx}"));
            annotated_lines.push(format!("    pubkey_hex: {}", material.pubkey_hex_no_prefix));
            annotated_lines.push(format!("    privkey_file: {}", material.privkey_file));
        }
    }
    let annotated_validators_path = out_dir.join("annotated_validators.yaml");
    fs::write(
        &annotated_validators_path,
        annotated_lines.join("\n") + "\n",
    )
    .unwrap_or_else(|err| {
        eprintln!(
            "failed writing {}: {err}",
            annotated_validators_path.display()
        );
        std::process::exit(1);
    });

    println!("generated:");
    println!("  {}", config_path.display());
    println!("  {}", validators_path.display());
    println!("  {}", annotated_validators_path.display());
    println!("  {}", manifest_path.display());
}
