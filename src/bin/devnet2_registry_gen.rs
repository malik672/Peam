use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use leansig::serialization::Serializable;
use peam::crypto::pq::{
    DevnetValidatorKeyRole, key_gen_for_devnet_validator_with_role, public_key_from_bytes,
};

const DEFAULT_VALIDATORS: usize = 3;
const DEFAULT_NODE_MAP: &str = "peam_0:0,peer1_0:1,peer2_0:2";
const DEFAULT_ATTESTATION_SUBNETS: u64 = 1;

#[derive(Clone)]
struct ValidatorMaterial {
    attestation_pubkey_hex_no_prefix: String,
    proposal_pubkey_hex_no_prefix: String,
    attestation_privkey_file: String,
    proposal_privkey_file: String,
}

fn print_usage() {
    eprintln!("Usage:");
    eprintln!(
        "  devnet2_registry_gen --out <dir> --genesis-time <u64> [--validators <usize>] [--node-map <name:i,name:j,...>] [--attestation-subnets <u64>]"
    );
    eprintln!();
    eprintln!("Example:");
    eprintln!(
        "  devnet2_registry_gen --out /tmp/devnet --genesis-time 1772472000 --validators 3 --node-map peam_0:0,peer1_0:1,peer2_0:2 --attestation-subnets 1"
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

fn synthetic_node_privkey_hex(node_index: usize) -> String {
    // Deterministic 32-byte hex key per node entry for devnet config compatibility.
    // This key is metadata for config interoperability and not used for validator signing.
    format!("{:064x}", node_index + 1)
}

fn ensure_dir(path: &Path) -> Result<(), String> {
    fs::create_dir_all(path).map_err(|err| format!("failed to create {}: {err}", path.display()))
}

fn write_file(path: &Path, bytes: impl AsRef<[u8]>) {
    fs::write(path, bytes).unwrap_or_else(|err| {
        eprintln!("failed writing {}: {err}", path.display());
        std::process::exit(1);
    });
}

fn write_json_file<T: serde::Serialize>(path: &Path, value: &T) {
    let bytes = serde_json::to_vec_pretty(value).unwrap_or_else(|err| {
        eprintln!("failed serializing {}: {err}", path.display());
        std::process::exit(1);
    });
    write_file(path, bytes);
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
    let mut attestation_subnets = DEFAULT_ATTESTATION_SUBNETS;

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
            "--attestation-subnets" => {
                let value = args.next().unwrap_or_default();
                if value.is_empty() {
                    eprintln!("Missing value for --attestation-subnets");
                    print_usage();
                    std::process::exit(2);
                }
                attestation_subnets = value.parse::<u64>().unwrap_or_else(|err| {
                    eprintln!("Invalid --attestation-subnets {value}: {err}");
                    std::process::exit(2);
                });
                if attestation_subnets == 0 {
                    eprintln!("--attestation-subnets must be > 0");
                    std::process::exit(2);
                }
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
    let mut mapped_validator_indexes = Vec::new();
    for indexes in node_map.values() {
        mapped_validator_indexes.extend(indexes.iter().copied());
    }
    mapped_validator_indexes.sort_unstable();
    mapped_validator_indexes.dedup();
    let mut aggregator_validators: BTreeSet<usize> = BTreeSet::new();
    let mut per_subnet_first_validator: BTreeMap<u64, usize> = BTreeMap::new();
    for idx in mapped_validator_indexes {
        let subnet_id = (idx as u64) % attestation_subnets;
        let first = per_subnet_first_validator.entry(subnet_id).or_insert(idx);
        aggregator_validators.insert(*first);
    }

    let hash_sig_dir = out_dir.join("hash-sig-keys");
    ensure_dir(&hash_sig_dir).unwrap_or_else(|err| {
        eprintln!("{err}");
        std::process::exit(1);
    });

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
        let (attestation_pubkey, attestation_secret_key) =
            key_gen_for_devnet_validator_with_role(idx, DevnetValidatorKeyRole::Attestation)
                .unwrap_or_else(|err| {
                    eprintln!("failed to derive attestation key for validator {idx}: {err}");
                    std::process::exit(1);
                });
        let (proposal_pubkey, proposal_secret_key) =
            key_gen_for_devnet_validator_with_role(idx, DevnetValidatorKeyRole::Proposal)
                .unwrap_or_else(|err| {
                    eprintln!("failed to derive proposal key for validator {idx}: {err}");
                    std::process::exit(1);
                });

        let attestation_pubkey_hex = hex_encode(attestation_pubkey.as_ref());
        let proposal_pubkey_hex = hex_encode(proposal_pubkey.as_ref());
        let attestation_public_key_json = public_key_from_bytes(&attestation_pubkey)
            .unwrap_or_else(|err| {
                eprintln!("failed to decode attestation public key for validator {idx}: {err}");
                std::process::exit(1);
            });
        let proposal_public_key_json =
            public_key_from_bytes(&proposal_pubkey).unwrap_or_else(|err| {
                eprintln!("failed to decode proposal public key for validator {idx}: {err}");
                std::process::exit(1);
            });

        let attestation_sk_bytes = attestation_secret_key.to_bytes();
        let attestation_sk_filename = format!("validator_{idx}_attestation_sk.ssz");
        let attestation_sk_path = hash_sig_dir.join(&attestation_sk_filename);
        write_file(&attestation_sk_path, &attestation_sk_bytes);

        let attestation_pk_bytes = attestation_pubkey.as_array();
        let attestation_pk_filename = format!("validator_{idx}_attestation_pk.ssz");
        let attestation_pk_path = hash_sig_dir.join(&attestation_pk_filename);
        write_file(&attestation_pk_path, attestation_pk_bytes);

        let proposal_sk_bytes = proposal_secret_key.to_bytes();
        let proposal_sk_filename = format!("validator_{idx}_proposal_sk.ssz");
        let proposal_sk_path = hash_sig_dir.join(&proposal_sk_filename);
        write_file(&proposal_sk_path, &proposal_sk_bytes);

        let proposal_pk_bytes = proposal_pubkey.as_array();
        let proposal_pk_filename = format!("validator_{idx}_proposal_pk.ssz");
        let proposal_pk_path = hash_sig_dir.join(&proposal_pk_filename);
        write_file(&proposal_pk_path, proposal_pk_bytes);

        // Legacy compatibility aliases still expected by lean-quickstart/qlean.
        // These point at the attestation keypair, while the split manifest carries
        // the actual dual-key devnet4 registry information.
        write_file(
            &hash_sig_dir.join(format!("validator_{idx}_pk.ssz")),
            attestation_pk_bytes,
        );
        write_file(
            &hash_sig_dir.join(format!("validator_{idx}_sk.ssz")),
            &attestation_sk_bytes,
        );
        write_json_file(
            &hash_sig_dir.join(format!("validator_{idx}_pk.json")),
            &attestation_public_key_json,
        );
        write_json_file(
            &hash_sig_dir.join(format!("validator_{idx}_sk.json")),
            &attestation_secret_key,
        );
        write_json_file(
            &hash_sig_dir.join(format!("validator_{idx}_attestation_pk.json")),
            &attestation_public_key_json,
        );
        write_json_file(
            &hash_sig_dir.join(format!("validator_{idx}_attestation_sk.json")),
            &attestation_secret_key,
        );
        write_json_file(
            &hash_sig_dir.join(format!("validator_{idx}_proposal_pk.json")),
            &proposal_public_key_json,
        );
        write_json_file(
            &hash_sig_dir.join(format!("validator_{idx}_proposal_sk.json")),
            &proposal_secret_key,
        );

        validator_material.push(ValidatorMaterial {
            attestation_pubkey_hex_no_prefix: attestation_pubkey_hex
                .trim_start_matches("0x")
                .to_string(),
            proposal_pubkey_hex_no_prefix: proposal_pubkey_hex.trim_start_matches("0x").to_string(),
            attestation_privkey_file: attestation_sk_filename.clone(),
            proposal_privkey_file: proposal_sk_filename.clone(),
        });

        manifest_lines.push(format!("- index: {idx}"));
        manifest_lines.push(format!(
            "  attestation_pubkey_hex: {attestation_pubkey_hex}"
        ));
        manifest_lines.push(format!("  proposal_pubkey_hex: {proposal_pubkey_hex}"));
        manifest_lines.push(format!(
            "  attestation_privkey_file: {attestation_sk_filename}"
        ));
        manifest_lines.push(format!("  proposal_privkey_file: {proposal_sk_filename}"));
    }

    let manifest_path = hash_sig_dir.join("validator-keys-manifest.yaml");
    fs::write(&manifest_path, manifest_lines.join("\n") + "\n").unwrap_or_else(|err| {
        eprintln!("failed writing {}: {err}", manifest_path.display());
        std::process::exit(1);
    });

    let mut config_lines = Vec::with_capacity(validator_material.len() * 3 + 3);
    config_lines.push(format!("GENESIS_TIME: {genesis_time}"));
    config_lines.push(format!("NUM_VALIDATORS: {validator_count}"));
    config_lines.push("GENESIS_VALIDATORS:".to_string());
    for material in &validator_material {
        config_lines.push(format!(
            "- attestation_pubkey: \"0x{}\"",
            material.attestation_pubkey_hex_no_prefix
        ));
        config_lines.push(format!(
            "  proposal_pubkey: \"0x{}\"",
            material.proposal_pubkey_hex_no_prefix
        ));
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
            annotated_lines.push(format!(
                "    attestation_pubkey_hex: {}",
                material.attestation_pubkey_hex_no_prefix
            ));
            annotated_lines.push(format!(
                "    proposal_pubkey_hex: {}",
                material.proposal_pubkey_hex_no_prefix
            ));
            annotated_lines.push(format!(
                "    attestation_privkey_file: {}",
                material.attestation_privkey_file
            ));
            annotated_lines.push(format!(
                "    proposal_privkey_file: {}",
                material.proposal_privkey_file
            ));
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

    let mut validator_config_lines = Vec::new();
    validator_config_lines.push("validators:".to_string());
    for (node_index, (node, indexes)) in node_map.iter().enumerate() {
        let is_aggregator = indexes
            .iter()
            .any(|index| aggregator_validators.contains(index));
        validator_config_lines.push(format!("  - name: \"{node}\""));
        validator_config_lines.push(format!(
            "    privkey: \"{}\"",
            synthetic_node_privkey_hex(node_index)
        ));
        validator_config_lines.push(format!(
            "    is_aggregator: {}",
            if is_aggregator { "true" } else { "false" }
        ));
        validator_config_lines.push("    enrFields:".to_string());
        validator_config_lines.push(format!(
            "      is_aggregator: {}",
            if is_aggregator { "true" } else { "false" }
        ));
    }
    let validator_config_path = out_dir.join("validator-config.yaml");
    fs::write(
        &validator_config_path,
        validator_config_lines.join("\n") + "\n",
    )
    .unwrap_or_else(|err| {
        eprintln!("failed writing {}: {err}", validator_config_path.display());
        std::process::exit(1);
    });

    println!("generated:");
    println!("  {}", config_path.display());
    println!("  {}", validators_path.display());
    println!("  {}", annotated_validators_path.display());
    println!("  {}", validator_config_path.display());
    println!("  {}", manifest_path.display());
}
