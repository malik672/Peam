use std::env;
use std::path::PathBuf;

use peam::containers::block::SignedBlockWithAttestation;
use peam::containers::state::NoopSignatureVerifier;
use peam::ssz::HashTreeRoot;
use peam::storage::{FileStore, Store};
use peam::types::bytes::Bytes32;

fn to_hex(bytes: &[u8]) -> String {
    const LUT: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(LUT[(b >> 4) as usize] as char);
        out.push(LUT[(b & 0x0f) as usize] as char);
    }
    out
}

fn parse_bytes32(hex: &str) -> Result<Bytes32, String> {
    let hex = hex.strip_prefix("0x").unwrap_or(hex);
    if hex.len() != 64 {
        return Err(format!(
            "expected 32-byte hex (64 chars), got length {}",
            hex.len()
        ));
    }
    let mut out = [0u8; 32];
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        let hi = (chunk[0] as char).to_digit(16).ok_or("invalid hex")?;
        let lo = (chunk[1] as char).to_digit(16).ok_or("invalid hex")?;
        out[i] = ((hi << 4) | lo) as u8;
    }
    Ok(Bytes32::from(out))
}

fn load_signed_block(
    store: &FileStore,
    root: &Bytes32,
) -> Result<SignedBlockWithAttestation, String> {
    store
        .get_signed_block(root)
        .ok_or_else(|| "signed block not found".to_string())
}

fn parse_slot(arg: &str) -> Option<u64> {
    let slot_str = arg.strip_prefix("slot:").unwrap_or(arg);
    if slot_str.is_empty() || slot_str.len() > 18 {
        return None;
    }
    if !slot_str.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    slot_str.parse::<u64>().ok()
}

fn main() -> Result<(), String> {
    let mut args = env::args().skip(1);
    let store_dir = args.next().ok_or_else(|| {
        "usage: debug_state_root <store_dir> <block_root_hex|slot:NN>".to_string()
    })?;
    let selector = args.next().ok_or_else(|| {
        "usage: debug_state_root <store_dir> <block_root_hex|slot:NN>".to_string()
    })?;

    let store = FileStore::open(PathBuf::from(store_dir))?;
    let block_root = if let Some(slot) = parse_slot(&selector) {
        let block = store
            .get_block_by_slot(slot)
            .ok_or_else(|| format!("block not found for slot {}", slot))?;
        Bytes32::from(block.hash_tree_root())
    } else {
        parse_bytes32(&selector)?
    };
    let signed = load_signed_block(&store, &block_root)?;
    let block = &signed.message.block;

    let parent_root = block.parent_root;
    let parent_block = store
        .get_block(&parent_root)
        .ok_or_else(|| "parent block not found".to_string())?;
    let parent_state_root = parent_block.state_root;
    let parent_state = store
        .get_state(&parent_state_root)
        .ok_or_else(|| "parent state not found".to_string())?;

    let mut state = parent_state.clone();
    let pre_root = Bytes32::from(state.hash_tree_root());
    let verifier = NoopSignatureVerifier;
    let transition_result = state.process_signed_block_with_verifier(&signed, &verifier);
    let computed_root = Bytes32::from(state.hash_tree_root());

    println!("block_root=0x{}", to_hex(&block_root.as_array()));
    println!("block_slot={}", block.slot.0.0);
    println!(
        "block_state_root=0x{}",
        to_hex(&block.state_root.as_array())
    );
    println!("parent_root=0x{}", to_hex(&parent_root.as_array()));
    println!(
        "parent_state_root=0x{}",
        to_hex(&parent_state_root.as_array())
    );
    println!("pre_state_root=0x{}", to_hex(&pre_root.as_array()));
    println!(
        "computed_state_root=0x{}",
        to_hex(&computed_root.as_array())
    );
    println!("state_transition_result={:?}", transition_result);

    if block.state_root == computed_root {
        println!("result=match");
    } else {
        println!("result=mismatch");
    }

    Ok(())
}
