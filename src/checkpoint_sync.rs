use std::io::Read;
use std::time::Duration;

use crate::ssz::HashTreeRoot;
use peam_consensus_types::containers::attestation::{
    Attestation, AttestationData, VALIDATOR_REGISTRY_LIMIT,
};
use peam_consensus_types::containers::block::{
    AttestationSignatures, Attestations, Block, BlockBody, BlockSignatures, BlockWithAttestation,
    SignedBlockWithAttestation,
};
use peam_consensus_types::containers::checkpoint::Checkpoint;
use peam_consensus_types::types::bitlist::BitList;
use peam_consensus_types::types::bytes::{Bytes32, Bytes3112};
use peam_state::state::State;

const FINALIZED_STATE_PATH: &str = "/lean/v0/states/finalized";
const CHECKPOINT_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const CHECKPOINT_READ_TIMEOUT: Duration = Duration::from_secs(15);

pub fn fetch_checkpoint_state(base_url: &str) -> Result<State, String> {
    let base = base_url.trim();
    if base.is_empty() {
        return Err("checkpoint sync url is empty".to_string());
    }
    let base = base.trim_end_matches('/');
    let url = format!("{base}{FINALIZED_STATE_PATH}");

    let agent = ureq::AgentBuilder::new()
        .timeout_connect(CHECKPOINT_CONNECT_TIMEOUT)
        .timeout_read(CHECKPOINT_READ_TIMEOUT)
        .build();
    let response = agent
        .get(&url)
        .set("Accept", "application/octet-stream")
        .call()
        .map_err(|err| match err {
            ureq::Error::Status(code, resp) => {
                let body = resp.into_string().unwrap_or_default();
                format!("checkpoint sync HTTP {code}: {body}")
            }
            ureq::Error::Transport(err) => format!("checkpoint sync transport error: {err}"),
        })?;

    let status = response.status();
    if status != 200 {
        let body = response.into_string().unwrap_or_default();
        return Err(format!("checkpoint sync HTTP {status}: {body}"));
    }

    let mut reader = response.into_reader();
    let mut bytes = Vec::new();
    reader
        .read_to_end(&mut bytes)
        .map_err(|err| format!("checkpoint sync read failed: {err}"))?;

    State::decode_ssz_checked(&bytes)
}

pub fn verify_checkpoint_state(state: &State, expected_genesis: &State) -> Result<(), String> {
    if state.validators.is_empty() {
        return Err("checkpoint state has empty validator registry".to_string());
    }
    if state.validators.len() != expected_genesis.validators.len() {
        return Err(format!(
            "checkpoint validator count {} does not match genesis {}",
            state.validators.len(),
            expected_genesis.validators.len()
        ));
    }
    if state.config.genesis_time != expected_genesis.config.genesis_time {
        return Err(format!(
            "checkpoint genesis_time {} does not match config {}",
            state.config.genesis_time.0, expected_genesis.config.genesis_time.0
        ));
    }
    for (idx, validator) in state.validators.iter().enumerate() {
        let expected = expected_genesis
            .validators
            .get(idx)
            .ok_or_else(|| format!("missing genesis validator {idx}"))?;
        if validator.attestation_pubkey != expected.attestation_pubkey
            || validator.proposal_pubkey != expected.proposal_pubkey
        {
            return Err(format!("checkpoint validator key mismatch at index {idx}"));
        }
        if validator.index.0.0 != idx as u64 {
            return Err(format!(
                "checkpoint validator index mismatch at {idx}: expected {idx}, got {}",
                validator.index.0.0
            ));
        }
    }

    let latest_slot = state.slot.0.0;
    let header_slot = state.latest_block_header.slot.0.0;
    if header_slot > latest_slot {
        return Err(format!(
            "checkpoint header slot {header_slot} is ahead of state slot {latest_slot}"
        ));
    }
    if state.latest_finalized.slot.0.0 > latest_slot {
        return Err("checkpoint finalized slot is in the future".to_string());
    }
    if state.latest_justified.slot < state.latest_finalized.slot {
        return Err("checkpoint justified slot is before finalized slot".to_string());
    }
    if state.latest_justified.slot == state.latest_finalized.slot
        && state.latest_justified.root != state.latest_finalized.root
    {
        return Err("checkpoint justified/finalized roots mismatch at same slot".to_string());
    }

    let header_root = Bytes32::from(state.latest_block_header.hash_tree_root());
    if state.latest_finalized.slot == state.latest_block_header.slot
        && state.latest_finalized.root != header_root
    {
        return Err("checkpoint finalized root does not match header root".to_string());
    }
    if state.latest_justified.slot == state.latest_block_header.slot
        && state.latest_justified.root != header_root
    {
        return Err("checkpoint justified root does not match header root".to_string());
    }

    let mut tmp = state.clone();
    let original_state_root = tmp.latest_block_header.state_root;
    tmp.latest_block_header.state_root = Bytes32::zero();
    let computed_root = Bytes32::from(tmp.hash_tree_root());
    if original_state_root != Bytes32::zero() && original_state_root != computed_root {
        return Err(format!(
            "checkpoint state_root mismatch: expected {computed_root:?}, got {original_state_root:?}"
        ));
    }

    Ok(())
}

pub fn build_anchor_block(state: &State) -> Block {
    let header = state.latest_block_header;
    let state_root = if header.state_root == Bytes32::zero() {
        Bytes32::from(state.hash_tree_root())
    } else {
        header.state_root
    };
    Block {
        slot: header.slot,
        proposer_index: header.proposer_index,
        parent_root: header.parent_root,
        state_root,
        body: BlockBody {
            attestations: Attestations::default(),
        },
    }
}

pub fn build_anchor_signed_block(
    _state: &State,
    anchor_block: &Block,
) -> Result<SignedBlockWithAttestation, String> {
    let block_root = Bytes32::from(anchor_block.hash_tree_root());
    let proposer_index = anchor_block.proposer_index.0.0 as usize;
    if proposer_index >= VALIDATOR_REGISTRY_LIMIT {
        return Err(format!(
            "checkpoint proposer index {proposer_index} exceeds registry limit {VALIDATOR_REGISTRY_LIMIT}"
        ));
    }

    let mut bits = vec![false; proposer_index + 1];
    bits[proposer_index] = true;
    let aggregation_bits = BitList::new(bits)?;
    let checkpoint = Checkpoint {
        root: block_root,
        slot: anchor_block.slot,
    };
    let proposer_attestation = Attestation {
        aggregation_bits,
        data: AttestationData {
            slot: anchor_block.slot,
            head: checkpoint,
            target: checkpoint,
            source: checkpoint,
        },
    };

    let signatures = BlockSignatures {
        attestation_signatures: AttestationSignatures::default(),
        proposer_signature: Bytes3112::zero(),
    };

    Ok(SignedBlockWithAttestation {
        message: BlockWithAttestation {
            block: anchor_block.clone(),
            proposer_attestation,
        },
        signature: signatures,
    })
}
