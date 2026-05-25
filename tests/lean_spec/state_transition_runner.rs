use std::path::Path;

use peam::containers::attestation::{Attestation, AttestationData};
use peam::containers::block::{
    Attestations, Block, BlockBody, BlockSignatures, BlockWithAttestation,
    SignedBlockWithAttestation,
};
use peam::containers::checkpoint::Checkpoint;
use peam::containers::state::{NoopSignatureVerifier, State, Validators};
use peam::containers::validator::{Validator, ValidatorIndex};
use peam::slot::Slot;
use peam::ssz::HashTreeRoot;
use peam::types::bitlist::BitList;
use peam::types::bytes::{Bytes32, Bytes52, Bytes3112};
use peam::types::collections::SszList;
use peam::types::uint::Uint64;
use serde::Deserialize;
use serde_json::Value;

use super::fixture_json::{fixture_entries, load_fixture_file};
use super::hex::bytes32_from_hex;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct StateTransitionScenario {
    validators: usize,
    blocks: Vec<BlockSpec>,
    #[serde(default)]
    expected_slot: Option<u64>,
    #[serde(default)]
    expected_history_len: Option<usize>,
    #[serde(default)]
    expected_error_contains: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BlockSpec {
    slot: u64,
    proposer: u64,
    #[serde(default)]
    override_proposer_index: Option<u64>,
    #[serde(default)]
    override_parent_root: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GeneratedStateTransitionFixture {
    pre: GeneratedPreState,
    blocks: Vec<GeneratedBlockSpec>,
    #[serde(default)]
    post: Option<GeneratedStateExpectation>,
    #[serde(default)]
    expect_exception: Option<String>,
    #[serde(default)]
    expect_exception_message: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GeneratedPreState {
    #[serde(default)]
    config: Option<GeneratedConfig>,
    #[serde(default)]
    slot: Option<u64>,
    #[serde(default)]
    validators: Vec<Value>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GeneratedConfig {
    #[serde(default)]
    genesis_time: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GeneratedBlockSpec {
    slot: u64,
    #[serde(default)]
    proposer_index: Option<u64>,
    #[serde(default)]
    parent_root: Option<String>,
    #[serde(default)]
    state_root: Option<String>,
    #[serde(default)]
    skip_slot_processing: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GeneratedStateExpectation {
    #[serde(default)]
    slot: Option<u64>,
    #[serde(default)]
    validator_count: Option<usize>,
    #[serde(default)]
    config_genesis_time: Option<u64>,
    #[serde(default)]
    historical_block_hashes_count: Option<usize>,
    #[serde(default)]
    latest_block_header_slot: Option<u64>,
    #[serde(default)]
    latest_block_header_proposer_index: Option<u64>,
    #[serde(default)]
    latest_block_header_parent_root: Option<String>,
    #[serde(default)]
    latest_block_header_state_root: Option<String>,
    #[serde(default)]
    latest_justified_slot: Option<u64>,
    #[serde(default)]
    latest_justified_root: Option<String>,
    #[serde(default)]
    latest_finalized_slot: Option<u64>,
    #[serde(default)]
    latest_finalized_root: Option<String>,
}

pub fn run_state_transition_fixture_file(path: &Path) -> Result<(), String> {
    let json = load_fixture_file(path);
    for (test_id, entry) in fixture_entries(&json) {
        run_state_transition_fixture_entry(test_id, entry)?;
    }
    Ok(())
}

pub fn run_state_transition_fixture_entry(test_id: &str, entry: &Value) -> Result<(), String> {
    if let Ok(scenario) = serde_json::from_value::<StateTransitionScenario>(entry.clone()) {
        return run_local_state_transition_scenario(test_id, scenario);
    }

    if let Ok(fixture) = serde_json::from_value::<GeneratedStateTransitionFixture>(entry.clone()) {
        return run_generated_state_transition_fixture(test_id, fixture);
    }

    Err(format!(
        "{test_id}: fixture did not match either the local Peam scenario schema or the generated leanSpec-compatible envelope"
    ))
}

fn run_local_state_transition_scenario(
    test_id: &str,
    scenario: StateTransitionScenario,
) -> Result<(), String> {
    if scenario.validators == 0 {
        return Err(format!("{test_id}: validators must be greater than zero"));
    }
    if scenario.blocks.is_empty() {
        return Err(format!("{test_id}: blocks must not be empty"));
    }

    let validators = build_validators(scenario.validators);
    let mut state = State::generate_genesis(Uint64(0), validators);
    let mut last_block = None;

    for block in scenario.blocks {
        let signed = build_signed_block(
            &state,
            block.slot,
            block.proposer,
            block.override_proposer_index,
            block.override_parent_root.as_deref(),
            None,
            false,
        )?;
        match state.process_signed_block_with_verifier(&signed, &NoopSignatureVerifier) {
            Ok(()) => {
                last_block = Some(signed.message.block);
            }
            Err(err) => {
                if let Some(expected_error) = scenario.expected_error_contains.as_deref() {
                    if err.contains(expected_error) {
                        return Ok(());
                    }
                    return Err(format!(
                        "{test_id}: expected error containing {:?}, got {:?}",
                        expected_error, err
                    ));
                }
                return Err(format!(
                    "{test_id}: failed to process slot {}: {err}",
                    block.slot
                ));
            }
        }
    }

    if let Some(expected_error) = scenario.expected_error_contains.as_deref() {
        return Err(format!(
            "{test_id}: expected error containing {:?}, but all blocks processed successfully",
            expected_error
        ));
    }

    let last_block = last_block.expect("checked non-empty blocks");
    let expected_slot = scenario
        .expected_slot
        .ok_or_else(|| format!("{test_id}: expectedSlot is required for success scenarios"))?;
    if state.slot != Slot(Uint64(expected_slot)) {
        return Err(format!(
            "{test_id}: expected state slot {} but got {}",
            expected_slot, state.slot.0.0
        ));
    }
    if state.latest_block_header.slot != Slot(Uint64(expected_slot)) {
        return Err(format!(
            "{test_id}: expected latest header slot {} but got {}",
            expected_slot, state.latest_block_header.slot.0.0
        ));
    }
    let expected_history_len = scenario.expected_history_len.ok_or_else(|| {
        format!("{test_id}: expectedHistoryLen is required for success scenarios")
    })?;
    if state.historical_block_hashes.len() != expected_history_len {
        return Err(format!(
            "{test_id}: expected historical len {} but got {}",
            expected_history_len,
            state.historical_block_hashes.len()
        ));
    }
    if state.latest_block_header.state_root != last_block.state_root {
        return Err(format!(
            "{test_id}: latest header state root did not match last block state root"
        ));
    }

    Ok(())
}

fn run_generated_state_transition_fixture(
    test_id: &str,
    fixture: GeneratedStateTransitionFixture,
) -> Result<(), String> {
    if fixture.pre.validators.is_empty() {
        return Err(format!(
            "{test_id}: generated fixture pre.validators must not be empty"
        ));
    }
    let pre_slot = fixture.pre.slot.unwrap_or(0);
    if pre_slot != 0 {
        return Err(format!(
            "{test_id}: generated fixture pre.slot={pre_slot} is not yet supported; expected genesis-like pre-state"
        ));
    }
    if fixture.blocks.is_empty() {
        return Err(format!(
            "{test_id}: generated fixture blocks must not be empty"
        ));
    }

    let validator_count = fixture.pre.validators.len();
    let genesis_time = fixture
        .pre
        .config
        .and_then(|config| config.genesis_time)
        .unwrap_or(0);
    let validators = build_validators(validator_count);
    let mut state = State::generate_genesis(Uint64(genesis_time), validators);
    let mut last_block = None;

    for block in fixture.blocks {
        let default_proposer = if validator_count == 0 {
            0
        } else {
            block.slot % validator_count as u64
        };
        let signed = build_signed_block(
            &state,
            block.slot,
            default_proposer,
            block
                .proposer_index
                .filter(|proposer_index| *proposer_index != default_proposer),
            block.parent_root.as_deref(),
            block.state_root.as_deref(),
            block.skip_slot_processing,
        )?;

        let process_result = if block.skip_slot_processing {
            state.process_block(&signed.message.block)
        } else {
            state.process_signed_block_with_verifier(&signed, &NoopSignatureVerifier)
        };

        match process_result {
            Ok(()) => {
                last_block = Some(signed.message.block);
            }
            Err(err) => {
                if let Some(expected_message) = fixture.expect_exception_message.as_deref() {
                    if err.contains(expected_message) {
                        return Ok(());
                    }
                    return Err(format!(
                        "{test_id}: expected generated fixture error containing {:?}, got {:?}",
                        expected_message, err
                    ));
                }
                if fixture.expect_exception.is_some() {
                    return Ok(());
                }
                return Err(format!(
                    "{test_id}: generated fixture failed to process slot {}: {err}",
                    block.slot
                ));
            }
        }
    }

    if let Some(expected_message) = fixture.expect_exception_message.as_deref() {
        return Err(format!(
            "{test_id}: expected generated fixture error containing {:?}, but all blocks processed successfully",
            expected_message
        ));
    }
    if fixture.expect_exception.is_some() {
        return Err(format!(
            "{test_id}: expected generated fixture exception {:?}, but all blocks processed successfully",
            fixture.expect_exception
        ));
    }

    let last_block = last_block.expect("checked non-empty blocks");
    let Some(post) = fixture.post else {
        return Ok(());
    };

    if let Some(expected_slot) = post.slot
        && state.slot != Slot(Uint64(expected_slot))
    {
        return Err(format!(
            "{test_id}: generated fixture expected state slot {} but got {}",
            expected_slot, state.slot.0.0
        ));
    }
    if let Some(expected_slot) = post.latest_block_header_slot
        && state.latest_block_header.slot != Slot(Uint64(expected_slot))
    {
        return Err(format!(
            "{test_id}: generated fixture expected latest header slot {} but got {}",
            expected_slot, state.latest_block_header.slot.0.0
        ));
    }
    if let Some(expected_len) = post.historical_block_hashes_count
        && state.historical_block_hashes.len() != expected_len
    {
        return Err(format!(
            "{test_id}: generated fixture expected historical len {} but got {}",
            expected_len,
            state.historical_block_hashes.len()
        ));
    }
    if let Some(expected_slot) = post.latest_justified_slot
        && state.latest_justified.slot != Slot(Uint64(expected_slot))
    {
        return Err(format!(
            "{test_id}: generated fixture expected latest justified slot {} but got {}",
            expected_slot, state.latest_justified.slot.0.0
        ));
    }
    if let Some(expected_slot) = post.latest_finalized_slot
        && state.latest_finalized.slot != Slot(Uint64(expected_slot))
    {
        return Err(format!(
            "{test_id}: generated fixture expected latest finalized slot {} but got {}",
            expected_slot, state.latest_finalized.slot.0.0
        ));
    }
    if let Some(expected_count) = post.validator_count
        && state.validators.len() != expected_count
    {
        return Err(format!(
            "{test_id}: generated fixture expected validator count {} but got {}",
            expected_count,
            state.validators.len()
        ));
    }
    if let Some(expected_genesis_time) = post.config_genesis_time
        && state.config.genesis_time.0 != expected_genesis_time
    {
        return Err(format!(
            "{test_id}: generated fixture expected config genesis time {} but got {}",
            expected_genesis_time,
            state.config.genesis_time.0
        ));
    }
    if let Some(expected_index) = post.latest_block_header_proposer_index
        && state.latest_block_header.proposer_index.0.0 != expected_index
    {
        return Err(format!(
            "{test_id}: generated fixture expected latest header proposer index {} but got {}",
            expected_index,
            state.latest_block_header.proposer_index.0.0
        ));
    }
    if let Some(expected_root) = post.latest_block_header_parent_root.as_deref() {
        let expected_root = bytes32_from_hex(expected_root);
        if state.latest_block_header.parent_root != expected_root {
            return Err(format!(
                "{test_id}: generated fixture expected latest header parent root {:?} but got {:?}",
                expected_root,
                state.latest_block_header.parent_root
            ));
        }
    }
    if let Some(expected_root) = post.latest_block_header_state_root.as_deref() {
        let expected_root = bytes32_from_hex(expected_root);
        if state.latest_block_header.state_root != expected_root {
            return Err(format!(
                "{test_id}: generated fixture expected latest header state root {:?} but got {:?}",
                expected_root,
                state.latest_block_header.state_root
            ));
        }
    }
    if let Some(expected_root) = post.latest_justified_root.as_deref() {
        let expected_root = bytes32_from_hex(expected_root);
        if state.latest_justified.root != expected_root {
            return Err(format!(
                "{test_id}: generated fixture expected latest justified root {:?} but got {:?}",
                expected_root,
                state.latest_justified.root
            ));
        }
    }
    if let Some(expected_root) = post.latest_finalized_root.as_deref() {
        let expected_root = bytes32_from_hex(expected_root);
        if state.latest_finalized.root != expected_root {
            return Err(format!(
                "{test_id}: generated fixture expected latest finalized root {:?} but got {:?}",
                expected_root,
                state.latest_finalized.root
            ));
        }
    }
    if state.latest_block_header.state_root != last_block.state_root {
        return Err(format!(
            "{test_id}: generated fixture latest header state root did not match last block state root"
        ));
    }

    Ok(())
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
    state: &State,
    slot: u64,
    proposer: u64,
    override_proposer_index: Option<u64>,
    override_parent_root: Option<&str>,
    override_state_root: Option<&str>,
    skip_slot_processing: bool,
) -> Result<SignedBlockWithAttestation, String> {
    let mut temp = state.clone();
    if !skip_slot_processing {
        temp.process_slots(Slot(Uint64(slot)))?;
    }
    let parent_root = if skip_slot_processing {
        Bytes32::from(state.latest_block_header.hash_tree_root())
    } else {
        Bytes32::from(temp.latest_block_header.hash_tree_root())
    };
    let body = BlockBody {
        attestations: Attestations::new(vec![]).expect("attestations"),
    };
    let mut block = Block {
        slot: Slot(Uint64(slot)),
        proposer_index: ValidatorIndex(Uint64(proposer)),
        parent_root,
        state_root: Bytes32::zero(),
        body,
    };

    if skip_slot_processing || override_state_root.is_some() {
        block.state_root = override_state_root
            .map(bytes32_from_hex)
            .unwrap_or_else(Bytes32::zero);
    } else {
        let mut post = state.clone();
        post.process_slots(block.slot)?;
        let header = block.header();
        post.process_block_header(header)?;
        post.process_block_body(&block.body, header.body_root)?;
        block.state_root = Bytes32::from(post.hash_tree_root());
    }

    if let Some(index) = override_proposer_index {
        block.proposer_index = ValidatorIndex(Uint64(index));
    }
    if let Some(root) = override_parent_root {
        block.parent_root = bytes32_from_hex(root);
    }

    let proposer_index = override_proposer_index.unwrap_or(proposer) as usize;
    let mut bits = vec![false; proposer_index + 1];
    bits[proposer_index] = true;
    let proposer_attestation = Attestation {
        aggregation_bits: BitList::new(bits).expect("participants"),
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

    Ok(SignedBlockWithAttestation {
        message: BlockWithAttestation {
            block,
            proposer_attestation,
        },
        signature: BlockSignatures {
            attestation_signatures: SszList::new(vec![]).expect("attestation signatures"),
            proposer_signature: Bytes3112::zero(),
        },
    })
}
