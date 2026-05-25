use std::collections::HashMap;
use std::path::Path;

use peam::containers::attestation::{Attestation, AttestationData};
use peam::containers::block::{
    Block, BlockBody, BlockSignatures, BlockWithAttestation, SignedBlockWithAttestation,
};
use peam::containers::checkpoint::Checkpoint;
use peam::containers::state::{State, Validators};
use peam::containers::validator::{Validator, ValidatorIndex};
use peam::fork_choice::ForkChoiceStore;
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
struct ForkChoiceScenario {
    validators: usize,
    anchor_slot: u64,
    blocks: Vec<BlockSpec>,
    #[serde(default)]
    votes: Vec<VoteSpec>,
    expected_head: String,
    #[serde(default)]
    expected_safe_target: Option<String>,
    #[serde(default)]
    expected_latest_justified: Option<String>,
    #[serde(default)]
    expected_latest_finalized: Option<String>,
    #[serde(default)]
    expected_reorgs_min: Option<u64>,
    #[serde(default)]
    present_checkpoints: Vec<String>,
    #[serde(default)]
    missing_checkpoints: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BlockSpec {
    label: String,
    parent: String,
    slot: u64,
    #[serde(default)]
    include_attestation: bool,
    #[serde(default)]
    justified_from: Option<String>,
    #[serde(default)]
    finalized_from: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct VoteSpec {
    #[serde(default)]
    validator: usize,
    #[serde(default)]
    participants: Vec<usize>,
    head: String,
    slot: u64,
    #[serde(default)]
    accept_after: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GeneratedForkChoiceFixture {
    #[serde(default)]
    anchor_state: Option<GeneratedAnchorState>,
    #[serde(default)]
    anchor_block: Option<GeneratedAnchorBlock>,
    steps: Vec<GeneratedForkChoiceStep>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GeneratedAnchorState {
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
struct GeneratedAnchorBlock {
    #[serde(default)]
    slot: Option<u64>,
}

fn generated_step_valid_default() -> bool {
    true
}

#[derive(Debug, Deserialize)]
#[serde(tag = "stepType", rename_all = "camelCase")]
enum GeneratedForkChoiceStep {
    Block {
        block: GeneratedBlockStepSpec,
        #[serde(default = "generated_step_valid_default")]
        valid: bool,
        #[serde(default)]
        expected_error: Option<String>,
        #[serde(default)]
        checks: Option<GeneratedStoreChecks>,
    },
    Attestation {
        attestation: GeneratedGossipAttestationSpec,
        #[serde(default = "generated_step_valid_default")]
        valid: bool,
        #[serde(default)]
        expected_error: Option<String>,
        #[serde(default)]
        checks: Option<GeneratedStoreChecks>,
    },
    Tick {
        time: u64,
        #[serde(default = "generated_step_valid_default")]
        valid: bool,
        #[serde(default)]
        expected_error: Option<String>,
        #[serde(default)]
        checks: Option<GeneratedStoreChecks>,
    },
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GeneratedBlockStepSpec {
    slot: u64,
    #[serde(default)]
    proposer_index: Option<u64>,
    #[serde(default)]
    block_root_label: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GeneratedGossipAttestationSpec {
    validator_id: u64,
    slot: u64,
    target_slot: u64,
    target_root_label: String,
    #[serde(default)]
    head_root_label: Option<String>,
    #[serde(default)]
    head_slot: Option<u64>,
    #[serde(default)]
    source_root_label: Option<String>,
    #[serde(default)]
    source_slot: Option<u64>,
    #[serde(default)]
    target_root_override: Option<String>,
    #[serde(default)]
    head_root_override: Option<String>,
    #[serde(default)]
    source_root_override: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GeneratedStoreChecks {
    #[serde(default)]
    time: Option<u64>,
    #[serde(default)]
    head_slot: Option<u64>,
    #[serde(default)]
    head_root: Option<String>,
    #[serde(default)]
    head_root_label: Option<String>,
    #[serde(default)]
    latest_justified_slot: Option<u64>,
    #[serde(default)]
    latest_justified_root: Option<String>,
    #[serde(default)]
    latest_justified_root_label: Option<String>,
    #[serde(default)]
    latest_finalized_slot: Option<u64>,
    #[serde(default)]
    latest_finalized_root: Option<String>,
    #[serde(default)]
    latest_finalized_root_label: Option<String>,
    #[serde(default)]
    safe_target: Option<String>,
    #[serde(default)]
    safe_target_label: Option<String>,
}

pub async fn run_fork_choice_fixture_file(path: &Path) -> Result<(), String> {
    let json = load_fixture_file(path);
    for (test_id, entry) in fixture_entries(&json) {
        run_fork_choice_fixture_entry(test_id, entry).await?;
    }
    Ok(())
}

pub async fn run_fork_choice_fixture_entry(test_id: &str, entry: &Value) -> Result<(), String> {
    if let Ok(scenario) = serde_json::from_value::<ForkChoiceScenario>(entry.clone()) {
        return run_local_fork_choice_scenario(test_id, scenario).await;
    }

    if let Ok(fixture) = serde_json::from_value::<GeneratedForkChoiceFixture>(entry.clone()) {
        return run_generated_fork_choice_fixture(test_id, fixture).await;
    }

    Err(format!(
        "{test_id}: fixture did not match either the local Peam scenario schema or the generated leanSpec-compatible envelope"
    ))
}

async fn run_local_fork_choice_scenario(
    test_id: &str,
    scenario: ForkChoiceScenario,
) -> Result<(), String> {
    if scenario.validators == 0 {
        return Err(format!("{test_id}: validators must be greater than zero"));
    }

    let validators = build_validators(scenario.validators);
    let genesis_state = State::generate_genesis(Uint64(0), validators);

    let (anchor_block, anchor_state, anchor_root) =
        build_signed_block(&genesis_state, scenario.anchor_slot, false);
    let mut store = ForkChoiceStore::new(anchor_block, anchor_state.clone())
        .map_err(|err| format!("{test_id}: failed to initialize fork-choice store: {err}"))?;

    let mut states = HashMap::new();
    let mut roots = HashMap::new();
    let mut checkpoints = HashMap::new();
    states.insert("anchor".to_string(), anchor_state.clone());
    roots.insert("anchor".to_string(), anchor_root);
    checkpoints.insert(
        "anchor".to_string(),
        Checkpoint {
            root: anchor_root,
            slot: Slot(Uint64(scenario.anchor_slot)),
        },
    );

    for block in scenario.blocks {
        let label = block.label.clone();
        let slot = block.slot;
        let parent_state = states
            .get(&block.parent)
            .cloned()
            .ok_or_else(|| format!("{test_id}: unknown parent label {}", block.parent))?;
        let (mut signed_block, mut post_state, _initial_root) =
            build_signed_block(&parent_state, slot, block.include_attestation);

        apply_checkpoint_overrides(
            test_id,
            &mut signed_block,
            &mut post_state,
            &checkpoints,
            block.justified_from.as_deref(),
            block.finalized_from.as_deref(),
        )?;
        let root = Bytes32::from(signed_block.message.block.hash_tree_root());

        store
            .on_block(signed_block, post_state.clone())
            .map_err(|err| format!("{test_id}: on_block for {} failed: {err}", label))?;
        states.insert(label.clone(), post_state);
        roots.insert(label.clone(), root);
        checkpoints.insert(
            label,
            Checkpoint {
                root,
                slot: Slot(Uint64(slot)),
            },
        );
    }

    for vote in scenario.votes {
        let root = *roots
            .get(&vote.head)
            .ok_or_else(|| format!("{test_id}: vote references unknown head {}", vote.head))?;
        let attestation = vote_for_root(root, vote.slot, vote.validator, &vote.participants)?;
        if !store.on_attestation(&attestation) {
            return Err(format!(
                "{test_id}: vote for {} with participants {:?} was rejected",
                vote.head,
                if vote.participants.is_empty() {
                    vec![vote.validator]
                } else {
                    vote.participants.clone()
                }
            ));
        }
        if vote.accept_after {
            store.accept_new_votes();
        }
    }
    store.accept_new_votes();

    let expected_root = *roots.get(&scenario.expected_head).ok_or_else(|| {
        format!(
            "{test_id}: expectedHead {} not built",
            scenario.expected_head
        )
    })?;
    let actual_root = store.head();
    if actual_root != expected_root {
        return Err(format!(
            "{test_id}: expected head {} but got {:?}",
            scenario.expected_head, actual_root
        ));
    }

    if let Some(expected_safe_target) = scenario.expected_safe_target.as_deref() {
        let expected_root = *roots.get(expected_safe_target).ok_or_else(|| {
            format!("{test_id}: expectedSafeTarget {expected_safe_target} not built")
        })?;
        if store.safe_target() != expected_root {
            return Err(format!(
                "{test_id}: expected safe target {} but got {:?}",
                expected_safe_target,
                store.safe_target()
            ));
        }
    }

    if let Some(expected_latest_justified) = scenario.expected_latest_justified.as_deref() {
        let expected_root = *roots.get(expected_latest_justified).ok_or_else(|| {
            format!("{test_id}: expectedLatestJustified {expected_latest_justified} not built")
        })?;
        if store.latest_justified().root != expected_root {
            return Err(format!(
                "{test_id}: expected latest justified {} but got {:?}",
                expected_latest_justified,
                store.latest_justified().root
            ));
        }
    }

    if let Some(expected_latest_finalized) = scenario.expected_latest_finalized.as_deref() {
        let expected_root = *roots.get(expected_latest_finalized).ok_or_else(|| {
            format!("{test_id}: expectedLatestFinalized {expected_latest_finalized} not built")
        })?;
        if store.latest_finalized().root != expected_root {
            return Err(format!(
                "{test_id}: expected latest finalized {} but got {:?}",
                expected_latest_finalized,
                store.latest_finalized().root
            ));
        }
    }

    if let Some(expected_reorgs_min) = scenario.expected_reorgs_min {
        if store.reorgs_total() < expected_reorgs_min {
            return Err(format!(
                "{test_id}: expected at least {expected_reorgs_min} reorgs but saw {}",
                store.reorgs_total()
            ));
        }
    }

    for label in scenario.present_checkpoints {
        let checkpoint = checkpoints
            .get(&label)
            .ok_or_else(|| format!("{test_id}: present checkpoint label {label} not built"))?;
        if store.checkpoint_for_root(checkpoint.root).is_none() {
            return Err(format!(
                "{test_id}: expected checkpoint/root presence for {label}, but it was missing"
            ));
        }
    }

    for label in scenario.missing_checkpoints {
        let checkpoint = checkpoints
            .get(&label)
            .ok_or_else(|| format!("{test_id}: missing checkpoint label {label} not built"))?;
        if store.checkpoint_for_root(checkpoint.root).is_some() {
            return Err(format!(
                "{test_id}: expected checkpoint/root for {label} to be pruned, but it was present"
            ));
        }
    }

    Ok(())
}

async fn run_generated_fork_choice_fixture(
    test_id: &str,
    fixture: GeneratedForkChoiceFixture,
) -> Result<(), String> {
    let Some(anchor_state_spec) = fixture.anchor_state else {
        return Err(format!("{test_id}: generated fixture missing anchorState"));
    };
    if anchor_state_spec.validators.is_empty() {
        return Err(format!(
            "{test_id}: generated fixture anchorState.validators must not be empty"
        ));
    }
    let anchor_pre_slot = anchor_state_spec.slot.unwrap_or(0);
    if anchor_pre_slot != 0 {
        return Err(format!(
            "{test_id}: generated fixture anchorState.slot={anchor_pre_slot} is not yet supported; expected genesis-like anchor state"
        ));
    }
    if fixture.steps.is_empty() {
        return Err(format!(
            "{test_id}: generated fixture steps must not be empty"
        ));
    }

    let validator_count = anchor_state_spec.validators.len();
    let genesis_time = anchor_state_spec
        .config
        .and_then(|config| config.genesis_time)
        .unwrap_or(0);
    let validators = build_validators(validator_count);
    let genesis_state = State::generate_genesis(Uint64(genesis_time), validators);
    let anchor_slot = fixture
        .anchor_block
        .and_then(|block| block.slot)
        .unwrap_or(1);
    let (anchor_block, anchor_state, anchor_root) =
        build_signed_block(&genesis_state, anchor_slot, false);
    let mut store = ForkChoiceStore::new(anchor_block, anchor_state.clone()).map_err(|err| {
        format!("{test_id}: failed to initialize generated fork-choice store: {err}")
    })?;

    let mut current_state = anchor_state;
    let mut label_roots = HashMap::new();
    let mut label_checkpoints = HashMap::new();
    label_roots.insert("anchor".to_string(), anchor_root);
    label_checkpoints.insert(
        "anchor".to_string(),
        Checkpoint {
            root: anchor_root,
            slot: Slot(Uint64(anchor_slot)),
        },
    );

    for (step_index, step) in fixture.steps.into_iter().enumerate() {
        match step {
            GeneratedForkChoiceStep::Block {
                block,
                valid,
                expected_error,
                checks,
            } => {
                if !valid {
                    return Err(format!(
                        "{test_id}: generated fixture block step {} requested valid=false but invalid block steps are not yet supported by the compatibility runner{}",
                        step_index,
                        expected_error
                            .as_deref()
                            .map(|value| format!(" (expectedError={value:?})"))
                            .unwrap_or_default()
                    ));
                }
                let default_proposer = if validator_count == 0 {
                    0
                } else {
                    block.slot % validator_count as u64
                };
                let (signed_block, post_state, root) =
                    build_signed_block(&current_state, block.slot, false);
                if signed_block.message.block.proposer_index.0.0
                    != block.proposer_index.unwrap_or(default_proposer)
                {
                    return Err(format!(
                        "{test_id}: generated fixture block step {} requested proposer {} but the current compatibility runner only supports the canonical proposer {}",
                        step_index,
                        block.proposer_index.unwrap_or(default_proposer),
                        signed_block.message.block.proposer_index.0.0
                    ));
                }

                store
                    .on_block(signed_block, post_state.clone())
                    .map_err(|err| {
                        format!(
                            "{test_id}: generated fixture on_block failed at step {}: {err}",
                            step_index
                        )
                    })?;
                current_state = post_state;

                if let Some(label) = block.block_root_label {
                    label_roots.insert(label.clone(), root);
                    label_checkpoints.insert(
                        label,
                        Checkpoint {
                            root,
                            slot: Slot(Uint64(block.slot)),
                        },
                    );
                }

                if let Some(checks) = checks {
                    validate_generated_store_checks(
                        test_id,
                        step_index,
                        &store,
                        &checks,
                        &label_roots,
                    )?;
                }
            }
            GeneratedForkChoiceStep::Attestation {
                attestation,
                valid,
                expected_error,
                checks,
            } => {
                let built =
                    generated_vote_for_labels(test_id, &attestation, &label_checkpoints)?;
                match validate_generated_gossip_attestation(
                    &store,
                    &built,
                    attestation.validator_id as usize,
                ) {
                    Ok(()) => {
                        if !valid {
                            return Err(format!(
                                "{test_id}: generated fixture attestation step {} succeeded but expected failure",
                                step_index
                            ));
                        }
                    }
                    Err(err) => {
                        if valid {
                            return Err(format!(
                                "{test_id}: generated fixture attestation step {} failed validation: {err}",
                                step_index
                            ));
                        }
                        if let Some(expected_error) = expected_error.as_deref()
                            && !err.contains(expected_error)
                        {
                            return Err(format!(
                                "{test_id}: generated fixture attestation step {} failed with wrong error. expected {:?}, got {:?}",
                                step_index,
                                expected_error,
                                err
                            ));
                        }
                        continue;
                    }
                }
                if !store.on_attestation(&built) {
                    if valid {
                        return Err(format!(
                            "{test_id}: generated fixture attestation step {} was rejected by the store",
                            step_index
                        ));
                    }
                    if let Some(expected_error) = expected_error.as_deref()
                        && !"Unknown head block".contains(expected_error)
                    {
                        return Err(format!(
                            "{test_id}: generated fixture attestation step {} was rejected by the store without matching expected error {:?}",
                            step_index,
                            expected_error
                        ));
                    }
                    continue;
                }
                store.accept_new_votes();

                if let Some(checks) = checks {
                    validate_generated_store_checks(
                        test_id,
                        step_index,
                        &store,
                        &checks,
                        &label_roots,
                    )?;
                }
            }
            GeneratedForkChoiceStep::Tick {
                time: _,
                valid,
                expected_error,
                checks,
            } => {
                if !valid {
                    return Err(format!(
                        "{test_id}: generated fixture tick step {} requested valid=false but invalid tick steps are not yet supported by the compatibility runner{}",
                        step_index,
                        expected_error
                            .as_deref()
                            .map(|value| format!(" (expectedError={value:?})"))
                            .unwrap_or_default()
                    ));
                }
                if let Some(checks) = checks {
                    validate_generated_store_checks(
                        test_id,
                        step_index,
                        &store,
                        &checks,
                        &label_roots,
                    )?;
                }
            }
        }
    }

    Ok(())
}

fn validate_generated_store_checks(
    test_id: &str,
    step_index: usize,
    store: &ForkChoiceStore,
    checks: &GeneratedStoreChecks,
    label_roots: &HashMap<String, Bytes32>,
) -> Result<(), String> {
    if let Some(expected_slot) = checks.head_slot
        && store.head_slot() != expected_slot
    {
        return Err(format!(
            "{test_id}: generated fixture step {} expected head slot {} but got {}",
            step_index,
            expected_slot,
            store.head_slot()
        ));
    }
    if let Some(expected_label) = checks.head_root_label.as_deref() {
        let expected_root = *label_roots.get(expected_label).ok_or_else(|| {
            format!(
                "{test_id}: generated fixture step {} referenced unknown headRootLabel {}",
                step_index, expected_label
            )
        })?;
        if store.head() != expected_root {
            return Err(format!(
                "{test_id}: generated fixture step {} expected head root label {} but got {:?}",
                step_index,
                expected_label,
                store.head()
            ));
        }
    }
    if let Some(expected_root) = checks.head_root.as_deref() {
        let expected_root = bytes32_from_hex(expected_root);
        if store.head() != expected_root {
            return Err(format!(
                "{test_id}: generated fixture step {} expected head root {:?} but got {:?}",
                step_index,
                expected_root,
                store.head()
            ));
        }
    }
    if let Some(expected_slot) = checks.latest_justified_slot
        && store.latest_justified().slot.0.0 != expected_slot
    {
        return Err(format!(
            "{test_id}: generated fixture step {} expected latest justified slot {} but got {}",
            step_index,
            expected_slot,
            store.latest_justified().slot.0.0
        ));
    }
    if let Some(expected_root) = generated_root_from_checks(
        test_id,
        step_index,
        label_roots,
        checks.latest_justified_root.as_deref(),
        checks.latest_justified_root_label.as_deref(),
        "latestJustified",
    )? && store.latest_justified().root != expected_root
    {
        return Err(format!(
            "{test_id}: generated fixture step {} expected latest justified root {:?} but got {:?}",
            step_index,
            expected_root,
            store.latest_justified().root
        ));
    }
    if let Some(expected_slot) = checks.latest_finalized_slot
        && store.latest_finalized().slot.0.0 != expected_slot
    {
        return Err(format!(
            "{test_id}: generated fixture step {} expected latest finalized slot {} but got {}",
            step_index,
            expected_slot,
            store.latest_finalized().slot.0.0
        ));
    }
    if let Some(expected_root) = generated_root_from_checks(
        test_id,
        step_index,
        label_roots,
        checks.latest_finalized_root.as_deref(),
        checks.latest_finalized_root_label.as_deref(),
        "latestFinalized",
    )? && store.latest_finalized().root != expected_root
    {
        return Err(format!(
            "{test_id}: generated fixture step {} expected latest finalized root {:?} but got {:?}",
            step_index,
            expected_root,
            store.latest_finalized().root
        ));
    }
    if let Some(expected_root) = checks.safe_target.as_deref() {
        let expected_root = bytes32_from_hex(expected_root);
        if store.safe_target() != expected_root {
            return Err(format!(
                "{test_id}: generated fixture step {} expected safe target root {:?} but got {:?}",
                step_index,
                expected_root,
                store.safe_target()
            ));
        }
    }
    if let Some(expected_label) = checks.safe_target_label.as_deref() {
        let expected_root = *label_roots.get(expected_label).ok_or_else(|| {
            format!(
                "{test_id}: generated fixture step {} referenced unknown safeTargetLabel {}",
                step_index, expected_label
            )
        })?;
        if store.safe_target() != expected_root {
            return Err(format!(
                "{test_id}: generated fixture step {} expected safe target label {} but got {:?}",
                step_index,
                expected_label,
                store.safe_target()
            ));
        }
    }
    Ok(())
}

fn generated_root_from_checks(
    test_id: &str,
    step_index: usize,
    label_roots: &HashMap<String, Bytes32>,
    raw_root: Option<&str>,
    root_label: Option<&str>,
    field_name: &str,
) -> Result<Option<Bytes32>, String> {
    match (raw_root, root_label) {
        (Some(raw_root), Some(root_label)) => Err(format!(
            "{test_id}: generated fixture step {} specified both {}Root and {}RootLabel ({:?}, {:?})",
            step_index, field_name, field_name, raw_root, root_label
        )),
        (Some(raw_root), None) => Ok(Some(bytes32_from_hex(raw_root))),
        (None, Some(root_label)) => label_roots.get(root_label).copied().ok_or_else(|| {
            format!(
                "{test_id}: generated fixture step {} referenced unknown {}RootLabel {}",
                step_index, field_name, root_label
            )
        }).map(Some),
        (None, None) => Ok(None),
    }
}

fn generated_vote_for_labels(
    test_id: &str,
    attestation: &GeneratedGossipAttestationSpec,
    label_checkpoints: &HashMap<String, Checkpoint>,
) -> Result<Attestation, String> {
    let (target_root, _target_known_slot) = resolve_generated_attestation_root(
        test_id,
        "target",
        attestation.target_root_override.as_deref(),
        Some(attestation.target_root_label.as_str()),
        label_checkpoints,
    )?;
    let (head_root, head_known_slot) = resolve_generated_attestation_root(
        test_id,
        "head",
        attestation.head_root_override.as_deref(),
        attestation
            .head_root_label
            .as_deref()
            .or(Some(attestation.target_root_label.as_str())),
        label_checkpoints,
    )?;
    let (source_root, source_known_slot) = resolve_generated_attestation_root(
        test_id,
        "source",
        attestation.source_root_override.as_deref(),
        attestation.source_root_label.as_deref().or(Some("anchor")),
        label_checkpoints,
    )?;

    let validator = attestation.validator_id as usize;
    let mut participants = vec![false; validator + 1];
    participants[validator] = true;

    Ok(Attestation {
        aggregation_bits: BitList::new(participants).expect("participants"),
        data: AttestationData {
            slot: Slot(Uint64(attestation.slot)),
            head: Checkpoint {
                root: head_root,
                slot: Slot(Uint64(
                    attestation
                        .head_slot
                        .or(head_known_slot)
                        .unwrap_or(attestation.target_slot),
                )),
            },
            target: Checkpoint {
                root: target_root,
                slot: Slot(Uint64(attestation.target_slot)),
            },
            source: Checkpoint {
                root: source_root,
                slot: Slot(Uint64(attestation.source_slot.or(source_known_slot).unwrap_or(0))),
            },
        },
    })
}

fn resolve_generated_attestation_root(
    test_id: &str,
    field_name: &str,
    raw_root: Option<&str>,
    root_label: Option<&str>,
    label_checkpoints: &HashMap<String, Checkpoint>,
) -> Result<(Bytes32, Option<u64>), String> {
    match (raw_root, root_label) {
        (Some(raw_root), Some(_)) => Ok((bytes32_from_hex(raw_root), None)),
        (Some(raw_root), None) => Ok((bytes32_from_hex(raw_root), None)),
        (None, Some(root_label)) => label_checkpoints
            .get(root_label)
            .map(|checkpoint| (checkpoint.root, Some(checkpoint.slot.0.0)))
            .ok_or_else(|| {
                format!(
                    "{test_id}: generated attestation references unknown {field_name}RootLabel {}",
                    root_label
                )
            }),
        (None, None) => Err(format!(
            "{test_id}: generated attestation did not provide a {field_name} root label or override"
        )),
    }
}

fn validate_generated_gossip_attestation(
    store: &ForkChoiceStore,
    attestation: &Attestation,
    validator_id: usize,
) -> Result<(), String> {
    if validator_id >= store.validator_count() {
        return Err("validator not found in state".to_string());
    }

    let data = &attestation.data;
    let Some(target_checkpoint) = store.checkpoint_for_root(data.target.root) else {
        return Err("Unknown target block".to_string());
    };
    let Some(head_checkpoint) = store.checkpoint_for_root(data.head.root) else {
        return Err("Unknown head block".to_string());
    };
    let Some(source_checkpoint) = store.checkpoint_for_root(data.source.root) else {
        return Err("Unknown source block".to_string());
    };

    if data.slot.0.0 > store.head_slot() + 1 {
        return Err("Attestation too far in future".to_string());
    }
    if data.source.slot.0.0 > data.target.slot.0.0 {
        return Err("Source checkpoint slot must not exceed target".to_string());
    }
    if data.head.slot.0.0 < data.target.slot.0.0 {
        return Err("Head checkpoint must not be older than target".to_string());
    }
    if source_checkpoint.slot.0.0 != data.source.slot.0.0 {
        return Err("Source checkpoint slot mismatch".to_string());
    }
    if target_checkpoint.slot.0.0 != data.target.slot.0.0 {
        return Err("Target checkpoint slot mismatch".to_string());
    }
    if head_checkpoint.slot.0.0 != data.head.slot.0.0 {
        return Err("Head checkpoint slot mismatch".to_string());
    }

    Ok(())
}

fn apply_checkpoint_overrides(
    test_id: &str,
    signed_block: &mut SignedBlockWithAttestation,
    post_state: &mut State,
    checkpoints: &HashMap<String, Checkpoint>,
    justified_from: Option<&str>,
    finalized_from: Option<&str>,
) -> Result<(), String> {
    if let Some(label) = justified_from {
        let checkpoint = *checkpoints
            .get(label)
            .ok_or_else(|| format!("{test_id}: justifiedFrom references unknown label {label}"))?;
        post_state.latest_justified = checkpoint;
    }

    if let Some(label) = finalized_from {
        let checkpoint = *checkpoints
            .get(label)
            .ok_or_else(|| format!("{test_id}: finalizedFrom references unknown label {label}"))?;
        post_state.latest_finalized = checkpoint;
    }

    if justified_from.is_some() || finalized_from.is_some() {
        let state_root = Bytes32::from(post_state.hash_tree_root());
        signed_block.message.block.state_root = state_root;
        post_state.latest_block_header.state_root = state_root;
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

fn vote_for_root(
    root: Bytes32,
    slot: u64,
    validator: usize,
    participants: &[usize],
) -> Result<Attestation, String> {
    let participant_indices = if participants.is_empty() {
        vec![validator]
    } else {
        participants.to_vec()
    };
    let max_participant = participant_indices
        .iter()
        .copied()
        .max()
        .ok_or_else(|| "vote must include at least one participant".to_string())?;
    let mut bits = vec![false; max_participant + 1];
    for participant in participant_indices {
        bits[participant] = true;
    }
    let aggregation_bits =
        BitList::new(bits).map_err(|err| format!("invalid aggregation bits: {err}"))?;
    Ok(Attestation {
        aggregation_bits,
        data: AttestationData {
            slot: Slot(Uint64(slot)),
            head: Checkpoint {
                root,
                slot: Slot(Uint64(slot)),
            },
            target: Checkpoint {
                root,
                slot: Slot(Uint64(slot)),
            },
            source: Checkpoint {
                root: Bytes32::zero(),
                slot: Slot(Uint64(0)),
            },
        },
    })
}
