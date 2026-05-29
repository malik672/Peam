mod lean_spec;

use lean_spec::fixture_discovery::discover_fixture_files;
use lean_spec::state_transition_runner::{
    run_state_transition_fixture_entry, run_state_transition_fixture_file,
};
use serde_json::json;

#[test]
fn lean_spec_state_transition_shared_fixtures() {
    let fixtures = discover_fixture_files("state_transition");

    if fixtures.is_empty() {
        eprintln!(
            "No state_transition fixtures found. Set LEAN_SPECTEST_FIXTURES or check out leanSpec."
        );
        return;
    }

    for path in fixtures {
        run_state_transition_fixture_file(&path).unwrap_or_else(|err| {
            panic!("state-transition fixture {} failed: {err}", path.display())
        });
    }
}

#[test]
fn lean_spec_state_transition_smoke_scenario() {
    let entry = json!({
        "validators": 1,
        "blocks": [
            {"slot": 1, "proposer": 0},
            {"slot": 4, "proposer": 0},
            {"slot": 8, "proposer": 0}
        ],
        "expectedSlot": 8,
        "expectedHistoryLen": 8
    });

    run_state_transition_fixture_entry("smoke/blocks_with_gaps", &entry)
        .expect("smoke state-transition scenario");
}
