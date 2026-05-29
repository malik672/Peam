mod lean_spec;

use lean_spec::fixture_discovery::discover_fixture_files;
use lean_spec::fork_choice_runner::{run_fork_choice_fixture_entry, run_fork_choice_fixture_file};
use serde_json::json;

#[tokio::test]
async fn lean_spec_fork_choice_shared_fixtures() {
    let fixtures = discover_fixture_files("fork_choice");

    if fixtures.is_empty() {
        eprintln!(
            "No fork_choice fixtures found. Set LEAN_SPECTEST_FIXTURES or check out leanSpec."
        );
        return;
    }

    for path in fixtures {
        run_fork_choice_fixture_file(&path)
            .await
            .unwrap_or_else(|err| panic!("fork-choice fixture {} failed: {err}", path.display()));
    }
}

#[tokio::test]
async fn lean_spec_fork_choice_smoke_scenario() {
    let entry = json!({
        "validators": 1,
        "anchorSlot": 1,
        "blocks": [
            {"label": "fork_a", "parent": "anchor", "slot": 2, "includeAttestation": false},
            {"label": "fork_b", "parent": "anchor", "slot": 2, "includeAttestation": true}
        ],
        "votes": [
            {"validator": 0, "head": "fork_b", "slot": 2}
        ],
        "expectedHead": "fork_b"
    });

    run_fork_choice_fixture_entry("smoke/fork_choice_prefers_voted_branch", &entry)
        .await
        .expect("smoke fork-choice scenario");
}
