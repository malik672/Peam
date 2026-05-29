use std::path::Path;

use serde_json::Value;

pub fn load_fixture_file(path: &Path) -> Value {
    let text = std::fs::read_to_string(path).expect("fixture file");
    serde_json::from_str(&text).expect("fixture json")
}

pub fn fixture_entries(json: &Value) -> Vec<(&str, &Value)> {
    let object = json.as_object().expect("fixture object");
    let mut entries = object
        .iter()
        .map(|(test_id, entry)| (test_id.as_str(), entry))
        .collect::<Vec<_>>();
    entries.sort_by(|(left, _), (right, _)| left.cmp(right));
    entries
}

pub fn first_fixture_entry(json: &Value) -> (&str, &Value) {
    fixture_entries(json)
        .into_iter()
        .next()
        .expect("fixture entry")
}
