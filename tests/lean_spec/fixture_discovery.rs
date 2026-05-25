#![allow(dead_code)]

use std::path::{Path, PathBuf};

fn candidate_fixture_roots() -> Vec<PathBuf> {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut candidates = Vec::new();

    if let Ok(env_path) = std::env::var("LEAN_SPECTEST_FIXTURES") {
        let trimmed = env_path.trim();
        if !trimmed.is_empty() {
            candidates.push(PathBuf::from(trimmed));
        }
    }

    candidates.push(manifest_dir.join("../leanSpec/fixtures"));
    candidates.push(manifest_dir.join("../leanSpec/fixtures/consensus"));
    candidates.push(manifest_dir.join("leanSpec/fixtures"));
    candidates.push(manifest_dir.join("leanSpec/fixtures/consensus"));
    candidates.push(manifest_dir.join("vendor/leanSpec/fixtures"));
    candidates.push(manifest_dir.join("vendor/leanSpec/fixtures/consensus"));
    candidates.push(manifest_dir.join("tests/fixtures/lean_spec"));

    candidates
}

fn normalize_fixture_root(root: &Path) -> PathBuf {
    let consensus_child = root.join("consensus");
    if consensus_child.is_dir() {
        return consensus_child;
    }
    root.to_path_buf()
}

pub fn fixtures_root() -> Option<PathBuf> {
    candidate_fixture_roots()
        .into_iter()
        .find(|candidate| candidate.is_dir())
        .map(|root| normalize_fixture_root(&root))
}

fn discover_fixture_files_from_root(root: &Path, kind: &str) -> Vec<PathBuf> {
    let safe_kind = std::path::Path::new(kind)
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or(kind);
    let kind_dir = root.join(safe_kind);

    if !kind_dir.is_dir() {
        return Vec::new();
    }

    let mut files = Vec::new();
    let mut stack = vec![kind_dir];

    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };

        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().and_then(|ext| ext.to_str()) == Some("json") {
                files.push(path);
            }
        }
    }

    files.sort();
    files
}

pub fn discover_fixture_files(kind: &str) -> Vec<PathBuf> {
    let Some(root) = fixtures_root() else {
        return Vec::new();
    };

    discover_fixture_files_from_root(&root, kind)
}

#[cfg(test)]
mod tests {
    use super::{discover_fixture_files_from_root, normalize_fixture_root};
    use std::path::{Path, PathBuf};

    #[test]
    fn normalize_keeps_consensus_root_when_already_selected() {
        let root = Path::new("/tmp/fixtures/consensus");
        assert_eq!(normalize_fixture_root(root), root);
    }

    #[test]
    fn normalize_accepts_repo_local_fixture_root() {
        let root = Path::new("/tmp/tests/fixtures/lean_spec");
        assert_eq!(normalize_fixture_root(root), root);
    }

    #[test]
    fn discover_accepts_bare_fixtures_root() {
        let root = unique_temp_path("peam-fixtures-root");
        let file = root
            .join("consensus")
            .join("fork_choice")
            .join("devnet")
            .join("test_case.json");
        std::fs::create_dir_all(file.parent().expect("parent")).expect("create fixture dir");
        std::fs::write(&file, "{}").expect("write fixture file");

        let discovered =
            discover_fixture_files_from_root(&normalize_fixture_root(&root), "fork_choice");
        assert_eq!(discovered, vec![file]);

        std::fs::remove_dir_all(root).expect("cleanup temp root");
    }

    fn unique_temp_path(prefix: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        std::env::temp_dir().join(format!("{prefix}-{nanos}"))
    }
}
