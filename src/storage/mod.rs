use std::fs;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use rapidhash::RapidHashMap;

use crate::containers::block::{Block, SignedBlockWithAttestation};
use crate::containers::state::State;
use crate::ssz::SszEncode;
use crate::types::bytes::Bytes32;

mod storage_utils;
use self::storage_utils::*;
mod mmr;
pub use self::mmr::{MmrInclusionProof, verify_mmr_inclusion_proof};
pub use self::mmr::FinalizedMmr;

const BLOCKS_DIR: &str = "blocks";
const SIGNED_BLOCKS_DIR: &str = "signed_blocks";
const STATES_DIR: &str = "states";
const META_FILE: &str = "meta.txt";
const STATE_INDEX_FILE: &str = "state_index.txt";
const BLOCK_INDEX_FILE: &str = "block_index.txt";
const FINALIZED_MMR_FILE: &str = "finalized_mmr.bin";
const SCHEMA_FILE: &str = "schema_version";
const SCHEMA_VERSION: &str = "1";
const BLOB_MAGIC: &[u8; 8] = b"LEANSTRG";
const BLOB_VERSION: u8 = 1;
const BLOB_KIND_STATE: u8 = 1;
const BLOB_KIND_BLOCK: u8 = 2;
const BLOB_KIND_SIGNED_BLOCK: u8 = 3;
// Maximum-performance mode: keep local-trust indexes only, skip MMR maintenance.
const ENABLE_FINALIZED_MMR: bool = false;
// Maximum-performance local-trust mode: trust on-disk slot indexes without
// checking every referenced blob at startup.
//
// Tradeoff:
// - Faster startup/open path for large stores.
// - If index files are stale/corrupt, failures shift to read time.
const TRUST_LOCAL_INDEX: bool = true;

#[derive(Clone, Debug, Default)]
// this might be better represented as a u64 per field or a u8

pub struct RecoveryReport {
    pub loaded_states: usize,
    pub loaded_blocks: usize,
    pub loaded_signed_blocks: usize,
    pub skipped_corrupt: usize,
    pub skipped_unknown_version: usize,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
// this might be better represented as a u64 per field or a u8
pub struct PruneReport {
    pub removed_states: usize,
    pub removed_blocks: usize,
    pub removed_signed_blocks: usize,
    pub kept_pinned: usize,
}

pub trait Store {
    fn get_state(&self, root: &Bytes32) -> Option<&State>;
    fn put_state(&mut self, root: Bytes32, state: State);
    fn get_block(&self, root: &Bytes32) -> Option<&Block>;
    fn get_signed_block(&self, root: &Bytes32) -> Option<SignedBlockWithAttestation>;
    fn put_block(&mut self, root: Bytes32, block: Block);
    fn put_signed_block(
        &mut self,
        root: Bytes32,
        signed: SignedBlockWithAttestation,
        state: &mut State,
    ) -> Result<(), String>;
    fn get_state_by_slot(&self, slot: u64) -> Option<&State>;
    fn get_block_by_slot(&self, slot: u64) -> Option<&Block>;
    fn finalized(&self) -> Option<Bytes32>;
    fn set_finalized(&mut self, root: Bytes32);
    fn justified(&self) -> Option<Bytes32>;
    fn set_justified(&mut self, root: Bytes32);
    fn head(&self) -> Option<Bytes32>;
    fn set_head(&mut self, root: Bytes32);
}

#[derive(Default)]
pub struct MemoryStore {
    states: RapidHashMap<Bytes32, State>,
    blocks: RapidHashMap<Bytes32, Block>,
    signed_blocks: RapidHashMap<Bytes32, SignedBlockWithAttestation>,
    state_by_slot: RapidHashMap<u64, Bytes32>,
    block_by_slot: RapidHashMap<u64, Bytes32>,
    head: Option<Bytes32>,
    finalized: Option<Bytes32>,
    justified: Option<Bytes32>,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Store for MemoryStore {
    fn get_state(&self, root: &Bytes32) -> Option<&State> {
        self.states.get(root)
    }

    fn put_state(&mut self, root: Bytes32, state: State) {
        self.state_by_slot.insert(state.slot.0.0, root);
        self.states.insert(root, state);
    }

    fn get_block(&self, root: &Bytes32) -> Option<&Block> {
        self.blocks.get(root)
    }

    fn get_signed_block(&self, root: &Bytes32) -> Option<SignedBlockWithAttestation> {
        self.signed_blocks.get(root).cloned()
    }

    fn put_block(&mut self, root: Bytes32, block: Block) {
        self.block_by_slot.insert(block.slot.0.0, root);
        self.blocks.insert(root, block);
    }

    fn put_signed_block(
        &mut self,
        root: Bytes32,
        signed: SignedBlockWithAttestation,
        state: &mut State,
    ) -> Result<(), String> {
        // we clone here, inevitable right ?
        state.process_signed_block(&signed)?;
        let block = signed.message.block.clone();
        self.block_by_slot.insert(block.slot.0.0, root);
        self.blocks.insert(root, block);
        self.signed_blocks.insert(root, signed);
        self.head = Some(root);
        self.justified = Some(state.latest_justified.root);
        self.finalized = Some(state.latest_finalized.root);
        Ok(())
    }

    fn get_state_by_slot(&self, slot: u64) -> Option<&State> {
        let root = self.state_by_slot.get(&slot)?;
        self.states.get(root)
    }

    fn get_block_by_slot(&self, slot: u64) -> Option<&Block> {
        let root = self.block_by_slot.get(&slot)?;
        self.blocks.get(root)
    }

    fn head(&self) -> Option<Bytes32> {
        self.head
    }

    fn set_head(&mut self, root: Bytes32) {
        self.head = Some(root);
    }

    fn finalized(&self) -> Option<Bytes32> {
        self.finalized
    }

    fn set_finalized(&mut self, root: Bytes32) {
        self.finalized = Some(root);
    }

    fn justified(&self) -> Option<Bytes32> {
        self.justified
    }

    fn set_justified(&mut self, root: Bytes32) {
        self.justified = Some(root);
    }
}

struct LazyStateEntry {
    path: PathBuf,
    decoded: OnceLock<Option<State>>,
}

impl LazyStateEntry {
    fn new(path: PathBuf) -> Self {
        Self {
            path,
            decoded: OnceLock::new(),
        }
    }

    fn with_value(path: PathBuf, state: State) -> Self {
        let decoded = OnceLock::new();
        let _ = decoded.set(Some(state));
        Self { path, decoded }
    }

    fn get(&self) -> Option<&State> {
        self.decoded
            .get_or_init(|| {
                let bytes = fs::read(&self.path).ok()?;
                let bytes = decode_blob(BLOB_KIND_STATE, &bytes)?;
                decode_state_safe(&bytes)
            })
            .as_ref()
    }

    fn has_sane_shape(&self) -> bool {
        blob_has_sane_shape(&self.path, BLOB_KIND_STATE)
    }
}

struct LazyBlockEntry {
    path: PathBuf,
    decoded: OnceLock<Option<Block>>,
}

impl LazyBlockEntry {
    fn new(path: PathBuf) -> Self {
        Self {
            path,
            decoded: OnceLock::new(),
        }
    }

    fn with_value(path: PathBuf, block: Block) -> Self {
        let decoded = OnceLock::new();
        let _ = decoded.set(Some(block));
        Self { path, decoded }
    }

    fn get(&self) -> Option<&Block> {
        self.decoded
            .get_or_init(|| {
                let bytes = fs::read(&self.path).ok()?;
                let bytes = decode_blob(BLOB_KIND_BLOCK, &bytes)?;
                decode_block_safe(&bytes)
            })
            .as_ref()
    }

    fn has_sane_shape(&self) -> bool {
        blob_has_sane_shape(&self.path, BLOB_KIND_BLOCK)
    }
}

struct LazySignedBlockEntry {
    path: PathBuf,
    decoded: OnceLock<Option<SignedBlockWithAttestation>>,
}

impl LazySignedBlockEntry {
    fn new(path: PathBuf) -> Self {
        Self {
            path,
            decoded: OnceLock::new(),
        }
    }

    fn with_value(path: PathBuf, signed: SignedBlockWithAttestation) -> Self {
        let decoded = OnceLock::new();
        let _ = decoded.set(Some(signed));
        Self { path, decoded }
    }

    fn get(&self) -> Option<&SignedBlockWithAttestation> {
        self.decoded
            .get_or_init(|| {
                let bytes = fs::read(&self.path).ok()?;
                let bytes = decode_blob(BLOB_KIND_SIGNED_BLOCK, &bytes)?;
                decode_signed_block_safe(&bytes)
            })
            .as_ref()
    }
}

pub struct FileStore {
    root: PathBuf,
    states: RapidHashMap<Bytes32, LazyStateEntry>,
    blocks: RapidHashMap<Bytes32, LazyBlockEntry>,
    signed_blocks: RapidHashMap<Bytes32, LazySignedBlockEntry>,
    state_by_slot: RapidHashMap<u64, Bytes32>,
    block_by_slot: RapidHashMap<u64, Bytes32>,
    head: Option<Bytes32>,
    finalized: Option<Bytes32>,
    justified: Option<Bytes32>,
    finalized_mmr: FinalizedMmr,
    recovery: RecoveryReport,
}

impl FileStore {
    pub fn open<P: AsRef<Path>>(root: P) -> Result<Self, String> {
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(root.join(BLOCKS_DIR)).map_err(|err| err.to_string())?;
        fs::create_dir_all(root.join(SIGNED_BLOCKS_DIR)).map_err(|err| err.to_string())?;
        fs::create_dir_all(root.join(STATES_DIR)).map_err(|err| err.to_string())?;
        ensure_schema_version(&root)?;

        let mut store = Self {
            root,
            states: RapidHashMap::default(),
            blocks: RapidHashMap::default(),
            signed_blocks: RapidHashMap::default(),
            state_by_slot: RapidHashMap::default(),
            block_by_slot: RapidHashMap::default(),
            head: None,
            finalized: None,
            justified: None,
            finalized_mmr: FinalizedMmr::default(),
            recovery: RecoveryReport::default(),
        };
        store.load_from_disk()?;
        Ok(store)
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    #[inline]
    pub fn recovery_report(&self) -> RecoveryReport {
        self.recovery.clone()
    }

    pub fn finalized_mmr_root(&self) -> Bytes32 {
        if !ENABLE_FINALIZED_MMR {
            return Bytes32::zero();
        }
        self.finalized_mmr.root()
    }

    pub fn finalized_mmr_size(&self) -> usize {
        if !ENABLE_FINALIZED_MMR {
            return 0;
        }
        self.finalized_mmr.size()
    }

    pub fn finalized_mmr_proof_by_index(&self, index: usize) -> Option<MmrInclusionProof> {
        if !ENABLE_FINALIZED_MMR {
            return None;
        }
        self.finalized_mmr.proof_by_index(index)
    }

    pub fn finalized_mmr_proof_by_root(&self, root: Bytes32) -> Option<MmrInclusionProof> {
        if !ENABLE_FINALIZED_MMR {
            return None;
        }
        self.finalized_mmr.proof_by_root(root)
    }

    /// Prunes data older than `finalized_slot - keep_recent_slots`.
    ///
    /// Safety rules:
    /// - never drops `head`, `justified`, or `finalized` roots
    /// - keeps prune best-effort on filesystem deletes (logs errors, continues)
    ///
    /// After pruning, slot indexes are rebuilt and persisted.
    /// X1
    #[inline]
    pub fn prune(
        &mut self,
        finalized_slot: u64,
        keep_recent_slots: u64,
    ) -> Result<PruneReport, String> {
        let prune_before = finalized_slot.saturating_sub(keep_recent_slots);
        let pinned = self.pinned_roots();
        let store_root = self.root.clone();
        let mut report = PruneReport::default();
        self.states.retain(|root, state_entry| {
            let Some(state) = state_entry.get() else {
                remove_blob_file(&store_root, STATES_DIR, *root);
                report.removed_states += 1;
                return false;
            };
            let slot = state.slot.0.0;
            if slot >= prune_before {
                return true;
            }
            if is_pinned(&pinned, root) {
                report.kept_pinned += 1;
                return true;
            }
            remove_blob_file(&store_root, STATES_DIR, *root);
            report.removed_states += 1;
            false
        });
        let mut pruned_block_roots: Vec<Bytes32> = Vec::new();
        self.blocks.retain(|root, block_entry| {
            let Some(block) = block_entry.get() else {
                remove_blob_file(&store_root, BLOCKS_DIR, *root);
                report.removed_blocks += 1;
                pruned_block_roots.push(*root);
                return false;
            };
            let slot = block.slot.0.0;
            if slot >= prune_before {
                return true;
            }
            if is_pinned(&pinned, root) {
                report.kept_pinned += 1;
                return true;
            }
            remove_blob_file(&store_root, BLOCKS_DIR, *root);
            report.removed_blocks += 1;
            pruned_block_roots.push(*root);
            false
        });
        for root in pruned_block_roots {
            if self.signed_blocks.remove(&root).is_some() {
                remove_blob_file(&store_root, SIGNED_BLOCKS_DIR, root);
                report.removed_signed_blocks += 1;
            }
        }
        self.signed_blocks.retain(|root, signed_entry| {
            let Some(signed) = signed_entry.get() else {
                remove_blob_file(&store_root, SIGNED_BLOCKS_DIR, *root);
                report.removed_signed_blocks += 1;
                return false;
            };
            let slot = signed.message.block.slot.0.0;
            if slot >= prune_before {
                return true;
            }
            if is_pinned(&pinned, root) {
                report.kept_pinned += 1;
                return true;
            }
            remove_blob_file(&store_root, SIGNED_BLOCKS_DIR, *root);
            report.removed_signed_blocks += 1;
            false
        });

        self.rebuild_state_index();
        self.rebuild_block_index();
        self.persist_state_index()?;
        self.persist_block_index()?;
        self.persist_meta()?;
        Ok(report)
    }

    /// Loads lightweight startup metadata and indexes.
    ///
    /// Startup now follows a production-style path:
    /// - discover object files and build root->path handles
    /// - load validated slot indexes (or rebuild if missing/corrupt)
    /// - load fork-choice metadata (`head`, `justified`, `finalized`)
    ///
    /// Object decode is deferred to first access (`get_*`).
    #[inline]
    fn load_from_disk(&mut self) -> Result<(), String> {
        self.load_state_handles()?;
        self.load_block_handles()?;
        self.load_state_index()?;
        self.load_block_index()?;
        self.load_signed_block_handles()?;
        if ENABLE_FINALIZED_MMR {
            self.load_finalized_mmr()?;
        }
        self.load_meta()?;
        Ok(())
    }

    fn load_finalized_mmr(&mut self) -> Result<(), String> {
        let path = self.root.join(FINALIZED_MMR_FILE);
        if !path.exists() {
            self.finalized_mmr = FinalizedMmr::default();
            return Ok(());
        }
        let raw = fs::read(path).map_err(|err| err.to_string())?;
        if raw.len() % 32 != 0 {
            self.recovery.skipped_corrupt += 1;
        }
        let mut leaves = Vec::with_capacity(raw.len() / 32);
        let whole = raw.len() / 32;
        for idx in 0..whole {
            let start = idx * 32;
            let mut out = [0u8; 32];
            out.copy_from_slice(&raw[start..start + 32]);
            leaves.push(Bytes32::from(out));
        }
        self.finalized_mmr = FinalizedMmr::from_leaves(leaves);
        Ok(())
    }

    fn maybe_append_finalized_root(&mut self, root: Bytes32) -> Result<(), String> {
        if !ENABLE_FINALIZED_MMR {
            return Ok(());
        }
        if root == Bytes32::zero() {
            return Ok(());
        }
        if self.finalized_mmr.last() == Some(root) {
            return Ok(());
        }
        self.finalized_mmr.append(root);
        let mut payload = Vec::with_capacity(self.finalized_mmr.size() * 32);
        for root in self.finalized_mmr.leaves() {
            payload.extend_from_slice(&root.as_array());
        }
        atomic_write(self.root.join(FINALIZED_MMR_FILE), &payload)
    }

    /// Returns roots that must never be pruned.
    ///
    /// Layout:
    /// - [0] head
    /// - [1] justified
    /// - [2] finalized
    #[inline]
    fn pinned_roots(&self) -> [Option<Bytes32>; 3] {
        [self.head, self.justified, self.finalized]
    }

    /// Registers `states/*.ssz` files as lazy-load handles.
    ///
    /// This step does not decode state payloads.
    fn load_state_handles(&mut self) -> Result<(), String> {
        for entry in fs::read_dir(self.root.join(STATES_DIR)).map_err(|err| err.to_string())? {
            let entry = entry.map_err(|err| err.to_string())?;
            let path = entry.path();
            let Ok(file_type) = entry.file_type() else {
                self.recovery.skipped_corrupt += 1;
                continue;
            };
            if !file_type.is_file() {
                continue;
            }
            if path.extension().and_then(|v| v.to_str()) != Some("ssz") {
                self.recovery.skipped_unknown_version += 1;
                continue;
            }
            let name = path
                .file_stem()
                .and_then(|v| v.to_str())
                .ok_or_else(|| "invalid state filename".to_string());
            let Ok(name) = name else {
                self.recovery.skipped_corrupt += 1;
                continue;
            };
            let Ok(root) = root_from_hex(name) else {
                self.recovery.skipped_corrupt += 1;
                continue;
            };
            let Ok(meta) = entry.metadata() else {
                self.recovery.skipped_corrupt += 1;
                continue;
            };
            if meta.len() < 8 {
                self.recovery.skipped_corrupt += 1;
                continue;
            }
            self.states.insert(root, LazyStateEntry::new(path));
            self.recovery.loaded_states += 1;
        }
        Ok(())
    }

    /// Registers `blocks/*.ssz` files as lazy-load handles.
    ///
    /// This step does not decode block payloads.
    fn load_block_handles(&mut self) -> Result<(), String> {
        for entry in fs::read_dir(self.root.join(BLOCKS_DIR)).map_err(|err| err.to_string())? {
            let entry = entry.map_err(|err| err.to_string())?;
            let path = entry.path();
            let Ok(file_type) = entry.file_type() else {
                self.recovery.skipped_corrupt += 1;
                continue;
            };
            if !file_type.is_file() {
                continue;
            }
            if path.extension().and_then(|v| v.to_str()) != Some("ssz") {
                self.recovery.skipped_unknown_version += 1;
                continue;
            }
            let name = path
                .file_stem()
                .and_then(|v| v.to_str())
                .ok_or_else(|| "invalid block filename".to_string());
            let Ok(name) = name else {
                self.recovery.skipped_corrupt += 1;
                continue;
            };
            let Ok(root) = root_from_hex(name) else {
                self.recovery.skipped_corrupt += 1;
                continue;
            };
            let Ok(meta) = entry.metadata() else {
                self.recovery.skipped_corrupt += 1;
                continue;
            };
            if meta.len() < 8 {
                self.recovery.skipped_corrupt += 1;
                continue;
            }
            self.blocks.insert(root, LazyBlockEntry::new(path));
            self.recovery.loaded_blocks += 1;
        }
        Ok(())
    }

    /// Registers `signed_blocks/*.ssz` files as lazy-load handles.
    fn load_signed_block_handles(&mut self) -> Result<(), String> {
        for entry in
            fs::read_dir(self.root.join(SIGNED_BLOCKS_DIR)).map_err(|err| err.to_string())?
        {
            let entry = entry.map_err(|err| err.to_string())?;
            let path = entry.path();
            let Ok(file_type) = entry.file_type() else {
                self.recovery.skipped_corrupt += 1;
                continue;
            };
            if !file_type.is_file() {
                continue;
            }
            if path.extension().and_then(|v| v.to_str()) != Some("ssz") {
                self.recovery.skipped_unknown_version += 1;
                continue;
            }
            let name = path
                .file_stem()
                .and_then(|v| v.to_str())
                .ok_or_else(|| "invalid signed block filename".to_string());
            let Ok(name) = name else {
                self.recovery.skipped_corrupt += 1;
                continue;
            };
            let Ok(root) = root_from_hex(name) else {
                self.recovery.skipped_corrupt += 1;
                continue;
            };
            let Ok(meta) = entry.metadata() else {
                self.recovery.skipped_corrupt += 1;
                continue;
            };
            if meta.len() < 8 {
                self.recovery.skipped_corrupt += 1;
                continue;
            }
            self.signed_blocks
                .insert(root, LazySignedBlockEntry::new(path));
            self.recovery.loaded_signed_blocks += 1;
        }
        Ok(())
    }

    /// Loads fork-choice metadata (`head`, `finalized`, `justified`) from `meta.txt`.
    ///
    /// Missing file is not an error. Malformed lines are counted in `self.recovery`.
    fn load_meta(&mut self) -> Result<(), String> {
        let path = self.root.join(META_FILE);
        if !path.exists() {
            return Ok(());
        }
        let meta = fs::read_to_string(path).map_err(|err| err.to_string())?;
        for line in meta.lines() {
            if let Some(value) = line.strip_prefix("head=") {
                if let Ok(root) = option_root_from_text(value) {
                    self.head = root;
                } else {
                    self.recovery.skipped_corrupt += 1;
                }
            } else if let Some(value) = line.strip_prefix("finalized=") {
                if let Ok(root) = option_root_from_text(value) {
                    self.finalized = root;
                } else {
                    self.recovery.skipped_corrupt += 1;
                }
            } else if let Some(value) = line.strip_prefix("justified=") {
                if let Ok(root) = option_root_from_text(value) {
                    self.justified = root;
                } else {
                    self.recovery.skipped_corrupt += 1;
                }
            } else if !line.trim().is_empty() {
                self.recovery.skipped_unknown_version += 1;
            }
        }
        Ok(())
    }

    /// Loads `state_index.txt` into `state_by_slot`.
    ///
    /// If missing/corrupt, keeps the rebuilt in-memory index and persists it
    /// for faster subsequent startups.
    fn load_state_index(&mut self) -> Result<(), String> {
        let path = self.root.join(STATE_INDEX_FILE);
        let Some(index) = self.load_index_file(&path, true)? else {
            // Rebuild index from decoded handles, then persist for next startup.
            self.rebuild_state_index();
            self.persist_state_index()?;
            return Ok(());
        };
        self.state_by_slot = index;
        Ok(())
    }

    /// Loads `block_index.txt` into `block_by_slot`.
    ///
    /// If missing/corrupt, keeps the rebuilt in-memory index and persists it
    /// for faster subsequent startups.
    fn load_block_index(&mut self) -> Result<(), String> {
        let path = self.root.join(BLOCK_INDEX_FILE);
        let Some(index) = self.load_index_file(&path, false)? else {
            // Rebuild index from decoded handles, then persist for next startup.
            self.rebuild_block_index();
            self.persist_block_index()?;
            return Ok(());
        };
        self.block_by_slot = index;
        Ok(())
    }

    /// Loads and validates a slot->root index file.
    ///
    /// Validation rules:
    /// - each non-empty line must parse as `slot=root`
    /// - when `TRUST_LOCAL_INDEX == false`, each root must exist in loaded blobs
    ///
    /// Returns:
    /// - `Ok(Some(index))` if fully valid
    /// - `Ok(None)` if missing or any line/root is invalid
    /// - `Err(...)` on I/O read failure
    fn load_index_file(
        &mut self,
        path: &Path,
        state_index: bool,
    ) -> Result<Option<RapidHashMap<u64, Bytes32>>, String> {
        if !path.exists() {
            return Ok(None);
        }
        let raw = fs::read(path).map_err(|err| err.to_string())?;
        let mut index = RapidHashMap::default();
        for line in raw.split(|byte| *byte == b'\n') {
            let line = trim_ascii_whitespace(line);
            if line.is_empty() {
                continue;
            }
            let (slot, root) = match parse_index_line_bytes(line) {
                Ok(v) => v,
                Err(_) => {
                    self.recovery.skipped_corrupt += 1;
                    return Ok(None);
                }
            };
            if !TRUST_LOCAL_INDEX {
                let exists = if state_index {
                    self.states
                        .get(&root)
                        .map(LazyStateEntry::has_sane_shape)
                        .unwrap_or(false)
                } else {
                    self.blocks
                        .get(&root)
                        .map(LazyBlockEntry::has_sane_shape)
                        .unwrap_or(false)
                };
                if !exists {
                    self.recovery.skipped_corrupt += 1;
                    return Ok(None);
                }
            }
            index.insert(slot, root);
        }
        Ok(Some(index))
    }

    /// Persists fork-choice metadata (`head`, `finalized`, `justified`) to `meta.txt`.
    ///
    /// Called on metadata-changing paths (e.g. signed block import, explicit
    /// setter updates, and prune checkpoints). Uses atomic write semantics to
    /// avoid partial file states on crash/interruption.
    /// X1
    #[inline]
    fn persist_meta(&self) -> Result<(), String> {
        let text = format!(
            "head={}\nfinalized={}\njustified={}\n",
            option_root_to_text(self.head),
            option_root_to_text(self.finalized),
            option_root_to_text(self.justified),
        );
        atomic_write(self.root.join(META_FILE), text.as_bytes())
    }

    fn persist_state_index(&self) -> Result<(), String> {
        let bytes = index_to_bytes(&self.state_by_slot);
        atomic_write(self.root.join(STATE_INDEX_FILE), &bytes)
    }

    fn persist_block_index(&self) -> Result<(), String> {
        let bytes = index_to_bytes(&self.block_by_slot);
        atomic_write(self.root.join(BLOCK_INDEX_FILE), &bytes)
    }

    fn persist_state(&self, root: Bytes32, state: &State) -> Result<(), String> {
        let path = self
            .root
            .join(STATES_DIR)
            .join(format!("{}.ssz", root_to_hex(root)));
        let encoded = encode_blob(BLOB_KIND_STATE, &state.encode_ssz());
        atomic_write(path, &encoded)
    }

    fn persist_block(&self, root: Bytes32, block: &Block) -> Result<(), String> {
        let path = self
            .root
            .join(BLOCKS_DIR)
            .join(format!("{}.ssz", root_to_hex(root)));
        let encoded = encode_blob(BLOB_KIND_BLOCK, &block.encode_ssz());
        atomic_write(path, &encoded)
    }

    fn persist_signed_block(
        &self,
        root: Bytes32,
        signed: &SignedBlockWithAttestation,
    ) -> Result<(), String> {
        let path = self
            .root
            .join(SIGNED_BLOCKS_DIR)
            .join(format!("{}.ssz", root_to_hex(root)));
        let encoded = encode_blob(BLOB_KIND_SIGNED_BLOCK, &signed.encode_ssz());
        atomic_write(path, &encoded)
    }

    /// Rebuild deterministic slot->root index from full state map in O(n):
    /// for duplicate slots, keep the lexicographically-max root.
    /// X1
    fn rebuild_state_index(&mut self) {
        self.state_by_slot.clear();
        for (root, state_entry) in &self.states {
            let Some(state) = state_entry.get() else {
                self.recovery.skipped_corrupt += 1;
                continue;
            };
            let slot = state.slot.0.0;
            self.state_by_slot
                .entry(slot)
                .and_modify(|existing| {
                    if root.as_array() > existing.as_array() {
                        *existing = *root;
                    }
                })
                .or_insert(*root);
        }
    }
    /// Same policy as state index rebuild.
    /// X1
    fn rebuild_block_index(&mut self) {
        // Same policy as state index rebuild.
        self.block_by_slot.clear();
        for (root, block_entry) in &self.blocks {
            let Some(block) = block_entry.get() else {
                self.recovery.skipped_corrupt += 1;
                continue;
            };
            let slot = block.slot.0.0;
            self.block_by_slot
                .entry(slot)
                .and_modify(|existing| {
                    if root.as_array() > existing.as_array() {
                        *existing = *root;
                    }
                })
                .or_insert(*root);
        }
    }
}

impl Store for FileStore {
    #[inline]
    fn get_state(&self, root: &Bytes32) -> Option<&State> {
        self.states.get(root)?.get()
    }

    // Box state here to prevent cache pollution ?
    fn put_state(&mut self, root: Bytes32, state: State) {
        self.state_by_slot.insert(state.slot.0.0, root);
        let path = self
            .root
            .join(STATES_DIR)
            .join(format!("{}.ssz", root_to_hex(root)));
        self.states
            .insert(root, LazyStateEntry::with_value(path, state.clone()));
        let _ = self.persist_state(root, &state);
        let _ = self.persist_state_index();
    }

    fn get_block(&self, root: &Bytes32) -> Option<&Block> {
        self.blocks.get(root)?.get()
    }

    fn get_signed_block(&self, root: &Bytes32) -> Option<SignedBlockWithAttestation> {
        self.signed_blocks.get(root)?.get().cloned()
    }

    fn put_block(&mut self, root: Bytes32, block: Block) {
        self.block_by_slot.insert(block.slot.0.0, root);
        let path = self
            .root
            .join(BLOCKS_DIR)
            .join(format!("{}.ssz", root_to_hex(root)));
        self.blocks
            .insert(root, LazyBlockEntry::with_value(path, block.clone()));
        let _ = self.persist_block(root, &block);
        let _ = self.persist_block_index();
    }

    fn put_signed_block(
        &mut self,
        root: Bytes32,
        signed: SignedBlockWithAttestation,
        state: &mut State,
    ) -> Result<(), String> {
        state.process_signed_block(&signed)?;
        let block = signed.message.block.clone();
        self.block_by_slot.insert(block.slot.0.0, root);
        let block_path = self
            .root
            .join(BLOCKS_DIR)
            .join(format!("{}.ssz", root_to_hex(root)));
        let signed_path = self
            .root
            .join(SIGNED_BLOCKS_DIR)
            .join(format!("{}.ssz", root_to_hex(root)));
        self.blocks
            .insert(root, LazyBlockEntry::with_value(block_path, block.clone()));
        self.signed_blocks
            .insert(root, LazySignedBlockEntry::with_value(signed_path, signed.clone()));
        self.head = Some(root);
        self.justified = Some(state.latest_justified.root);
        self.finalized = Some(state.latest_finalized.root);
        self.maybe_append_finalized_root(state.latest_finalized.root)?;

        self.persist_block(root, &block)?;
        self.persist_signed_block(root, &signed)?;
        self.persist_block_index()?;
        self.persist_meta()?;
        Ok(())
    }

    fn get_state_by_slot(&self, slot: u64) -> Option<&State> {
        let root = self.state_by_slot.get(&slot)?;
        self.states.get(root)?.get()
    }

    fn get_block_by_slot(&self, slot: u64) -> Option<&Block> {
        let root = self.block_by_slot.get(&slot)?;
        self.blocks.get(root)?.get()
    }

    fn head(&self) -> Option<Bytes32> {
        self.head
    }

    fn set_head(&mut self, root: Bytes32) {
        self.head = Some(root);
        let _ = self.persist_meta();
    }

    fn finalized(&self) -> Option<Bytes32> {
        self.finalized
    }

    fn set_finalized(&mut self, root: Bytes32) {
        self.finalized = Some(root);
        let _ = self.maybe_append_finalized_root(root);
        let _ = self.persist_meta();
    }

    fn justified(&self) -> Option<Bytes32> {
        self.justified
    }

    fn set_justified(&mut self, root: Bytes32) {
        self.justified = Some(root);
        let _ = self.persist_meta();
    }
}
