//! Low-level redb wrapper for `canonical.redb`.
//!
//! This is the only module that talks directly to redb. [`FileStore`] delegates
//! all disk I/O here and never opens tables or transactions itself.
//!
//! # Tables
//!
//! ```text
//! ┌────────────────────────────┬──────────────┬───────────────────────────┐
//! │ Table                      │ Key          │ Value                     │
//! ├────────────────────────────┼──────────────┼───────────────────────────┤
//! │ canonical_state_slot       │ u64 (slot)   │ [u8] (Bytes32 block root) │
//! │ canonical_block_slot       │ u64 (slot)   │ [u8] (Bytes32 root)       │
//! │ canonical_meta             │ &str (key)   │ [u8] (Bytes32 root)       │
//! │ canonical_state_root_index │ [u8]         │ [u8] (block root)         │
//! │ canonical_state_blob       │ [u8] (root)  │ [u8] (LEANSTRG envelope)  │
//! │ canonical_block_blob       │ [u8] (root)  │ [u8] (LEANSTRG envelope)  │
//! │ canonical_signed_block_blob│ [u8] (root)  │ [u8] (LEANSTRG envelope)  │
//! └────────────────────────────┴──────────────┴───────────────────────────┘
//! ```
//!
//! Slot tables map `slot → block_root` (canonical index). `canonical_state_root_index`
//! maps `state_root → block_root`. Blob tables map `root → envelope` (the
//! actual serialized data). Meta stores three
//! string-keyed roots: `"head"`, `"finalized"`, `"justified"`, plus
//! an optional `"finalized_slot"` u64 for checkpoint sync metadata.
//!
//! # Transaction model
//!
//! - Reads use `begin_read` (shared, lock-free on redb).
//! - Single-blob writes use `begin_write` + commit (one table touched).
//! - [`persist_snapshot`] and [`persist_signed_block_bundle`] batch multiple
//!   table writes into a single `begin_write` → commit for atomicity.

use std::path::Path;

use rapidhash::{RapidHashMap, RapidHashSet};
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};

use super::Bytes32;

/// Canonical state slot index: `slot → Bytes32 block root`.
const STATE_SLOT_TABLE: TableDefinition<'static, u64, &'static [u8]> =
    TableDefinition::new("canonical_state_slot");
/// Canonical block slot index: `slot → Bytes32 block root`.
const BLOCK_SLOT_TABLE: TableDefinition<'static, u64, &'static [u8]> =
    TableDefinition::new("canonical_block_slot");
/// Fork-choice metadata: `"head"|"finalized"|"justified" → Bytes32 root`,
/// plus `"finalized_slot" → u64` (LE bytes).
const META_TABLE: TableDefinition<'static, &'static str, &'static [u8]> =
    TableDefinition::new("canonical_meta");
/// State root lookup: `Bytes32 state_root → Bytes32 block_root`.
const STATE_ROOT_INDEX_TABLE: TableDefinition<'static, &'static [u8], &'static [u8]> =
    TableDefinition::new("canonical_state_root_index");
/// State blobs keyed by block root: `Bytes32 block_root → LEANSTRG envelope`.
const STATE_BLOB_TABLE: TableDefinition<'static, &'static [u8], &'static [u8]> =
    TableDefinition::new("canonical_state_blob");
/// Block blobs keyed by root: `Bytes32 block_root → LEANSTRG envelope`.
const BLOCK_BLOB_TABLE: TableDefinition<'static, &'static [u8], &'static [u8]> =
    TableDefinition::new("canonical_block_blob");
/// Signed block blobs keyed by root: `Bytes32 block_root → LEANSTRG envelope`.
const SIGNED_BLOCK_BLOB_TABLE: TableDefinition<'static, &'static [u8], &'static [u8]> =
    TableDefinition::new("canonical_signed_block_blob");

/// Thin wrapper around a single `redb::Database` file (`canonical.redb`).
///
/// All methods are synchronous and operate on a single redb `Database` handle.
/// Thread safety comes from redb's internal locking (single-writer, multi-reader).
pub(super) struct CanonicalDb {
    db: Database,
}

/// Result counters from blob garbage collection.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct BlobGcReport {
    pub removed_state_blobs: usize,
    pub removed_block_blobs: usize,
    pub removed_signed_block_blobs: usize,
}

impl CanonicalDb {
    /// Opens an existing redb file or creates a new one at `path`.
    ///
    /// Table creation (`ensure_tables`) only runs when the DB is first created.
    /// Existing DBs skip the write txn entirely, avoiding the lock acquisition
    /// + commit overhead on cold open.
    pub(super) fn open(path: &Path) -> Result<Self, String> {
        let is_new = !path.exists();
        let db = if is_new {
            Database::create(path).map_err(to_string)?
        } else {
            Database::open(path).map_err(to_string)?
        };
        let out = Self { db };
        if is_new {
            // Fresh DB: create all tables once.
            out.ensure_tables()?;
        } else if !out.tables_exist() {
            // Existing DB: avoid a write txn on the hot open path.
            // Only repair if a table is actually missing.
            out.ensure_tables()?;
        }
        Ok(out)
    }

    /// Fast existence check for all canonical tables using a read txn.
    ///
    /// Returns `false` when any table is missing or unreadable, allowing
    /// [`open`] to run one-time repair via [`ensure_tables`].
    #[inline]
    fn tables_exist(&self) -> bool {
        let Ok(read_txn) = self.db.begin_read() else {
            return false;
        };
        read_txn.open_table(STATE_SLOT_TABLE).is_ok()
            && read_txn.open_table(BLOCK_SLOT_TABLE).is_ok()
            && read_txn.open_table(META_TABLE).is_ok()
            && read_txn.open_table(STATE_ROOT_INDEX_TABLE).is_ok()
            && read_txn.open_table(STATE_BLOB_TABLE).is_ok()
            && read_txn.open_table(BLOCK_BLOB_TABLE).is_ok()
            && read_txn.open_table(SIGNED_BLOCK_BLOB_TABLE).is_ok()
    }

    /// Creates all canonical tables if they don't already exist.
    ///
    /// redb's `open_table` inside a write txn is idempotent — it creates the
    /// table on first call and returns the existing handle on subsequent calls.
    /// The write txn + commit is the cost paid on every `open()`, even when
    /// the DB is already fully initialized.
    #[inline]
    fn ensure_tables(&self) -> Result<(), String> {
        let write_txn = self.db.begin_write().map_err(to_string)?;
        {
            let _ = write_txn.open_table(STATE_SLOT_TABLE).map_err(to_string)?;
            let _ = write_txn.open_table(BLOCK_SLOT_TABLE).map_err(to_string)?;
            let _ = write_txn.open_table(META_TABLE).map_err(to_string)?;
            let _ = write_txn
                .open_table(STATE_ROOT_INDEX_TABLE)
                .map_err(to_string)?;
            let _ = write_txn.open_table(STATE_BLOB_TABLE).map_err(to_string)?;
            let _ = write_txn.open_table(BLOCK_BLOB_TABLE).map_err(to_string)?;
            let _ = write_txn
                .open_table(SIGNED_BLOCK_BLOB_TABLE)
                .map_err(to_string)?;
        }
        write_txn.commit().map_err(to_string)
    }

    /// Loads the full `canonical_state_slot` table into a `RapidHashMap`.
    /// Called once at startup by [`FileStore::load_from_disk`].
    pub(super) fn load_state_index(&self) -> Result<RapidHashMap<u64, Bytes32>, String> {
        self.load_slot_index(STATE_SLOT_TABLE)
    }

    /// Loads the full `canonical_block_slot` table into a `RapidHashMap`.
    /// Called once at startup by [`FileStore::load_from_disk`].
    pub(super) fn load_block_index(&self) -> Result<RapidHashMap<u64, Bytes32>, String> {
        self.load_slot_index(BLOCK_SLOT_TABLE)
    }

    /// Loads the full `state_root -> block_root` lookup table into memory.
    pub(super) fn load_state_root_index(&self) -> Result<RapidHashMap<Bytes32, Bytes32>, String> {
        let read_txn = self.db.begin_read().map_err(to_string)?;
        let table = read_txn
            .open_table(STATE_ROOT_INDEX_TABLE)
            .map_err(to_string)?;
        let mut out = RapidHashMap::default();
        for row in table.iter().map_err(to_string)? {
            let (state_root, block_root) = row.map_err(to_string)?;
            out.insert(
                bytes_to_root(state_root.value())?,
                bytes_to_root(block_root.value())?,
            );
        }
        Ok(out)
    }

    /// Generic slot-index loader. Opens a read txn, iterates every row in the
    /// B-tree, and builds a `slot → Bytes32` hashmap. Cost is proportional
    /// to the number of canonical rows (one B-tree scan).
    fn load_slot_index(
        &self,
        table_def: TableDefinition<'static, u64, &'static [u8]>,
    ) -> Result<RapidHashMap<u64, Bytes32>, String> {
        let read_txn = self.db.begin_read().map_err(to_string)?;
        let table = read_txn.open_table(table_def).map_err(to_string)?;
        let mut out = RapidHashMap::default();
        for row in table.iter().map_err(to_string)? {
            let (slot, root_bytes) = row.map_err(to_string)?;
            out.insert(slot.value(), bytes_to_root(root_bytes.value())?);
        }
        Ok(out)
    }

    /// Replaces the entire `canonical_state_slot` table with `index`.
    pub(super) fn persist_state_index(
        &self,
        index: &RapidHashMap<u64, Bytes32>,
    ) -> Result<(), String> {
        self.persist_slot_index(STATE_SLOT_TABLE, index)
    }

    /// Replaces the entire `canonical_block_slot` table with `index`.
    pub(super) fn persist_block_index(
        &self,
        index: &RapidHashMap<u64, Bytes32>,
    ) -> Result<(), String> {
        self.persist_slot_index(BLOCK_SLOT_TABLE, index)
    }

    /// Destructive rewrite of a slot index table: clears all existing rows
    /// via [`clear_u64_table`] (repeated `pop_first`), then inserts every
    /// entry from the in-memory hashmap. Single write txn for atomicity.
    fn persist_slot_index(
        &self,
        table_def: TableDefinition<'static, u64, &'static [u8]>,
        index: &RapidHashMap<u64, Bytes32>,
    ) -> Result<(), String> {
        let write_txn = self.db.begin_write().map_err(to_string)?;
        {
            let mut table = write_txn.open_table(table_def).map_err(to_string)?;
            clear_u64_table(&mut table)?;
            for (slot, root) in index {
                table
                    .insert(*slot, root.as_array().as_slice())
                    .map_err(to_string)?;
            }
        }
        write_txn.commit().map_err(to_string)
    }

    /// Reads fork-choice metadata from `canonical_meta`.
    ///
    /// Returns `(head, finalized, justified, finalized_slot)` as optional values.
    /// A missing key yields `None` for that position (normal for a fresh DB).
    pub(super) fn load_meta(
        &self,
    ) -> Result<
        (
            Option<Bytes32>,
            Option<Bytes32>,
            Option<Bytes32>,
            Option<u64>,
        ),
        String,
    > {
        let read_txn = self.db.begin_read().map_err(to_string)?;
        let table = read_txn.open_table(META_TABLE).map_err(to_string)?;

        let head = table
            .get("head")
            .map_err(to_string)?
            .map(|v| bytes_to_root(v.value()))
            .transpose()?;
        let finalized = table
            .get("finalized")
            .map_err(to_string)?
            .map(|v| bytes_to_root(v.value()))
            .transpose()?;
        let justified = table
            .get("justified")
            .map_err(to_string)?
            .map(|v| bytes_to_root(v.value()))
            .transpose()?;
        let finalized_slot = table
            .get("finalized_slot")
            .map_err(to_string)?
            .and_then(|v| bytes_to_u64(v.value()).ok());
        Ok((head, finalized, justified, finalized_slot))
    }

    /// Atomic full-snapshot write: clears and rewrites both slot index tables
    /// and upserts all three metadata keys in a single write transaction.
    ///
    /// Called by [`FileStore::flush_canonical`] when dirty flags are set.
    /// This is the "full rewrite" path — every canonical row is written,
    /// not just deltas.
    pub(super) fn persist_snapshot(
        &self,
        state_index: &RapidHashMap<u64, Bytes32>,
        block_index: &RapidHashMap<u64, Bytes32>,
        state_root_index: &RapidHashMap<Bytes32, Bytes32>,
        rewrite_state_root_index: bool,
        head: Option<Bytes32>,
        finalized: Option<Bytes32>,
        finalized_slot: Option<u64>,
        justified: Option<Bytes32>,
    ) -> Result<(), String> {
        let write_txn = self.db.begin_write().map_err(to_string)?;
        {
            let mut state_table = write_txn.open_table(STATE_SLOT_TABLE).map_err(to_string)?;
            clear_u64_table(&mut state_table)?;
            for (slot, root) in state_index {
                state_table
                    .insert(*slot, root.as_array().as_slice())
                    .map_err(to_string)?;
            }
        }
        {
            let mut block_table = write_txn.open_table(BLOCK_SLOT_TABLE).map_err(to_string)?;
            clear_u64_table(&mut block_table)?;
            for (slot, root) in block_index {
                block_table
                    .insert(*slot, root.as_array().as_slice())
                    .map_err(to_string)?;
            }
        }
        if rewrite_state_root_index {
            let mut state_root_table = write_txn
                .open_table(STATE_ROOT_INDEX_TABLE)
                .map_err(to_string)?;
            clear_bytes_table(&mut state_root_table)?;
            for (state_root, block_root) in state_root_index {
                state_root_table
                    .insert(
                        state_root.as_array().as_slice(),
                        block_root.as_array().as_slice(),
                    )
                    .map_err(to_string)?;
            }
        }
        {
            let mut meta_table = write_txn.open_table(META_TABLE).map_err(to_string)?;
            upsert_or_remove_meta(&mut meta_table, "head", head)?;
            upsert_or_remove_meta(&mut meta_table, "finalized", finalized)?;
            upsert_or_remove_meta_u64(&mut meta_table, "finalized_slot", finalized_slot)?;
            upsert_or_remove_meta(&mut meta_table, "justified", justified)?;
        }
        write_txn.commit().map_err(to_string)
    }

    /// Atomic delta write for the hot `put_signed_block` path.
    ///
    /// Unlike [`persist_snapshot`] this does **not** clear-and-rewrite the
    /// slot tables. Instead it:
    /// 1. Inserts the three blobs (state, block, signed block) by root.
    /// 2. Upserts only the changed slot→block-root rows (`state_upserts`,
    ///    `block_upserts`) — the new block plus any promoted pending entries.
    /// 3. Upserts metadata (head, finalized, justified).
    ///
    /// All writes happen in a single `begin_write` → `commit` so either
    /// everything lands on disk or nothing does.
    pub(super) fn persist_signed_block_bundle(
        &self,
        block_root: Bytes32,
        block_blob: &[u8],
        signed_blob: &[u8],
        state_root: Bytes32,
        state_blob: &[u8],
        state_upserts: &[(u64, Bytes32)],
        block_upserts: &[(u64, Bytes32)],
        head: Option<Bytes32>,
        finalized: Option<Bytes32>,
        finalized_slot: Option<u64>,
        justified: Option<Bytes32>,
    ) -> Result<(), String> {
        let write_txn = self.db.begin_write().map_err(to_string)?;
        {
            let mut state_root_index = write_txn
                .open_table(STATE_ROOT_INDEX_TABLE)
                .map_err(to_string)?;
            state_root_index
                .insert(
                    state_root.as_array().as_slice(),
                    block_root.as_array().as_slice(),
                )
                .map_err(to_string)?;
        }
        {
            let mut state_blob_table = write_txn.open_table(STATE_BLOB_TABLE).map_err(to_string)?;
            state_blob_table
                .insert(block_root.as_array().as_slice(), state_blob)
                .map_err(to_string)?;
        }
        {
            let mut block_blob_table = write_txn.open_table(BLOCK_BLOB_TABLE).map_err(to_string)?;
            block_blob_table
                .insert(block_root.as_array().as_slice(), block_blob)
                .map_err(to_string)?;
        }
        {
            let mut signed_blob_table = write_txn
                .open_table(SIGNED_BLOCK_BLOB_TABLE)
                .map_err(to_string)?;
            signed_blob_table
                .insert(block_root.as_array().as_slice(), signed_blob)
                .map_err(to_string)?;
        }
        {
            let mut state_table = write_txn.open_table(STATE_SLOT_TABLE).map_err(to_string)?;
            for (slot, root) in state_upserts {
                state_table
                    .insert(*slot, root.as_array().as_slice())
                    .map_err(to_string)?;
            }
        }
        {
            let mut block_table = write_txn.open_table(BLOCK_SLOT_TABLE).map_err(to_string)?;
            for (slot, root) in block_upserts {
                block_table
                    .insert(*slot, root.as_array().as_slice())
                    .map_err(to_string)?;
            }
        }
        {
            let mut meta_table = write_txn.open_table(META_TABLE).map_err(to_string)?;
            upsert_or_remove_meta(&mut meta_table, "head", head)?;
            upsert_or_remove_meta(&mut meta_table, "finalized", finalized)?;
            upsert_or_remove_meta_u64(&mut meta_table, "finalized_slot", finalized_slot)?;
            upsert_or_remove_meta(&mut meta_table, "justified", justified)?;
        }
        write_txn.commit().map_err(to_string)
    }

    /// Zero-copy state blob decode: reads from redb mmap and decodes via `f`
    /// without any intermediate heap allocation.
    pub(super) fn with_state_blob<T>(
        &self,
        root: Bytes32,
        f: impl FnOnce(&[u8]) -> Option<T>,
    ) -> Result<Option<T>, String> {
        self.with_blob(STATE_BLOB_TABLE, root, f)
    }

    /// Zero-copy block blob decode.
    pub(super) fn with_block_blob<T>(
        &self,
        root: Bytes32,
        f: impl FnOnce(&[u8]) -> Option<T>,
    ) -> Result<Option<T>, String> {
        self.with_blob(BLOCK_BLOB_TABLE, root, f)
    }

    /// Zero-copy signed-block blob decode.
    pub(super) fn with_signed_block_blob<T>(
        &self,
        root: Bytes32,
        f: impl FnOnce(&[u8]) -> Option<T>,
    ) -> Result<Option<T>, String> {
        self.with_blob(SIGNED_BLOCK_BLOB_TABLE, root, f)
    }

    /// Writes a state-root lookup row: `state_root -> block_root`.
    pub(super) fn persist_state_root_mapping(
        &self,
        state_root: Bytes32,
        block_root: Bytes32,
    ) -> Result<(), String> {
        let write_txn = self.db.begin_write().map_err(to_string)?;
        {
            let mut table = write_txn
                .open_table(STATE_ROOT_INDEX_TABLE)
                .map_err(to_string)?;
            table
                .insert(
                    state_root.as_array().as_slice(),
                    block_root.as_array().as_slice(),
                )
                .map_err(to_string)?;
        }
        write_txn.commit().map_err(to_string)
    }

    /// Writes a state blob (already LEANSTRG-wrapped) keyed by block root.
    /// Used by [`FileStore::put_state`] for individual state persistence.
    pub(super) fn persist_state_blob(
        &self,
        block_root: Bytes32,
        encoded: &[u8],
    ) -> Result<(), String> {
        self.persist_blob(STATE_BLOB_TABLE, block_root, encoded)
    }

    /// Writes a block blob (already LEANSTRG-wrapped) keyed by block root.
    /// Used by [`FileStore::put_block`] for individual block persistence.
    pub(super) fn persist_block_blob(&self, root: Bytes32, encoded: &[u8]) -> Result<(), String> {
        self.persist_blob(BLOCK_BLOB_TABLE, root, encoded)
    }

    /// Removes blob rows that are no longer referenced by canonical/pending roots.
    ///
    /// `keep_state_block_roots` is used for state blobs and `keep_block_roots` for
    /// block + signed block blobs.
    pub(super) fn gc_unreferenced_blobs(
        &self,
        keep_state_block_roots: &RapidHashSet<Bytes32>,
        keep_block_roots: &RapidHashSet<Bytes32>,
    ) -> Result<BlobGcReport, String> {
        let write_txn = self.db.begin_write().map_err(to_string)?;
        let report = {
            let mut state_blob_table = write_txn.open_table(STATE_BLOB_TABLE).map_err(to_string)?;
            let removed_state_blobs =
                gc_blob_table(&mut state_blob_table, keep_state_block_roots).map_err(to_string)?;

            let mut block_blob_table = write_txn.open_table(BLOCK_BLOB_TABLE).map_err(to_string)?;
            let removed_block_blobs =
                gc_blob_table(&mut block_blob_table, keep_block_roots).map_err(to_string)?;

            let mut signed_blob_table = write_txn
                .open_table(SIGNED_BLOCK_BLOB_TABLE)
                .map_err(to_string)?;
            let removed_signed_block_blobs =
                gc_blob_table(&mut signed_blob_table, keep_block_roots).map_err(to_string)?;

            BlobGcReport {
                removed_state_blobs,
                removed_block_blobs,
                removed_signed_block_blobs,
            }
        };
        write_txn.commit().map_err(to_string)?;
        Ok(report)
    }

    /// Zero-copy blob read: opens a read txn, looks up the key, and passes
    /// the raw mmap `&[u8]` directly to `f` — no `.to_vec()`, no heap alloc.
    /// The closure runs while the redb read guard is alive.
    #[inline]
    fn with_blob<T>(
        &self,
        table_def: TableDefinition<'static, &'static [u8], &'static [u8]>,
        root: Bytes32,
        f: impl FnOnce(&[u8]) -> Option<T>,
    ) -> Result<Option<T>, String> {
        let read_txn = self.db.begin_read().map_err(to_string)?;
        let table = read_txn.open_table(table_def).map_err(to_string)?;
        match table.get(root.as_array().as_slice()).map_err(to_string)? {
            Some(guard) => Ok(f(guard.value())),
            None => Ok(None),
        }
    }

    /// Generic single-blob write: `begin_write` → `insert` → `commit`.
    ///
    /// Used for individual `put_state` / `put_block` calls (not the hot
    /// `put_signed_block` path which uses [`persist_signed_block_bundle`]).
    fn persist_blob(
        &self,
        table_def: TableDefinition<'static, &'static [u8], &'static [u8]>,
        root: Bytes32,
        encoded: &[u8],
    ) -> Result<(), String> {
        let write_txn = self.db.begin_write().map_err(to_string)?;
        {
            let mut table = write_txn.open_table(table_def).map_err(to_string)?;
            table
                .insert(root.as_array().as_slice(), encoded)
                .map_err(to_string)?;
        }
        write_txn.commit().map_err(to_string)
    }
}

/// Converts a raw `&[u8]` from redb into a `Bytes32`. Rejects non-32-byte slices.
#[inline]
fn bytes_to_root(raw: &[u8]) -> Result<Bytes32, String> {
    if raw.len() != 32 {
        return Err("canonical db root length must be 32".to_string());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(raw);
    Ok(Bytes32::from(out))
}

/// Converts a raw `&[u8]` from redb into a `u64`. Rejects non-8-byte slices.
#[inline]
fn bytes_to_u64(raw: &[u8]) -> Result<u64, String> {
    if raw.len() != 8 {
        return Err("canonical db u64 length must be 8".to_string());
    }
    let mut out = [0u8; 8];
    out.copy_from_slice(raw);
    Ok(u64::from_le_bytes(out))
}

/// Adapter to convert any `Display` error into `String` for `map_err`.
#[inline]
fn to_string<E: core::fmt::Display>(err: E) -> String {
    err.to_string()
}

/// Removes all rows from a `u64`-keyed table by draining via `pop_first`.
///
/// redb has no `TRUNCATE`-equivalent, so this pops one row at a time.
/// Cost is `O(n)` in the number of existing rows.
fn clear_u64_table(table: &mut redb::Table<'_, u64, &'static [u8]>) -> Result<(), String> {
    while table.pop_first().map_err(to_string)?.is_some() {}
    Ok(())
}

/// Inserts a metadata key if `value` is `Some`, removes it if `None`.
fn upsert_or_remove_meta(
    table: &mut redb::Table<'_, &'static str, &'static [u8]>,
    key: &'static str,
    value: Option<Bytes32>,
) -> Result<(), String> {
    if let Some(root) = value {
        table
            .insert(key, root.as_array().as_slice())
            .map_err(to_string)?;
    } else {
        let _ = table.remove(key).map_err(to_string)?;
    }
    Ok(())
}

/// Inserts a metadata key if `value` is `Some`, removes it if `None`.
fn upsert_or_remove_meta_u64(
    table: &mut redb::Table<'_, &'static str, &'static [u8]>,
    key: &'static str,
    value: Option<u64>,
) -> Result<(), String> {
    if let Some(value) = value {
        let bytes = value.to_le_bytes();
        table.insert(key, bytes.as_ref()).map_err(to_string)?;
    } else {
        let _ = table.remove(key).map_err(to_string)?;
    }
    Ok(())
}

/// Removes every blob row whose key (root) is not in `keep_roots`.
fn gc_blob_table(
    table: &mut redb::Table<'_, &'static [u8], &'static [u8]>,
    keep_roots: &RapidHashSet<Bytes32>,
) -> Result<usize, String> {
    let mut to_delete = Vec::<[u8; 32]>::new();
    for row in table.iter().map_err(to_string)? {
        let (root, _) = row.map_err(to_string)?;
        let root = bytes_to_root(root.value())?;
        if !keep_roots.contains(&root) {
            to_delete.push(root.as_array());
        }
    }
    for root in &to_delete {
        let _ = table.remove(root.as_slice()).map_err(to_string)?;
    }
    Ok(to_delete.len())
}

/// Removes every key/value row from a bytes-keyed table.
fn clear_bytes_table(
    table: &mut redb::Table<'_, &'static [u8], &'static [u8]>,
) -> Result<(), String> {
    while table.pop_first().map_err(to_string)?.is_some() {}
    Ok(())
}
