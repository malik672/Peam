use std::path::Path;

use rapidhash::RapidHashMap;
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};

use super::Bytes32;

const STATE_SLOT_TABLE: TableDefinition<'static, u64, &'static [u8]> =
    TableDefinition::new("canonical_state_slot");
const BLOCK_SLOT_TABLE: TableDefinition<'static, u64, &'static [u8]> =
    TableDefinition::new("canonical_block_slot");
const META_TABLE: TableDefinition<'static, &'static str, &'static [u8]> =
    TableDefinition::new("canonical_meta");
const STATE_BLOB_TABLE: TableDefinition<'static, &'static [u8], &'static [u8]> =
    TableDefinition::new("canonical_state_blob");
const BLOCK_BLOB_TABLE: TableDefinition<'static, &'static [u8], &'static [u8]> =
    TableDefinition::new("canonical_block_blob");
const SIGNED_BLOCK_BLOB_TABLE: TableDefinition<'static, &'static [u8], &'static [u8]> =
    TableDefinition::new("canonical_signed_block_blob");

pub(super) struct CanonicalDb {
    db: Database,
}

impl CanonicalDb {
    pub(super) fn open(path: &Path) -> Result<Self, String> {
        let db = if path.exists() {
            Database::open(path).map_err(to_string)?
        } else {
            Database::create(path).map_err(to_string)?
        };
        let out = Self { db };
        out.ensure_tables()?;
        Ok(out)
    }

    fn ensure_tables(&self) -> Result<(), String> {
        let write_txn = self.db.begin_write().map_err(to_string)?;
        {
            let _ = write_txn.open_table(STATE_SLOT_TABLE).map_err(to_string)?;
            let _ = write_txn.open_table(BLOCK_SLOT_TABLE).map_err(to_string)?;
            let _ = write_txn.open_table(META_TABLE).map_err(to_string)?;
            let _ = write_txn.open_table(STATE_BLOB_TABLE).map_err(to_string)?;
            let _ = write_txn.open_table(BLOCK_BLOB_TABLE).map_err(to_string)?;
            let _ = write_txn
                .open_table(SIGNED_BLOCK_BLOB_TABLE)
                .map_err(to_string)?;
        }
        write_txn.commit().map_err(to_string)
    }

    pub(super) fn load_state_index(&self) -> Result<RapidHashMap<u64, Bytes32>, String> {
        self.load_slot_index(STATE_SLOT_TABLE)
    }

    pub(super) fn load_block_index(&self) -> Result<RapidHashMap<u64, Bytes32>, String> {
        self.load_slot_index(BLOCK_SLOT_TABLE)
    }

    fn load_slot_index(
        &self,
        table_def: TableDefinition<'static, u64, &'static [u8]>,
    ) -> Result<RapidHashMap<u64, Bytes32>, String> {
        let read_txn = self.db.begin_read().map_err(to_string)?;
        let table = read_txn.open_table(table_def).map_err(to_string)?;
        let mut out = RapidHashMap::default();
        for row in table.iter().map_err(to_string)? {
            let (slot, root_bytes) = row.map_err(to_string)?;
            let root = bytes_to_root(root_bytes.value())?;
            out.insert(slot.value(), root);
        }
        Ok(out)
    }

    pub(super) fn persist_state_index(
        &self,
        index: &RapidHashMap<u64, Bytes32>,
    ) -> Result<(), String> {
        self.persist_slot_index(STATE_SLOT_TABLE, index)
    }

    pub(super) fn persist_block_index(
        &self,
        index: &RapidHashMap<u64, Bytes32>,
    ) -> Result<(), String> {
        self.persist_slot_index(BLOCK_SLOT_TABLE, index)
    }

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

    pub(super) fn load_meta(
        &self,
    ) -> Result<(Option<Bytes32>, Option<Bytes32>, Option<Bytes32>), String> {
        let read_txn = self.db.begin_read().map_err(to_string)?;
        let table = read_txn.open_table(META_TABLE).map_err(to_string)?;

        let head = match table.get("head").map_err(to_string)? {
            Some(v) => Some(bytes_to_root(v.value())?),
            None => None,
        };
        let finalized = match table.get("finalized").map_err(to_string)? {
            Some(v) => Some(bytes_to_root(v.value())?),
            None => None,
        };
        let justified = match table.get("justified").map_err(to_string)? {
            Some(v) => Some(bytes_to_root(v.value())?),
            None => None,
        };
        Ok((head, finalized, justified))
    }

    pub(super) fn persist_snapshot(
        &self,
        state_index: &RapidHashMap<u64, Bytes32>,
        block_index: &RapidHashMap<u64, Bytes32>,
        head: Option<Bytes32>,
        finalized: Option<Bytes32>,
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
        {
            let mut meta_table = write_txn.open_table(META_TABLE).map_err(to_string)?;
            upsert_or_remove_meta(&mut meta_table, "head", head)?;
            upsert_or_remove_meta(&mut meta_table, "finalized", finalized)?;
            upsert_or_remove_meta(&mut meta_table, "justified", justified)?;
        }
        write_txn.commit().map_err(to_string)
    }

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
        justified: Option<Bytes32>,
    ) -> Result<(), String> {
        let write_txn = self.db.begin_write().map_err(to_string)?;
        {
            let mut state_blob_table = write_txn.open_table(STATE_BLOB_TABLE).map_err(to_string)?;
            state_blob_table
                .insert(state_root.as_array().as_slice(), state_blob)
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
            upsert_or_remove_meta(&mut meta_table, "justified", justified)?;
        }
        write_txn.commit().map_err(to_string)
    }

    pub(super) fn load_state_blob(&self, root: Bytes32) -> Result<Option<Vec<u8>>, String> {
        self.load_blob(STATE_BLOB_TABLE, root)
    }

    pub(super) fn load_block_blob(&self, root: Bytes32) -> Result<Option<Vec<u8>>, String> {
        self.load_blob(BLOCK_BLOB_TABLE, root)
    }

    pub(super) fn load_signed_block_blob(&self, root: Bytes32) -> Result<Option<Vec<u8>>, String> {
        self.load_blob(SIGNED_BLOCK_BLOB_TABLE, root)
    }

    pub(super) fn persist_state_blob(&self, root: Bytes32, encoded: &[u8]) -> Result<(), String> {
        self.persist_blob(STATE_BLOB_TABLE, root, encoded)
    }

    pub(super) fn persist_block_blob(&self, root: Bytes32, encoded: &[u8]) -> Result<(), String> {
        self.persist_blob(BLOCK_BLOB_TABLE, root, encoded)
    }

    fn load_blob(
        &self,
        table_def: TableDefinition<'static, &'static [u8], &'static [u8]>,
        root: Bytes32,
    ) -> Result<Option<Vec<u8>>, String> {
        let read_txn = self.db.begin_read().map_err(to_string)?;
        let table = read_txn.open_table(table_def).map_err(to_string)?;
        Ok(table
            .get(root.as_array().as_slice())
            .map_err(to_string)?
            .map(|value| value.value().to_vec()))
    }

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

fn bytes_to_root(raw: &[u8]) -> Result<Bytes32, String> {
    if raw.len() != 32 {
        return Err("canonical db root length must be 32".to_string());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(raw);
    Ok(Bytes32::from(out))
}

#[inline]
fn to_string<E: core::fmt::Display>(err: E) -> String {
    err.to_string()
}

fn clear_u64_table(table: &mut redb::Table<'_, u64, &'static [u8]>) -> Result<(), String> {
    while table.pop_first().map_err(to_string)?.is_some() {}
    Ok(())
}

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
