use lean_eth::containers::attestation::{Attestation, AttestationData};
use lean_eth::containers::block::{
    Block, BlockBody, BlockSignatures, BlockWithAttestation, SignedBlockWithAttestation,
};
use lean_eth::containers::checkpoint::Checkpoint;
use lean_eth::containers::req_resp::Status;
use lean_eth::containers::state::{State, Validators};
use lean_eth::containers::validator::{Validator, ValidatorIndex};
use lean_eth::networking::{
    LeanRequestMessage, LeanResponseMessage, ReqRespHandler, StoreReqRespHandler,
};
use lean_eth::slot::Slot;
use lean_eth::ssz::HashTreeRoot;
use lean_eth::storage::{FileStore, MemoryStore, Store};
use lean_eth::types::bitlist::BitList;
use lean_eth::types::bytes::{Bytes32, Bytes52, Bytes3112};
use lean_eth::types::collections::SszList;
use lean_eth::types::uint::Uint64;
use redb::{Database, TableDefinition};
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

fn temp_store_dir(test_name: &str) -> std::path::PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    std::env::temp_dir().join(format!("lean_eth_store_{test_name}_{stamp}"))
}

const STATE_BLOB_TABLE: TableDefinition<'static, &'static [u8], &'static [u8]> =
    TableDefinition::new("canonical_state_blob");
const BLOCK_BLOB_TABLE: TableDefinition<'static, &'static [u8], &'static [u8]> =
    TableDefinition::new("canonical_block_blob");

fn overwrite_blob_in_db(
    dir: &std::path::Path,
    table: TableDefinition<'static, &'static [u8], &'static [u8]>,
    root: Bytes32,
    raw: &[u8],
) {
    let db = Database::open(dir.join("canonical.redb")).expect("open canonical db");
    let write_txn = db.begin_write().expect("begin write");
    {
        let mut t = write_txn.open_table(table).expect("open table");
        t.insert(root.as_array().as_slice(), raw)
            .expect("insert raw blob");
    }
    write_txn.commit().expect("commit");
}

fn dummy_block() -> Block {
    let body = BlockBody {
        attestations: SszList::new(vec![]).expect("attestations"),
    };
    Block {
        slot: Slot(Uint64(0)),
        proposer_index: ValidatorIndex(Uint64(0)),
        parent_root: Bytes32::zero(),
        state_root: Bytes32::zero(),
        body,
    }
}

fn dummy_state() -> State {
    State::generate_genesis(Uint64(0), Validators::new(vec![]).expect("validators"))
}

fn dummy_validating_state() -> State {
    let v = Validator {
        pubkey: Bytes52::from([0x01u8; 52]),
        index: ValidatorIndex(Uint64(0)),
        balance: Uint64(0),
    };
    let validators = Validators::new(vec![v]).expect("validators");
    State::generate_genesis(Uint64(0), validators)
}

fn build_signed_block(state: &State, slot: u64) -> SignedBlockWithAttestation {
    // clone again
    let mut temp = state.clone();
    temp.process_slots(Slot(Uint64(slot)))
        .expect("process slots");
    let parent_root = Bytes32::from(temp.latest_block_header.hash_tree_root());
    let body = BlockBody {
        attestations: SszList::new(vec![]).expect("attestations"),
    };
    let mut block = Block {
        slot: Slot(Uint64(slot)),
        proposer_index: ValidatorIndex(Uint64(0)),
        parent_root,
        state_root: Bytes32::zero(),
        body,
    };
    let mut post = state.clone();
    post.process_slots(block.slot).expect("process slots");
    let header = block.header();
    post.process_block_header(header).expect("process header");
    post.process_block_body(&block.body, header.body_root)
        .expect("process body");
    block.state_root = Bytes32::from(post.hash_tree_root());

    let proposer_attestation = Attestation {
        aggregation_bits: BitList::new(vec![true]).expect("participants"),
        data: AttestationData {
            slot: block.slot,
            head: Checkpoint {
                root: Bytes32::zero(),
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
    SignedBlockWithAttestation { message, signature }
}

#[test]
fn memory_store_roundtrip() {
    let mut store = MemoryStore::new();
    let root = Bytes32::from([0x11u8; 32]);
    let block = dummy_block();
    let state_root = Bytes32::from([0x22u8; 32]);
    let state = dummy_state();

    store.put_block(root, block.clone());
    let fetched = store.get_block(&root).expect("block");
    assert_eq!(fetched, block);
    let fetched_by_slot = store.get_block_by_slot(0).expect("block by slot");
    assert_eq!(fetched_by_slot, block);

    store.put_state(state_root, state.clone());
    let fetched_state = store.get_state(&state_root).expect("state");
    assert_eq!(fetched_state, state);
    let fetched_state_by_slot = store.get_state_by_slot(0).expect("state by slot");
    assert_eq!(fetched_state_by_slot, state);

    store.set_head(root);
    assert_eq!(store.head(), Some(root));

    store.set_finalized(state_root);
    assert_eq!(store.finalized(), Some(state_root));

    store.set_justified(root);
    assert_eq!(store.justified(), Some(root));
}

#[test]
fn put_signed_block_updates_forkchoice_roots() {
    let v = Validator {
        pubkey: Bytes52::from([0x01u8; 52]),
        index: ValidatorIndex(Uint64(0)),
        balance: Uint64(0),
    };
    let validators = Validators::new(vec![v]).expect("validators");
    let mut state = State::generate_genesis(Uint64(0), validators);

    let signed = build_signed_block(&state, 1);
    let root = Bytes32::from([0x33u8; 32]);
    let mut store = MemoryStore::new();
    store
        .put_signed_block(root, signed, &mut state)
        .expect("put signed block");

    assert_eq!(store.head(), Some(root));
    assert_eq!(store.justified(), Some(state.latest_justified.root));
    assert_eq!(store.finalized(), Some(state.latest_finalized.root));
}

#[test]
fn status_prefers_store_head_and_finalized() {
    let v = Validator {
        pubkey: Bytes52::from([0x01u8; 52]),
        index: ValidatorIndex(Uint64(0)),
        balance: Uint64(0),
    };
    let validators = Validators::new(vec![v]).expect("validators");
    let mut state = State::generate_genesis(Uint64(0), validators);

    let signed = build_signed_block(&state, 1);
    let head_root = Bytes32::from([0x44u8; 32]);
    let mut store = MemoryStore::new();
    store
        .put_signed_block(head_root, signed, &mut state)
        .expect("put signed block");

    let store = Arc::new(RwLock::new(store));
    let state = Arc::new(RwLock::new(state));
    let handler = StoreReqRespHandler::new(state.clone(), store);

    let resp = handler
        .on_request(LeanRequestMessage::Status(Status {
            fork_digest: Bytes32::zero(),
            finalized_root: Bytes32::zero(),
            finalized_epoch: Uint64(0),
            head_root: Bytes32::zero(),
            head_slot: Uint64(0),
        }))
        .expect("status response");
    let LeanResponseMessage::Status(status) = resp else {
        panic!("expected status");
    };

    assert_eq!(status.head_root, head_root);
    let finalized_root = state.read().expect("state lock").latest_finalized.root;
    assert_eq!(status.finalized_root, finalized_root);
}

#[test]
fn file_store_roundtrip_persists_data_and_meta() {
    let dir = temp_store_dir("roundtrip");
    let mut store = FileStore::open(&dir).expect("open file store");

    let root = Bytes32::from([0x55u8; 32]);
    let block = dummy_block();
    store.put_block(root, block.clone());

    let state_root = Bytes32::from([0x66u8; 32]);
    let state = dummy_state();
    store.put_state(state_root, state.clone());

    store.set_head(root);
    store.set_finalized(state_root);
    store.set_justified(root);

    drop(store);

    let reopened = FileStore::open(&dir).expect("reopen file store");
    assert_eq!(reopened.get_block(&root), Some(block.clone()));
    assert_eq!(reopened.get_block_by_slot(0), Some(block));
    assert_eq!(reopened.get_state(&state_root), Some(state.clone()));
    assert_eq!(reopened.get_state_by_slot(0), Some(state));
    assert_eq!(reopened.head(), Some(root));
    assert_eq!(reopened.finalized(), Some(state_root));
    assert_eq!(reopened.justified(), Some(root));

    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn file_store_put_signed_block_persists_chain_heads() {
    let dir = temp_store_dir("signed_block");
    let mut store = FileStore::open(&dir).expect("open file store");

    let v = Validator {
        pubkey: Bytes52::from([0x01u8; 52]),
        index: ValidatorIndex(Uint64(0)),
        balance: Uint64(0),
    };
    let validators = Validators::new(vec![v]).expect("validators");
    let mut state = State::generate_genesis(Uint64(0), validators);

    let signed = build_signed_block(&state, 1);
    let root = Bytes32::from([0x77u8; 32]);
    store
        .put_signed_block(root, signed.clone(), &mut state)
        .expect("put signed block");

    drop(store);

    let reopened = FileStore::open(&dir).expect("reopen file store");
    assert!(reopened.get_signed_block(&root).is_some());
    // Slot 1 is non-finalized and lives in the in-memory pending window only.
    // After reopen, pending is empty by design.
    assert_eq!(reopened.get_block_by_slot(1), None);
    assert_eq!(reopened.get_block(&root), Some(signed.message.block.clone()));
    assert_eq!(reopened.head(), Some(root));
    assert_eq!(reopened.justified(), Some(state.latest_justified.root));
    assert_eq!(reopened.finalized(), Some(state.latest_finalized.root));

    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn file_store_skips_corrupt_entries_and_reports_recovery() {
    let dir = temp_store_dir("corrupt_recovery");
    std::fs::create_dir_all(&dir).expect("store dir");
    // Legacy file blobs are ignored by DB-backed storage.
    std::fs::create_dir_all(dir.join("blocks")).expect("legacy blocks dir");
    std::fs::write(dir.join("blocks").join("invalid_root.ssz"), [0x01, 0x02])
        .expect("write legacy corrupt block");

    let store = FileStore::open(&dir).expect("open file store");
    let report = store.recovery_report();
    assert_eq!(report.skipped_corrupt, 0);
    assert_eq!(store.head(), None);
    assert_eq!(store.finalized(), None);
    assert_eq!(store.justified(), None);

    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn file_store_rejects_unsupported_schema_version() {
    let dir = temp_store_dir("schema_mismatch");
    std::fs::create_dir_all(&dir).expect("root dir");
    std::fs::write(dir.join("schema_version"), "999\n").expect("schema file");

    let err = match FileStore::open(&dir) {
        Ok(_) => panic!("expected schema mismatch error"),
        Err(err) => err,
    };
    assert!(err.contains("unsupported storage schema version"));

    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn file_store_skips_blob_with_bad_checksum_header() {
    let dir = temp_store_dir("bad_checksum");
    std::fs::create_dir_all(dir.join("blocks")).expect("blocks dir");
    std::fs::create_dir_all(dir.join("signed_blocks")).expect("signed blocks dir");
    std::fs::create_dir_all(dir.join("states")).expect("states dir");

    let mut bad = Vec::new();
    bad.extend_from_slice(b"LEANSTRG"); // magic
    bad.push(1); // version
    bad.push(2); // kind block
    bad.extend_from_slice(&1u32.to_le_bytes()); // payload len
    bad.extend_from_slice(&[0u8; 32]); // bad checksum
    bad.push(0x42); // payload

    std::fs::write(
        dir.join("blocks")
            .join("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff.ssz"),
        bad,
    )
    .expect("write bad blob");

    let store = FileStore::open(&dir).expect("open file store");
    let report = store.recovery_report();
    assert_eq!(report.skipped_corrupt, 0);
    assert!(store.get_block_by_slot(0).is_none());

    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn file_store_persists_slot_indexes() {
    let dir = temp_store_dir("slot_indexes");
    let mut store = FileStore::open(&dir).expect("open file store");

    let mut state = dummy_state();
    state.slot = Slot(Uint64(7));
    let state_root = Bytes32::from([0x88u8; 32]);
    store.put_state(state_root, state.clone());

    let mut block = dummy_block();
    block.slot = Slot(Uint64(9));
    let block_root = Bytes32::from([0x99u8; 32]);
    store.put_block(block_root, block.clone());

    drop(store);

    assert!(dir.join("canonical.redb").exists());

    let reopened = FileStore::open(&dir).expect("reopen file store");
    assert_eq!(reopened.get_state_by_slot(7), Some(state));
    assert_eq!(reopened.get_block_by_slot(9), Some(block));

    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn file_store_rebuilds_indexes_when_index_file_is_corrupt() {
    let dir = temp_store_dir("corrupt_indexes");
    let mut store = FileStore::open(&dir).expect("open file store");

    let mut state = dummy_state();
    state.slot = Slot(Uint64(3));
    let state_root = Bytes32::from([0xAAu8; 32]);
    store.put_state(state_root, state.clone());

    let mut block = dummy_block();
    block.slot = Slot(Uint64(4));
    let block_root = Bytes32::from([0xBBu8; 32]);
    store.put_block(block_root, block.clone());
    drop(store);

    std::fs::write(dir.join("state_index.txt"), "not-an-index\n").expect("corrupt state index");
    std::fs::write(dir.join("block_index.txt"), "bad=zz\n").expect("corrupt block index");

    let reopened = FileStore::open(&dir).expect("reopen file store");
    let report = reopened.recovery_report();
    assert_eq!(report.skipped_corrupt, 0);
    assert_eq!(reopened.get_state_by_slot(3), Some(state));
    assert_eq!(reopened.get_block_by_slot(4), Some(block));

    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn prune_keeps_head_justified_finalized() {
    let dir = temp_store_dir("prune_pinned");
    let mut store = FileStore::open(&dir).expect("open file store");

    let mut old_block_a = dummy_block();
    old_block_a.slot = Slot(Uint64(1));
    let old_root_a = Bytes32::from([0x10u8; 32]);
    store.put_block(old_root_a, old_block_a.clone());

    let mut old_block_b = dummy_block();
    old_block_b.slot = Slot(Uint64(2));
    let old_root_b = Bytes32::from([0x11u8; 32]);
    store.put_block(old_root_b, old_block_b.clone());

    let mut old_block_c = dummy_block();
    old_block_c.slot = Slot(Uint64(3));
    let old_root_c = Bytes32::from([0x12u8; 32]);
    store.put_block(old_root_c, old_block_c);

    let mut new_block = dummy_block();
    new_block.slot = Slot(Uint64(20));
    let new_root = Bytes32::from([0x13u8; 32]);
    store.put_block(new_root, new_block);

    store.set_head(old_root_a);
    store.set_justified(old_root_b);
    store.set_finalized(old_root_b);

    let report = store.prune(20, 5).expect("prune");
    assert!(report.kept_pinned >= 2);
    assert!(report.removed_blocks >= 1);

    assert!(store.get_block(&old_root_a).is_some());
    assert!(store.get_block(&old_root_b).is_some());
    assert!(store.get_block(&old_root_c).is_some());
    assert!(store.get_block(&new_root).is_some());

    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn prune_removes_old_noncanonical_entries() {
    let dir = temp_store_dir("prune_noncanonical");
    let mut store = FileStore::open(&dir).expect("open file store");

    let mut old_state = dummy_state();
    old_state.slot = Slot(Uint64(2));
    let old_state_root = Bytes32::from([0x21u8; 32]);
    store.put_state(old_state_root, old_state);

    let mut new_state = dummy_state();
    new_state.slot = Slot(Uint64(27));
    let new_state_root = Bytes32::from([0x22u8; 32]);
    store.put_state(new_state_root, new_state);

    let mut old_block = dummy_block();
    old_block.slot = Slot(Uint64(3));
    let old_block_root = Bytes32::from([0x23u8; 32]);
    store.put_block(old_block_root, old_block);

    let mut new_block = dummy_block();
    new_block.slot = Slot(Uint64(28));
    let new_block_root = Bytes32::from([0x24u8; 32]);
    store.put_block(new_block_root, new_block);

    let mut chain_state = dummy_validating_state();
    let old_signed = build_signed_block(&chain_state, 4);
    let old_signed_root = Bytes32::from([0x25u8; 32]);
    store
        .put_signed_block(old_signed_root, old_signed, &mut chain_state)
        .expect("put old signed");

    let new_signed = build_signed_block(&chain_state, 26);
    let new_signed_root = Bytes32::from([0x26u8; 32]);
    store
        .put_signed_block(new_signed_root, new_signed, &mut chain_state)
        .expect("put new signed");

    let report = store.prune(30, 5).expect("prune");
    assert!(report.removed_states >= 1);
    // Canonical-index prune only; pending/noncanonical block entries are not counted.
    assert!(report.removed_blocks >= 1);
    assert_eq!(report.removed_signed_blocks, 0);

    assert!(store.get_state(&old_state_root).is_some());
    assert!(store.get_state(&new_state_root).is_some());
    assert!(store.get_block(&old_block_root).is_some());
    assert!(store.get_block(&new_block_root).is_some());
    assert!(store.get_signed_block(&old_signed_root).is_some());
    assert!(store.get_signed_block(&new_signed_root).is_some());

    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn prune_rewrites_indexes_consistently() {
    let dir = temp_store_dir("prune_indexes");
    let mut store = FileStore::open(&dir).expect("open file store");

    let mut old_state = dummy_state();
    old_state.slot = Slot(Uint64(5));
    let old_state_root = Bytes32::from([0x31u8; 32]);
    store.put_state(old_state_root, old_state);

    let mut new_state = dummy_state();
    new_state.slot = Slot(Uint64(44));
    let new_state_root = Bytes32::from([0x32u8; 32]);
    store.put_state(new_state_root, new_state.clone());

    let mut old_block = dummy_block();
    old_block.slot = Slot(Uint64(7));
    let old_block_root = Bytes32::from([0x33u8; 32]);
    store.put_block(old_block_root, old_block);

    let mut new_block = dummy_block();
    new_block.slot = Slot(Uint64(45));
    let new_block_root = Bytes32::from([0x34u8; 32]);
    store.put_block(new_block_root, new_block.clone());

    store.prune(50, 10).expect("prune");

    assert!(store.get_state_by_slot(5).is_none());
    assert_eq!(store.get_state_by_slot(44), Some(new_state));
    assert!(store.get_block_by_slot(7).is_none());
    assert_eq!(store.get_block_by_slot(45), Some(new_block));

    assert!(dir.join("canonical.redb").exists());

    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn prune_persists_across_reopen() {
    let dir = temp_store_dir("prune_reopen");
    let mut store = FileStore::open(&dir).expect("open file store");

    let mut old_block = dummy_block();
    old_block.slot = Slot(Uint64(2));
    let old_root = Bytes32::from([0x41u8; 32]);
    store.put_block(old_root, old_block);

    let mut new_block = dummy_block();
    new_block.slot = Slot(Uint64(52));
    let new_root = Bytes32::from([0x42u8; 32]);
    store.put_block(new_root, new_block.clone());

    store.prune(60, 10).expect("prune");
    drop(store);

    let reopened = FileStore::open(&dir).expect("reopen file store");
    assert!(reopened.get_block(&old_root).is_some());
    assert_eq!(reopened.get_block(&new_root), Some(new_block.clone()));
    assert!(reopened.get_block_by_slot(2).is_none());
    assert_eq!(reopened.get_block_by_slot(52), Some(new_block));

    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn interrupted_temp_file_does_not_break_reopen() {
    let dir = temp_store_dir("interrupted_temp");
    let mut store = FileStore::open(&dir).expect("open file store");

    let mut block = dummy_block();
    block.slot = Slot(Uint64(13));
    let root = Bytes32::from([0x51u8; 32]);
    store.put_block(root, block.clone());
    drop(store);

    std::fs::write(dir.join(".canonical.redb.tmp.interrupted"), [0xAB, 0xCD])
        .expect("write temp blob");

    let reopened = FileStore::open(&dir).expect("reopen file store");
    assert_eq!(reopened.get_block(&root), Some(block));
    let report = reopened.recovery_report();
    assert_eq!(report.skipped_unknown_version, 0);

    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn pending_slot_index_is_ephemeral_but_blob_is_durable() {
    let dir = temp_store_dir("pending_ephemeral");
    let mut store = FileStore::open(&dir).expect("open file store");

    let mut finalized_block = dummy_block();
    finalized_block.slot = Slot(Uint64(1));
    let finalized_root = Bytes32::from([0x61u8; 32]);
    store.put_block(finalized_root, finalized_block.clone());
    store.set_finalized(finalized_root);

    let mut pending_block = dummy_block();
    pending_block.slot = Slot(Uint64(2));
    let pending_root = Bytes32::from([0x62u8; 32]);
    store.put_block(pending_root, pending_block.clone());
    assert_eq!(store.get_block_by_slot(2), Some(pending_block.clone()));

    drop(store);

    let reopened = FileStore::open(&dir).expect("reopen");
    // Pending slot index is memory-only and should not survive restart.
    assert_eq!(reopened.get_block_by_slot(2), None);
    // Blob remains durable and should still be retrievable by root.
    assert_eq!(reopened.get_block(&pending_root), Some(pending_block));

    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn truncated_blob_recovery_after_simulated_crash() {
    let dir = temp_store_dir("truncated_blob");
    let mut store = FileStore::open(&dir).expect("open file store");

    let mut block = dummy_block();
    block.slot = Slot(Uint64(17));
    let root = Bytes32::from([0x52u8; 32]);
    store.put_block(root, block);
    drop(store);

    // Simulate interrupted write by replacing blob value with truncated bytes.
    overwrite_blob_in_db(&dir, BLOCK_BLOB_TABLE, root, &[0x01, 0x02, 0x03, 0x04]);

    let reopened = FileStore::open(&dir).expect("reopen file store");
    assert!(reopened.get_block(&root).is_none());
    assert!(reopened.get_block_by_slot(17).is_none());

    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn write_failure_on_one_key_does_not_corrupt_existing_entries() {
    let dir = temp_store_dir("write_failure_isolation");
    let mut store = FileStore::open(&dir).expect("open file store");

    let mut good_state = dummy_state();
    good_state.slot = Slot(Uint64(30));
    let good_root = Bytes32::from([0x53u8; 32]);
    store.put_state(good_root, good_state.clone());
    // Insert a second state and then corrupt only its blob bytes.
    let bad_root = Bytes32::from([0x54u8; 32]);
    let mut bad_state = dummy_state();
    bad_state.slot = Slot(Uint64(31));
    store.put_state(bad_root, bad_state);
    drop(store);

    overwrite_blob_in_db(&dir, STATE_BLOB_TABLE, bad_root, &[0xAA, 0xBB, 0xCC]);

    let reopened = FileStore::open(&dir).expect("reopen after failed write");
    assert_eq!(reopened.get_state(&good_root), Some(good_state.clone()));
    assert!(reopened.get_state(&bad_root).is_none());
    assert_eq!(reopened.get_state_by_slot(30), Some(good_state));
    assert!(reopened.get_state_by_slot(31).is_none());

    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn signed_block_write_advances_canonical_indexes_and_meta() {
    let dir = temp_store_dir("signed_block_failure_ordering");
    let mut store = FileStore::open(&dir).expect("open file store");
    let mut state = dummy_validating_state();
    let signed = build_signed_block(&state, 1);
    let root = Bytes32::from([0x56u8; 32]);
    store
        .put_signed_block(root, signed.clone(), &mut state)
        .expect("put signed block");

    // DB-backed blob persistence should advance indexes and fork-choice atomically
    // from the caller point of view.
    assert_eq!(
        store.get_block_by_slot(1),
        Some(signed.message.block.clone())
    );
    assert_eq!(store.head(), Some(root));
    assert_eq!(store.justified(), Some(state.latest_justified.root));
    assert_eq!(store.finalized(), Some(state.latest_finalized.root));

    drop(store);
    let reopened = FileStore::open(&dir).expect("reopen after signed block write");
    // Slot 1 is pending/non-finalized and is not durable across restart.
    assert_eq!(reopened.get_block_by_slot(1), None);
    assert_eq!(reopened.get_block(&root), Some(signed.message.block));
    assert_eq!(reopened.head(), Some(root));
    assert_eq!(reopened.justified(), Some(state.latest_justified.root));
    assert_eq!(reopened.finalized(), Some(state.latest_finalized.root));

    let _ = std::fs::remove_dir_all(dir);
}
