use criterion::{BatchSize, Criterion, black_box, criterion_group, criterion_main};

use peam::containers::state::State as LeanEthState;
use peam::containers::state::Validators as LeanEthValidators;
use peam::containers::validator::Validator as LeanEthValidator;
use peam::containers::validator::ValidatorIndex as LeanEthValidatorIndex;
use peam::slot::Slot as LeanEthSlot;
use peam::ssz::hash::{chunkify_fixed, merkleize};
use peam::ssz::{
    HashTreeRoot as LeanEthHashTreeRoot, SszDecode as LeanEthSszDecode,
    SszFixedLen as LeanEthSszFixedLen,
};
use peam::types::bytes::Bytes32 as LeanEthBytes32;
use peam::types::bytes::Bytes52 as LeanEthBytes52;
use peam::types::collections::SszList as LeanEthSszList;
use peam::types::uint::Uint64 as LeanEthUint64;

fn make_peam_state(num_validators: u64) -> LeanEthState {
    let mut vals = Vec::with_capacity(num_validators as usize);
    for i in 0..num_validators {
        vals.push(LeanEthValidator {
            pubkey: LeanEthBytes52::from([0x11u8; 52]),
            index: LeanEthValidatorIndex(LeanEthUint64(i)),
            balance: LeanEthUint64(0),
        });
    }
    let validators: LeanEthValidators = LeanEthSszList::new(vals).unwrap();
    LeanEthState::generate_genesis(LeanEthUint64(0), validators)
}

#[allow(dead_code)]
#[derive(Clone)]
struct ReamLikeHeader {
    slot: u64,
    proposer_index: u64,
    parent_root: [u8; 32],
    state_root: [u8; 32],
    body_root: [u8; 32],
}

#[allow(dead_code)]
#[derive(Clone)]
struct ReamLikeState {
    slot: u64,
    latest_block_header: ReamLikeHeader,
    validators: Vec<[u8; 52]>,
}

impl ReamLikeState {
    fn generate_genesis(num_validators: u64) -> Self {
        let mut validators = Vec::with_capacity(num_validators as usize);
        for _ in 0..num_validators {
            validators.push([0x11u8; 52]);
        }
        Self {
            slot: 0,
            latest_block_header: ReamLikeHeader {
                slot: 0,
                proposer_index: 0,
                parent_root: [0u8; 32],
                state_root: [0u8; 32],
                body_root: [0u8; 32],
            },
            validators,
        }
    }

    fn hash_tree_root(&self) -> [u8; 32] {
        let slot_bytes = self.slot.to_le_bytes();
        let proposer_bytes = self.latest_block_header.proposer_index.to_le_bytes();

        let slot_root = {
            let chunks = chunkify_fixed(&slot_bytes);
            merkleize(&chunks)
        };
        let proposer_root = {
            let chunks = chunkify_fixed(&proposer_bytes);
            merkleize(&chunks)
        };

        let header_roots = [
            slot_root,
            proposer_root,
            LeanEthBytes32::from(self.latest_block_header.parent_root),
            LeanEthBytes32::from(self.latest_block_header.state_root),
            LeanEthBytes32::from(self.latest_block_header.body_root),
        ];
        let header_root = merkleize(&header_roots);

        let state_roots = [
            LeanEthBytes32::from(slot_root.as_array()),
            LeanEthBytes32::from(header_root.as_array()),
        ];
        merkleize(&state_roots).as_array()
    }

    fn process_slots(&mut self, target_slot: u64) {
        while self.slot < target_slot {
            if self.latest_block_header.state_root == [0u8; 32] {
                self.latest_block_header.state_root = self.hash_tree_root();
            }
            self.slot += 1;
        }
    }
}

fn bench_hash_tree_root(c: &mut Criterion) {
    let mut group = c.benchmark_group("hash_tree_root");

    group.bench_function("peam_state_root", |b| {
        b.iter_batched(
            || make_peam_state(16),
            |state| black_box(state.hash_tree_root()),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("ream_like_state_root", |b| {
        b.iter_batched(
            || ReamLikeState::generate_genesis(16),
            |state| black_box(state.hash_tree_root()),
            BatchSize::SmallInput,
        )
    });

    group.finish();
}

fn bench_process_slots(c: &mut Criterion) {
    let mut group = c.benchmark_group("process_slots");

    group.bench_function("peam_process_slots", |b| {
        b.iter_batched(
            || make_peam_state(16),
            |mut state| {
                let _ = state.process_slots(LeanEthSlot(LeanEthUint64(1024)));
                black_box(state)
            },
            BatchSize::SmallInput,
        )
    });

    group.bench_function("ream_like_process_slots", |b| {
        b.iter_batched(
            || ReamLikeState::generate_genesis(16),
            |mut state| {
                state.process_slots(1024);
                black_box(state)
            },
            BatchSize::SmallInput,
        )
    });

    group.finish();
}

fn make_u64_list_bytes(len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len * 8);
    for i in 0..len as u64 {
        out.extend_from_slice(&i.to_le_bytes());
    }
    out
}

fn ream_like_decode_u64_list(bytes: &[u8]) -> Result<LeanEthSszList<LeanEthUint64, 4096>, String> {
    let elem_len = <LeanEthUint64 as LeanEthSszFixedLen>::fixed_len();
    let len = bytes.len() / elem_len;
    let mut data = Vec::with_capacity(len);
    for i in 0..len {
        let start = i * elem_len;
        let end = start + elem_len;
        data.push(<LeanEthUint64 as LeanEthSszDecode>::decode_ssz(
            &bytes[start..end],
        )?);
    }
    LeanEthSszList::new(data)
}

fn bench_decode_list(c: &mut Criterion) {
    let mut group = c.benchmark_group("decode_ssz_list_u64");
    let bytes = make_u64_list_bytes(4096);

    group.bench_function("peam_decode_ssz", |b| {
        b.iter(|| {
            let decoded = <LeanEthSszList<LeanEthUint64, 4096> as LeanEthSszDecode>::decode_ssz(
                black_box(&bytes),
            )
            .unwrap();
            black_box(decoded)
        })
    });

    group.bench_function("ream_like_push_decode", |b| {
        b.iter(|| {
            let decoded = ream_like_decode_u64_list(black_box(&bytes)).unwrap();
            black_box(decoded)
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_hash_tree_root,
    bench_process_slots,
    bench_decode_list
);
criterion_main!(benches);
