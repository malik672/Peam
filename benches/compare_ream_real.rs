use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};
use ream_consensus_lean::block::BlockHeader as ReamBlockHeader;
use ream_consensus_lean::checkpoint::Checkpoint as ReamCheckpoint;
use ream_consensus_lean::config::Config as ReamConfig;
use ssz::Encode as ReamEncode;
use tree_hash::TreeHash;

use lean_eth::containers::block::BlockHeader as LeanHeader;
use lean_eth::containers::checkpoint::Checkpoint as LeanCheckpoint;
use lean_eth::containers::config::Config as LeanConfig;
use lean_eth::containers::validator::ValidatorIndex as LeanValidatorIndex;
use lean_eth::slot::Slot as LeanSlot;
use lean_eth::ssz::HashTreeRoot as LeanHashTreeRoot;
use lean_eth::ssz::SszEncode as LeanEncode;
use lean_eth::types::bytes::Bytes32 as LeanBytes32;
use lean_eth::types::uint::Uint64 as LeanUint64;

fn make_lean_config() -> LeanConfig {
    LeanConfig {
        genesis_time: LeanUint64(1609459200),
    }
}

fn make_ream_config() -> ReamConfig {
    ReamConfig {
        genesis_time: 1609459200,
    }
}

fn make_lean_checkpoint() -> LeanCheckpoint {
    LeanCheckpoint {
        root: LeanBytes32::from([0x11u8; 32]),
        slot: LeanSlot(LeanUint64(12345)),
    }
}

fn make_ream_checkpoint() -> ReamCheckpoint {
    ReamCheckpoint {
        root: [0x11u8; 32].into(),
        slot: 12345,
    }
}

fn make_lean_header() -> LeanHeader {
    LeanHeader {
        slot: LeanSlot(LeanUint64(100)),
        proposer_index: LeanValidatorIndex(LeanUint64(3)),
        parent_root: LeanBytes32::from([0x01u8; 32]),
        state_root: LeanBytes32::from([0x02u8; 32]),
        body_root: LeanBytes32::from([0x03u8; 32]),
    }
}

fn make_ream_header() -> ReamBlockHeader {
    ReamBlockHeader {
        slot: 100,
        proposer_index: 3,
        parent_root: [0x01u8; 32].into(),
        state_root: [0x02u8; 32].into(),
        body_root: [0x03u8; 32].into(),
    }
}

fn bench_ssz_encode(c: &mut Criterion) {
    let mut group = c.benchmark_group("ssz_encode");

    group.bench_function("lean_config", |b| {
        b.iter_batched(make_lean_config, |v| black_box(v.encode_ssz()), BatchSize::SmallInput)
    });
    group.bench_function("ream_config", |b| {
        b.iter_batched(make_ream_config, |v| black_box(v.as_ssz_bytes()), BatchSize::SmallInput)
    });

    group.bench_function("lean_checkpoint", |b| {
        b.iter_batched(
            make_lean_checkpoint,
            |v| black_box(v.encode_ssz()),
            BatchSize::SmallInput,
        )
    });
    group.bench_function("ream_checkpoint", |b| {
        b.iter_batched(
            make_ream_checkpoint,
            |v| black_box(v.as_ssz_bytes()),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("lean_block_header", |b| {
        b.iter_batched(
            make_lean_header,
            |v| black_box(v.encode_ssz()),
            BatchSize::SmallInput,
        )
    });
    group.bench_function("ream_block_header", |b| {
        b.iter_batched(
            make_ream_header,
            |v| black_box(v.as_ssz_bytes()),
            BatchSize::SmallInput,
        )
    });

    group.finish();
}

fn bench_tree_hash_root(c: &mut Criterion) {
    let mut group = c.benchmark_group("tree_hash_root");

    group.bench_function("lean_block_header", |b| {
        b.iter_batched(
            make_lean_header,
            |v| black_box(v.hash_tree_root()),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("ream_block_header", |b| {
        b.iter_batched(
            make_ream_header,
            |v| black_box(v.tree_hash_root()),
            BatchSize::SmallInput,
        )
    });

    group.finish();
}

criterion_group!(benches, bench_ssz_encode, bench_tree_hash_root);
criterion_main!(benches);
