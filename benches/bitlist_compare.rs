use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};

use lean_eth::ssz::{SszDecode as LeanSszDecode, SszEncode as LeanSszEncode};
use lean_eth::types::bitlist::BitList as LeanBitList;

use ssz::Decode as ReamDecode;
use ssz::Encode as ReamEncode;
use ssz_types::typenum::U4096;
use ssz_types::BitList as ReamBitList;

const BIT_LEN: usize = 4096;

fn make_bool_vec(len: usize) -> Vec<bool> {
    let mut out: Vec<bool> = Vec::with_capacity(len);
    unsafe { out.set_len(len) };
    for i in 0..len {
        let bit = (i % 3) == 0 || (i % 7) == 0;
        unsafe {
            let slot = out.as_mut_ptr().add(i);
            core::ptr::write(slot, bit);
        }
    }
    out
}

fn make_lean_bitlist() -> LeanBitList<BIT_LEN> {
    LeanBitList::new(make_bool_vec(BIT_LEN)).unwrap()
}

fn make_ream_bitlist() -> ReamBitList<U4096> {
    let mut list = ReamBitList::<U4096>::with_capacity(BIT_LEN).unwrap();
    for i in 0..BIT_LEN {
        let bit = (i % 3) == 0 || (i % 7) == 0;
        let _ = list.set(i, bit);
    }
    list
}

fn bench_bitlist_encode(c: &mut Criterion) {
    let mut group = c.benchmark_group("bitlist_encode");

    group.bench_function("lean_eth_encode", |b| {
        b.iter_batched(
            || make_lean_bitlist(),
            |list| black_box(list.encode_ssz()),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("ream_encode", |b| {
        b.iter_batched(
            || make_ream_bitlist(),
            |list| black_box(list.as_ssz_bytes()),
            BatchSize::SmallInput,
        )
    });

    group.finish();
}

fn bench_bitlist_decode(c: &mut Criterion) {
    let mut group = c.benchmark_group("bitlist_decode");
    let bytes = make_ream_bitlist().as_ssz_bytes();

    group.bench_function("lean_eth_decode", |b| {
        b.iter(|| {
            let decoded = <LeanBitList<BIT_LEN> as LeanSszDecode>::decode_ssz(black_box(&bytes))
                .unwrap();
            black_box(decoded)
        })
    });

    group.bench_function("ream_decode", |b| {
        b.iter(|| {
            let decoded = <ReamBitList<U4096> as ReamDecode>::from_ssz_bytes(black_box(&bytes))
                .unwrap();
            black_box(decoded)
        })
    });

    group.finish();
}

criterion_group!(benches, bench_bitlist_encode, bench_bitlist_decode);
criterion_main!(benches);
