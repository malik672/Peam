use criterion::black_box;
use criterion::{Criterion, criterion_group, criterion_main};

use peam::crypto::pq;

fn bench_pq_signature_baseline(c: &mut Criterion) {
    let mut group = c.benchmark_group("pq_signature_baseline");
    pq::setup_aggregate_prover();
    pq::setup_aggregate_verifier();

    let (pk0, sk0) = pq::key_gen_for_devnet_validator(0).expect("key0");
    let (pk1, sk1) = pq::key_gen_for_devnet_validator(1).expect("key1");
    let (pk2, sk2) = pq::key_gen_for_devnet_validator(2).expect("key2");
    let (pk3, sk3) = pq::key_gen_for_devnet_validator(3).expect("key3");
    let (pk4, sk4) = pq::key_gen_for_devnet_validator(4).expect("key4");

    let message = [0x42u8; 32];
    let sig0 = pq::sign_message(&sk0, 1, &message).expect("sig0");

    let agg2 = pq::sign_aggregate_concat(&[pk0, pk1], &[&sk0, &sk1], 1, &message).expect("agg2");
    let agg5 = pq::sign_aggregate_concat(
        &[pk0, pk1, pk2, pk3, pk4],
        &[&sk0, &sk1, &sk2, &sk3, &sk4],
        1,
        &message,
    )
    .expect("agg5");

    group.bench_function("sign_single", |b| {
        b.iter(|| {
            let sig = pq::sign_message(black_box(&sk0), 1, black_box(&message)).expect("sign");
            black_box(sig)
        })
    });

    group.bench_function("verify_single", |b| {
        b.iter(|| {
            pq::verify_signature(black_box(&pk0), 1, black_box(&message), black_box(&sig0))
                .expect("verify");
        })
    });

    group.bench_function("verify_aggregate_multisig_2", |b| {
        b.iter(|| {
            pq::verify_aggregate_signature(
                black_box(&[pk0, pk1]),
                black_box(&message),
                black_box(&agg2),
                1,
            )
            .expect("verify agg2");
        })
    });

    group.bench_function("verify_aggregate_multisig_5", |b| {
        b.iter(|| {
            pq::verify_aggregate_signature(
                black_box(&[pk0, pk1, pk2, pk3, pk4]),
                black_box(&message),
                black_box(&agg5),
                1,
            )
            .expect("verify agg5");
        })
    });

    group.finish();
}

criterion_group!(pq_signature_baseline_group, bench_pq_signature_baseline);
criterion_main!(pq_signature_baseline_group);
