use criterion::{Criterion, black_box, criterion_group, criterion_main};
use peam::containers::attestation::VALIDATOR_REGISTRY_LIMIT;
use peam::types::bitlist::BitList;
use peam::types::bytes::Bytes52;

fn lcg_next(state: &mut u64) -> u64 {
    *state = state
        .wrapping_mul(6364136223846793005)
        .wrapping_add(1442695040888963407);
    *state
}

fn make_validator_pubkeys() -> Vec<Bytes52> {
    let mut out = Vec::with_capacity(VALIDATOR_REGISTRY_LIMIT);
    for i in 0..VALIDATOR_REGISTRY_LIMIT {
        let mut bytes = [0u8; 52];
        bytes[..8].copy_from_slice(&(i as u64).to_le_bytes());
        out.push(Bytes52::from(bytes));
    }
    out
}

fn make_attestation_bits(
    count: usize,
    density_per_mille: u16,
) -> Vec<BitList<VALIDATOR_REGISTRY_LIMIT>> {
    let mut out = Vec::with_capacity(count);
    let mut seed = 0xA5A5_5A5A_DEAD_BEEFu64;
    let byte_len = VALIDATOR_REGISTRY_LIMIT.div_ceil(8);
    for _ in 0..count {
        let mut packed = vec![0u8; byte_len];
        for idx in 0..VALIDATOR_REGISTRY_LIMIT {
            if (lcg_next(&mut seed) % 1000) < density_per_mille as u64 {
                packed[idx / 8] |= 1u8 << (idx % 8);
            }
        }
        out.push(BitList {
            data: packed,
            len: VALIDATOR_REGISTRY_LIMIT,
        });
    }
    out
}

fn old_set_bits(bits: &BitList<VALIDATOR_REGISTRY_LIMIT>) -> Vec<usize> {
    let mut out = Vec::new();
    let len = bits.len;
    for i in 0..len {
        let byte = bits.data[i / 8];
        if (byte & (1u8 << (i % 8))) != 0 {
            out.push(i);
        }
    }
    out
}

fn old_collect_all(
    attestations: &[BitList<VALIDATOR_REGISTRY_LIMIT>],
    validators: &[Bytes52],
) -> usize {
    let mut total = 0usize;
    for bits in attestations {
        let mut public_keys = Vec::new();
        for idx in old_set_bits(bits) {
            public_keys.push(validators[idx]);
        }
        total += public_keys.len();
    }
    total
}

fn new_collect_all(
    attestations: &[BitList<VALIDATOR_REGISTRY_LIMIT>],
    validators: &[Bytes52],
) -> usize {
    let mut total = 0usize;
    let mut public_keys = Vec::new();
    for bits in attestations {
        public_keys.clear();
        let bit_len = bits.len;
        for (byte_idx, byte) in bits.data.iter().copied().enumerate() {
            let mut remaining = byte;
            while remaining != 0 {
                let bit = remaining.trailing_zeros() as usize;
                let idx = byte_idx * 8 + bit;
                if idx >= bit_len {
                    break;
                }
                public_keys.push(validators[idx]);
                remaining &= remaining - 1;
            }
        }
        total += public_keys.len();
    }
    total
}

fn bench_verify_signed_block_gather(c: &mut Criterion) {
    let validators = make_validator_pubkeys();

    let mut group = c.benchmark_group("verify_signed_block_pubkey_gather");
    for (att_count, density_per_mille) in [
        (64usize, 50u16),
        (64usize, 250u16),
        (64usize, 500u16),
        (256usize, 250u16),
    ] {
        let attestations = make_attestation_bits(att_count, density_per_mille);

        group.bench_function(
            format!(
                "old_set_bits_alloc_att{}_dens{}",
                att_count, density_per_mille
            ),
            |b| {
                b.iter(|| {
                    black_box(old_collect_all(
                        black_box(&attestations),
                        black_box(&validators),
                    ))
                })
            },
        );

        group.bench_function(
            format!(
                "new_byte_scan_reuse_att{}_dens{}",
                att_count, density_per_mille
            ),
            |b| {
                b.iter(|| {
                    black_box(new_collect_all(
                        black_box(&attestations),
                        black_box(&validators),
                    ))
                })
            },
        );
    }
    group.finish();
}

criterion_group!(benches, bench_verify_signed_block_gather);
criterion_main!(benches);
