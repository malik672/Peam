use std::sync::{Arc, RwLock};

use criterion::{BatchSize, Criterion, black_box, criterion_group, criterion_main};
use peam::containers::attestation::{Attestation, AttestationData, VALIDATOR_REGISTRY_LIMIT};
use peam::containers::checkpoint::Checkpoint;
use peam::fork_choice::ForkChoiceStore;
use peam::node::proposal_head_from_pending;
use peam::slot::Slot;
use peam::types::bitlist::BitList;
use peam::types::bytes::Bytes32;
use peam::types::uint::Uint64;

fn checkpoint(seed: u64, slot: u64) -> Checkpoint {
    let mut root = [0u8; 32];
    root[..8].copy_from_slice(&seed.to_le_bytes());
    Checkpoint {
        root: Bytes32::from(root),
        slot: Slot(Uint64(slot)),
    }
}

fn attestation_data(group: u64) -> AttestationData {
    let head = checkpoint(group.wrapping_mul(0x9E37_79B9), group + 1);
    let target = checkpoint(group.wrapping_mul(0x85EB_CA6B), group);
    let source = checkpoint(group.wrapping_mul(0xC2B2_AE35), group.saturating_sub(1));
    AttestationData {
        slot: Slot(Uint64(group + 1)),
        head,
        target,
        source,
    }
}

fn single_participant_bits(validator_id: usize) -> BitList<VALIDATOR_REGISTRY_LIMIT> {
    let mut bits = vec![false; validator_id + 1];
    bits[validator_id] = true;
    BitList::new(bits).expect("bitlist")
}

fn build_template(total: usize, groups: usize) -> Vec<Attestation> {
    let mut out = Vec::with_capacity(total);
    for i in 0..total {
        let group = (i % groups) as u64;
        let validator = i % VALIDATOR_REGISTRY_LIMIT;
        out.push(Attestation {
            aggregation_bits: single_participant_bits(validator),
            data: attestation_data(group),
        });
    }
    out
}

fn bench_proposal_head_from_pending(c: &mut Criterion) {
    let mut group = c.benchmark_group("proposal_head_from_pending");

    for &(total, unique_groups) in &[(1024usize, 256usize), (4096usize, 512usize)] {
        let template = build_template(total, unique_groups);
        let fork_choice: Arc<RwLock<Option<ForkChoiceStore>>> = Arc::new(RwLock::new(None));
        let pending: Arc<RwLock<Vec<Attestation>>> = Arc::new(RwLock::new(Vec::new()));

        group.bench_function(
            format!("pending_total_{total}_groups_{unique_groups}"),
            |b| {
                b.iter_batched(
                    || template.clone(),
                    |next| {
                        *pending.write().expect("pending lock") = next;
                        let head = proposal_head_from_pending(&fork_choice, &pending);
                        black_box(head);
                    },
                    BatchSize::LargeInput,
                )
            },
        );
    }

    group.finish();
}

criterion_group!(benches, bench_proposal_head_from_pending);
criterion_main!(benches);
