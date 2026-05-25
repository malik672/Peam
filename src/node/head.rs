use std::sync::{Arc, RwLock};

use peam_consensus_types::containers::attestation::{Attestation, VALIDATOR_REGISTRY_LIMIT};
use peam_consensus_types::types::bitlist::BitList;
use peam_consensus_types::types::bytes::Bytes32;
use peam_fork_choice::fork_choice::ForkChoiceStore;
use rapidhash::RapidHashMap;

use crate::ssz::HashTreeRoot;

/// Snapshot pending attestations and return the current proposal head root.
///
/// Takes a read lock on `pending_attestations` and evaluates proposal head with
/// those votes without consuming them.
///
/// Returns `None` if fork-choice has not yet been initialized (i.e. no block
/// has been imported yet).
pub fn proposal_head_from_pending(
    fork_choice: &Arc<RwLock<Option<ForkChoiceStore>>>,
    pending_attestations: &Arc<RwLock<Vec<Attestation>>>,
) -> Option<Bytes32> {
    let pending_snapshot = pending_attestations
        .read()
        .expect("pending attestations lock")
        .clone();
    let aggregated = aggregate_attestations(pending_snapshot);
    let mut fc = fork_choice.write().expect("fork choice lock");
    let fc = fc.as_mut()?;
    Some(fc.get_proposal_head_with_pending(aggregated.iter()))
}

/// Merge attestations with identical `AttestationData` using bitwise OR over
/// participant sets.
#[inline]
pub(super) fn aggregate_attestations(attestations: Vec<Attestation>) -> Vec<Attestation> {
    let mut grouped: RapidHashMap<[u8; 32], Attestation> =
        RapidHashMap::with_capacity_and_hasher(attestations.len(), Default::default());
    for attestation in attestations {
        let key = attestation.data.hash_tree_root();
        if let Some(existing) = grouped.get_mut(&key) {
            merge_aggregation_bits(
                &mut existing.aggregation_bits,
                &attestation.aggregation_bits,
            );
        } else {
            grouped.insert(key, attestation);
        }
    }
    grouped.into_values().collect()
}

#[inline]
fn merge_aggregation_bits(
    dst: &mut BitList<VALIDATOR_REGISTRY_LIMIT>,
    src: &BitList<VALIDATOR_REGISTRY_LIMIT>,
) {
    let target_len = dst.len.max(src.len);
    let target_bytes = target_len.div_ceil(8);
    if dst.data.len() < target_bytes {
        dst.data.resize(target_bytes, 0);
    }

    let merge_bytes = src.data.len().min(dst.data.len());

    // Process 8 bytes at a time via u64 OR.
    let full_chunks = merge_bytes / 8;
    let dst_ptr = dst.data.as_mut_ptr();
    let src_ptr = src.data.as_ptr();
    for i in 0..full_chunks {
        unsafe {
            let off = i * 8;
            let d = (dst_ptr.add(off) as *mut u64).read_unaligned();
            let s = (src_ptr.add(off) as *const u64).read_unaligned();
            (dst_ptr.add(off) as *mut u64).write_unaligned(d | s);
        }
    }
    let tail = full_chunks * 8;
    for i in tail..merge_bytes {
        dst.data[i] |= src.data[i];
    }

    dst.len = target_len;
}
