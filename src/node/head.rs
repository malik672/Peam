use std::sync::{Arc, RwLock};

use rapidhash::RapidHashMap;

use crate::containers::attestation::Attestation;
use crate::fork_choice::ForkChoiceStore;
use crate::ssz::HashTreeRoot;
use crate::types::bitlist::BitList;
use crate::types::bytes::Bytes32;

/// Drain all pending attestations into the fork-choice store and return the
/// current proposal head root.
///
/// Takes a write lock on `pending_attestations`, drains the buffer, then takes
/// a write lock on `fork_choice` and calls
/// [`ForkChoiceStore::get_proposal_head_with_pending`].
///
/// Returns `None` if fork-choice has not yet been initialized (i.e. no block
/// has been imported yet).
pub fn proposal_head_from_pending(
    fork_choice: &Arc<RwLock<Option<ForkChoiceStore>>>,
    pending_attestations: &Arc<RwLock<Vec<Attestation>>>,
) -> Option<Bytes32> {
    let drained = {
        let mut pending = pending_attestations
            .write()
            .expect("pending attestations lock");
        std::mem::take(&mut *pending)
    };
    let aggregated = aggregate_attestations(drained);
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
    dst: &mut BitList<{ crate::containers::attestation::VALIDATOR_REGISTRY_LIMIT }>,
    src: &BitList<{ crate::containers::attestation::VALIDATOR_REGISTRY_LIMIT }>,
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
