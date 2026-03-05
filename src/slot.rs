use crate::ssz::{HashTreeRoot, SszDecode, SszEncode, SszFixedLen};
use crate::types::uint::Uint64;
use crate::unsafe_vec::write_bytes_at;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Target slot duration.
pub const SLOT_DURATION_SECS: u64 = 4;
/// Target slot duration in milliseconds.
pub const SLOT_DURATION_MILLIS: u128 = (SLOT_DURATION_SECS as u128) * 1_000;
/// Number of fork-choice processing intervals within a slot.
pub const INTERVALS_PER_SLOT: u64 = 4;
/// Slot interval duration in milliseconds.
pub const SLOT_INTERVAL_MILLIS: u128 = SLOT_DURATION_MILLIS / (INTERVALS_PER_SLOT as u128);
/// Interval index at which new gossip attestations are promoted to active votes.
pub const ACCEPTANCE_INTERVAL_INDEX: u64 = 3;
/// Interval index at which safe-target recomputation should run.
pub const SAFE_TARGET_INTERVAL_INDEX: u64 = 2;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct Slot(pub Uint64);

impl From<u64> for Slot {
    fn from(value: u64) -> Self {
        Slot(Uint64(value))
    }
}

impl SszEncode for Slot {
    fn encode_ssz(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(8);
        unsafe { out.set_len(8) };
        unsafe { write_bytes_at(&mut out, 0, &self.0.0.to_le_bytes()) };
        out
    }
}

impl SszDecode for Slot {
    fn decode_ssz(bytes: &[u8]) -> Result<Self, String> {
        Uint64::decode_ssz(bytes).map(Slot)
    }
}

impl Slot {
    pub fn decode_ssz_checked(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() != Self::fixed_len() {
            return Err(format!(
                "Slot expects {} bytes, got {}",
                Self::fixed_len(),
                bytes.len()
            ));
        }
        Self::decode_ssz(bytes)
    }
}

impl HashTreeRoot for Slot {
    #[inline]
    fn hash_tree_root(&self) -> [u8; 32] {
        self.0.hash_tree_root()
    }
}

impl SszFixedLen for Slot {
    fn fixed_len() -> usize {
        8
    }
}

pub fn justified_index_after(candidate_slot: Slot, finalized_slot: Slot) -> Option<u64> {
    if candidate_slot <= finalized_slot {
        return None;
    }
    Some(candidate_slot.0.0 - finalized_slot.0.0 - 1)
}

/// Computes the current slot index from unix wall-clock time.
///
/// Formula:
/// `slot = max(0, (unix_now_secs - genesis_time_secs) / SLOT_DURATION_SECS)`.
#[inline]
pub fn slot_index_from_unix_secs(genesis_time_secs: u64, unix_now_secs: u64) -> u64 {
    slot_index_from_unix_millis(genesis_time_secs, (unix_now_secs as u128) * 1_000)
}

/// Computes the current slot index from unix wall-clock time in milliseconds.
///
/// Formula:
/// `slot = max(0, (unix_now_millis - genesis_time_millis) / SLOT_DURATION_MILLIS)`.
#[inline]
pub fn slot_index_from_unix_millis(genesis_time_secs: u64, unix_now_millis: u128) -> u64 {
    let genesis_millis = (genesis_time_secs as u128) * 1_000;
    let elapsed = unix_now_millis.saturating_sub(genesis_millis);
    (elapsed / SLOT_DURATION_MILLIS) as u64
}

/// Returns the current unix timestamp in seconds.
#[inline]
pub fn unix_now_secs() -> Option<u64> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?;
    Some(now.as_secs())
}

/// Returns the current unix timestamp in milliseconds.
#[inline]
pub fn unix_now_millis() -> Option<u128> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?;
    Some(now.as_millis())
}

/// Returns the delay until the next slot boundary.
///
/// This is used to anchor a strict slot ticker with
/// `tokio::time::interval_at(start, Duration::from_secs(SLOT_DURATION_SECS))`.
#[inline]
pub fn next_slot_boundary_delay(genesis_time_secs: u64, unix_now_millis: u128) -> Duration {
    let genesis_millis = (genesis_time_secs as u128) * 1_000;
    let elapsed = unix_now_millis.saturating_sub(genesis_millis);
    let next_slot = (elapsed / SLOT_DURATION_MILLIS) + 1;
    let next_boundary_millis = genesis_millis + next_slot * SLOT_DURATION_MILLIS;
    let delay_millis = next_boundary_millis.saturating_sub(unix_now_millis);
    Duration::from_millis(delay_millis.min(u128::from(u64::MAX)) as u64)
}

/// Returns the current interval index within the slot `[0, INTERVALS_PER_SLOT)`.
#[inline]
pub fn interval_index_from_unix_millis(genesis_time_secs: u64, unix_now_millis: u128) -> u64 {
    let genesis_millis = (genesis_time_secs as u128) * 1_000;
    let elapsed = unix_now_millis.saturating_sub(genesis_millis);
    let in_slot = elapsed % SLOT_DURATION_MILLIS;
    (in_slot / SLOT_INTERVAL_MILLIS) as u64
}

#[inline]
pub fn is_justifiable_after(candidate_slot: Slot, finalized_slot: Slot) -> Result<bool, String> {
    if candidate_slot < finalized_slot {
        return Err("candidate slot must be >= finalized slot".to_string());
    }
    let delta = candidate_slot.0.0 - finalized_slot.0.0;
    if delta <= 5 {
        return Ok(true);
    }
    let sqrt = isqrt_u64(delta);
    if sqrt * sqrt == delta {
        return Ok(true);
    }
    let four_delta_plus_one = 4 * delta + 1;
    let sqrt2 = isqrt_u64(four_delta_plus_one);
    Ok(sqrt2 * sqrt2 == four_delta_plus_one && sqrt2 % 2 == 1)
}

#[inline]
fn isqrt_u64(n: u64) -> u64 {
    let mut x = n;
    let mut res = 0u64;
    let mut bit = 1u64 << 62;
    while bit > x {
        bit >>= 2;
    }
    while bit != 0 {
        let tmp = res + bit;
        if x >= tmp {
            x -= tmp;
            res = (res >> 1) + bit;
        } else {
            res >>= 1;
        }
        bit >>= 2;
    }
    res
}
