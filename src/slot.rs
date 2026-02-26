use crate::ssz::{HashTreeRoot, SszDecode, SszEncode, SszFixedLen};
use crate::types::uint::Uint64;
use crate::unsafe_vec::write_bytes_at;

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
