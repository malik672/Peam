use crate::ssz::hash::merkleize_tree_root_3;
use crate::ssz::{HashTreeRoot, SszDecode, SszEncode, SszFixedLen};
use crate::types::bytes::Bytes32;
use crate::types::bytes::Bytes52;
use crate::types::container::Container;
use crate::types::uint::Uint64;
use crate::unsafe_vec::write_bytes_at;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct ValidatorIndex(pub Uint64);

impl ValidatorIndex {
    #[inline]
    pub fn is_proposer_for(self, slot: crate::slot::Slot, num_validators: u64) -> bool {
        if num_validators == 0 {
            return false;
        }
        (slot.0).0 % num_validators == (self.0).0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct Validator {
    pub pubkey: Bytes52,
    pub index: ValidatorIndex,
    pub balance: Uint64,
}

impl Container for Validator {}

impl SszEncode for ValidatorIndex {
    fn encode_ssz(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(8);
        unsafe { out.set_len(8) };
        unsafe { write_bytes_at(&mut out, 0, &self.0 .0.to_le_bytes()) };
        out
    }
}

impl SszDecode for ValidatorIndex {
    fn decode_ssz(bytes: &[u8]) -> Result<Self, String> {
        Uint64::decode_ssz(bytes).map(ValidatorIndex)
    }
}

impl ValidatorIndex {
    pub fn decode_ssz_checked(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() != Self::fixed_len() {
            return Err(format!(
                "ValidatorIndex expects {} bytes, got {}",
                Self::fixed_len(),
                bytes.len()
            ));
        }
        Self::decode_ssz(bytes)
    }
}

impl HashTreeRoot for ValidatorIndex {
    fn hash_tree_root(&self) -> [u8; 32] {
        self.0.hash_tree_root()
    }
}

impl SszFixedLen for ValidatorIndex {
    fn fixed_len() -> usize {
        8
    }
}

impl SszEncode for Validator {
    fn encode_ssz(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(52 + 8 + 8);
        unsafe { out.set_len(52 + 8 + 8) };
        unsafe { write_bytes_at(&mut out, 0, self.pubkey.as_ref()) };
        unsafe { write_bytes_at(&mut out, 52, &self.index.0 .0.to_le_bytes()) };
        unsafe { write_bytes_at(&mut out, 60, &self.balance.0.to_le_bytes()) };
        out
    }
}

impl SszDecode for Validator {
    fn decode_ssz(bytes: &[u8]) -> Result<Self, String> {
        let pubkey = Bytes52::from_slice(&bytes[0..52]);
        let index = ValidatorIndex::decode_ssz(&bytes[52..60])?;
        let balance = Uint64::decode_ssz(&bytes[60..68])?;
        Ok(Validator {
            pubkey,
            index,
            balance,
        })
    }
}

impl Validator {
    pub fn decode_ssz_checked(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() != Self::fixed_len() {
            return Err(format!(
                "Validator expects {} bytes, got {}",
                Self::fixed_len(),
                bytes.len()
            ));
        }
        Self::decode_ssz(bytes)
    }
}

impl HashTreeRoot for Validator {
    fn hash_tree_root(&self) -> [u8; 32] {
        let pubkey_root = Bytes32::from(self.pubkey.hash_tree_root());
        let index_root = Bytes32::from(self.index.hash_tree_root());
        let balance_root = Bytes32::from(self.balance.hash_tree_root());
        let root = merkleize_tree_root_3(&[pubkey_root, index_root, balance_root]);
        *root.as_ref()
    }
}

impl SszFixedLen for Validator {
    #[inline]
    fn fixed_len() -> usize {
        68
    }
}
