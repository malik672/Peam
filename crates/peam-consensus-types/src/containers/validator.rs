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
    pub attestation_pubkey: Bytes52,
    pub proposal_pubkey: Bytes52,
    pub index: ValidatorIndex,
    pub balance: Uint64,
}

impl Container for Validator {}

impl SszEncode for ValidatorIndex {
    fn encode_ssz(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(8);
        unsafe { out.set_len(8) };
        unsafe { write_bytes_at(&mut out, 0, &self.0.0.to_le_bytes()) };
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
        let mut out = Vec::with_capacity(52 + 52 + 8);
        unsafe { out.set_len(52 + 52 + 8) };
        unsafe { write_bytes_at(&mut out, 0, self.attestation_pubkey.as_ref()) };
        unsafe { write_bytes_at(&mut out, 52, self.proposal_pubkey.as_ref()) };
        unsafe { write_bytes_at(&mut out, 104, &self.index.0.0.to_le_bytes()) };
        out
    }
}

impl SszDecode for Validator {
    fn decode_ssz(bytes: &[u8]) -> Result<Self, String> {
        let attestation_pubkey = Bytes52::from_slice(&bytes[0..52]);
        let proposal_pubkey = Bytes52::from_slice(&bytes[52..104]);
        let index = ValidatorIndex::decode_ssz(&bytes[104..112])?;
        let balance = Uint64(0);
        Ok(Validator {
            attestation_pubkey,
            proposal_pubkey,
            index,
            balance,
        })
    }
}

impl SszFixedLen for Validator {
    fn fixed_len() -> usize {
        112
    }
}

impl Validator {
    pub fn decode_ssz_checked(bytes: &[u8]) -> Result<Self, String> {
        const VALIDATOR_BYTES: usize = 112;
        if bytes.len() != VALIDATOR_BYTES {
            return Err(format!(
                "Validator expects {} bytes, got {}",
                VALIDATOR_BYTES,
                bytes.len()
            ));
        }
        Self::decode_ssz(bytes)
    }
}

impl HashTreeRoot for Validator {
    fn hash_tree_root(&self) -> [u8; 32] {
        let attestation_pubkey_root = Bytes32::from(self.attestation_pubkey.hash_tree_root());
        let proposal_pubkey_root = Bytes32::from(self.proposal_pubkey.hash_tree_root());
        let index_root = Bytes32::from(self.index.hash_tree_root());
        // Lean interop consensus root uses only pubkeys + index.
        // `balance` is local metadata and is intentionally excluded.
        //
        // This is still a 3-field SSZ container, so the index field must be
        // merkleized with the implicit zero right sibling from the 4-leaf tree.
        let root =
            merkleize_tree_root_3(&[attestation_pubkey_root, proposal_pubkey_root, index_root]);
        *root.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::{Validator, ValidatorIndex};
    use crate::ssz::HashTreeRoot;
    use crate::ssz::hash::merkleize_tree_root_3;
    use crate::types::bytes::{Bytes32, Bytes52};
    use crate::types::uint::Uint64;

    #[test]
    fn validator_hash_tree_root_uses_three_field_container_shape() {
        let validator = Validator {
            attestation_pubkey: Bytes52::from([0x11; 52]),
            proposal_pubkey: Bytes52::from([0x22; 52]),
            index: ValidatorIndex(Uint64(3)),
            balance: Uint64(0),
        };

        let expected = merkleize_tree_root_3(&[
            Bytes32::from(validator.attestation_pubkey.hash_tree_root()),
            Bytes32::from(validator.proposal_pubkey.hash_tree_root()),
            Bytes32::from(validator.index.hash_tree_root()),
        ]);

        assert_eq!(Bytes32::from(validator.hash_tree_root()), expected);
    }
}
