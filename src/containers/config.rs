use crate::types::uint::Uint64;
use crate::ssz::{HashTreeRoot, SszDecode, SszEncode, SszFixedLen};
use crate::unsafe_vec::write_bytes_at;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct Config {
    pub genesis_time: Uint64,
}

impl SszEncode for Config {
    fn encode_ssz(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(8);
        unsafe { out.set_len(8) };
        unsafe { write_bytes_at(&mut out, 0, &self.genesis_time.0.to_le_bytes()) };
        out
    }
}

impl SszDecode for Config {
    fn decode_ssz(bytes: &[u8]) -> Result<Self, String> {
        let genesis_time = Uint64::decode_ssz(bytes)?;
        Ok(Self { genesis_time })
    }
}

impl Config {
    pub fn decode_ssz_checked(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() != Self::fixed_len() {
            return Err(format!(
                "Config expects {} bytes, got {}",
                Self::fixed_len(),
                bytes.len()
            ));
        }
        Self::decode_ssz(bytes)
    }
}

impl HashTreeRoot for Config {
    fn hash_tree_root(&self) -> [u8; 32] {
        self.genesis_time.hash_tree_root()
    }
}

impl SszFixedLen for Config {
    fn fixed_len() -> usize {
        8
    }
}
