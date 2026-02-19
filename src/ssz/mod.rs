pub mod hash;

pub trait SszEncode {
    fn encode_ssz(&self) -> Vec<u8>;
}

pub trait SszDecode: Sized {
    /// Safety: This assumes the caller validated length/limits/offsets.
    /// Passing malformed input is undefined behavior at the library level.
    fn decode_ssz(bytes: &[u8]) -> Result<Self, String>;
}

pub trait SszFixedLen {
    fn fixed_len() -> usize;
}

pub trait SszElement {
    fn fixed_len_opt() -> Option<usize> {
        None
    }
}

impl<T: SszFixedLen> SszElement for T {
    fn fixed_len_opt() -> Option<usize> {
        Some(T::fixed_len())
    }
}

pub trait HashTreeRoot {
    fn hash_tree_root(&self) -> [u8; 32];
}
