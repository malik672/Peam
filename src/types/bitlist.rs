use crate::ssz::hash::{BYTES_PER_CHUNK, chunkify_fixed, merkleize_with_limit, mix_in_length};
use crate::ssz::{HashTreeRoot, SszDecode, SszElement, SszEncode};
use crate::types::bytes::Bytes32;

/// Safety: callers must validate bit lengths and limits before construction/decoding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BitList<const LIMIT: usize> {
    pub data: Vec<u8>,
    pub len: usize,
}

impl<const LIMIT: usize> BitList<LIMIT> {
    pub fn new(data: Vec<bool>) -> Result<Self, String> {
        let len = data.len();
        let byte_len = (len + 7) / 8;
        let mut packed: Vec<u8> = vec![0u8; byte_len];
        for (i, bit) in data.iter().enumerate() {
            if *bit {
                packed[i / 8] |= 1u8 << (i % 8);
            }
        }
        Ok(Self { data: packed, len })
    }

    pub fn len(&self) -> usize {
        self.len
    }

    fn pack_bits_with_terminator(&self) -> Vec<u8> {
        let bit_len = self.len;
        let out_len = (bit_len + 1 + 7) / 8;
        let mut out = vec![0u8; out_len];
        let copy_len = self.data.len().min(out_len);
        out[..copy_len].copy_from_slice(&self.data[..copy_len]);
        let term_index = bit_len;
        out[term_index / 8] |= 1u8 << (term_index % 8);
        out
    }

    fn unpack_bits_with_terminator(bytes: &[u8]) -> Result<(Vec<u8>, usize), String> {
        fn highest_set_bit(bytes: &[u8]) -> Option<usize> {
            let mut i = bytes.len();
            while i > 0 {
                let chunk_start = i.saturating_sub(16);
                let chunk_end = i;
                let mut buf = [0u8; 16];
                let len = chunk_end - chunk_start;
                buf[..len].copy_from_slice(&bytes[chunk_start..chunk_end]);
                let chunk = u128::from_le_bytes(buf);
                if chunk != 0 {
                    let msb = 127 - chunk.leading_zeros() as usize;
                    return Some(chunk_start * 8 + msb);
                }
                i = chunk_start;
            }
            None
        }

        let bit_len =
            highest_set_bit(bytes).ok_or_else(|| "bitlist missing length marker".to_string())?;
        let byte_len = (bit_len + 7) / 8;
        let mut data: Vec<u8> = Vec::with_capacity(byte_len);
        unsafe { data.set_len(byte_len) };
        if byte_len != 0 {
            unsafe {
                core::ptr::copy_nonoverlapping(bytes.as_ptr(), data.as_mut_ptr(), byte_len);
            }
        }
        // Clear the terminator bit.
        let term_index = bit_len;
        let term_byte = term_index / 8;
        if term_byte < data.len() {
            data[term_byte] &= !(1u8 << (term_index % 8));
        }
        Ok((data, bit_len))
    }

    pub fn decode_ssz_checked(bytes: &[u8]) -> Result<Self, String> {
        let (data, len) = Self::unpack_bits_with_terminator(bytes)?;
        if len >= LIMIT {
            return Err(format!("BitList length {} exceeds limit {}", len, LIMIT));
        }
        Ok(Self { data, len })
    }
}

/// Safety: callers must validate bit lengths before construction/decoding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BitVector<const LENGTH: usize> {
    pub data: Vec<u8>,
}

impl<const LENGTH: usize> BitVector<LENGTH> {
    pub fn new(data: Vec<bool>) -> Result<Self, String> {
        let byte_len = (LENGTH + 7) / 8;
        let mut packed: Vec<u8> = vec![0u8; byte_len];
        for (i, bit) in data.iter().enumerate() {
            if *bit && i < LENGTH {
                packed[i / 8] |= 1u8 << (i % 8);
            }
        }
        Ok(Self { data: packed })
    }

    fn pack_bits(&self) -> Vec<u8> {
        self.data.clone()
    }

    fn unpack_bits(bytes: &[u8]) -> Result<Vec<u8>, String> {
        let byte_len = (LENGTH + 7) / 8;
        let mut data = vec![0u8; byte_len];
        let copy_len = bytes.len().min(byte_len);
        data[..copy_len].copy_from_slice(&bytes[..copy_len]);
        Ok(data)
    }

    pub fn decode_ssz_checked(bytes: &[u8]) -> Result<Self, String> {
        let expected = (LENGTH + 7) / 8;
        if bytes.len() != expected {
            return Err(format!(
                "BitVector expects {} bytes, got {}",
                expected,
                bytes.len()
            ));
        }
        Self::decode_ssz(bytes)
    }
}

impl<const LENGTH: usize> SszEncode for BitVector<LENGTH> {
    fn encode_ssz(&self) -> Vec<u8> {
        self.pack_bits()
    }
}

impl<const LENGTH: usize> SszDecode for BitVector<LENGTH> {
    fn decode_ssz(bytes: &[u8]) -> Result<Self, String> {
        let data = Self::unpack_bits(bytes)?;
        Ok(Self { data })
    }
}

impl<const LENGTH: usize> HashTreeRoot for BitVector<LENGTH> {
    fn hash_tree_root(&self) -> [u8; 32] {
        let packed = self.pack_bits();
        let chunks = chunkify_fixed(&packed);
        let limit_chunks = (LENGTH + (BYTES_PER_CHUNK * 8) - 1) / (BYTES_PER_CHUNK * 8);
        let root = merkleize_with_limit(&chunks, limit_chunks).unwrap_or_else(|_| Bytes32::zero());
        *root.as_ref()
    }
}

impl<const LENGTH: usize> SszElement for BitVector<LENGTH> {
    fn fixed_len_opt() -> Option<usize> {
        Some((LENGTH + 7) / 8)
    }
}

impl<const LIMIT: usize> SszEncode for BitList<LIMIT> {
    fn encode_ssz(&self) -> Vec<u8> {
        self.pack_bits_with_terminator()
    }
}

impl<const LIMIT: usize> SszDecode for BitList<LIMIT> {
    fn decode_ssz(bytes: &[u8]) -> Result<Self, String> {
        let (data, len) = Self::unpack_bits_with_terminator(bytes)?;
        Ok(Self { data, len })
    }
}

impl<const LIMIT: usize> HashTreeRoot for BitList<LIMIT> {
    fn hash_tree_root(&self) -> [u8; 32] {
        let packed = self.data.clone();
        let chunks = chunkify_fixed(&packed);
        let limit_chunks = (LIMIT + (BYTES_PER_CHUNK * 8) - 1) / (BYTES_PER_CHUNK * 8);
        let root = merkleize_with_limit(&chunks, limit_chunks).unwrap_or_else(|_| Bytes32::zero());
        let mixed = mix_in_length(&root, self.len);
        *mixed.as_ref()
    }
}

impl<const LIMIT: usize> SszElement for BitList<LIMIT> {}
