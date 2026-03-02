use crate::ssz::hash::{BYTES_PER_CHUNK, chunkify_fixed, merkleize_with_limit, mix_in_length};
use crate::ssz::{HashTreeRoot, SszDecode, SszElement, SszEncode};
use crate::types::bytes::Bytes32;
use crate::unsafe_vec::{write_at, write_bytes_at};

/// Fixed-length homogeneous sequence of exactly `LENGTH` elements.
///
/// SSZ encoding: fixed-size elements are concatenated directly; variable-size
/// elements use a 4-byte offset table followed by serialized payloads.
/// hash_tree_root merkleizes element roots (or packed bytes for fixed-size
/// primitives) with limit = `LENGTH`. No mix-in-length (size is static).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SszVector<T, const LENGTH: usize> {
    pub data: Vec<T>,
}

/// Variable-length homogeneous sequence bounded by `LIMIT` elements.
///
/// SSZ encoding matches `SszVector` but the element count is inferred from
/// the offset table (variable-size) or total byte length (fixed-size).
/// hash_tree_root merkleizes element roots with limit = `LIMIT`, then
/// mixes in the actual length as a separate 32-byte LE chunk.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SszList<T, const LIMIT: usize> {
    pub data: Vec<T>,
}

impl<T, const LENGTH: usize> SszVector<T, LENGTH> {
    pub fn new(data: Vec<T>) -> Result<Self, String> {
        Ok(Self { data })
    }

    //ONLY USED IN TEST NOW(NEED TO COME BACK TO THIS)
    pub fn decode_ssz_checked(bytes: &[u8]) -> Result<Self, String>
    where
        T: SszDecode + SszElement,
    {
        if let Some(elem_len) = T::fixed_len_opt() {
            let expected = elem_len * LENGTH;
            if bytes.len() != expected {
                return Err(format!(
                    "SszVector expects {} bytes, got {}",
                    expected,
                    bytes.len()
                ));
            }
            return Self::decode_ssz(bytes);
        }

        let count = LENGTH;
        let table_len = 4 * count;
        if bytes.len() < table_len {
            return Err("SszVector offset table exceeds input length".to_string());
        }

        // remove the first iteration outside the loop
        let off = u32::from_le_bytes(bytes[0..4].try_into().unwrap()) as usize;
        if off != table_len {
            return Err("SszVector first offset must equal table length".to_string());
        }

        let mut prev = off;
        for i in 1..count {
            let off_start = i * 4;
            let off_end = off_start + 4;
            let off = u32::from_le_bytes(bytes[off_start..off_end].try_into().unwrap()) as usize;
            if off < prev || off > bytes.len() {
                return Err("SszVector offsets are invalid".to_string());
            }
            prev = off;
        }
        Self::decode_ssz(bytes)
    }
}

impl<T, const LIMIT: usize> SszList<T, LIMIT> {
    pub fn new(data: Vec<T>) -> Result<Self, String> {
        Ok(Self { data })
    }

    //ONLY USED IN TEST NOW(NEED TO COME BACK TO THIS)
    pub fn decode_ssz_checked(bytes: &[u8]) -> Result<Self, String>
    where
        T: SszDecode + SszElement,
    {
        if let Some(elem_len) = T::fixed_len_opt() {
            if bytes.len() % elem_len != 0 {
                return Err("SszList length is not a multiple of element size".to_string());
            }
            let len = bytes.len() / elem_len;
            if len > LIMIT {
                return Err(format!("SszList length {} exceeds limit {}", len, LIMIT));
            }
            return Self::decode_ssz(bytes);
        }

        if bytes.is_empty() {
            return Ok(Self { data: Vec::new() });
        }
        if bytes.len() < 4 {
            return Err("SszList missing offset table".to_string());
        }

        let first = u32::from_le_bytes(bytes[0..4].try_into().unwrap()) as usize;
        if first % 4 != 0 {
            return Err("SszList first offset must be multiple of 4".to_string());
        }
        let len = first / 4;
        if len > LIMIT {
            return Err(format!("SszList length {} exceeds limit {}", len, LIMIT));
        }
        let table_len = 4 * len;
        if first != table_len {
            return Err("SszList first offset must equal table length".to_string());
        }
        if bytes.len() < table_len {
            return Err("SszList offset table exceeds input length".to_string());
        }

        let mut prev = table_len;
        for i in 1..len {
            let off_start = i * 4;
            let off_end = off_start + 4;
            let off = u32::from_le_bytes(bytes[off_start..off_end].try_into().unwrap()) as usize;
            if off < prev || off > bytes.len() {
                return Err("SszList offsets are invalid".to_string());
            }
            prev = off;
        }
        Self::decode_ssz(bytes)
    }
}

impl<T, const LENGTH: usize> SszEncode for SszVector<T, LENGTH>
where
    T: SszEncode + SszElement,
{
    #[inline]
    fn encode_ssz(&self) -> Vec<u8> {
        if let Some(elem_len) = T::fixed_len_opt() {
            let total = elem_len * LENGTH;
            let mut out: Vec<u8> = Vec::with_capacity(total);
            unsafe { out.set_len(total) };
            let mut cursor = 0usize;
            for item in &self.data {
                let bytes = item.encode_ssz();
                unsafe { write_bytes_at(&mut out, cursor, &bytes) };
                cursor += bytes.len();
            }
            return out;
        }

        let count = self.data.len();
        let mut offsets: Vec<u32> = Vec::with_capacity(count);
        let mut elems: Vec<Vec<u8>> = Vec::with_capacity(count);
        unsafe {
            offsets.set_len(count);
            elems.set_len(count);
        }
        let mut cursor = 4 * count;
        for (i, item) in self.data.iter().enumerate() {
            let bytes = item.encode_ssz();
            let len = bytes.len();
            unsafe {
                write_at(&mut offsets, i, cursor as u32);
                write_at(&mut elems, i, bytes);
            }
            cursor += len;
        }
        let mut out: Vec<u8> = Vec::with_capacity(cursor);
        unsafe { out.set_len(cursor) };
        let mut cursor = 0usize;
        for off in offsets {
            let bytes = off.to_le_bytes();
            unsafe { write_bytes_at(&mut out, cursor, &bytes) };
            cursor += bytes.len();
        }
        for bytes in elems {
            unsafe { write_bytes_at(&mut out, cursor, &bytes) };
            cursor += bytes.len();
        }
        out
    }
}

impl<T, const LIMIT: usize> SszEncode for SszList<T, LIMIT>
where
    T: SszEncode + SszElement,
{
    fn encode_ssz(&self) -> Vec<u8> {
        if let Some(elem_len) = T::fixed_len_opt() {
            let total = elem_len * self.data.len();
            let mut out = Vec::with_capacity(total);
            unsafe { out.set_len(total) };
            let mut cursor = 0usize;
            for item in &self.data {
                let bytes = item.encode_ssz();
                unsafe { write_bytes_at(&mut out, cursor, &bytes) };
                cursor += bytes.len();
            }
            return out;
        }

        let count = self.data.len();
        let mut offsets: Vec<u32> = Vec::with_capacity(count);
        let mut elems: Vec<Vec<u8>> = Vec::with_capacity(count);
        let mut cursor = 4 * count;
        for item in &self.data {
            let bytes = item.encode_ssz();
            offsets.push(cursor as u32);
            cursor += bytes.len();
            elems.push(bytes);
        }
        let mut out = Vec::with_capacity(cursor);
        unsafe { out.set_len(cursor) };
        let mut cursor = 0usize;
        for off in offsets {
            let bytes = off.to_le_bytes();
            unsafe { write_bytes_at(&mut out, cursor, &bytes) };
            cursor += bytes.len();
        }
        for bytes in elems {
            unsafe { write_bytes_at(&mut out, cursor, &bytes) };
            cursor += bytes.len();
        }
        out
    }
}

impl<T, const LENGTH: usize> SszDecode for SszVector<T, LENGTH>
where
    T: SszDecode + SszElement,
{
    fn decode_ssz(bytes: &[u8]) -> Result<Self, String> {
        if let Some(elem_len) = T::fixed_len_opt() {
            let mut data = Vec::with_capacity(LENGTH);
            // Note: caller must ensure bytes length == elem_len * LENGTH (no defensive checks).
            unsafe { data.set_len(LENGTH) };
            for i in 0..LENGTH {
                let start = i * elem_len;
                let end = start + elem_len;
                let x = match T::decode_ssz(&bytes[start..end]) {
                    Ok(val) => val,
                    Err(err) => {
                        unsafe {
                            let ptr: *mut T = data.as_mut_ptr();
                            for j in 0..i {
                                core::ptr::drop_in_place(ptr.add(j));
                            }
                            data.set_len(0);
                        }
                        return Err(err);
                    }
                };
                unsafe { write_at(&mut data, i, x) };
            }
            return Ok(Self { data });
        }

        // Note: caller must ensure offsets are valid and bytes contain LENGTH elements.
        let mut data = Vec::with_capacity(LENGTH);
        unsafe { data.set_len(LENGTH) };
        for i in 0..LENGTH {
            let off_start = i * 4;
            let off_end = off_start + 4;
            let start = u32::from_le_bytes(bytes[off_start..off_end].try_into().unwrap()) as usize;
            let end = if i + 1 < LENGTH {
                let next_start = (i + 1) * 4;
                let next_end = next_start + 4;
                u32::from_le_bytes(bytes[next_start..next_end].try_into().unwrap()) as usize
            } else {
                bytes.len()
            };
            let x = match T::decode_ssz(&bytes[start..end]) {
                Ok(val) => val,
                Err(err) => {
                    unsafe {
                        let ptr: *mut T = data.as_mut_ptr();
                        for j in 0..i {
                            core::ptr::drop_in_place(ptr.add(j));
                        }
                        data.set_len(0);
                    }
                    return Err(err);
                }
            };
            unsafe { write_at(&mut data, i, x) };
        }
        Ok(Self { data })
    }
}

impl<T, const LIMIT: usize> SszDecode for SszList<T, LIMIT>
where
    T: SszDecode + SszElement,
{
    /// X1:
    #[inline]
    fn decode_ssz(bytes: &[u8]) -> Result<Self, String> {
        if let Some(elem_len) = T::fixed_len_opt() {
            let len = bytes.len() / elem_len;
            let mut data: Vec<T> = Vec::with_capacity(len);
            // Note: caller must ensure bytes length is a multiple of elem_len (no defensive checks).
            unsafe { data.set_len(len) };
            for i in 0..len {
                let start = i * elem_len;
                let end = start + elem_len;

                let x = match T::decode_ssz(&bytes[start..end]) {
                    Ok(val) => val,
                    Err(err) => {
                        unsafe {
                            let ptr: *mut T = data.as_mut_ptr();
                            for j in 0..i {
                                core::ptr::drop_in_place(ptr.add(j));
                            }
                            data.set_len(0);
                        }
                        return Err(err);
                    }
                };
                unsafe { write_at(&mut data, i, x) };
            }
            return Ok(Self { data });
        }

        if bytes.is_empty() {
            return Ok(Self { data: Vec::new() });
        }

        let first = u32::from_le_bytes(bytes[0..4].try_into().unwrap()) as usize;
        let len = first / 4;
        let mut data: Vec<T> = Vec::with_capacity(len);
        unsafe { data.set_len(len) };
        for i in 0..len {
            let off_start = i * 4;
            let off_end = off_start + 4;
            let start = u32::from_le_bytes(bytes[off_start..off_end].try_into().unwrap()) as usize;
            let end = if i + 1 < len {
                let next_start = (i + 1) * 4;
                let next_end = next_start + 4;
                u32::from_le_bytes(bytes[next_start..next_end].try_into().unwrap()) as usize
            } else {
                bytes.len()
            };

            let x = match T::decode_ssz(&bytes[start..end]) {
                Ok(val) => val,
                Err(err) => {
                    unsafe {
                        let ptr: *mut T = data.as_mut_ptr();
                        for j in 0..i {
                            core::ptr::drop_in_place(ptr.add(j));
                        }
                        data.set_len(0);
                    }
                    return Err(err);
                }
            };
            unsafe { write_at(&mut data, i, x) };
        }
        Ok(Self { data })
    }
}

impl<T, const LENGTH: usize> HashTreeRoot for SszVector<T, LENGTH>
where
    T: SszEncode + SszElement + HashTreeRoot,
{
    fn hash_tree_root(&self) -> [u8; 32] {
        if let Some(elem_len) = T::fixed_len_opt() {
            let bytes = self.encode_ssz();
            let chunks = chunkify_fixed(&bytes);
            let limit_chunks = ((LENGTH * elem_len) + BYTES_PER_CHUNK - 1) / BYTES_PER_CHUNK;
            let root =
                merkleize_with_limit(&chunks, limit_chunks).unwrap_or_else(|_| Bytes32::zero());
            return *root.as_ref();
        }

        let count = self.data.len();
        let mut chunks: Vec<Bytes32> = Vec::with_capacity(count);
        unsafe { chunks.set_len(count) };
        for (i, item) in self.data.iter().enumerate() {
            let root = Bytes32::from(item.hash_tree_root());
            unsafe { write_at(&mut chunks, i, root) };
        }
        let root = merkleize_with_limit(&chunks, LENGTH).unwrap_or_else(|_| Bytes32::zero());
        *root.as_ref()
    }
}

impl<T, const LIMIT: usize> HashTreeRoot for SszList<T, LIMIT>
where
    T: SszEncode + SszElement + HashTreeRoot,
{
    fn hash_tree_root(&self) -> [u8; 32] {
        if let Some(elem_len) = T::fixed_len_opt() {
            let bytes = self.encode_ssz();
            let chunks = chunkify_fixed(&bytes);
            let limit_chunks = ((LIMIT * elem_len) + BYTES_PER_CHUNK - 1) / BYTES_PER_CHUNK;
            let root =
                merkleize_with_limit(&chunks, limit_chunks).unwrap_or_else(|_| Bytes32::zero());
            let mixed = mix_in_length(&root, self.data.len());
            return *mixed.as_ref();
        }

        let count = self.data.len();
        let mut chunks: Vec<Bytes32> = Vec::with_capacity(count);
        unsafe { chunks.set_len(count) };
        for (i, item) in self.data.iter().enumerate() {
            let root = Bytes32::from(item.hash_tree_root());
            unsafe { write_at(&mut chunks, i, root) };
        }
        let root = merkleize_with_limit(&chunks, LIMIT).unwrap_or_else(|_| Bytes32::zero());
        let mixed = mix_in_length(&root, self.data.len());
        *mixed.as_ref()
    }
}
