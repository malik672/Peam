#![allow(dead_code)]

#[inline]
pub unsafe fn write_at<T>(vec: &mut Vec<T>, index: usize, value: T) {
    unsafe {
        core::ptr::write(vec.as_mut_ptr().add(index), value);
    }
}

#[inline]
pub unsafe fn write_bytes_at(vec: &mut Vec<u8>, offset: usize, bytes: &[u8]) {
    unsafe {
        core::ptr::copy_nonoverlapping(bytes.as_ptr(), vec.as_mut_ptr().add(offset), bytes.len());
    }
}
