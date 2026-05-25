use peam::types::bytes::Bytes32;

pub fn decode_hex(s: &str) -> Vec<u8> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    assert!(s.len().is_multiple_of(2), "hex string has odd length");

    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    let mut i = 0usize;

    while i < bytes.len() {
        let hi = (bytes[i] as char).to_digit(16).expect("hex digit");
        let lo = (bytes[i + 1] as char).to_digit(16).expect("hex digit");
        out.push(((hi << 4) | lo) as u8);
        i += 2;
    }

    out
}

pub fn bytes32_from_hex(s: &str) -> Bytes32 {
    let bytes = decode_hex(s);
    Bytes32::from_slice(&bytes)
}
