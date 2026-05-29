/// Primitive and composite SSZ types for peam.
///
/// This module provides the type system that underpins SSZ serialization,
/// merkleization, and consensus data structures:
///
/// - [`bytes`] — Fixed-size byte arrays (`Bytes32`, `Bytes52`, `Bytes3112`) and
///   variable-length `ByteList<LIMIT>`. `Bytes32` is the universal root/hash type.
/// - [`uint`] — `Uint64` wrapper with little-endian SSZ encoding.
/// - [`bitlist`] — `BitList<LIMIT>` (variable-length) and `BitVector<LENGTH>`
///   (fixed-length) bitfields for attestation aggregation bits.
/// - [`collections`] — `SszList<T, LIMIT>` (bounded variable-length) and
///   `SszVector<T, LENGTH>` (fixed-length) generic containers.
/// - [`container`] — `Container` marker trait for SSZ composite types.
pub mod bitlist {
    pub use peam_consensus_types::types::bitlist::*;
}

pub mod bytes {
    pub use peam_consensus_types::types::bytes::*;
}

pub mod collections {
    pub use peam_consensus_types::types::collections::*;
}

pub mod container {
    pub use peam_consensus_types::types::container::*;
}

pub mod uint {
    pub use peam_consensus_types::types::uint::*;
}
