/// Marker trait for SSZ composite (container) types. Containers are structs
/// whose fields are individually SSZ-encoded and whose hash_tree_root is the
/// merkleization of their per-field roots.
pub trait Container {}
