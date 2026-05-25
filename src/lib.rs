//! Peam workspace facade crate.
//!
//! The workspace is split into a few layers:
//!
//! - `peam-consensus-types` for consensus-model data structures and SSZ-facing types
//! - `peam-state` for state transition logic and generic verifier/metrics traits
//! - `peam-fork-choice` for fork-choice tracking and head selection
//! - `peam-storage` for storage engines, canonical indexes, and persistence
//! - `peam` (this crate) for node/runtime orchestration, networking, HTTP
//!   surfaces, and PQ-specific integration glue
//!
//! The modules re-exported here intentionally keep the older `peam::*` paths
//! available while the internals continue moving toward direct workspace-crate
//! boundaries.
//!
#![allow(clippy::uninit_vec)]
#![allow(clippy::manual_div_ceil)]
#![allow(clippy::collapsible_if)]
#![allow(clippy::clone_on_copy)]
#![allow(clippy::needless_range_loop)]
#![allow(clippy::redundant_closure)]
#![allow(clippy::type_complexity)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::manual_is_multiple_of)]
#![allow(clippy::len_without_is_empty)]
#![allow(clippy::missing_safety_doc)]

pub mod app;
pub mod checkpoint_sync;
pub mod containers;
pub mod crypto;
/// Facade re-export for the extracted fork-choice crate.
pub mod fork_choice {
    pub use peam_fork_choice::fork_choice::*;
}
pub mod logfmt;
pub mod metrics;
pub mod networking;
pub mod node;
pub mod ssz;
pub mod storage;
/// PQ-specific state-transition helpers that remain crate-local glue.
pub(crate) mod state_pq;
pub mod types;
pub mod unsafe_vec;

/// Facade re-export for the extracted slot/time model.
pub mod slot {
    pub use peam_consensus_types::slot::*;
}
