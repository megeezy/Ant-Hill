//! anthill-core — shared types, config, and proto-generated structs.
//!
//! Every crate in the workspace depends on this. Keep it lean.

pub mod config;
pub mod proto;
pub mod types;

pub use types::*;
