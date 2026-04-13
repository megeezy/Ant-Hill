//! Tier 5 — Persistence layer.
//!
//! SQLite (rusqlite) for verdicts and threat records.
//! sled for the ephemeral pheromone dedup cache.

pub mod sled_cache;
pub mod sqlite;

pub use sqlite::ThreatDb;
pub use sled_cache::PheromoneCache;
