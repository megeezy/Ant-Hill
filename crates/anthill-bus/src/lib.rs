//! Tier 2 — Pheromone event bus.
//!
//! Bounded Tokio MPSC channels per agent + an append-only replay ring file.

pub mod channel;
pub mod replay;

pub use channel::{Bus, BusReceiver, BusSender};
