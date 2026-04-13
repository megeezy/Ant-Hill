//! Tier 1.5 — Pre-filter layer.
//!
//! Runs inside each sensor agent process (zero IPC cost).
//! Three responsibilities: deduplication, burst collapse, allowlist gate.

pub mod allowlist;
pub mod burst;
pub mod dedup;

use anthill_core::{config::PrefilterConfig, proto::ThreatSignal};
use allowlist::Allowlist;
use burst::BurstTracker;
use dedup::DedupCache;

/// Single entry point. Call this for every raw event before pushing to the bus.
/// Returns `Some(signal)` if the event should be forwarded, `None` to drop it.
pub struct PreFilter {
    dedup:     DedupCache,
    burst:     BurstTracker,
    allowlist: Allowlist,
    cfg:       PrefilterConfig,
}

impl PreFilter {
    pub fn new(cfg: PrefilterConfig, allowlist: Allowlist) -> Self {
        Self {
            dedup: DedupCache::new(cfg.dedup_window_ms),
            burst: BurstTracker::new(cfg.burst_threshold),
            allowlist,
            cfg,
        }
    }

    pub fn process(&mut self, signal: ThreatSignal) -> Option<ThreatSignal> {
        // 1. Deduplication
        if self.dedup.is_duplicate(&signal) {
            return None;
        }
        self.dedup.record(&signal);

        // 2. Allowlist gate — drop low-confidence known-safe events
        if self.allowlist.matches(&signal) && signal.confidence < self.cfg.max_confidence_drop {
            return None;
        }

        // 3. Burst collapse — may return a FileBurstEvent instead
        self.burst.push(signal)
    }
}
