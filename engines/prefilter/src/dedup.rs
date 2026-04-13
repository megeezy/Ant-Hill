use anthill_core::proto::ThreatSignal;
use dashmap::DashMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// Rolling deduplication cache. Events with the same key seen within
/// `window_ms` milliseconds are suppressed.
pub struct DedupCache {
    /// key → last-seen timestamp (Unix ms)
    seen:      DashMap<u64, u64>,
    window_ms: u64,
}

impl DedupCache {
    pub fn new(window_ms: u64) -> Self {
        Self {
            seen: DashMap::new(),
            window_ms,
        }
    }

    pub fn is_duplicate(&self, signal: &ThreatSignal) -> bool {
        let key = event_key(signal);
        let now = now_ms();
        if let Some(last) = self.seen.get(&key) {
            if now.saturating_sub(*last) < self.window_ms {
                return true;
            }
        }
        false
    }

    pub fn record(&self, signal: &ThreatSignal) {
        self.seen.insert(event_key(signal), now_ms());
    }

    /// Evict stale entries. Call periodically (e.g. every 5 s) to prevent
    /// unbounded growth.
    pub fn evict_stale(&self) {
        let now = now_ms();
        let window = self.window_ms;
        self.seen.retain(|_, last_seen| now.saturating_sub(*last_seen) < window * 10);
    }
}

fn event_key(s: &ThreatSignal) -> u64 {
    use std::hash::{Hash, Hasher};
    use std::collections::hash_map::DefaultHasher;
    let mut h = DefaultHasher::new();
    // Hash the source + confidence bucket + event discriminant
    s.source.hash(&mut h);
    ((s.confidence * 10.0) as u32).hash(&mut h);
    // Include a rough event fingerprint (path/pid) without full proto decode
    s.ts.hash(&mut h);
    h.finish()
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
