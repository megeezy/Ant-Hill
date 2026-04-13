//! Burst tracker — collapses rapid repeated operations into a single
//! `FileBurstEvent` with aggregate entropy delta.

use anthill_core::proto::{FileBurstEvent, ThreatSignal, threat_signal};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

struct BurstBucket {
    count:           u32,
    #[allow(dead_code)]
    entropy_sum:     f32,
    #[allow(dead_code)]
    window_start_ts: i64,
    #[allow(dead_code)]
    source:          i32,
    #[allow(dead_code)]
    base_path:       String,
}

pub struct BurstTracker {
    threshold: u32,
    buckets:   HashMap<String, BurstBucket>,
}

impl BurstTracker {
    pub fn new(threshold: u32) -> Self {
        Self {
            threshold,
            buckets: HashMap::new(),
        }
    }

    /// Push a signal. Returns:
    /// - `None`          if the event was absorbed into an active burst bucket
    /// - `Some(signal)`  either the original signal (no burst) or a FileBurstEvent
    pub fn push(&mut self, signal: ThreatSignal) -> Option<ThreatSignal> {
        // Only collapse FileEvents into bursts
        let (path, entropy, source) = match &signal.event {
            Some(threat_signal::Event::FileEvent(fe)) => {
                let dir = parent_dir(&fe.path);
                (dir, fe.entropy, signal.source)
            }
            _ => return Some(signal), // non-file events pass through unchanged
        };

        let bucket = self.buckets.entry(path.clone()).or_insert_with(|| BurstBucket {
            count:           0,
            entropy_sum:     0.0,
            window_start_ts: signal.ts,
            source,
            base_path:       path.clone(),
        });

        bucket.count += 1;
        bucket.entropy_sum += entropy;

        if bucket.count >= self.threshold {
            let burst = self.flush_bucket(&path);
            return Some(burst);
        }

        // Event absorbed — not yet at threshold
        None
    }

    fn flush_bucket(&mut self, path: &str) -> ThreatSignal {
        let b = self.buckets.remove(path).unwrap();
        let now = now_ms();
        ThreatSignal {
            source:     b.source,
            confidence: 1.0, // bursts are always high-priority
            ttl_seconds: 60,
            ts:         now,
            event: Some(threat_signal::Event::FileBurst(FileBurstEvent {
                base_path:       b.base_path,
                count:           b.count,
                entropy_delta:   b.entropy_sum / b.count as f32,
                source:          b.source,
                window_start_ts: b.window_start_ts,
                window_end_ts:   now,
            })),
        }
    }
}

fn parent_dir(path: &str) -> String {
    std::path::Path::new(path)
        .parent()
        .and_then(|p| p.to_str())
        .unwrap_or("/")
        .to_owned()
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}
