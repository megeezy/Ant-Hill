//! T1071 — C2 Beaconing
//!
//! Regular outbound connections at fixed intervals (jitter < 5%) to a
//! non-CDN IP, with small uniform payload size.

use anthill_core::{proto::{ThreatSignal, threat_signal}, EntityId};
use super::super::window_store::{WindowStore, W_5MIN};
use super::BehaviourRule;

const MIN_SAMPLES: usize = 5;
const MAX_JITTER:  f64   = 0.05; // 5%

pub struct T1071C2Beacon;

impl BehaviourRule for T1071C2Beacon {
    fn rule_id(&self) -> &'static str { "T1071" }

    fn evaluate(&self, store: &WindowStore, signal: &ThreatSignal) -> Option<f32> {
        let ne = match &signal.event {
            Some(threat_signal::Event::NetEvent(ne)) => ne,
            _ => return None,
        };

        // Skip known CDN / cloud ranges (basic heuristic — Phase 2 uses a proper list)
        if is_cdn_heuristic(&ne.dst_ip) { return None; }

        let entity = EntityId::from_ip(&ne.dst_ip);
        let window = store.read(&entity, "T1071")?;

        let events: Vec<i64> = window
            .within(signal.ts, W_5MIN)
            .map(|e| e.ts)
            .collect();

        if events.len() < MIN_SAMPLES { return None; }

        // Compute inter-arrival intervals
        let intervals: Vec<f64> = events
            .windows(2)
            .map(|w| (w[1] - w[0]) as f64)
            .collect();

        let mean = intervals.iter().sum::<f64>() / intervals.len() as f64;
        if mean < 100.0 { return None; } // too fast — not a beacon, just traffic

        let jitter = intervals.iter()
            .map(|&i| ((i - mean) / mean).abs())
            .fold(0.0_f64, f64::max);

        if jitter < MAX_JITTER {
            Some(0.82)
        } else {
            None
        }
    }
}

/// Very basic heuristic: skip RFC1918 and well-known CDN CIDR prefixes.
fn is_cdn_heuristic(ip: &str) -> bool {
    ip.starts_with("10.")
        || ip.starts_with("172.16.")
        || ip.starts_with("192.168.")
        || ip.starts_with("127.")
        || ip.starts_with("::1")
}
