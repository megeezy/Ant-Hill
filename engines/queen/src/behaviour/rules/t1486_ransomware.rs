//! T1486 — Ransomware Pattern
//!
//! More than 200 file rename/overwrite operations within 10 seconds,
//! with average entropy increase > 1.5 bits per file.

use anthill_core::{proto::{ThreatSignal, threat_signal}, EntityId};
use super::super::window_store::WindowStore;
use super::BehaviourRule;

const RENAME_THRESHOLD: usize = 200;
const ENTROPY_THRESHOLD: f32  = 1.5;
const WINDOW_MS: i64          = 10_000; // 10 seconds

pub struct T1486Ransomware;

impl BehaviourRule for T1486Ransomware {
    fn rule_id(&self) -> &'static str { "T1486" }

    fn evaluate(&self, store: &WindowStore, signal: &ThreatSignal) -> Option<f32> {
        let fe = match &signal.event {
            Some(threat_signal::Event::FileEvent(fe)) => fe,
            Some(threat_signal::Event::FileBurst(fb)) => {
                // Fast path: burst event already aggregates the count + entropy
                if fb.count >= RENAME_THRESHOLD as u32
                    && fb.entropy_delta >= ENTROPY_THRESHOLD
                {
                    return Some(0.97); // near-certain ransomware
                }
                return None;
            }
            _ => return None,
        };

        // Slow path: count individual file events per directory
        let entity = EntityId::from_path(&fe.path);
        let window = store.read(&entity, "T1486")?;
        let now    = signal.ts;

        let recent: Vec<_> = window.within(now, WINDOW_MS).collect();
        if recent.len() < RENAME_THRESHOLD { return None; }

        let avg_entropy: f32 = recent.iter().map(|e| e.weight).sum::<f32>()
            / recent.len() as f32;

        if avg_entropy >= ENTROPY_THRESHOLD {
            Some(0.97)
        } else {
            None
        }
    }
}
