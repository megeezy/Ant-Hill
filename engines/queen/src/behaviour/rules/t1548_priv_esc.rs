//! T1548 — Privilege Escalation
//!
//! Process transitions from UID > 1000 to UID 0, or acquires
//! CAP_SYS_ADMIN outside of a known installer context.

use anthill_core::{proto::{ThreatSignal, threat_signal}, EntityId};
use super::super::window_store::WindowStore;
use super::BehaviourRule;

/// Known installer / package manager processes that legitimately escalate.
const TRUSTED_ESCALATORS: &[&str] = &[
    "sudo", "su", "pkexec", "polkit",
    "apt", "dpkg", "rpm", "yum", "dnf", "pacman", "snap",
];

pub struct T1548PrivEsc;

impl BehaviourRule for T1548PrivEsc {
    fn rule_id(&self) -> &'static str { "T1548" }

    fn evaluate(&self, store: &WindowStore, signal: &ThreatSignal) -> Option<f32> {
        let pe = match &signal.event {
            Some(threat_signal::Event::ProcEvent(pe)) => pe,
            _ => return None,
        };

        // Skip trusted escalators
        if TRUSTED_ESCALATORS.iter().any(|&t| pe.comm.contains(t)) {
            return None;
        }

        // Check window for a UID transition: earlier entry had uid > 1000,
        // this entry has uid == 0
        if pe.uid != 0 { return None; }

        let entity = EntityId::from_pid(pe.pid);
        let window = store.read(&entity, "T1548")?;

        // Look back 30s for a previous event from the same PID with uid > 1000
        let had_user_uid = window
            .within(signal.ts, 30_000)
            .any(|e| e.kind.starts_with("uid:") && {
                e.kind[4..].parse::<u32>().unwrap_or(0) > 1000
            });

        if had_user_uid {
            Some(0.85)
        } else {
            None
        }
    }
}
