//! T1055 — Process Injection
//!
//! Detects WriteProcessMemory + CreateRemoteThread pair within 500ms
//! on the same target PID.

use anthill_core::{proto::ThreatSignal, EntityId};
use super::super::window_store::WindowStore;
use super::BehaviourRule;

pub struct T1055Injection;

impl BehaviourRule for T1055Injection {
    fn rule_id(&self) -> &'static str { "T1055" }

    fn evaluate(&self, store: &WindowStore, signal: &ThreatSignal) -> Option<f32> {
        let pid = match &signal.event {
            Some(anthill_core::proto::threat_signal::Event::MemEvent(me)) => me.pid,
            _ => return None,
        };

        let entity = EntityId::from_pid(pid);
        let window = store.read(&entity, "T1055")?;
        let now    = signal.ts;

        // Within any 500ms sub-window, need both exec_anon AND write_proc_mem
        let recent: Vec<_> = window.within(now, 500).collect();
        let has_write = recent.iter().any(|e| e.kind == "write_proc_mem");
        let has_exec  = recent.iter().any(|e| e.kind == "exec_anon");

        if has_write && has_exec {
            Some(0.92)
        } else {
            None
        }
    }
}
