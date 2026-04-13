//! T1059 — Script Execution
//!
//! Detects any interpreter (python, bash, powershell) spawned by a
//! non-interactive process that has an open network connection within 30s.

use anthill_core::{proto::{ThreatSignal, threat_signal}, EntityId};
use super::super::window_store::WindowStore;
use super::BehaviourRule;

const INTERPRETERS: &[&str] = &[
    "python", "python3", "bash", "sh", "dash", "zsh",
    "powershell", "pwsh", "perl", "ruby", "node",
];

pub struct T1059ScriptExec;

impl BehaviourRule for T1059ScriptExec {
    fn rule_id(&self) -> &'static str { "T1059" }

    fn evaluate(&self, store: &WindowStore, signal: &ThreatSignal) -> Option<f32> {
        let pe = match &signal.event {
            Some(threat_signal::Event::ProcEvent(pe)) => pe,
            _ => return None,
        };

        // Is this process an interpreter?
        let is_interpreter = INTERPRETERS.iter().any(|&i| pe.comm.contains(i));
        if !is_interpreter { return None; }

        // Was its parent a non-interactive process? (ppid is not a known shell/terminal)
        // Heuristic: ppid != 0 and parent comm is not in INTERPRETERS
        // Full parent-comm lookup deferred to Phase 2 (eBPF process tree)

        // Is there a recent network event from this PID?
        let entity = EntityId::from_pid(pe.pid);
        if let Some(net_window) = store.read(&entity, "T1071") {
            let recent_net = net_window.within(signal.ts, 30_000).count();
            if recent_net > 0 {
                return Some(0.78);
            }
        }

        None
    }
}
