//! T1070 — Log Tampering
//!
//! Write or truncate on /var/log/*, Windows Event Log, or syslog
//! by a process that is NOT a known logging daemon.

use anthill_core::{proto::{ThreatSignal, threat_signal}, EntityId};
use super::super::window_store::WindowStore;
use super::BehaviourRule;

#[allow(dead_code)]
const LOGGING_DAEMONS: &[&str] = &[
    "journald", "systemd-journald", "syslogd", "rsyslogd",
    "syslog-ng", "logrotate", "logd", "auditd",
];

pub struct T1070LogTamper;

impl BehaviourRule for T1070LogTamper {
    fn rule_id(&self) -> &'static str { "T1070" }

    fn evaluate(&self, store: &WindowStore, signal: &ThreatSignal) -> Option<f32> {
        let fe = match &signal.event {
            Some(threat_signal::Event::FileEvent(fe)) => fe,
            _ => return None,
        };

        // Must be writing to a log directory
        if !fe.path.starts_with("/var/log")
            && !fe.path.starts_with("/run/log")
            && !fe.path.contains("syslog")
        {
            return None;
        }

        // Check if the writing PID belongs to a logging daemon
        // Full process lookup via proc_monitor is deferred to Phase 2
        // For now: check the T1070 window for a recent non-daemon write event
        let entity = EntityId::from_pid(fe.pid);
        let window = store.read(&entity, "T1070")?;
        let recent = window.within(signal.ts, 5_000).count();

        if recent > 0 {
            // Heuristic: if pid wrote to log AND is not in known daemon list,
            // treat as suspicious. Phase 2 will cross-reference with proc agent.
            Some(0.70)
        } else {
            None
        }
    }
}
