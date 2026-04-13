//! Behaviour rules — one file per MITRE ATT&CK technique.

pub mod t1055_injection;
pub mod t1059_script_exec;
pub mod t1070_log_tamper;
pub mod t1071_c2_beacon;
pub mod t1486_ransomware;
pub mod t1548_priv_esc;

use anthill_core::proto::ThreatSignal;
use super::window_store::WindowStore;

/// Every behaviour rule implements this trait.
pub trait BehaviourRule {
    fn rule_id(&self) -> &'static str;
    /// Returns `Some(confidence)` if the rule fires, `None` otherwise.
    fn evaluate(&self, store: &WindowStore, signal: &ThreatSignal) -> Option<f32>;
}

/// Instantiate all rules. Add new rules here.
#[allow(non_snake_case)]
pub fn ALL_RULES() -> Vec<Box<dyn BehaviourRule + Send + Sync>> {
    vec![
        Box::new(t1055_injection::T1055Injection),
        Box::new(t1059_script_exec::T1059ScriptExec),
        Box::new(t1070_log_tamper::T1070LogTamper),
        Box::new(t1071_c2_beacon::T1071C2Beacon),
        Box::new(t1486_ransomware::T1486Ransomware),
        Box::new(t1548_priv_esc::T1548PrivEsc),
    ]
}
