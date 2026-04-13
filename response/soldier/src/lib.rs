//! Tier 4 — Soldier Ant Response Layer.
//!
//! Pipeline: SafetyChecker → ForensicSnapshot → Action

pub mod actions;
pub mod forensics;
pub mod protected;
pub mod safety;

use anthill_core::{config::{ResponseConfig, PersistenceConfig}, RiskScore, Verdict};
use anyhow::Result;
use tracing::{info, warn};

pub use safety::{SafetyChecker, ProtectionLevel, ResponseDecision};
pub use forensics::ForensicCapture;

/// Main response handler. Call once per verdict.
pub struct SoldierLayer {
    safety:      SafetyChecker,
    forensics:   ForensicCapture,
    #[allow(dead_code)]
    cfg:         ResponseConfig,
    persistence: PersistenceConfig,
}

impl SoldierLayer {
    pub fn new(cfg: ResponseConfig, persistence: PersistenceConfig) -> Result<Self> {
        Ok(Self {
            safety:    SafetyChecker::load(&cfg)?,
            forensics: ForensicCapture::new(&persistence.forensics_path),
            cfg,
            persistence,
        })
    }

    /// Process a risk score from the Queen engine.
    /// Returns the action taken as a human-readable string.
    pub async fn respond(&self, score: &RiskScore, pid: u32, path: &str) -> String {
        if score.verdict == Verdict::Clean {
            return "CLEAN — no action".into();
        }

        // 1. Safety check
        let decision = self.safety.check(pid, path, score);
        info!(
            verdict   = ?score.verdict,
            score     = score.composite,
            pid,
            path,
            decision  = ?decision,
            "response decision"
        );

        // 2. Pre-action forensic snapshot (always, before any destructive action)
        if let Err(e) = self.forensics.capture(pid, path, score.verdict_id()).await {
            warn!("forensic capture failed: {e}");
        }

        // 3. Execute
        match decision {
            ResponseDecision::Inviolable => {
                warn!(pid, "inviolable process — soft-quarantine only");
                actions::quarantine::soft_quarantine(path).await
                    .map(|_| format!("SOFT_QUARANTINE (inviolable: {path})"))
                    .unwrap_or_else(|e| format!("SOFT_QUARANTINE_FAILED: {e}"))
            }
            ResponseDecision::SoftQuarantine => {
                actions::quarantine::soft_quarantine(path).await
                    .map(|_| format!("SOFT_QUARANTINE: {path}"))
                    .unwrap_or_else(|e| format!("FAILED: {e}"))
            }
            ResponseDecision::ConfirmRequired { reason } => {
                // Soft-quarantine immediately, then ask for user confirmation
                let _ = actions::quarantine::soft_quarantine(path).await;
                format!("PENDING_CONFIRM: {reason}")
            }
            ResponseDecision::Execute => {
                self.execute_verdict(score, pid, path).await
            }
            ResponseDecision::Monitor => {
                "MONITOR — logged, no action".into()
            }
        }
    }

    async fn execute_verdict(&self, score: &RiskScore, pid: u32, path: &str) -> String {
        match score.verdict {
            Verdict::Kill => {
                if let Err(e) = actions::kill::kill_process(pid).await {
                    return format!("KILL_FAILED: {e}");
                }
                if let Err(e) = actions::quarantine::hard_quarantine(path, &self.persistence).await {
                    warn!("hard quarantine after kill failed: {e}");
                }
                format!("KILLED pid={pid}, QUARANTINED {path}")
            }
            Verdict::Quarantine => {
                actions::quarantine::hard_quarantine(path, &self.persistence).await
                    .map(|_| format!("QUARANTINED: {path}"))
                    .unwrap_or_else(|e| format!("QUARANTINE_FAILED: {e}"))
            }
            Verdict::Clean => unreachable!(),
        }
    }
}
