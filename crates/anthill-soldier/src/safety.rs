//! Safety checker — maps a verdict + process info → ResponseDecision.
//!
//! The three-level protection model:
//!   Inviolable         → soft-quarantine only, never kill
//!   RequiresConfirmation → pause + TUI dialog
//!   Normal             → execute according to configured ResponseMode

use anthill_core::{config::{ResponseConfig, ResponseMode}, RiskScore};
use anyhow::Result;
use super::protected::{IMMUTABLE_PROTECTED, CONFIRM_REQUIRED_UIDS, UserAllowlist};
use tracing::info;

#[derive(Debug, Clone, PartialEq)]
pub enum ProtectionLevel {
    /// Processes that must never be killed under any circumstance.
    Inviolable,
    /// Root-owned or otherwise sensitive processes that need human sign-off.
    RequiresConfirmation,
    /// Normal process — apply configured response mode.
    Normal,
}

#[derive(Debug, Clone)]
pub enum ResponseDecision {
    /// Skip all destructive actions. Soft-quarantine + log only.
    Inviolable,
    /// Immediately soft-quarantine; prompt TUI for human decision.
    SoftQuarantine,
    /// Pause execution, emit TUI confirmation request.
    ConfirmRequired { reason: String },
    /// Execute the verdict's action immediately.
    Execute,
    /// ResponseMode::Monitor — detect and log, zero action.
    Monitor,
}

pub struct SafetyChecker {
    allowlist: UserAllowlist,
    mode:      ResponseMode,
}

impl SafetyChecker {
    pub fn load(cfg: &ResponseConfig) -> Result<Self> {
        let allowlist = UserAllowlist::load(&cfg.protected.allowlist_path);
        Ok(Self {
            allowlist,
            mode: cfg.mode.clone(),
        })
    }

    /// Compute the protection level for a process.
    pub fn protection_level(&self, pid: u32, name: &str, uid: u32, ppid: u32) -> ProtectionLevel {
        // Tier 1: immutable hardcoded list
        if IMMUTABLE_PROTECTED.contains(&name) {
            return ProtectionLevel::Inviolable;
        }
        // Tier 2: user allowlist (logged with ⚠ badge)
        if self.allowlist.process_allowed(name) {
            info!(name, "⚠ process allowed via user override");
            return ProtectionLevel::Inviolable;
        }
        // Root-owned PID-1 children require confirmation
        if CONFIRM_REQUIRED_UIDS.contains(&uid) && ppid == 1 {
            return ProtectionLevel::RequiresConfirmation;
        }
        ProtectionLevel::Normal
    }

    /// Full check — maps verdict + process info → ResponseDecision.
    /// `pid`, `name`, `uid`, `ppid` should come from the process monitor.
    pub fn check(&self, pid: u32, path: &str, score: &RiskScore) -> ResponseDecision {
        // Monitor mode: always log only, regardless of verdict
        if self.mode == ResponseMode::Monitor {
            return ResponseDecision::Monitor;
        }

        // Path-based allowlist check
        if self.allowlist.path_allowed(path) {
            info!(path, "⚠ path allowed via user override");
            return ResponseDecision::Monitor;
        }

        // For now use heuristic protection level on pid 0 = unknown
        // Phase 2 will wire in live process info from the proc_monitor
        let level = if pid == 0 {
            ProtectionLevel::Normal
        } else {
            self.protection_level(pid, "", 1000, 100) // stubs until proc lookup
        };

        match level {
            ProtectionLevel::Inviolable => ResponseDecision::Inviolable,
            ProtectionLevel::RequiresConfirmation => ResponseDecision::ConfirmRequired {
                reason: format!("protected process pid={pid}, score={:.2}", score.composite),
            },
            ProtectionLevel::Normal => match self.mode {
                ResponseMode::Auto    => ResponseDecision::Execute,
                ResponseMode::Confirm => ResponseDecision::ConfirmRequired {
                    reason: format!("score={:.2}, verdict={:?}", score.composite, score.verdict),
                },
                ResponseMode::Monitor => ResponseDecision::Monitor,
            },
        }
    }
}
