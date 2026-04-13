//! Protected process lists — two-tier design.
//!
//! Tier 1: Immutable / hardcoded. Cannot be overridden.
//! Tier 2: User allowlist from /etc/anthill/allowlist.toml (admin-only, 0600).

use serde::{Deserialize, Serialize};
use std::path::Path;
use tracing::{info, warn};

// ─────────────────────────────────────────────────────────────────────────────
// Tier 1 — Immutable (hardcoded + signed in release builds)
// ─────────────────────────────────────────────────────────────────────────────

/// These processes can NEVER be killed. Soft-quarantine is the maximum action.
/// This list is baked into the binary and cannot be overridden by any config.
pub const IMMUTABLE_PROTECTED: &[&str] = &[
    // Linux init & supervision
    "systemd", "init", "openrc", "runit", "s6-svscan",
    // Kernel threads (cannot be killed anyway, but explicit)
    "kthreadd", "kworker", "ksoftirqd", "migration", "rcu_sched",
    // macOS (Phase 3)
    "launchd", "kernel_task",
    // Anthill itself — prevent self-termination
    "anthill-queen", "anthill-agent", "anthill-soldier", "anthill",
    // Critical logging daemons
    "systemd-journald", "journald", "syslogd", "rsyslogd",
    // Network (killing these = silent network loss)
    "NetworkManager", "systemd-networkd", "dhclient", "dhcpcd",
];

/// Root-owned PID-1 children require human confirmation before any action.
pub const CONFIRM_REQUIRED_UIDS: &[u32] = &[0]; // UID 0 + ppid=1 = confirm

// ─────────────────────────────────────────────────────────────────────────────
// Tier 2 — User allowlist
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UserAllowlist {
    #[serde(default)]
    pub processes: Vec<String>,
    #[serde(default)]
    pub paths: Vec<String>,
}

impl UserAllowlist {
    /// Load from /etc/anthill/allowlist.toml.
    /// Silently returns empty allowlist if file does not exist.
    pub fn load(path: &Path) -> Self {
        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => return Self::default(),
        };

        let list: UserAllowlist = match toml::from_str(&content) {
            Ok(l) => l,
            Err(e) => {
                warn!("allowlist parse error: {e} — using empty allowlist");
                return Self::default();
            }
        };

        // Reject root-level wildcards
        for p in &list.paths {
            if matches!(p.as_str(), "*" | "/*" | "/**" | "/") {
                warn!("allowlist path '{}' is too broad — ignoring entire allowlist", p);
                return Self::default();
            }
        }

        info!(
            processes = list.processes.len(),
            paths = list.paths.len(),
            "user allowlist loaded"
        );
        list
    }

    pub fn process_allowed(&self, name: &str) -> bool {
        self.processes.iter().any(|p| p == name)
    }

    pub fn path_allowed(&self, path: &str) -> bool {
        self.paths.iter().any(|p| {
            let prefix = p.trim_end_matches('*');
            path.starts_with(prefix)
        })
    }
}

// Re-export toml for the load above
use toml;
