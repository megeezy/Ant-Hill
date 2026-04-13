//! Allowlist — Tier 2 (user-configurable) process and path allowlist.
//! Tier 1 (immutable system processes) is enforced separately in anthill-soldier.

use anthill_core::proto::{ThreatSignal, threat_signal};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AllowlistConfig {
    #[serde(default)]
    pub processes: Vec<String>,
    #[serde(default)]
    pub paths: Vec<String>,
}

pub struct Allowlist {
    processes: Vec<String>,
    path_prefixes: Vec<String>,
}

impl Allowlist {
    /// Load from a TOML file. Rejects root-level wildcards for safety.
    pub fn load(toml_path: &Path) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(toml_path)
            .unwrap_or_default(); // missing file = empty allowlist

        let cfg: AllowlistConfig = toml::from_str(&content)
            .unwrap_or_default();

        // Safety: reject wildcards at the root (e.g. "/*" or "*")
        for p in &cfg.paths {
            if p == "*" || p == "/*" || p == "/**" {
                anyhow::bail!("allowlist path '{}' is too broad — rejected", p);
            }
        }

        tracing::info!(
            processes = cfg.processes.len(),
            paths = cfg.paths.len(),
            "allowlist loaded"
        );

        Ok(Self {
            processes: cfg.processes,
            path_prefixes: cfg.paths
                .into_iter()
                .map(|p| p.trim_end_matches('*').to_owned())
                .collect::<Vec<String>>(),
        })
    }

    pub fn empty() -> Self {
        Self { processes: vec![], path_prefixes: vec![] }
    }

    /// Returns true if the signal matches an allowlisted process or path.
    pub fn matches(&self, signal: &ThreatSignal) -> bool {
        match &signal.event {
            Some(threat_signal::Event::FileEvent(fe)) => {
                self.path_prefixes.iter().any(|p| fe.path.starts_with(p.as_str()))
            }
            Some(threat_signal::Event::ProcEvent(pe)) => {
                self.processes.iter().any(|p| pe.comm == *p || pe.exe_path.contains(p.as_str()))
            }
            _ => false,
        }
    }
}

impl Default for AllowlistConfig {
    fn default() -> Self {
        Self {
            processes: vec![],
            paths: vec![],
        }
    }
}
