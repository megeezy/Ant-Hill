use anyhow::{Context, Result};
use config::{Config, Environment, File};
use directories::ProjectDirs;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

// ─────────────────────────────────────────────────────────────────────────────
// Top-level profile
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum ProfileType {
    Enterprise,
    #[default]
    Developer,
    Personal,
}

// ─────────────────────────────────────────────────────────────────────────────
// Response configuration
// ─────────────────────────────────────────────────────────────────────────────

/// The three operating modes for the response layer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum ResponseMode {
    /// Execute countermeasures immediately — no human in loop.
    Auto,
    /// Pause, show TUI dialog, await human approval (5-min timeout → safe default).
    #[default]
    Confirm,
    /// Detect and log only. Zero destructive action. Ideal for onboarding / auditing.
    Monitor,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseConfig {
    pub mode:                   ResponseMode,
    pub confirm_timeout_s:      u64,
    pub safe_default_on_timeout: String, // "quarantine" | "kill" | "allow"
    pub protected:              ProtectedConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtectedConfig {
    pub allowlist_path: PathBuf,
}

// ─────────────────────────────────────────────────────────────────────────────
// Queen / detection configuration
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueenConfig {
    pub sig_weight:           f32,
    pub beh_weight:           f32,
    pub ml_weight:            f32,
    pub box_weight:           f32,
    pub clean_threshold:      f32,
    pub quarantine_threshold: f32,
    pub behaviour:            BehaviourConfig,
    pub ml:                   MlConfig,
    pub sandbox:              SandboxConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehaviourConfig {
    pub window_5s_cap:    usize,
    pub window_30s_cap:   usize,
    pub window_5min_cap:  usize,
    pub window_30min_cap: usize,
    pub max_tracked_pids: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MlConfig {
    pub model_path:           PathBuf,
    pub model_meta_path:      PathBuf,
    pub drift_threshold_kl:   f64,
    pub drift_sample_minimum: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SandboxBackend {
    Gvisor,
    Firecracker,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxConfig {
    pub enabled:                bool,
    pub backend:                SandboxBackend,
    pub pool_slots:             usize,
    pub queue_max:              usize,
    pub verdict_timeout_s:      u64,
    pub fast_path_ml_threshold: f32,
}

// ─────────────────────────────────────────────────────────────────────────────
// Pre-filter configuration
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrefilterConfig {
    pub burst_threshold:     u32,
    pub dedup_window_ms:     u64,
    pub max_confidence_drop: f32,
}

// ─────────────────────────────────────────────────────────────────────────────
// Persistence configuration
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistenceConfig {
    pub db_path:       PathBuf,
    pub sled_path:     PathBuf,
    pub forensics_path: PathBuf,
    pub vault_path:    PathBuf,
}

// ─────────────────────────────────────────────────────────────────────────────
// Agent configuration (Worker Ants)
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    pub file_monitor_enabled: bool,
    pub proc_monitor_enabled: bool,
    pub net_sniffer_enabled:  bool,
    pub mem_probe_enabled:    bool,
    pub scan_interval_ms:     u64,
}

// ─────────────────────────────────────────────────────────────────────────────
// Root config
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnthillConfig {
    pub profile:     ProfileSection,
    pub prefilter:   PrefilterConfig,
    pub agent:       AgentConfig,
    pub queen:       QueenConfig,
    pub response:    ResponseConfig,
    pub persistence: PersistenceConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileSection {
    #[serde(rename = "type")]
    pub profile_type: ProfileType,
}

impl AnthillConfig {
    /// Load config in priority order:
    ///   1. Built-in default.toml
    ///   2. Profile overlay (enterprise.toml / developer.toml)
    ///   3. /etc/anthill/anthill.toml  (system-wide override)
    ///   4. ~/.config/anthill/anthill.toml  (user override)
    ///   5. ANTHILL_* environment variables
    pub fn load(profile: Option<&str>) -> Result<Self> {
        let exe_dir = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(PathBuf::from))
            .unwrap_or_default();
        let config_dir = exe_dir.join("config");

        let profile_file = match profile {
            Some("enterprise") => "enterprise",
            Some("developer") | Some("personal") => "developer",
            _ => "developer",
        };

        let proj_dirs = ProjectDirs::from("io", "anthill", "anthill");
        let user_cfg = proj_dirs
            .as_ref()
            .map(|d| d.config_dir().join("anthill.toml"));

        let mut builder = Config::builder()
            .add_source(File::from(config_dir.join("default.toml")).required(true))
            .add_source(File::from(config_dir.join(profile_file)).required(false))
            .add_source(File::from(PathBuf::from("/etc/anthill/anthill.toml")).required(false));

        if let Some(user) = user_cfg {
            builder = builder.add_source(File::from(user).required(false));
        }

        let cfg = builder
            .add_source(Environment::with_prefix("ANTHILL").separator("__"))
            .build()
            .context("failed to build config")?;

        cfg.try_deserialize::<AnthillConfig>()
            .context("failed to deserialize config")
    }
}
