use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// Risk / verdict enums (Rust-native mirror of proto enums)
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum Verdict {
    Clean,
    Quarantine,
    Kill,
}

impl Verdict {
    pub fn from_score(score: f32) -> Self {
        if score < 0.35 {
            Verdict::Clean
        } else if score < 0.70 {
            Verdict::Quarantine
        } else {
            Verdict::Kill
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Entity identifiers
// ─────────────────────────────────────────────────────────────────────────────

/// Unique identifier for a tracked entity (pid, ip, path hash, etc.)
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EntityId(pub String);

impl EntityId {
    pub fn from_pid(pid: u32) -> Self {
        Self(format!("pid:{pid}"))
    }
    pub fn from_ip(ip: &str) -> Self {
        Self(format!("ip:{ip}"))
    }
    pub fn from_path(path: &str) -> Self {
        Self(format!("path:{path}"))
    }
}

/// Identifies a specific behaviour rule
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RuleId(pub &'static str); // e.g. "T1055", "T1486"

// ─────────────────────────────────────────────────────────────────────────────
// Composite risk score — output of the rule correlator
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskScore {
    pub verdict_id:    String,
    pub pid:           u32,
    pub subject_path:  String,
    pub composite:     f32,
    pub sig_conf:      f32,
    pub beh_conf:      f32,
    pub ml_conf:       f32,
    pub box_conf:      f32,
    pub rules_fired:   Vec<String>,
    pub verdict:       Verdict,
}

impl RiskScore {
    pub fn verdict_id(&self) -> &str { &self.verdict_id }
    pub fn pid(&self) -> u32 { self.pid }
    pub fn subject_path(&self) -> &str { &self.subject_path }
}

impl RiskScore {
    pub fn compute(
        verdict_id: String, pid: u32, subject_path: String,
        sig_conf: f32, beh_conf: f32, ml_conf: f32, box_conf: f32,
        w_sig: f32, w_beh: f32, w_ml: f32, w_box: f32,
        rules_fired: Vec<String>,
    ) -> Self {
        let composite =
            w_sig * sig_conf + w_beh * beh_conf + w_ml * ml_conf + w_box * box_conf;
        Self {
            verdict_id,
            pid,
            subject_path,
            composite,
            sig_conf,
            beh_conf,
            ml_conf,
            box_conf,
            rules_fired,
            verdict: Verdict::from_score(composite),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Feature vector for ML inference / drift monitoring
// ─────────────────────────────────────────────────────────────────────────────

/// Static features extracted from a PE or script file for ML inference.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileFeatureVector {
    pub import_entropy:  f32,
    pub section_count:   u8,
    pub has_packer_sig:  bool,
    pub string_entropy:  f32,
    pub file_size_kb:    u32,
    pub has_overlay:     bool,
    pub is_signed:       bool,
}

// ─────────────────────────────────────────────────────────────────────────────
// Forensic bundle — captured before every destructive action
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForensicBundle {
    pub verdict_id:   String,
    pub pid:          u32,
    pub file_path:    String,
    pub file_sha256:  String,
    pub proc_maps:    String,
    pub proc_cmdline: String,
    pub proc_environ: String,
    pub open_fds:     Vec<String>,
    pub open_sockets: Vec<String>,
    pub captured_at:  i64, // Unix ms
}

// ─────────────────────────────────────────────────────────────────────────────
// Shared error taxonomy
// ─────────────────────────────────────────────────────────────────────────────

#[derive(thiserror::Error, Debug)]
pub enum AnthillError {
    #[error("agent error: {0}")]
    Agent(String),
    #[error("bus error: {0}")]
    Bus(String),
    #[error("queen error: {0}")]
    Queen(String),
    #[error("soldier error: {0}")]
    Soldier(String),
    #[error("config error: {0}")]
    Config(String),
    #[error("io error: {source}")]
    Io { #[from] source: std::io::Error },
}
