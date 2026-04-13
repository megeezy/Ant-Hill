//! Signature engine — SHA-256 hash DB + YARA rule matching.

use anthill_core::{config::AnthillConfig, proto::{ThreatSignal, threat_signal}};
use anyhow::Result;
use dashmap::DashMap;
use tracing::{debug, info, warn};

/// A local hash database entry.
#[derive(Debug, Clone)]
pub struct HashEntry {
    pub sha256:   String,
    pub label:    String,  // "clean" | "malware"
    pub family:   String,
}

pub struct SignatureEngine {
    /// sha256 → HashEntry
    hash_db: DashMap<String, HashEntry>,
    // yara: yara::Rules,   // Phase 1: add YARA in week 2
}

impl SignatureEngine {
    pub async fn new(_cfg: &AnthillConfig) -> Result<Self> {
        let engine = Self {
            hash_db: DashMap::new(),
        };
        // TODO: load hash DB from SQLite in Phase 1
        // TODO: load YARA rules from /etc/anthill/rules/*.yar in Phase 1
        info!("signature engine initialised (hash_db = 0 entries, YARA = stub)");
        Ok(engine)
    }

    /// Returns confidence [0.0, 1.0].
    /// 0.0 = unknown, 0.05 = clean match, 0.95 = malware match.
    pub async fn evaluate(&self, signal: &ThreatSignal) -> f32 {
        match &signal.event {
            Some(threat_signal::Event::FileEvent(fe)) => {
                if fe.sha256.is_empty() { return 0.0; }
                match self.hash_db.get(&fe.sha256) {
                    Some(entry) if entry.label == "malware" => {
                        debug!(hash = fe.sha256, family = entry.family, "signature hit");
                        0.95
                    }
                    Some(_) => 0.05, // known clean
                    None    => 0.0,  // unknown
                }
            }
            _ => 0.0,
        }
    }

    /// Hot-reload the signature DB without restarting the process.
    pub fn reload(&self) {
        warn!("signature hot-reload: not yet implemented");
    }
}
