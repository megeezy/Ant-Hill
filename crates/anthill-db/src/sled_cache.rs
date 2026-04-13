//! sled-based pheromone cache — ephemeral, high-frequency signal state.
//! Used for deduplication and rate-limiting across process restarts.

use anthill_core::config::PersistenceConfig;
use anyhow::Result;
use sled::Db;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::info;

pub struct PheromoneCache {
    db: Db,
    ttl_secs: u64,
}

impl PheromoneCache {
    pub fn open(cfg: &PersistenceConfig, ttl_secs: u64) -> Result<Self> {
        std::fs::create_dir_all(&cfg.sled_path)?;
        let db = sled::open(&cfg.sled_path)?;
        info!(path = ?cfg.sled_path, "pheromone cache opened");
        Ok(Self { db, ttl_secs })
    }

    /// Record that a hash was seen. Returns true if this is the first time.
    pub fn seen_hash(&self, sha256: &str) -> Result<bool> {
        let key = sha256.as_bytes();
        let now = now_secs();
        let existing = self.db.get(key)?;
        let is_new = existing.is_none();
        self.db.insert(key, now.to_le_bytes().as_ref())?;
        Ok(is_new)
    }

    /// Check if a hash was seen within TTL.
    pub fn is_recent(&self, sha256: &str) -> Result<bool> {
        let key = sha256.as_bytes();
        if let Some(bytes) = self.db.get(key)? {
            if bytes.len() == 8 {
                let ts = u64::from_le_bytes(bytes.as_ref().try_into().unwrap_or([0u8; 8]));
                return Ok(now_secs().saturating_sub(ts) < self.ttl_secs);
            }
        }
        Ok(false)
    }

    /// Evict all expired entries. Call from a background task every 60s.
    pub fn evict_expired(&self) -> Result<usize> {
        let now = now_secs();
        let ttl = self.ttl_secs;
        let mut removed = 0usize;
        for item in self.db.iter() {
            let (key, val) = item?;
            if val.len() == 8 {
                let ts = u64::from_le_bytes(val.as_ref().try_into().unwrap_or([0u8; 8]));
                if now.saturating_sub(ts) >= ttl {
                    self.db.remove(key)?;
                    removed += 1;
                }
            }
        }
        Ok(removed)
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
