//! SQLite threat database — stores all verdicts, signal chains, and quarantine metadata.

use anthill_core::{config::PersistenceConfig, RiskScore};
use anyhow::{Context, Result};
use rusqlite::{Connection, params};
use std::sync::Mutex;
use tracing::info;

pub struct ThreatDb {
    conn: Mutex<Connection>,
}

impl ThreatDb {
    pub fn open(cfg: &PersistenceConfig) -> Result<Self> {
        if let Some(parent) = cfg.db_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let conn = Connection::open(&cfg.db_path)
            .context("failed to open SQLite database")?;

        let db = Self { conn: Mutex::new(conn) };
        db.migrate()?;
        info!(path = ?cfg.db_path, "threat database opened");
        Ok(db)
    }

    fn migrate(&self) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute_batch(include_str!("migrations/V1__initial.sql"))
            .context("migration V1 failed")?;
        Ok(())
    }

    /// Persist a completed verdict to the database.
    pub fn insert_verdict(
        &self,
        verdict_id: &str,
        path: &str,
        pid: u32,
        score: &RiskScore,
    ) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO verdicts
             (verdict_id, subject_path, subject_pid, verdict, risk_score,
              sig_conf, beh_conf, ml_conf, box_conf, rules_fired, created_at)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10, strftime('%s','now'))",
            params![
                verdict_id,
                path,
                pid,
                format!("{:?}", score.verdict),
                score.composite,
                score.sig_conf,
                score.beh_conf,
                score.ml_conf,
                score.box_conf,
                score.rules_fired.join(","),
            ],
        )?;
        Ok(())
    }

    /// Retrieve the N most recent verdicts for the TUI.
    pub fn recent_verdicts(&self, limit: u32) -> Result<Vec<VerdictRow>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT verdict_id, subject_path, verdict, risk_score, created_at
             FROM verdicts ORDER BY created_at DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit], |row| {
            Ok(VerdictRow {
                verdict_id:   row.get(0)?,
                subject_path: row.get(1)?,
                verdict:      row.get(2)?,
                risk_score:   row.get(3)?,
                created_at:   row.get(4)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>().context("query failed")
    }
}

#[derive(Debug, Clone)]
pub struct VerdictRow {
    pub verdict_id:   String,
    pub subject_path: String,
    pub verdict:      String,
    pub risk_score:   f64,
    pub created_at:   i64,
}
