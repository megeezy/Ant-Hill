-- V1 — Initial schema
-- All future changes use V2__, V3__, etc. (same include_str! pattern)

CREATE TABLE IF NOT EXISTS verdicts (
    verdict_id   TEXT PRIMARY KEY,
    subject_path TEXT NOT NULL,
    subject_pid  INTEGER NOT NULL DEFAULT 0,
    verdict      TEXT NOT NULL,         -- CLEAN | QUARANTINE | KILL
    risk_score   REAL NOT NULL,
    sig_conf     REAL NOT NULL DEFAULT 0,
    beh_conf     REAL NOT NULL DEFAULT 0,
    ml_conf      REAL NOT NULL DEFAULT 0,
    box_conf     REAL NOT NULL DEFAULT 0,
    rules_fired  TEXT NOT NULL DEFAULT '',
    action_taken TEXT,
    user_approved INTEGER DEFAULT 0,
    created_at   INTEGER NOT NULL       -- Unix timestamp
);

CREATE INDEX IF NOT EXISTS idx_verdicts_created ON verdicts (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_verdicts_verdict  ON verdicts (verdict);

CREATE TABLE IF NOT EXISTS quarantine_vault (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    verdict_id   TEXT NOT NULL REFERENCES verdicts(verdict_id),
    original_path TEXT NOT NULL,
    vault_path   TEXT NOT NULL,
    sha256       TEXT NOT NULL,
    quarantined_at INTEGER NOT NULL,
    restored_at  INTEGER
);

CREATE TABLE IF NOT EXISTS ml_training_labels (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    sha256       TEXT NOT NULL UNIQUE,
    label        TEXT NOT NULL,         -- malware | clean
    source       TEXT NOT NULL,         -- analyst | av_consensus
    label_confidence REAL NOT NULL DEFAULT 1.0,
    created_at   INTEGER NOT NULL
);
