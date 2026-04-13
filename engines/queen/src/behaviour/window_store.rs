//! Sliding time-window store keyed by (EntityId, RuleId).
//!
//! Each window is a fixed-capacity ring buffer of (timestamp_ms, weight) pairs.
//! Entries older than the window TTL are lazily evicted on read.

use anthill_core::{config::BehaviourConfig, proto::{ThreatSignal, threat_signal}, EntityId, RuleId};
use dashmap::DashMap;
use std::collections::VecDeque;

// Window TTLs in milliseconds
pub const W_5S:    i64 = 5_000;
pub const W_30S:   i64 = 30_000;
pub const W_5MIN:  i64 = 300_000;
pub const W_30MIN: i64 = 1_800_000;

#[derive(Debug, Clone)]
pub struct WindowEntry {
    pub ts:     i64,   // Unix ms
    pub weight: f32,
    pub kind:   String, // event sub-type tag: "write_proc_mem", "fork", etc.
}

#[derive(Debug)]
pub struct RingWindow {
    buf: VecDeque<WindowEntry>,
    cap: usize,
}

impl RingWindow {
    pub fn new(cap: usize) -> Self {
        Self { buf: VecDeque::with_capacity(cap), cap }
    }

    pub fn push(&mut self, entry: WindowEntry) {
        if self.buf.len() >= self.cap {
            self.buf.pop_front();
        }
        self.buf.push_back(entry);
    }

    /// Returns entries within the last `duration_ms` milliseconds.
    pub fn within(&self, now_ms: i64, duration_ms: i64) -> impl Iterator<Item = &WindowEntry> {
        let cutoff = now_ms - duration_ms;
        self.buf.iter().filter(move |e| e.ts >= cutoff)
    }

    /// Evict entries older than `max_age_ms`.
    pub fn evict(&mut self, now_ms: i64, max_age_ms: i64) {
        let cutoff = now_ms - max_age_ms;
        while let Some(front) = self.buf.front() {
            if front.ts < cutoff {
                self.buf.pop_front();
            } else {
                break;
            }
        }
    }
}

/// The central store — shared across all rules.
pub struct WindowStore {
    /// (entity_id, rule_id) → time-windowed ring buffer
    windows: DashMap<(String, &'static str), RingWindow>,
    cfg:     BehaviourConfig,
}

impl WindowStore {
    pub fn new(cfg: &BehaviourConfig) -> Self {
        Self {
            windows: DashMap::new(),
            cfg:     cfg.clone(),
        }
    }

    pub fn push(&self, entity: &EntityId, rule: &'static str, entry: WindowEntry) {
        let key = (entity.0.clone(), rule);
        let cap = self.cfg.window_5min_cap; // default; rules can use any TTL
        self.windows
            .entry(key)
            .or_insert_with(|| RingWindow::new(cap))
            .push(entry);
    }

    pub fn read<'a>(
        &'a self,
        entity: &EntityId,
        rule: &'static str,
    ) -> Option<dashmap::mapref::one::Ref<'a, (String, &'static str), RingWindow>> {
        self.windows.get(&(entity.0.clone(), rule))
    }

    /// Ingest a raw ThreatSignal — pushes relevant entries per rule.
    pub fn ingest(&self, signal: &ThreatSignal) {
        let now = signal.ts;
        match &signal.event {
            Some(threat_signal::Event::FileEvent(fe)) => {
                let entity = EntityId::from_path(&fe.path);
                // Ransomware window
                self.push(&entity, "T1486", WindowEntry { ts: now, weight: signal.confidence, kind: "file_write".into() });
                // Log tamper window
                if fe.path.starts_with("/var/log") {
                    let ent = EntityId::from_pid(fe.pid);
                    self.push(&ent, "T1070", WindowEntry { ts: now, weight: 0.7, kind: "log_write".into() });
                }
            }
            Some(threat_signal::Event::ProcEvent(pe)) => {
                let entity = EntityId::from_pid(pe.pid);
                self.push(&entity, "T1059", WindowEntry { ts: now, weight: signal.confidence, kind: pe.comm.clone() });
                // Priv esc: track uid transitions
                let uid_tag = format!("uid:{}", pe.uid);
                self.push(&entity, "T1548", WindowEntry { ts: now, weight: signal.confidence, kind: uid_tag });
            }
            Some(threat_signal::Event::MemEvent(me)) => {
                let entity = EntityId::from_pid(me.pid);
                let kind = if me.exec_anon { "exec_anon" } else { "write_proc_mem" };
                self.push(&entity, "T1055", WindowEntry { ts: now, weight: 0.8, kind: kind.into() });
            }
            Some(threat_signal::Event::NetEvent(ne)) => {
                let entity = EntityId::from_ip(&ne.dst_ip);
                self.push(&entity, "T1071", WindowEntry { ts: now, weight: signal.confidence, kind: "outbound".into() });
            }
            _ => {}
        }
    }

    /// Evict stale windows. Call every 60s from a maintenance task.
    pub fn evict_stale(&self, now_ms: i64) {
        let max_age = W_30MIN * 2; // double the longest window
        for mut entry in self.windows.iter_mut() {
            entry.value_mut().evict(now_ms, max_age);
        }
        // Remove entirely empty windows
        self.windows.retain(|_, w| !w.buf.is_empty());
    }
}
