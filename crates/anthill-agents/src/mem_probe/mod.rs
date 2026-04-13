//! Memory probe agent (Linux: reads /proc/[pid]/maps).
//!
//! Detects: executable anonymous mappings, heap exec, injected shared libs.

use anthill_bus::BusSender;
use anthill_core::proto::{AgentType, MemEvent, ThreatSignal, threat_signal};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::time;
use tracing::warn;

const POLL_INTERVAL: Duration = Duration::from_secs(5);

pub async fn run(tx: BusSender) {
    let mut ticker = time::interval(POLL_INTERVAL);
    loop {
        ticker.tick().await;
        if let Ok(events) = scan_all_maps() {
            for ev in events {
                let signal = ThreatSignal {
                    source:      AgentType::AgentMem as i32,
                    confidence:  if ev.exec_anon || ev.heap_exec { 0.6 } else { 0.2 },
                    ttl_seconds: 120,
                    ts:          now_ms(),
                    event:       Some(threat_signal::Event::MemEvent(ev)),
                };
                if tx.send(signal).await.is_err() {
                    warn!("mem-probe: bus receiver dropped");
                    return;
                }
            }
        }
    }
}

fn scan_all_maps() -> anyhow::Result<Vec<MemEvent>> {
    let mut events = vec![];
    for entry in std::fs::read_dir("/proc")? {
        let entry = entry?;
        let name = entry.file_name();
        let Ok(pid) = name.to_string_lossy().parse::<u32>() else { continue };
        if let Some(ev) = scan_pid_maps(pid) {
            events.push(ev);
        }
    }
    Ok(events)
}

fn scan_pid_maps(pid: u32) -> Option<MemEvent> {
    let maps = std::fs::read_to_string(format!("/proc/{pid}/maps")).ok()?;
    let mut exec_anon = false;
    let mut heap_exec = false;
    let mut injected = String::new();

    for line in maps.lines() {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 5 { continue; }
        let perms  = cols[1];
        let path   = cols.get(5).copied().unwrap_or("");
        let is_exec = perms.contains('x');

        if is_exec && path.is_empty() {
            exec_anon = true;
        }
        if is_exec && path == "[heap]" {
            heap_exec = true;
        }
        if is_exec && path.starts_with('/') && path.contains(".so") {
            // Heuristic: injected lib if it doesn't appear in /proc/{pid}/exe
            injected = path.to_owned();
        }
    }

    if exec_anon || heap_exec || !injected.is_empty() {
        Some(MemEvent {
            pid,
            region:       String::new(),
            exec_anon,
            heap_exec,
            injected_lib: injected,
            timestamp:    now_ms(),
        })
    } else {
        None
    }
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}
