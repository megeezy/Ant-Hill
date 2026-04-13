//! Process monitor agent (Linux: reads /proc + eBPF kprobes via aya).
//!
//! Phase 1: procfs polling (no eBPF dependency).
//! Phase 2: aya eBPF kprobes for execve, clone, ptrace, mmap.

use anthill_bus::BusSender;
use anthill_core::proto::{AgentType, ProcEvent, ThreatSignal, threat_signal};
use std::collections::HashSet;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::time;
use tracing::{debug, warn};

const POLL_INTERVAL: Duration = Duration::from_secs(1);

pub async fn run(tx: BusSender) {
    let mut known_pids: HashSet<u32> = HashSet::new();
    let mut ticker = time::interval(POLL_INTERVAL);

    loop {
        ticker.tick().await;
        match scan_procs(&known_pids) {
            Ok(new_events) => {
                for event in new_events {
                    let pid = event.pid;
                    known_pids.insert(pid);
                    let signal = wrap_proc_event(event);
                    if tx.send(signal).await.is_err() {
                        warn!("proc-monitor: bus receiver dropped");
                        return;
                    }
                }
                // Purge dead pids
                known_pids.retain(|pid| proc_exists(*pid));
            }
            Err(e) => warn!("proc scan error: {e}"),
        }
    }
}

fn scan_procs(known: &HashSet<u32>) -> anyhow::Result<Vec<ProcEvent>> {
    let mut events = vec![];
    for entry in std::fs::read_dir("/proc")? {
        let entry = entry?;
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        let Ok(pid) = name_str.parse::<u32>() else { continue };

        if known.contains(&pid) { continue; }

        if let Some(ev) = read_proc_event(pid) {
            debug!(pid, comm = ev.comm, "new process");
            events.push(ev);
        }
    }
    Ok(events)
}

fn read_proc_event(pid: u32) -> Option<ProcEvent> {
    let base = format!("/proc/{pid}");
    let comm = std::fs::read_to_string(format!("{base}/comm"))
        .map(|s| s.trim().to_owned())
        .unwrap_or_default();
    let cmdline = std::fs::read_to_string(format!("{base}/cmdline"))
        .map(|s| s.replace('\0', " ").trim().to_owned())
        .unwrap_or_default();
    let exe = std::fs::read_link(format!("{base}/exe"))
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_default();
    let ppid = read_ppid(pid).unwrap_or(0);
    let uid  = read_uid(pid).unwrap_or(0);

    Some(ProcEvent {
        pid, ppid, uid, comm, cmdline,
        exe_path:  exe,
        timestamp: now_ms(),
        syscall:   String::new(), // populated by eBPF in Phase 2
    })
}

fn read_ppid(pid: u32) -> Option<u32> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("PPid:\t") {
            return rest.trim().parse().ok();
        }
    }
    None
}

fn read_uid(pid: u32) -> Option<u32> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("Uid:\t") {
            return rest.split_whitespace().next()?.parse().ok();
        }
    }
    None
}

fn proc_exists(pid: u32) -> bool {
    std::path::Path::new(&format!("/proc/{pid}")).exists()
}

fn wrap_proc_event(ev: ProcEvent) -> ThreatSignal {
    ThreatSignal {
        source:      AgentType::AgentProc as i32,
        confidence:  0.05,
        ttl_seconds: 60,
        ts:          now_ms(),
        event:       Some(threat_signal::Event::ProcEvent(ev)),
    }
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}
