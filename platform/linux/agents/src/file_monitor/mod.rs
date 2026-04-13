//! File monitor agent (Linux: inotify via `notify` crate).
//!
//! Watches the filesystem for create/write/rename/delete/chmod events,
//! computes SHA-256 of created/modified files, and emits FileEvent signals.

use anthill_bus::BusSender;
use anthill_core::proto::{FileEvent, FileOp, ThreatSignal, AgentType, threat_signal};
use notify::{Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use sha2::{Digest, Sha256};
use std::path::Path;
use std::sync::mpsc as std_mpsc;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, error, warn};

/// Directories watched by default. Configurable in a future PR.
const WATCH_ROOTS: &[&str] = &[
    "/home",
    "/tmp",
    "/var/tmp",
    "/opt",
    "/usr/local/bin",
    "/etc",
];

pub async fn run(tx: BusSender) {
    if let Err(e) = watch_loop(tx).await {
        error!("file-monitor exited with error: {e}");
    }
}

async fn watch_loop(tx: BusSender) -> anyhow::Result<()> {
    let (notify_tx, notify_rx) = std_mpsc::channel();
    let mut watcher = RecommendedWatcher::new(notify_tx, Config::default())?;

    for root in WATCH_ROOTS {
        let path = Path::new(root);
        if path.exists() {
            watcher.watch(path, RecursiveMode::Recursive)?;
            debug!("watching {root}");
        }
    }

    // Offload blocking notify_rx into a Tokio blocking thread
    let tx_clone = tx.clone();
    tokio::task::spawn_blocking(move || {
        for result in notify_rx {
            match result {
                Ok(event) => {
                    if let Some(signal) = event_to_signal(event) {
                        let _ = tx_clone.blocking_send(signal);
                    }
                }
                Err(e) => warn!("notify error: {e}"),
            }
        }
    })
    .await?;

    Ok(())
}

fn event_to_signal(event: Event) -> Option<ThreatSignal> {
    let op = match event.kind {
        EventKind::Create(_) => FileOp::FileCreate,
        EventKind::Modify(_) => FileOp::FileWrite,
        EventKind::Remove(_) => FileOp::FileDelete,
        EventKind::Access(_) => return None, // access events are noise
        _                    => return None,
    };

    let path = event.paths.first()?;
    let path_str = path.to_string_lossy().to_string();
    let entropy = estimate_entropy(path);
    let sha256  = compute_sha256(path).unwrap_or_default();

    Some(ThreatSignal {
        source:      AgentType::AgentFile as i32,
        confidence:  0.1, // raw sensor confidence — queen will update
        ttl_seconds: 30,
        ts:          now_ms(),
        event: Some(threat_signal::Event::FileEvent(FileEvent {
            path: path_str,
            sha256,
            pid:       0, // inotify doesn't give us pid — eBPF does
            uid:       0,
            operation: op as i32,
            timestamp: now_ms(),
            entropy,
        })),
    })
}

fn compute_sha256(path: &Path) -> Option<String> {
    if !path.is_file() { return None; }
    let bytes = std::fs::read(path).ok()?;
    if bytes.len() > 50 * 1024 * 1024 { return None; } // skip huge files
    let mut h = Sha256::new();
    h.update(&bytes);
    Some(hex::encode(h.finalize()))
}

fn estimate_entropy(path: &Path) -> f32 {
    let Ok(bytes) = std::fs::read(path) else { return 0.0 };
    if bytes.is_empty() { return 0.0; }
    let sample = &bytes[..bytes.len().min(4096)];
    let mut counts = [0u32; 256];
    for &b in sample { counts[b as usize] += 1; }
    let len = sample.len() as f32;
    counts.iter()
        .filter(|&&c| c > 0)
        .map(|&c| { let p = c as f32 / len; -p * p.log2() })
        .sum()
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}
