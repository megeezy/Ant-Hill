//! Tier 1 — Sensor agents entry point.
//! Each agent runs as a long-lived Tokio task.

pub mod file_monitor;
pub mod mem_probe;
pub mod net_sniffer;
pub mod proc_monitor;

use anthill_core::config::AnthillConfig;
use anthill_bus::Bus;
use anyhow::Result;
use tokio::task::JoinHandle;

/// Spawn all enabled agents. Returns join handles for supervision.
pub async fn spawn_all(cfg: &AnthillConfig, bus: &Bus) -> Result<Vec<JoinHandle<()>>> {
    let mut handles = vec![];

    if cfg.agent.file_monitor_enabled {
        let tx = bus.file_tx.clone();
        handles.push(tokio::spawn(file_monitor::run(tx)));
    }
    if cfg.agent.proc_monitor_enabled {
        let tx = bus.proc_tx.clone();
        handles.push(tokio::spawn(proc_monitor::run(tx)));
    }
    if cfg.agent.net_sniffer_enabled {
        let tx = bus.net_tx.clone();
        handles.push(tokio::spawn(net_sniffer::run(tx)));
    }
    if cfg.agent.mem_probe_enabled {
        let tx = bus.mem_tx.clone();
        handles.push(tokio::spawn(mem_probe::run(tx)));
    }

    Ok(handles)
}
