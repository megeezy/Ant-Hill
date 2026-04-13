//! Forensic capture — snapshot of /proc/[pid]/ taken before any destructive action.

use anthill_core::ForensicBundle;
use anyhow::Result;
use std::path::{Path, PathBuf};
use tracing::debug;
use uuid::Uuid;

pub struct ForensicCapture {
    output_dir: PathBuf,
}

impl ForensicCapture {
    pub fn new(output_dir: &Path) -> Self {
        Self { output_dir: output_dir.to_path_buf() }
    }

    /// Capture all available forensic data for `pid` and save to disk.
    pub async fn capture(&self, pid: u32, file_path: &str, verdict: &str) -> Result<ForensicBundle> {
        let verdict_id = Uuid::new_v4().to_string();
        let bundle_dir = self.output_dir.join(&verdict_id);
        tokio::fs::create_dir_all(&bundle_dir).await?;

        let proc_maps    = read_proc_file(pid, "maps").await;
        let proc_cmdline = read_proc_file(pid, "cmdline").await
            .replace('\0', " ");
        let proc_environ = read_proc_file(pid, "environ").await
            .replace('\0', "\n");

        let open_fds    = list_fds(pid).await;
        let open_sockets = capture_sockets(pid).await;

        let file_sha256 = hash_file(file_path).await;

        let bundle = ForensicBundle {
            verdict_id:   verdict_id.clone(),
            pid,
            file_path:    file_path.to_owned(),
            file_sha256,
            proc_maps,
            proc_cmdline,
            proc_environ,
            open_fds,
            open_sockets,
            captured_at:  chrono::Utc::now().timestamp_millis(),
        };

        // Write JSON snapshot to disk
        let json = serde_json::to_string_pretty(&bundle)?;
        tokio::fs::write(bundle_dir.join("forensics.json"), json).await?;

        debug!(verdict_id, pid, "forensic bundle saved");
        Ok(bundle)
    }
}

async fn read_proc_file(pid: u32, name: &str) -> String {
    tokio::fs::read_to_string(format!("/proc/{pid}/{name}"))
        .await
        .unwrap_or_default()
}

async fn list_fds(pid: u32) -> Vec<String> {
    let fd_dir = format!("/proc/{pid}/fd");
    let mut fds = vec![];
    if let Ok(mut entries) = tokio::fs::read_dir(&fd_dir).await {
        while let Ok(Some(entry)) = entries.next_entry().await {
            if let Ok(target) = tokio::fs::read_link(entry.path()).await {
                fds.push(target.to_string_lossy().into_owned());
            }
        }
    }
    fds
}

async fn capture_sockets(_pid: u32) -> Vec<String> {
    // Phase 2: parse /proc/{pid}/net/tcp and /proc/{pid}/net/tcp6
    vec![]
}

async fn hash_file(path: &str) -> String {
    use sha2::{Digest, Sha256};
    let Ok(bytes) = tokio::fs::read(path).await else { return String::new() };
    if bytes.len() > 100 * 1024 * 1024 { return "TOO_LARGE".into(); }
    hex::encode(Sha256::digest(&bytes))
}

use sha2;
use hex;
use chrono;
use serde_json;
use uuid;
