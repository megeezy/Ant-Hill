//! Sandbox scheduler — token-bucket priority queue with fast-path skip logic.
//!
//! Three priority tiers:
//!   URGENT  risk > 0.50 → dedicated slot, immediate dispatch
//!   NORMAL  0.20–0.50  → FIFO queue, max wait 60s
//!   LOW     < 0.20     → best-effort, shed when queue > 32

use anthill_core::config::SandboxConfig;
use std::collections::VecDeque;
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, Semaphore};
use tracing::{debug, info, warn};

/// A request to sandbox a specific file.
#[derive(Debug)]
pub struct SandboxRequest {
    pub file_path:  String,
    pub sha256:     String,
    pub ml_score:   f32,
    pub is_signed:  bool,
    pub queued_at:  Instant,
    pub priority:   Priority,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Priority { Low, Normal, Urgent }

impl Priority {
    pub fn from_score(score: f32) -> Self {
        if score > 0.50 { Priority::Urgent }
        else if score >= 0.20 { Priority::Normal }
        else { Priority::Low }
    }
}

/// Result from sandbox execution.
#[derive(Debug, Clone)]
pub struct SandboxVerdict {
    pub file_path:  String,
    pub confidence: f32,
    pub clean:      bool,
    pub reason:     String,
}

pub enum SkipReason {
    TrustedClean,
    HighRisk,       // skip sandbox → immediate KILL
    RequiresSandbox(Priority),
}

pub struct SandboxScheduler {
    cfg:        SandboxConfig,
    slots:      Semaphore,         // pool semaphore (N concurrent)
    queue:      Mutex<VecDeque<SandboxRequest>>,
}

impl SandboxScheduler {
    pub fn new(cfg: SandboxConfig) -> Self {
        let pool = cfg.pool_slots;
        Self {
            slots: Semaphore::new(pool),
            queue: Mutex::new(VecDeque::new()),
            cfg,
        }
    }

    /// Decide whether to skip sandbox or queue the file.
    pub fn classify(
        &self,
        path: &str,
        sha256: &str,
        ml_score: f32,
        is_signed: bool,
        known_clean: bool,
    ) -> SkipReason {
        if ml_score < self.cfg.fast_path_ml_threshold && is_signed && known_clean {
            return SkipReason::TrustedClean;
        }
        if ml_score > 0.70 {
            return SkipReason::HighRisk;
        }
        SkipReason::RequiresSandbox(Priority::from_score(ml_score))
    }

    /// Enqueue a file for sandboxing. Returns false if queue is full and the
    /// request was shed (LOW priority only).
    pub async fn enqueue(&self, req: SandboxRequest) -> bool {
        let mut q = self.queue.lock().await;
        let depth = q.len();

        match req.priority {
            Priority::Low if depth >= 32 => {
                warn!(path = req.file_path, "sandbox queue > 32 — shedding LOW priority request");
                return false;
            }
            _ if depth >= self.cfg.queue_max => {
                warn!(
                    path = req.file_path,
                    "sandbox queue FULL ({}) — soft-quarantining until slot opens",
                    self.cfg.queue_max
                );
                // Caller must soft-quarantine the file
                return false;
            }
            _ => {}
        }

        // Insert URGENT at front, others at back
        match req.priority {
            Priority::Urgent => q.push_front(req),
            _                => q.push_back(req),
        }

        debug!(depth = q.len(), "file queued for sandbox");
        true
    }

    /// Acquire a pool slot and run the next queued request.
    /// Returns None if queue is empty.
    pub async fn run_next(&self) -> Option<SandboxVerdict> {
        let req = {
            let mut q = self.queue.lock().await;
            q.pop_front()?
        };

        // Acquire a slot from the pool (blocks if all busy)
        let _permit = self.slots.acquire().await.ok()?;

        info!(
            file = req.file_path,
            priority = ?req.priority,
            wait_ms = req.queued_at.elapsed().as_millis(),
            "sandbox slot acquired"
        );

        // Dispatch to gVisor (Phase 3); stub returns clean for now
        let verdict = gvisor_run_stub(&req, self.cfg.verdict_timeout_s).await;
        Some(verdict)
    }
}

async fn gvisor_run_stub(req: &SandboxRequest, _timeout_s: u64) -> SandboxVerdict {
    // Phase 3: spawn `runsc run --rootless` and parse syscall profile
    tokio::time::sleep(Duration::from_millis(100)).await; // simulate work
    SandboxVerdict {
        file_path:  req.file_path.clone(),
        confidence: 0.05,
        clean:      true,
        reason:     "sandbox-stub: no syscall analysis yet".into(),
    }
}

mod gvisor {
    // Phase 3: full gVisor runsc integration
}
