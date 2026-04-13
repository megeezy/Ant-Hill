//! Sandbox scheduler — priority queue in front of the gVisor/Firecracker pool.

pub mod gvisor;
pub mod scheduler;

pub use scheduler::{SandboxScheduler, SandboxVerdict};
