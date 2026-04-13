//! Process kill action.
//!
//! Sends SIGKILL to the offending PID. Refuses to kill protected processes
//! (enforced by SafetyChecker before this is ever called).

use anyhow::{bail, Result};
use tracing::info;

pub async fn kill_process(pid: u32) -> Result<()> {
    if pid == 0 || pid == 1 {
        bail!("refusing to kill pid={pid} — safety guard");
    }

    info!(pid, "sending SIGKILL");
    let result = unsafe { libc::kill(pid as i32, libc::SIGKILL) };
    if result != 0 {
        let err = std::io::Error::last_os_error();
        bail!("kill({pid}) failed: {err}");
    }
    Ok(())
}


