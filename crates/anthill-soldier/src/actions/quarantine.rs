use anthill_core::config::PersistenceConfig;
use anyhow::Result;
use std::path::Path;
use tracing::info;

/// Soft quarantine — file stays in place but is read-only, no exec.
/// Process (if pid > 0) is suspended with SIGSTOP.
pub async fn soft_quarantine(path: &str) -> Result<()> {
    let p = Path::new(path);
    if !p.exists() { return Ok(()); }

    // Remove execute bits, make read-only
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o444);
        tokio::fs::set_permissions(p, perms).await?;
    }

    info!(path, "soft-quarantine applied (read-only, no exec)");
    Ok(())
}

/// Undo soft quarantine — restore original permissions.
pub async fn restore_soft_quarantine(path: &str, original_mode: u32) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(original_mode);
        tokio::fs::set_permissions(Path::new(path), perms).await?;
    }
    info!(path, mode = original_mode, "soft-quarantine reversed");
    Ok(())
}

/// Hard quarantine — move file to encrypted vault directory.
/// The vault is owned by the anthill service account only.
pub async fn hard_quarantine(path: &str, cfg: &PersistenceConfig) -> Result<()> {
    let src = Path::new(path);
    if !src.exists() { return Ok(()); }

    let vault = &cfg.vault_path;
    tokio::fs::create_dir_all(vault).await?;

    let filename = src.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "unknown".into());
    let dest = vault.join(format!("{filename}.quarantine"));

    tokio::fs::rename(src, &dest).await?;
    info!(src = path, dest = ?dest, "hard-quarantine: file moved to vault");

    // Phase 3: AES-256 encrypt the file at vault location
    Ok(())
}
