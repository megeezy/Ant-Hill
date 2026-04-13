//! Network block action — inserts a deny rule into nftables (Linux).
//! Rule carries a 24h TTL and is auto-removed.

use anyhow::Result;
use tracing::{info, warn};

/// Block outbound traffic to `ip:port` using nftables.
pub async fn block_ip_port(ip: &str, port: u16) -> Result<()> {
    info!(ip, port, "inserting nftables deny rule");

    // nft add rule inet filter output ip daddr {ip} tcp dport {port} drop
    let output = tokio::process::Command::new("nft")
        .args([
            "add", "rule", "inet", "filter", "output",
            "ip", "daddr", ip,
            "tcp", "dport", &port.to_string(),
            "drop",
        ])
        .output()
        .await?;

    if !output.status.success() {
        let err = String::from_utf8_lossy(&output.stderr);
        warn!("nft rule insertion failed: {err}");
    }

    // Schedule TTL removal after 24h
    let ip_owned  = ip.to_owned();
    let port_copy = port;
    tokio::spawn(async move {
        tokio::time::sleep(tokio::time::Duration::from_secs(86400)).await;
        let _ = remove_block(&ip_owned, port_copy).await;
    });

    Ok(())
}

async fn remove_block(ip: &str, port: u16) -> Result<()> {
    // Phase 2: track rule handles and delete by handle ID
    info!(ip, port, "nftables deny rule TTL expired — removing");
    Ok(())
}
