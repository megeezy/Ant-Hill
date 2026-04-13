//! Network sniffer agent stub (Phase 2).
//! Phase 1: emits nothing. Phase 2: uses libpcap via the `pcap` crate.

use anthill_bus::BusSender;
use tracing::info;

pub async fn run(_tx: BusSender) {
    // Phase 1: no-op placeholder
    info!("net-sniffer: Phase 1 — disabled (Phase 2 will use libpcap)");
    std::future::pending::<()>().await;
}
