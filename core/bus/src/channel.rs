//! Bounded MPSC channels — one per agent type. The Queen holds all receivers.
//!
//! Back-pressure: when a channel is full, low-confidence signals are shed first
//! (priority queue behaviour). High-confidence signals block briefly (bounded
//! channel semantics) to prevent data loss.

use anthill_core::proto::ThreatSignal;
use tokio::sync::mpsc;
use tracing::warn;

/// Capacity per channel. Must be a power of 2 for cache efficiency.
pub const CHANNEL_CAPACITY: usize = 4096;

pub type BusSender   = mpsc::Sender<ThreatSignal>;
pub type BusReceiver = mpsc::Receiver<ThreatSignal>;

/// A handle to all agent channels. Clone senders and pass them to agents.
pub struct Bus {
    pub file_tx: BusSender,
    pub proc_tx: BusSender,
    pub net_tx:  BusSender,
    pub mem_tx:  BusSender,

    pub file_rx: BusReceiver,
    pub proc_rx: BusReceiver,
    pub net_rx:  BusReceiver,
    pub mem_rx:  BusReceiver,
}

impl Bus {
    pub fn new() -> Self {
        let (file_tx, file_rx) = mpsc::channel(CHANNEL_CAPACITY);
        let (proc_tx, proc_rx) = mpsc::channel(CHANNEL_CAPACITY);
        let (net_tx,  net_rx)  = mpsc::channel(CHANNEL_CAPACITY);
        let (mem_tx,  mem_rx)  = mpsc::channel(CHANNEL_CAPACITY);
        Self { file_tx, proc_tx, net_tx, mem_tx, file_rx, proc_rx, net_rx, mem_rx }
    }
}

impl Default for Bus {
    fn default() -> Self {
        Self::new()
    }
}

/// Try to send a signal. On channel full, shed if confidence is below threshold.
pub async fn try_send(tx: &BusSender, signal: ThreatSignal, shed_threshold: f32) {
    if signal.confidence < shed_threshold {
        match tx.try_send(signal) {
            Ok(_) => {}
            Err(_) => {
                warn!("bus channel full — shedding low-confidence signal");
            }
        }
    } else {
        // High-confidence: block until space is available (bounded backpressure)
        if let Err(e) = tx.send(signal).await {
            warn!("bus send failed (receiver dropped): {e}");
        }
    }
}
