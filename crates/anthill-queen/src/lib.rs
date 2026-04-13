//! Tier 3 — Queen Intelligence Engine.
//!
//! Runs four detection modules in parallel against every incoming signal batch,
//! then passes all module outputs to the rule correlator for a final verdict.

pub mod behaviour;
pub mod correlator;
pub mod ml;
pub mod sandbox;
pub mod signature;

use anthill_bus::Bus;
use anthill_core::{config::AnthillConfig, proto::ThreatSignal, RiskScore};
use anyhow::Result;
use tokio::sync::mpsc;
use tracing::{error, info};

/// Output channel from Queen → Soldier.
pub type VerdictSender   = mpsc::Sender<RiskScore>;
pub type VerdictReceiver = mpsc::Receiver<RiskScore>;

pub struct QueenEngine {
    cfg:       AnthillConfig,
    sig:       signature::SignatureEngine,
    beh:       behaviour::BehaviourEngine,
    correlator: correlator::Correlator,
}

impl QueenEngine {
    pub async fn new(cfg: AnthillConfig) -> Result<Self> {
        let sig = signature::SignatureEngine::new(&cfg).await?;
        let beh = behaviour::BehaviourEngine::new(&cfg.queen.behaviour);
        let correlator = correlator::Correlator::new(&cfg.queen);
        Ok(Self { cfg, sig, beh, correlator })
    }

    /// Main event loop. Reads from all bus receivers, runs detection modules,
    /// emits verdicts on `verdict_tx`.
    pub async fn run(
        mut self,
        mut bus: Bus,
        verdict_tx: VerdictSender,
    ) {
        info!("queen engine started");
        loop {
            // Select from any agent channel — whichever has data first
            let signal: ThreatSignal = tokio::select! {
                Some(s) = bus.file_rx.recv() => s,
                Some(s) = bus.proc_rx.recv() => s,
                Some(s) = bus.net_rx.recv()  => s,
                Some(s) = bus.mem_rx.recv()  => s,
                else => { info!("all bus channels closed — queen exiting"); break; }
            };

            let score = self.process(signal).await;

            if let Err(e) = verdict_tx.send(score).await {
                error!("verdict channel closed: {e}");
                break;
            }
        }
    }

    async fn process(&mut self, signal: ThreatSignal) -> RiskScore {
        let sig_conf = self.sig.evaluate(&signal).await;
        let beh_conf = self.beh.evaluate(&signal);
        // ML and sandbox run in Phase 3; stubs return 0.0 for now
        let ml_conf  = 0.0_f32;
        let box_conf = 0.0_f32;

        let q = &self.cfg.queen;
        self.correlator.score(sig_conf, beh_conf, ml_conf, box_conf, &signal)
    }
}
