//! Behaviour engine — stateful, sliding-window rule evaluation.

pub mod rules;
pub mod window_store;

use anthill_core::{config::BehaviourConfig, proto::ThreatSignal};
use window_store::WindowStore;
use rules::{BehaviourRule, ALL_RULES};

pub struct BehaviourEngine {
    store: WindowStore,
    rules: Vec<Box<dyn BehaviourRule + Send + Sync>>,
}

impl BehaviourEngine {
    pub fn new(cfg: &BehaviourConfig) -> Self {
        Self {
            store: WindowStore::new(cfg),
            rules: ALL_RULES(),
        }
    }

    /// Evaluate all rules against the incoming signal.
    /// Returns the highest confidence score across all firing rules.
    pub fn evaluate(&mut self, signal: &ThreatSignal) -> f32 {
        // Push raw signal weights into relevant windows
        self.store.ingest(signal);

        let mut max_conf = 0.0_f32;
        for rule in &self.rules {
            if let Some(conf) = rule.evaluate(&self.store, signal) {
                max_conf = max_conf.max(conf);
            }
        }
        max_conf
    }
}
