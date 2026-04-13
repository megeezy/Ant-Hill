//! ML inference engine + live drift monitor + model registry.
//! Enabled with `--features ml` (Phase 3).

pub mod drift_monitor;
pub mod model_registry;

/// Stub available in Phase 1–2 when the `ml` feature is not enabled.
#[cfg(not(feature = "ml"))]
pub mod inference {
    use anthill_core::proto::ThreatSignal;
    pub struct MlEngine;
    impl MlEngine {
        pub fn new() -> Self { Self }
        pub fn evaluate(&self, _signal: &ThreatSignal) -> f32 { 0.0 }
    }
    impl Default for MlEngine {
        fn default() -> Self { Self::new() }
    }
}

#[cfg(feature = "ml")]
pub mod inference {
    use anthill_core::{config::MlConfig, proto::ThreatSignal, FileFeatureVector};
    use anyhow::Result;
    use ort::{Environment, Session, SessionBuilder, Value};
    use std::sync::Arc;
    use tracing::{info, warn};

    pub struct MlEngine {
        session: Session,
    }

    impl MlEngine {
        pub fn load(cfg: &MlConfig) -> Result<Self> {
            let env = Arc::new(Environment::builder().build()?);
            let session = SessionBuilder::new(&env)?
                .with_model_from_file(&cfg.model_path)?;
            info!("ML model loaded from {:?}", cfg.model_path);
            Ok(Self { session })
        }

        /// Returns ML confidence [0.0, 1.0]. 0.0 if file is not a PE/script.
        pub fn evaluate(&self, signal: &ThreatSignal) -> f32 {
            // Feature extraction and inference — Phase 3 implementation
            0.0
        }
    }
}
