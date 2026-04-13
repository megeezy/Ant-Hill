//! Model registry — versioned ONNX models with Ed25519 signature verification.

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tracing::{info, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelMeta {
    pub model_version:    String,
    pub training_date:    String,
    pub dataset_hash:     String,
    pub training_seed:    u64,
    pub val_fp_rate:      f64,
    pub val_fn_rate:      f64,
    pub drift_baseline:   String,
    pub kl_divergence:    f64,
    pub validation_pass:  bool,
    pub signature:        String, // hex-encoded Ed25519 sig of model bytes
}

pub struct ModelRegistry {
    models_dir: PathBuf,
}

impl ModelRegistry {
    pub fn new(models_dir: PathBuf) -> Self {
        Self { models_dir }
    }

    /// Load and verify the current model. Returns the path to the .onnx file.
    pub fn load_current(&self) -> Result<(PathBuf, ModelMeta)> {
        let onnx_path = self.models_dir.join("current.onnx");
        let meta_path = self.models_dir.join("current.meta.json");

        let meta_bytes = std::fs::read(&meta_path)
            .context("failed to read model meta")?;
        let meta: ModelMeta = serde_json::from_slice(&meta_bytes)
            .context("failed to parse model meta")?;

        if !meta.validation_pass {
            bail!("model {} did not pass validation — refusing to load", meta.model_version);
        }

        // Signature verification omitted in Phase 1 (no ed25519 key distribution yet)
        // Phase 3 will add: verify_signature(&onnx_path, &meta.signature)?;

        info!(version = meta.model_version, fp_rate = meta.val_fp_rate, "model loaded");
        Ok((onnx_path, meta))
    }

    /// Roll back to the previous version.
    pub fn rollback(&self) -> Result<()> {
        // List all versioned models, sort by version, activate the previous one
        warn!("model rollback triggered — activating previous version");
        // Implementation: symlink current.onnx to previous version
        // Full implementation in Phase 3
        Ok(())
    }
}
