//! Live distribution drift monitor.
//!
//! Maintains a rolling feature histogram and computes KL divergence
//! against the training-time baseline. Auto-rollback if threshold exceeded.

use anthill_core::config::MlConfig;
use tracing::{info, warn};

#[derive(Debug, Clone)]
pub enum DriftStatus {
    Insufficient,
    Ok,
    Exceeded { kl_score: f64 },
}

/// Simplified histogram over bucketized feature values (256 bins per dimension).
#[derive(Debug, Clone)]
pub struct FeatureHistogram {
    bins: Vec<f64>,
}

impl FeatureHistogram {
    pub fn uniform(n_bins: usize) -> Self {
        let v = 1.0 / n_bins as f64;
        Self { bins: vec![v; n_bins] }
    }

    pub fn from_counts(counts: &[u64]) -> Self {
        let total: u64 = counts.iter().sum();
        let bins = if total == 0 {
            vec![0.0; counts.len()]
        } else {
            counts.iter().map(|&c| c as f64 / total as f64).collect()
        };
        Self { bins }
    }
}

fn kl_divergence(p: &FeatureHistogram, q: &FeatureHistogram) -> f64 {
    p.bins.iter().zip(q.bins.iter())
        .filter(|(&pi, &qi)| pi > 0.0 && qi > 0.0)
        .map(|(&pi, &qi)| pi * (pi / qi).ln())
        .sum()
}

pub struct DriftMonitor {
    baseline:         FeatureHistogram,
    live_counts:      Vec<u64>,
    #[allow(dead_code)]
    n_bins:           usize,
    sample_count:     usize,
    threshold_kl:     f64,
    min_samples:      usize,
}

impl DriftMonitor {
    pub fn new(cfg: &MlConfig, baseline: FeatureHistogram) -> Self {
        let n_bins = baseline.bins.len();
        Self {
            baseline,
            live_counts:  vec![0; n_bins],
            n_bins,
            sample_count: 0,
            threshold_kl: cfg.drift_threshold_kl,
            min_samples:  cfg.drift_sample_minimum,
        }
    }

    /// Feed a new sample (single feature value, bucketized 0–255).
    pub fn tick(&mut self, bucket: u8) -> DriftStatus {
        self.live_counts[bucket as usize] += 1;
        self.sample_count += 1;

        if self.sample_count < self.min_samples {
            return DriftStatus::Insufficient;
        }

        let live = FeatureHistogram::from_counts(&self.live_counts);
        let kl   = kl_divergence(&self.baseline, &live);

        if kl > self.threshold_kl {
            warn!(kl_score = kl, threshold = self.threshold_kl, "model drift detected");
            DriftStatus::Exceeded { kl_score: kl }
        } else {
            DriftStatus::Ok
        }
    }

    /// Reset the live window (call after model rollback or re-baseline).
    pub fn reset(&mut self) {
        self.live_counts.iter_mut().for_each(|c| *c = 0);
        self.sample_count = 0;
        info!("drift monitor reset");
    }
}
