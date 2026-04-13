//! Rule correlator — weighted risk scoring with verdict thresholds.

use anthill_core::{config::QueenConfig, proto::ThreatSignal, RiskScore, Verdict};

pub struct Correlator {
    w_sig: f32,
    w_beh: f32,
    w_ml:  f32,
    w_box: f32,
}

impl Correlator {
    pub fn new(cfg: &QueenConfig) -> Self {
        Self {
            w_sig: cfg.sig_weight,
            w_beh: cfg.beh_weight,
            w_ml:  cfg.ml_weight,
            w_box: cfg.box_weight,
        }
    }

    /// risk_score = w_sig*sig + w_beh*beh + w_ml*ml + w_box*box
    /// < 0.35 → CLEAN | 0.35–0.70 → QUARANTINE | > 0.70 → KILL
    pub fn score(
        &self,
        sig_conf: f32,
        beh_conf: f32,
        ml_conf:  f32,
        box_conf: f32,
        signal:   &ThreatSignal,
    ) -> RiskScore {
        let composite =
            self.w_sig * sig_conf
            + self.w_beh * beh_conf
            + self.w_ml  * ml_conf
            + self.w_box * box_conf;

        let mut rules_fired = vec![];
        if sig_conf > 0.0 { rules_fired.push("SIG".into()); }
        if beh_conf > 0.0 { rules_fired.push("BEH".into()); }
        if ml_conf  > 0.0 { rules_fired.push("ML".into());  }
        if box_conf > 0.0 { rules_fired.push("BOX".into()); }

        let (pid, subject_path) = match &signal.event {
            Some(anthill_core::proto::threat_signal::Event::FileEvent(fe)) => (fe.pid, fe.path.clone()),
            Some(anthill_core::proto::threat_signal::Event::ProcEvent(pe)) => (pe.pid, pe.exe_path.clone()),
            Some(anthill_core::proto::threat_signal::Event::MemEvent(me)) => (me.pid, "memory".into()),
            Some(anthill_core::proto::threat_signal::Event::NetEvent(ne)) => (0, ne.dst_ip.clone()),
            _ => (0, "unknown".into()),
        };

        RiskScore {
            verdict_id:   uuid::Uuid::new_v4().to_string(),
            pid,
            subject_path,
            composite,
            sig_conf,
            beh_conf,
            ml_conf,
            box_conf,
            rules_fired,
            verdict: Verdict::from_score(composite),
        }
    }
}
