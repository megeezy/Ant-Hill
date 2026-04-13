//! anthill — main entry point.
//!
//! Boots all tiers in order:
//!   1. Load config
//!   2. Open persistence (SQLite + sled)
//!   3. Create pheromone bus
//!   4. Spawn sensor agents
//!   5. Start Queen engine
//!   6. Start Soldier response layer
//!   7. Start TUI dashboard
//!   8. (Optional) Start gRPC API

use anthill_bus::Bus;
use anthill_core::config::AnthillConfig;
use anthill_db::{PheromoneCache, ThreatDb};
use anthill_queen::QueenEngine;
use anthill_soldier::SoldierLayer;
use anthill_tui::App;
use anyhow::Result;
use clap::Parser;
use tokio::sync::mpsc;
use tracing::{error, info};
use tracing_subscriber::{EnvFilter, fmt};

#[derive(Parser, Debug)]
#[command(name = "anthill", about = "Anthill Antivirus System", version)]
struct Cli {
    /// Configuration profile to load (enterprise | developer | personal)
    #[arg(short, long, default_value = "developer")]
    profile: String,

    /// Override response mode (auto | confirm | monitor)
    #[arg(short, long)]
    mode: Option<String>,

    /// Run in headless mode (no TUI — log to stdout only)
    #[arg(long)]
    headless: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // ── Logging ─────────────────────────────────────────────────────────────
    fmt()
        .with_env_filter(EnvFilter::from_default_env()
            .add_directive("anthill=debug".parse()?)
            .add_directive("warn".parse()?))
        .init();

    info!("🐜 Anthill starting — profile={}", cli.profile);

    // ── Config ───────────────────────────────────────────────────────────────
    let mut cfg = AnthillConfig::load(Some(&cli.profile))?;
    if let Some(mode) = &cli.mode {
        cfg.response.mode = match mode.to_lowercase().as_str() {
            "auto"    => anthill_core::config::ResponseMode::Auto,
            "confirm" => anthill_core::config::ResponseMode::Confirm,
            "monitor" => anthill_core::config::ResponseMode::Monitor,
            _ => anyhow::bail!("invalid mode: {mode}"),
        };
    }
    info!(mode = ?cfg.response.mode, "response mode active");

    // ── Persistence ──────────────────────────────────────────────────────────
    let _db    = ThreatDb::open(&cfg.persistence)?;
    let _cache = PheromoneCache::open(&cfg.persistence, 3600)?;

    // ── Bus ──────────────────────────────────────────────────────────────────
    let bus = Bus::new();

    // ── Verdict channel: Queen → Soldier ─────────────────────────────────────
    let (verdict_tx, mut verdict_rx) = mpsc::channel(1024);

    // ── TUI event channel ────────────────────────────────────────────────────
    let (tui_tx, tui_rx) = mpsc::channel(256);

    // ── Spawn sensor agents ──────────────────────────────────────────────────
    anthill_agents::spawn_all(&cfg, &bus).await?;
    info!("sensor agents started");

    // ── Queen engine ─────────────────────────────────────────────────────────
    let queen = QueenEngine::new(cfg.clone()).await?;
    let verdict_tx_clone = verdict_tx.clone();
    tokio::spawn(async move {
        queen.run(bus, verdict_tx_clone).await;
    });
    info!("queen engine started");

    // ── Soldier response layer ────────────────────────────────────────────────
    let _tui_tx_soldier = tui_tx.clone();
    let soldier_cfg    = cfg.response.clone();
    let persist_cfg    = cfg.persistence.clone();
    tokio::spawn(async move {
        let soldier = match SoldierLayer::new(soldier_cfg, persist_cfg) {
            Ok(s) => s,
            Err(e) => { error!("soldier init failed: {e}"); return; }
        };
        while let Some(score) = verdict_rx.recv().await {
            let result = soldier.respond(&score, score.pid(), score.subject_path()).await;
            info!(action = result, "soldier executed");
            // Push to TUI
            // tui_tx_soldier.send(TuiEvent::VerdictReady(...)).await.ok();
        }
    });
    info!("soldier layer started");

    // ── TUI or headless ──────────────────────────────────────────────────────
    if cli.headless {
        info!("headless mode — press Ctrl+C to stop");
        tokio::signal::ctrl_c().await?;
    } else {
        let app = App::new();
        app.run(tui_rx).await?;
    }

    info!("🐜 Anthill stopped");
    Ok(())
}
