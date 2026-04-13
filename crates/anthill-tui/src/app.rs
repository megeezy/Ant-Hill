//! TUI App state and main event loop.

use anthill_core::RiskScore;
use anthill_db::sqlite::VerdictRow;
use crossterm::{
    event::{self, Event, KeyCode, KeyModifiers},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, enable_raw_mode, disable_raw_mode},
};
use ratatui::{
    Terminal,
    backend::CrosstermBackend,
};
use std::io;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::info;

/// Messages from the Queen / Soldier layer pushed to the TUI.
#[derive(Debug, Clone)]
pub enum TuiEvent {
    VerdictReady(VerdictRow),
    AgentStatus  { name: String, alive: bool },
    ConfirmRequest {
        verdict_id: String,
        path:       String,
        score:      f32,
        reason:     String,
    },
    ModelDriftAlert { kl_score: f64 },
    Quit,
}

pub struct App {
    pub verdicts:     Vec<VerdictRow>,
    pub agent_status: Vec<(String, bool)>,
    pub confirm_queue: Vec<TuiEvent>,
    pub running:      bool,
}

impl App {
    pub fn new() -> Self {
        Self {
            verdicts:      vec![],
            agent_status:  vec![
                ("file-monitor".into(), false),
                ("proc-monitor".into(), false),
                ("net-sniffer".into(),  false),
                ("mem-probe".into(),    false),
            ],
            confirm_queue: vec![],
            running:       true,
        }
    }

    /// Run the TUI. Blocks until the user presses `q` or `Ctrl+C`.
    pub async fn run(
        mut self,
        mut rx: mpsc::Receiver<TuiEvent>,
    ) -> anyhow::Result<()> {
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen)?;
        let backend  = CrosstermBackend::new(stdout);
        let mut term = Terminal::new(backend)?;

        info!("TUI started");

        loop {
            // Draw frame
            term.draw(|f| super::layout::draw(f, &self))?;

            // Handle TUI events from Queen/Soldier
            if let Ok(ev) = rx.try_recv() {
                self.handle_tui_event(ev);
            }

            // Handle keyboard input
            if event::poll(Duration::from_millis(250))? {
                if let Event::Key(key) = event::read()? {
                    match (key.modifiers, key.code) {
                        (KeyModifiers::CONTROL, KeyCode::Char('c'))
                        | (_, KeyCode::Char('q')) => {
                            self.running = false;
                        }
                        _ => {}
                    }
                }
            }

            if !self.running { break; }
        }

        disable_raw_mode()?;
        execute!(term.backend_mut(), LeaveAlternateScreen)?;
        Ok(())
    }

    fn handle_tui_event(&mut self, ev: TuiEvent) {
        match ev {
            TuiEvent::VerdictReady(row) => {
                self.verdicts.insert(0, row);
                self.verdicts.truncate(200); // keep last 200
            }
            TuiEvent::AgentStatus { name, alive } => {
                for (n, a) in &mut self.agent_status {
                    if *n == name { *a = alive; }
                }
            }
            TuiEvent::ConfirmRequest { .. } => {
                self.confirm_queue.push(ev);
            }
            TuiEvent::ModelDriftAlert { kl_score } => {
                tracing::warn!(kl_score, "⚠ model drift — check dashboard");
            }
            TuiEvent::Quit => self.running = false,
        }
    }
}

impl Default for App {
    fn default() -> Self {
        Self::new()
    }
}
