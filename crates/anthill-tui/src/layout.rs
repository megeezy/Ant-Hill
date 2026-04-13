//! TUI layout — defines the screen grid and call into widgets.

use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
};
use super::app::App;
use super::widgets::{agent_status, event_stream, threat_list, confirm_dialog};

pub fn draw(f: &mut Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),   // header bar
            Constraint::Min(0),      // main content
            Constraint::Length(3),   // footer / key hints
        ])
        .split(f.area());

    draw_header(f, chunks[0]);
    draw_main(f, app, chunks[1]);
    draw_footer(f, chunks[2]);

    // Overlay confirm dialog if there are pending requests
    if !app.confirm_queue.is_empty() {
        confirm_dialog::draw(f, app, f.area());
    }
}

fn draw_header(f: &mut Frame, area: Rect) {
    use ratatui::{
        widgets::{Block, Borders, Paragraph},
        style::{Color, Style, Modifier},
        text::{Span, Line},
    };
    let title = Paragraph::new(Line::from(vec![
        Span::styled("🐜 ANTHILL ", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
        Span::styled("Antivirus System v0.1", Style::default().fg(Color::DarkGray)),
    ]))
    .block(Block::default().borders(Borders::ALL));
    f.render_widget(title, area);
}

fn draw_footer(f: &mut Frame, area: Rect) {
    use ratatui::{widgets::{Block, Borders, Paragraph}, style::{Color, Style}, text::Span};
    let hints = Paragraph::new(
        Span::styled("  q — quit   ↑↓ — scroll   a — allow   k — kill   enter — confirm",
                     Style::default().fg(Color::DarkGray))
    )
    .block(Block::default().borders(Borders::ALL));
    f.render_widget(hints, area);
}

fn draw_main(f: &mut Frame, app: &App, area: Rect) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(20), // agent status panel
            Constraint::Percentage(80), // event stream + threats
        ])
        .split(area);

    agent_status::draw(f, app, cols[0]);

    let right = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage(50),
            Constraint::Percentage(50),
        ])
        .split(cols[1]);

    event_stream::draw(f, app, right[0]);
    threat_list::draw(f, app, right[1]);
}
