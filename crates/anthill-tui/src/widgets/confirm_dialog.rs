//! CONFIRM dialog overlay — shown when ResponseMode::Confirm is active.
//!
//! Displayed as a centered popup. User presses:
//!   k = kill   q = quarantine   a = allow   i = inspect (open forensics)

use ratatui::{
    Frame,
    layout::{Alignment, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph},
};
use crate::app::{App, TuiEvent};

pub fn draw(f: &mut Frame, app: &App, area: Rect) {
    let Some(TuiEvent::ConfirmRequest { verdict_id, path, score, reason }) =
        app.confirm_queue.first()
    else {
        return;
    };

    // Center a 60×10 popup
    let popup_area = centered_rect(60, 10, area);
    f.render_widget(Clear, popup_area); // clear background

    let text = vec![
        Line::from(Span::styled(
            "⚠  Security Threat Detected",
            Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(vec![
            Span::styled("File: ", Style::default().fg(Color::DarkGray)),
            Span::raw(path.as_str()),
        ]),
        Line::from(vec![
            Span::styled("Score: ", Style::default().fg(Color::DarkGray)),
            Span::styled(format!("{score:.2}"), Style::default().fg(Color::Red)),
            Span::raw(format!("   {reason}")),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            "[ k ] Kill   [ q ] Quarantine   [ a ] Allow   [ i ] Inspect",
            Style::default().fg(Color::Cyan),
        )),
        Line::from(Span::styled(
            "(Auto-quarantine in 5 min if no action)",
            Style::default().fg(Color::DarkGray),
        )),
    ];

    let popup = Paragraph::new(text)
        .alignment(Alignment::Center)
        .block(Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Yellow))
            .title(Span::styled(" ACTION REQUIRED ", Style::default().fg(Color::Yellow))));

    f.render_widget(popup, popup_area);
}

fn centered_rect(percent_x: u16, height: u16, area: Rect) -> Rect {
    let width = area.width * percent_x / 100;
    let x = (area.width.saturating_sub(width)) / 2;
    let y = (area.height.saturating_sub(height)) / 2;
    Rect::new(area.x + x, area.y + y, width, height)
}
