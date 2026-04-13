//! Threat list widget — recent verdicts table.

use ratatui::{
    Frame,
    layout::{Constraint, Rect},
    style::{Color, Modifier, Style},
    text::Span,
    widgets::{Block, Borders, Cell, Row, Table},
};
use crate::app::App;

pub fn draw(f: &mut Frame, app: &App, area: Rect) {
    let header = Row::new(vec![
        Cell::from(Span::styled("Verdict", Style::default().add_modifier(Modifier::BOLD))),
        Cell::from(Span::styled("Score",   Style::default().add_modifier(Modifier::BOLD))),
        Cell::from(Span::styled("Path",    Style::default().add_modifier(Modifier::BOLD))),
    ])
    .style(Style::default().fg(Color::Yellow));

    let rows: Vec<Row> = app.verdicts.iter().take(50).map(|v| {
        let color = match v.verdict.as_str() {
            "Kill"       => Color::Red,
            "Quarantine" => Color::Yellow,
            _            => Color::Green,
        };
        Row::new(vec![
            Cell::from(Span::styled(v.verdict.clone(), Style::default().fg(color))),
            Cell::from(format!("{:.2}", v.risk_score)),
            Cell::from(truncate(&v.subject_path, 50)),
        ])
    }).collect();

    let table = Table::new(
        rows,
        [Constraint::Length(12), Constraint::Length(6), Constraint::Min(20)],
    )
    .header(header)
    .block(Block::default().borders(Borders::ALL)
        .title(Span::styled(" Threats ", Style::default().add_modifier(Modifier::BOLD))));

    f.render_widget(table, area);
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max { s.to_owned() }
    else { format!("…{}", &s[s.len() - (max - 1)..]) }
}
