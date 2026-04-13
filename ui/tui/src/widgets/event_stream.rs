//! Live event stream panel — scrolling list of raw signals.

use ratatui::{
    Frame,
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem},
};
use crate::app::App;

pub fn draw(f: &mut Frame, app: &App, area: Rect) {
    // Show the most recent 100 verdicts as event stream lines
    let items: Vec<ListItem> = app.verdicts.iter()
        .take(100)
        .map(|v| {
            let color = match v.verdict.as_str() {
                "Kill"       => Color::Red,
                "Quarantine" => Color::Yellow,
                _            => Color::DarkGray,
            };
            ListItem::new(Line::from(vec![
                Span::styled(format!("[{:>11}] ", v.verdict), Style::default().fg(color)),
                Span::raw(truncate(&v.subject_path, 45)),
                Span::styled(format!(" {:.2}", v.risk_score),
                             Style::default().fg(Color::DarkGray)),
            ]))
        })
        .collect();

    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL)
            .title(Span::styled(" Event Stream ", Style::default().add_modifier(Modifier::BOLD))));

    f.render_widget(list, area);
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max { s.to_owned() }
    else { format!("…{}", &s[s.len() - (max - 1)..]) }
}
