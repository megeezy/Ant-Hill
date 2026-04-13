//! Agent status panel — shows live/dead status for each sensor agent.

use ratatui::{
    Frame,
    layout::Rect,
    style::{Color, Style, Modifier},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem},
};
use crate::app::App;

pub fn draw(f: &mut Frame, app: &App, area: Rect) {
    let items: Vec<ListItem> = app.agent_status.iter().map(|(name, alive)| {
        let (icon, color) = if *alive {
            ("● ", Color::Green)
        } else {
            ("○ ", Color::Red)
        };
        ListItem::new(Line::from(vec![
            Span::styled(icon, Style::default().fg(color)),
            Span::raw(name.clone()),
        ]))
    }).collect();

    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL)
            .title(Span::styled(" Agents ", Style::default().add_modifier(Modifier::BOLD))));

    f.render_widget(list, area);
}
