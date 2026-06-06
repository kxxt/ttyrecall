use std::collections::HashMap;

use chrono::{Datelike, Local, NaiveDate};
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span, Text},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap},
    Frame,
};

use super::app::App;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum ClickTarget {
    HeatmapDate(String),
    RecordingRow(usize),
}

#[derive(Debug, Default, Clone)]
pub(super) struct ClickMap {
    heatmap_dates: Vec<(Rect, String)>,
    recording_rows: Vec<(Rect, usize)>,
}

impl ClickMap {
    pub(super) fn hit_test(&self, x: u16, y: u16) -> Option<ClickTarget> {
        self.heatmap_dates
            .iter()
            .find(|(area, _)| contains(*area, x, y))
            .map(|(_, date)| ClickTarget::HeatmapDate(date.clone()))
            .or_else(|| {
                self.recording_rows
                    .iter()
                    .find(|(area, _)| contains(*area, x, y))
                    .map(|(_, index)| ClickTarget::RecordingRow(*index))
            })
    }

    fn clear(&mut self) {
        self.heatmap_dates.clear();
        self.recording_rows.clear();
    }

    fn add_heatmap_date(&mut self, area: Rect, date: NaiveDate) {
        self.heatmap_dates
            .push((area, date.format("%Y-%m-%d").to_string()));
    }

    fn add_recording_row(&mut self, area: Rect, index: usize) {
        self.recording_rows.push((area, index));
    }
}

pub(super) fn draw(frame: &mut Frame<'_>, app: &mut App, click_map: &mut ClickMap) {
    click_map.clear();
    let size = frame.area();
    let root = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(1), Constraint::Length(1)])
        .split(size);

    let body = if size.width < 100 {
        Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Percentage(45), Constraint::Percentage(55)])
            .split(root[0])
    } else {
        Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(42), Constraint::Percentage(58)])
            .split(root[0])
    };

    let left = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(10), Constraint::Min(1)])
        .split(body[0]);

    draw_heatmap(frame, left[0], app, click_map);
    draw_recordings(frame, left[1], app, click_map);
    draw_preview(frame, body[1], app);
    draw_status(frame, root[1], app);
}

fn draw_heatmap(frame: &mut Frame<'_>, area: Rect, app: &App, click_map: &mut ClickMap) {
    let title = match app.date_filter.as_deref() {
        Some(date) => format!(" Activity: {} | filter {date} ", app.username),
        None => format!(" Activity: {} ", app.username),
    };
    let block = Block::default().title(title).borders(Borders::ALL);
    let inner_width = area.width.saturating_sub(2).max(8);
    let weeks = ((inner_width / 2).max(4) as i64).min(26);
    let today = Local::now().date_naive();
    let first = today
        - chrono::Duration::days(today.weekday().num_days_from_sunday() as i64 + (weeks - 1) * 7);
    let counts: HashMap<_, _> = app
        .heatmap
        .iter()
        .filter_map(|day| {
            NaiveDate::parse_from_str(&day.date, "%Y-%m-%d")
                .ok()
                .map(|date| (date, day.count))
        })
        .collect();
    let max_count = counts.values().copied().max().unwrap_or(1);

    let mut lines = Vec::new();
    lines.push(Line::from(Span::styled(
        format!(
            "{} to {}",
            first.format("%Y-%m-%d"),
            today.format("%Y-%m-%d")
        ),
        Style::default().fg(Color::DarkGray),
    )));

    for weekday in 0..7 {
        let mut spans = Vec::new();
        for week in 0..weeks {
            let date = first + chrono::Duration::days(week * 7 + weekday);
            let count = counts.get(&date).copied().unwrap_or(0);
            let symbol = if count == 0 { "  " } else { "[]" };
            spans.push(Span::styled(symbol, heat_style(count, max_count)));
            if date <= today {
                click_map.add_heatmap_date(
                    Rect::new(
                        area.x + 1 + 4 + (week as u16 * 2),
                        area.y + 2 + weekday as u16,
                        2,
                        1,
                    ),
                    date,
                );
            }
        }
        let label = match weekday {
            0 => "Sun ",
            3 => "Wed ",
            6 => "Sat ",
            _ => "    ",
        };
        let mut row_spans = vec![Span::styled(label, Style::default().fg(Color::DarkGray))];
        row_spans.extend(spans);
        lines.push(Line::from(row_spans));
    }

    let text = Text::from(lines);
    frame.render_widget(Paragraph::new(text).block(block), area);
}

fn heat_style(count: usize, max_count: usize) -> Style {
    if count == 0 {
        return Style::default().bg(Color::Rgb(31, 36, 42));
    }
    let level = ((count * 4).div_ceil(max_count)).clamp(1, 4);
    let color = match level {
        1 => Color::Rgb(86, 122, 96),
        2 => Color::Rgb(74, 151, 103),
        3 => Color::Rgb(51, 185, 112),
        _ => Color::Rgb(30, 220, 128),
    };
    Style::default().fg(color).bg(color)
}

fn draw_recordings(frame: &mut Frame<'_>, area: Rect, app: &mut App, click_map: &mut ClickMap) {
    let visible_rows = area.height.saturating_sub(2) as usize;
    app.ensure_selected_visible(visible_rows);
    let visible_start = app.list_offset;
    let visible_recordings = app.visible_recordings(visible_rows);
    let items: Vec<ListItem> = app
        .visible_recordings(visible_rows)
        .iter()
        .map(|recording| {
            let badge = if recording.compressed { " zst" } else { "" };
            let date = if recording.date.is_empty() {
                "unknown".to_string()
            } else {
                recording.date.clone()
            };
            ListItem::new(Line::from(vec![
                Span::styled(
                    format!("{} ", recording.display),
                    Style::default().fg(Color::White),
                ),
                Span::styled(
                    format!("{}{} {}", date, badge, format_bytes(recording.size)),
                    Style::default().fg(Color::DarkGray),
                ),
            ]))
        })
        .collect();

    let mut state = ListState::default();
    if !visible_recordings.is_empty() && app.selected >= visible_start {
        state.select(Some(app.selected - visible_start));
    }

    let title = match app.date_filter.as_deref() {
        Some(date) => format!(" Recordings ({}) | {date} ", app.recordings.len()),
        None => format!(" Recordings ({}) ", app.recordings.len()),
    };
    let list = List::new(items)
        .block(Block::default().title(title).borders(Borders::ALL))
        .highlight_style(
            Style::default()
                .fg(Color::Black)
                .bg(Color::Rgb(216, 199, 155))
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("> ");

    for row in 0..visible_recordings.len() {
        click_map.add_recording_row(
            Rect::new(
                area.x + 1,
                area.y + 1 + row as u16,
                area.width.saturating_sub(2),
                1,
            ),
            visible_start + row,
        );
    }

    frame.render_stateful_widget(list, area, &mut state);
}

fn draw_preview(frame: &mut Frame<'_>, area: Rect, app: &mut App) {
    let inner_rows = area.height.saturating_sub(2).max(1);
    let inner_cols = area.width.saturating_sub(2).max(1);
    app.playback.ensure_size(inner_rows, inner_cols);

    let block = Block::default()
        .title(format!(" Preview: {} ", app.playback.title))
        .borders(Borders::ALL);
    let paragraph = Paragraph::new(app.playback.screen_text())
        .block(block)
        .style(Style::default().fg(Color::Rgb(211, 216, 217)))
        .wrap(Wrap { trim: false });
    frame.render_widget(paragraph, area);
}

fn draw_status(frame: &mut Frame<'_>, area: Rect, app: &App) {
    let controls = " q quit  up/down select  click filter/select  a all  r refresh ";
    let status = if app.status.is_empty() {
        controls.to_string()
    } else {
        format!("{} | {}", app.status, controls)
    };
    frame.render_widget(
        Paragraph::new(status).style(Style::default().fg(Color::DarkGray)),
        area,
    );
}

fn contains(area: Rect, x: u16, y: u16) -> bool {
    x >= area.x
        && x < area.x.saturating_add(area.width)
        && y >= area.y
        && y < area.y.saturating_add(area.height)
}

fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 4] = ["B", "KB", "MB", "GB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value > 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{} {}", bytes, UNITS[unit])
    } else if value < 10.0 {
        format!("{value:.1} {}", UNITS[unit])
    } else {
        format!("{value:.0} {}", UNITS[unit])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_byte_counts() {
        assert_eq!(format_bytes(999), "999 B");
        assert_eq!(format_bytes(2048), "2.0 KB");
        assert_eq!(format_bytes(11 * 1024), "11 KB");
    }

    #[test]
    fn heat_style_has_empty_and_non_empty_states() {
        assert_eq!(heat_style(0, 10).bg, Some(Color::Rgb(31, 36, 42)));
        assert_eq!(heat_style(10, 10).fg, Some(Color::Rgb(30, 220, 128)));
    }

    #[test]
    fn click_map_returns_heatmap_before_list_targets() {
        let mut map = ClickMap::default();
        map.add_recording_row(Rect::new(0, 0, 10, 1), 3);
        map.add_heatmap_date(
            Rect::new(0, 0, 2, 1),
            NaiveDate::from_ymd_opt(2026, 6, 6).unwrap(),
        );

        assert_eq!(
            map.hit_test(1, 0),
            Some(ClickTarget::HeatmapDate("2026-06-06".to_string()))
        );
        assert_eq!(map.hit_test(5, 0), Some(ClickTarget::RecordingRow(3)));
    }
}
