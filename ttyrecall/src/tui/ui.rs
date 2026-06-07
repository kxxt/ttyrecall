use std::collections::HashMap;

use chrono::{Datelike, Local, NaiveDate};
use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span, Text},
    widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Wrap},
    Frame,
};

use super::app::{App, HEATMAP_TOTAL_ROWS, HEATMAP_TOTAL_WEEKS};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum ClickTarget {
    HeatmapDate(String),
    RecordingRow(usize),
    Resize(ResizeTarget),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ResizeTarget {
    MainSplit,
    HeatmapSplit,
}

#[derive(Debug, Clone, Copy)]
pub(super) struct ResizeGeometry {
    pub(super) target: ResizeTarget,
    pub(super) area: Rect,
    pub(super) direction: Direction,
}

#[derive(Debug, Default, Clone)]
pub(super) struct ClickMap {
    heatmap_dates: Vec<(Rect, String)>,
    recording_rows: Vec<(Rect, usize)>,
    resize_targets: Vec<(Rect, ResizeTarget)>,
    heatmap_area: Option<Rect>,
    main_geometry: Option<ResizeGeometry>,
    heatmap_geometry: Option<ResizeGeometry>,
}

impl ClickMap {
    pub(super) fn hit_test(&self, x: u16, y: u16) -> Option<ClickTarget> {
        self.resize_targets
            .iter()
            .find(|(area, _)| contains(*area, x, y))
            .map(|(_, target)| ClickTarget::Resize(*target))
            .or_else(|| {
                self.heatmap_dates
                    .iter()
                    .find(|(area, _)| contains(*area, x, y))
                    .map(|(_, date)| ClickTarget::HeatmapDate(date.clone()))
            })
            .or_else(|| {
                self.recording_rows
                    .iter()
                    .find(|(area, _)| contains(*area, x, y))
                    .map(|(_, index)| ClickTarget::RecordingRow(*index))
            })
    }

    pub(super) fn resize_geometry(&self, target: ResizeTarget) -> Option<ResizeGeometry> {
        match target {
            ResizeTarget::MainSplit => self.main_geometry,
            ResizeTarget::HeatmapSplit => self.heatmap_geometry,
        }
    }

    pub(super) fn is_heatmap(&self, x: u16, y: u16) -> bool {
        self.heatmap_area
            .map(|area| contains(area, x, y))
            .unwrap_or(false)
    }

    fn clear(&mut self) {
        self.heatmap_dates.clear();
        self.recording_rows.clear();
        self.resize_targets.clear();
        self.heatmap_area = None;
        self.main_geometry = None;
        self.heatmap_geometry = None;
    }

    fn add_heatmap_date(&mut self, area: Rect, date: NaiveDate) {
        self.heatmap_dates
            .push((area, date.format("%Y-%m-%d").to_string()));
    }

    fn add_recording_row(&mut self, area: Rect, index: usize) {
        self.recording_rows.push((area, index));
    }

    fn set_heatmap_area(&mut self, area: Rect) {
        self.heatmap_area = Some(area);
    }

    fn add_resize_target(&mut self, area: Rect, target: ResizeTarget) {
        self.resize_targets.push((area, target));
    }

    fn set_resize_geometry(&mut self, geometry: ResizeGeometry) {
        match geometry.target {
            ResizeTarget::MainSplit => self.main_geometry = Some(geometry),
            ResizeTarget::HeatmapSplit => self.heatmap_geometry = Some(geometry),
        }
    }
}

pub(super) fn draw(frame: &mut Frame<'_>, app: &mut App, click_map: &mut ClickMap) {
    click_map.clear();
    let size = frame.area();
    let root = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(1), Constraint::Length(1)])
        .split(size);

    let main_direction = if size.width < 100 {
        Direction::Vertical
    } else {
        Direction::Horizontal
    };
    let body = if main_direction == Direction::Vertical {
        Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Percentage(app.main_split_percent),
                Constraint::Percentage(100 - app.main_split_percent),
            ])
            .split(root[0])
    } else {
        Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Percentage(app.main_split_percent),
                Constraint::Percentage(100 - app.main_split_percent),
            ])
            .split(root[0])
    };

    register_main_split(root[0], body[0], main_direction, click_map);

    let heatmap_rows = app
        .heatmap_rows
        .min(body[0].height.saturating_sub(3).max(1));
    let left = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(heatmap_rows), Constraint::Min(1)])
        .split(body[0]);

    register_heatmap_split(body[0], left[0], click_map);

    draw_heatmap(frame, left[0], app, click_map);
    draw_recordings(frame, left[1], app, click_map);
    draw_preview(frame, body[1], app);
    draw_status(frame, root[1], app);
    draw_delete_confirmation(frame, size, app);
}

fn draw_heatmap(frame: &mut Frame<'_>, area: Rect, app: &mut App, click_map: &mut ClickMap) {
    click_map.set_heatmap_area(area);
    let title = match app.date_filter.as_deref() {
        Some(date) => format!(" Activity: {} | filter {date} ", app.username),
        None => format!(" Activity: {} ", app.username),
    };
    let block = Block::default().title(title).borders(Borders::ALL);
    let inner_width = area.width.saturating_sub(2);
    let visible_lines = area.height.saturating_sub(2) as usize;
    let visible_weeks = visible_heatmap_weeks(inner_width);
    app.clamp_heatmap_scroll(visible_lines, visible_weeks);
    let today = Local::now().date_naive();
    let first = today
        - chrono::Duration::days(
            today.weekday().num_days_from_sunday() as i64 + (HEATMAP_TOTAL_WEEKS as i64 - 1) * 7,
        );
    let max_week_scroll = HEATMAP_TOTAL_WEEKS.saturating_sub(visible_weeks.max(1));
    let start_week = max_week_scroll.saturating_sub(app.heatmap_week_scroll);
    let end_week = (start_week + visible_weeks).min(HEATMAP_TOTAL_WEEKS);
    let start_line = app.heatmap_row_offset;
    let end_line = (start_line + visible_lines).min(HEATMAP_TOTAL_ROWS);
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

    for line_index in start_line..end_line {
        if line_index == 0 {
            let first_visible = first + chrono::Duration::days((start_week * 7) as i64);
            let last_visible =
                first + chrono::Duration::days((end_week * 7).saturating_sub(1) as i64);
            lines.push(Line::from(Span::styled(
                format!(
                    "{} to {}",
                    first_visible.format("%Y-%m-%d"),
                    last_visible.min(today).format("%Y-%m-%d")
                ),
                Style::default().fg(Color::DarkGray),
            )));
            continue;
        }

        let weekday = line_index - 1;
        let mut spans = Vec::new();
        for week in start_week..end_week {
            let date = first + chrono::Duration::days((week * 7 + weekday) as i64);
            let count = counts.get(&date).copied().unwrap_or(0);
            let symbol = if count == 0 { "  " } else { "[]" };
            spans.push(Span::styled(symbol, heat_style(count, max_count)));
            if date <= today {
                let screen_row = area.y + 1 + (line_index - start_line) as u16;
                let screen_col = area.x + 1 + 4 + ((week - start_week) as u16 * 2);
                click_map.add_heatmap_date(Rect::new(screen_col, screen_row, 2, 1), date);
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
            let date = if recording.date.is_empty() {
                "unknown".to_string()
            } else {
                recording.date.clone()
            };
            ListItem::new(Line::from(vec![
                Span::styled(
                    format!("{} ", recording.name),
                    Style::default().fg(Color::White),
                ),
                Span::styled(
                    format!("{} {}", date, format_bytes(recording.size)),
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
    let paragraph = Paragraph::new(preview_text(app))
        .block(block)
        .style(Style::default().fg(Color::Rgb(211, 216, 217)))
        .wrap(Wrap { trim: false });
    frame.render_widget(paragraph, area);
}

fn preview_text(app: &App) -> Text<'static> {
    let Some(screen) = app.playback.screen() else {
        return Text::from(app.playback.screen_text());
    };
    if !screen_has_renderable_cells(screen) {
        return Text::from(app.playback.screen_text());
    }

    let (rows, cols) = screen.size();
    let mut lines = Vec::with_capacity(rows as usize);
    for row in 0..rows {
        lines.push(preview_line(screen, row, cols));
    }
    Text::from(lines)
}

fn preview_line(screen: &vt100::Screen, row: u16, cols: u16) -> Line<'static> {
    let mut spans = Vec::new();
    let mut pending = String::new();
    let mut pending_style: Option<Style> = None;

    for col in 0..cols {
        let Some(cell) = screen.cell(row, col) else {
            continue;
        };
        if cell.is_wide_continuation() {
            continue;
        }
        let style = cell_style(cell);
        if pending_style != Some(style) {
            flush_span(&mut spans, &mut pending, pending_style);
            pending_style = Some(style);
        }
        if cell.has_contents() {
            pending.push_str(&cell.contents());
        } else {
            pending.push(' ');
        }
    }
    flush_span(&mut spans, &mut pending, pending_style);
    Line::from(spans)
}

fn flush_span(spans: &mut Vec<Span<'static>>, pending: &mut String, style: Option<Style>) {
    if pending.is_empty() {
        return;
    }
    spans.push(Span::styled(
        std::mem::take(pending),
        style.unwrap_or_default(),
    ));
}

fn screen_has_renderable_cells(screen: &vt100::Screen) -> bool {
    let (rows, cols) = screen.size();
    for row in 0..rows {
        for col in 0..cols {
            if let Some(cell) = screen.cell(row, col) {
                if cell.has_contents() || cell_style(cell) != Style::default() {
                    return true;
                }
            }
        }
    }
    false
}

fn cell_style(cell: &vt100::Cell) -> Style {
    let mut style = Style::default();
    if let Some(color) = preview_color(cell.fgcolor()) {
        style = style.fg(color);
    }
    if let Some(color) = preview_color(cell.bgcolor()) {
        style = style.bg(color);
    }
    if cell.bold() {
        style = style.add_modifier(Modifier::BOLD);
    }
    if cell.italic() {
        style = style.add_modifier(Modifier::ITALIC);
    }
    if cell.underline() {
        style = style.add_modifier(Modifier::UNDERLINED);
    }
    if cell.inverse() {
        style = style.add_modifier(Modifier::REVERSED);
    }
    style
}

fn preview_color(color: vt100::Color) -> Option<Color> {
    match color {
        vt100::Color::Default => None,
        vt100::Color::Idx(index) => Some(Color::Indexed(index)),
        vt100::Color::Rgb(red, green, blue) => Some(Color::Rgb(red, green, blue)),
    }
}

fn draw_status(frame: &mut Frame<'_>, area: Rect, app: &App) {
    let controls = if app.search_enabled {
        " q quit  / search  d delete  c clear filter  click/drag resize  ctrl-left/right main  ctrl-up/down heatmap  pg scroll "
    } else {
        " q quit  d delete  c clear filter  click/drag resize  ctrl-left/right main  ctrl-up/down heatmap  pg scroll "
    };
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

fn draw_delete_confirmation(frame: &mut Frame<'_>, area: Rect, app: &App) {
    let Some(confirmation) = &app.delete_confirmation else {
        return;
    };

    let popup = centered_rect(62, 9, area);
    let checkbox = if confirmation.dont_ask_again {
        "[x]"
    } else {
        "[ ]"
    };
    let text = Text::from(vec![
        Line::from("Delete this recording?"),
        Line::from(Span::styled(
            confirmation.recording.name.clone(),
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(Span::styled(
            format!("{}  Don't ask again", checkbox),
            Style::default().fg(Color::Rgb(216, 199, 155)),
        )),
        Line::from(""),
        Line::from(vec![
            Span::styled("Enter/Y", Style::default().fg(Color::LightRed)),
            Span::raw(" delete  "),
            Span::styled("N/Esc", Style::default().fg(Color::DarkGray)),
            Span::raw(" cancel  "),
            Span::styled("Space", Style::default().fg(Color::DarkGray)),
            Span::raw(" toggle"),
        ]),
    ]);
    let paragraph = Paragraph::new(text)
        .block(
            Block::default()
                .title(" Confirm Delete ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::LightRed)),
        )
        .alignment(Alignment::Center)
        .style(Style::default().fg(Color::Rgb(211, 216, 217)));

    frame.render_widget(Clear, popup);
    frame.render_widget(paragraph, popup);
}

fn centered_rect(width: u16, height: u16, area: Rect) -> Rect {
    let width = width.min(area.width);
    let height = height.min(area.height);
    Rect::new(
        area.x + area.width.saturating_sub(width) / 2,
        area.y + area.height.saturating_sub(height) / 2,
        width,
        height,
    )
}

fn register_main_split(
    body_area: Rect,
    first_pane: Rect,
    direction: Direction,
    click_map: &mut ClickMap,
) {
    click_map.set_resize_geometry(ResizeGeometry {
        target: ResizeTarget::MainSplit,
        area: body_area,
        direction,
    });
    let divider = match direction {
        Direction::Horizontal => Rect::new(
            first_pane
                .x
                .saturating_add(first_pane.width)
                .saturating_sub(1),
            body_area.y,
            1,
            body_area.height,
        ),
        Direction::Vertical => Rect::new(
            body_area.x,
            first_pane
                .y
                .saturating_add(first_pane.height)
                .saturating_sub(1),
            body_area.width,
            1,
        ),
    };
    click_map.add_resize_target(divider, ResizeTarget::MainSplit);
}

fn register_heatmap_split(left_area: Rect, heatmap_area: Rect, click_map: &mut ClickMap) {
    click_map.set_resize_geometry(ResizeGeometry {
        target: ResizeTarget::HeatmapSplit,
        area: left_area,
        direction: Direction::Vertical,
    });
    let divider = Rect::new(
        left_area.x,
        heatmap_area
            .y
            .saturating_add(heatmap_area.height)
            .saturating_sub(1),
        left_area.width,
        1,
    );
    click_map.add_resize_target(divider, ResizeTarget::HeatmapSplit);
}

fn visible_heatmap_weeks(inner_width: u16) -> usize {
    inner_width.saturating_sub(4) as usize / 2
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
    fn preview_cell_style_preserves_terminal_attrs() {
        let mut parser = vt100::Parser::new(1, 8, 0);
        parser.process(b"\x1b[1;31mR\x1b[38;2;1;2;3;48;5;4mG");

        let red = cell_style(parser.screen().cell(0, 0).unwrap());
        assert_eq!(red.fg, Some(Color::Indexed(1)));
        assert!(red.add_modifier.contains(Modifier::BOLD));

        let rgb_on_blue = cell_style(parser.screen().cell(0, 1).unwrap());
        assert_eq!(rgb_on_blue.fg, Some(Color::Rgb(1, 2, 3)));
        assert_eq!(rgb_on_blue.bg, Some(Color::Indexed(4)));
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

    #[test]
    fn click_map_prioritizes_resize_targets() {
        let mut map = ClickMap::default();
        map.add_heatmap_date(
            Rect::new(0, 0, 2, 1),
            NaiveDate::from_ymd_opt(2026, 6, 6).unwrap(),
        );
        map.add_resize_target(Rect::new(0, 0, 1, 1), ResizeTarget::MainSplit);

        assert_eq!(
            map.hit_test(0, 0),
            Some(ClickTarget::Resize(ResizeTarget::MainSplit))
        );
    }

    #[test]
    fn visible_heatmap_weeks_respects_label_width() {
        assert_eq!(visible_heatmap_weeks(4), 0);
        assert_eq!(visible_heatmap_weeks(10), 3);
    }
}
