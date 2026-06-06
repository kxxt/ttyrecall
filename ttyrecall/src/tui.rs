use std::{
    collections::HashMap,
    io,
    path::{Path, PathBuf},
    sync::{Arc, RwLock as StdRwLock},
    time::{Duration, Instant},
};

use chrono::{Datelike, Local, NaiveDate};
use color_eyre::eyre::{bail, WrapErr};
use crossterm::{
    event::{self, Event as CrosstermEvent, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span, Text},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap},
    Frame, Terminal,
};
use serde::Deserialize;

use crate::web::{self, HeatmapDay, RecordingIndex, RecordingInfo};

const REFRESH_INTERVAL: Duration = Duration::from_secs(1);
const FRAME_INTERVAL: Duration = Duration::from_millis(50);

pub(crate) fn run(config_path: Option<PathBuf>) -> color_eyre::Result<()> {
    let context = web::browse_context(config_path)?;
    let mut app = App::new(
        context.storage_root,
        context.uid,
        context.username,
        context.recording_index,
    );
    app.refresh();

    let mut terminal = setup_terminal()?;
    let result = run_loop(&mut terminal, &mut app);
    restore_terminal(&mut terminal)?;
    result
}

fn setup_terminal() -> color_eyre::Result<Terminal<CrosstermBackend<io::Stdout>>> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    terminal.clear()?;
    Ok(terminal)
}

fn restore_terminal(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
) -> color_eyre::Result<()> {
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    Ok(())
}

fn run_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    app: &mut App,
) -> color_eyre::Result<()> {
    loop {
        let now = Instant::now();
        if now.duration_since(app.last_refresh) >= REFRESH_INTERVAL {
            app.refresh();
        }
        app.playback.tick(now);

        terminal.draw(|frame| draw(frame, app))?;

        if event::poll(FRAME_INTERVAL)? {
            let CrosstermEvent::Key(key) = event::read()? else {
                continue;
            };
            if key.kind != KeyEventKind::Press {
                continue;
            }
            match key.code {
                KeyCode::Char('q') | KeyCode::Esc => break,
                KeyCode::Char('j') | KeyCode::Down => app.select_next(),
                KeyCode::Char('k') | KeyCode::Up => app.select_prev(),
                KeyCode::Home => app.select_first(),
                KeyCode::End => app.select_last(),
                KeyCode::Enter | KeyCode::Char(' ') => app.reload_selected(),
                KeyCode::Char('r') => app.refresh(),
                _ => {}
            }
        }
    }
    Ok(())
}

struct App {
    storage_root: PathBuf,
    uid: u32,
    username: String,
    recording_index: Arc<StdRwLock<RecordingIndex>>,
    recordings: Vec<RecordingInfo>,
    heatmap: Vec<HeatmapDay>,
    selected: usize,
    selected_id: Option<String>,
    last_refresh: Instant,
    playback: Playback,
    status: String,
}

impl App {
    fn new(
        storage_root: PathBuf,
        uid: u32,
        username: String,
        recording_index: Arc<StdRwLock<RecordingIndex>>,
    ) -> Self {
        Self {
            storage_root,
            uid,
            username,
            recording_index,
            recordings: Vec::new(),
            heatmap: Vec::new(),
            selected: 0,
            selected_id: None,
            last_refresh: Instant::now() - REFRESH_INTERVAL,
            playback: Playback::empty(),
            status: String::new(),
        }
    }

    fn refresh(&mut self) {
        self.recordings = web::list_recordings_for_user(&self.recording_index, self.uid);
        self.heatmap = web::heatmap_for_user(&self.recording_index, self.uid);
        if self.selected >= self.recordings.len() {
            self.selected = self.recordings.len().saturating_sub(1);
        }
        self.last_refresh = Instant::now();
        self.load_selected_if_needed();
    }

    fn select_next(&mut self) {
        if self.recordings.is_empty() {
            return;
        }
        self.selected = (self.selected + 1).min(self.recordings.len() - 1);
        self.load_selected_if_needed();
    }

    fn select_prev(&mut self) {
        self.selected = self.selected.saturating_sub(1);
        self.load_selected_if_needed();
    }

    fn select_first(&mut self) {
        self.selected = 0;
        self.load_selected_if_needed();
    }

    fn select_last(&mut self) {
        if !self.recordings.is_empty() {
            self.selected = self.recordings.len() - 1;
            self.load_selected_if_needed();
        }
    }

    fn reload_selected(&mut self) {
        self.selected_id = None;
        self.load_selected_if_needed();
    }

    fn selected_recording(&self) -> Option<&RecordingInfo> {
        self.recordings.get(self.selected)
    }

    fn load_selected_if_needed(&mut self) {
        let Some(recording) = self.selected_recording().cloned() else {
            self.selected_id = None;
            self.playback = Playback::empty();
            self.status = "No recordings found".to_string();
            return;
        };

        if self.selected_id.as_deref() == Some(recording.id.as_str()) {
            return;
        }
        self.selected_id = Some(recording.id.clone());

        let Some(path) = web::resolve_recording_path(&self.storage_root, self.uid, &recording.id)
        else {
            self.playback = Playback::error(
                recording.display.clone(),
                "recording path no longer exists".to_string(),
            );
            self.status = format!("Missing {}", recording.display);
            return;
        };

        match Playback::load(path, recording.display.clone()) {
            Ok(playback) => {
                self.playback = playback;
                self.status = format!("Playing {}", recording.display);
            }
            Err(err) => {
                self.playback = Playback::error(recording.display.clone(), err.to_string());
                self.status = format!("Failed to load {}", recording.display);
            }
        }
    }
}

#[derive(Debug, Deserialize)]
struct CastHeader {
    version: u32,
    width: Option<u16>,
    height: Option<u16>,
}

#[derive(Debug)]
enum CastEvent {
    Output { time: f64, data: String },
    Other { time: f64 },
}

impl CastEvent {
    fn time(&self) -> f64 {
        match self {
            Self::Output { time, .. } => *time,
            Self::Other { time } => *time,
        }
    }
}

struct Playback {
    title: String,
    error: Option<String>,
    events: Vec<CastEvent>,
    next_event: usize,
    started_at: Instant,
    parser: vt100::Parser,
    parser_rows: u16,
    parser_cols: u16,
}

impl Playback {
    fn empty() -> Self {
        Self {
            title: "Preview".to_string(),
            error: None,
            events: Vec::new(),
            next_event: 0,
            started_at: Instant::now(),
            parser: vt100::Parser::new(24, 80, 0),
            parser_rows: 24,
            parser_cols: 80,
        }
    }

    fn error(title: String, error: String) -> Self {
        let mut playback = Self::empty();
        playback.title = title;
        playback.error = Some(error);
        playback
    }

    fn load(path: PathBuf, title: String) -> color_eyre::Result<Self> {
        let (header, events) = load_cast(&path)?;
        let rows = header.height.unwrap_or(24).clamp(1, 200);
        let cols = header.width.unwrap_or(80).clamp(1, 400);
        Ok(Self {
            title,
            error: None,
            events,
            next_event: 0,
            started_at: Instant::now(),
            parser: vt100::Parser::new(rows, cols, 0),
            parser_rows: rows,
            parser_cols: cols,
        })
    }

    fn ensure_size(&mut self, rows: u16, cols: u16) {
        let rows = rows.max(1);
        let cols = cols.max(1);
        if rows == self.parser_rows && cols == self.parser_cols {
            return;
        }
        self.parser_rows = rows;
        self.parser_cols = cols;
        self.restart_at(Instant::now());
    }

    fn tick(&mut self, now: Instant) {
        if self.error.is_some() || self.events.is_empty() {
            return;
        }

        let elapsed = now.duration_since(self.started_at).as_secs_f64();
        while let Some(event) = self.events.get(self.next_event) {
            let event_time = normalize_time(event.time());
            if event_time > elapsed {
                break;
            }
            match event {
                CastEvent::Output { data, .. } => {
                    self.parser.process(data.as_bytes());
                }
                CastEvent::Other { .. } => {}
            }
            self.next_event += 1;
        }

        if self.next_event >= self.events.len() {
            self.restart_at(now);
        }
    }

    fn restart_at(&mut self, now: Instant) {
        self.parser = vt100::Parser::new(self.parser_rows, self.parser_cols, 0);
        self.next_event = 0;
        self.started_at = now;
    }

    fn screen_text(&self) -> String {
        if let Some(error) = &self.error {
            return error.clone();
        }
        if self.events.is_empty() {
            return "Select a recording to preview it here.".to_string();
        }
        let contents = self.parser.screen().contents();
        if contents.trim().is_empty() {
            "Waiting for output...".to_string()
        } else {
            contents
        }
    }
}

fn load_cast(path: &Path) -> color_eyre::Result<(CastHeader, Vec<CastEvent>)> {
    let bytes = web::read_cast_bytes(path)
        .wrap_err_with(|| format!("failed to read {}", path.display()))?;
    let text = String::from_utf8(bytes)
        .wrap_err_with(|| format!("recording is not valid UTF-8: {}", path.display()))?;
    let mut lines = text.lines();
    let header_line = lines
        .next()
        .ok_or_else(|| color_eyre::eyre::eyre!("empty asciicast file"))?;
    let header: CastHeader = serde_json::from_str(header_line).wrap_err("invalid header")?;
    if header.version != 2 {
        bail!(
            "unsupported asciicast version {}; only v2 is supported",
            header.version
        );
    }

    let mut events = Vec::new();
    for line in lines {
        if line.trim().is_empty() {
            continue;
        }
        events.push(parse_cast_event(line)?);
    }
    Ok((header, events))
}

fn parse_cast_event(line: &str) -> color_eyre::Result<CastEvent> {
    let value: serde_json::Value = serde_json::from_str(line)?;
    let arr = value
        .as_array()
        .ok_or_else(|| color_eyre::eyre::eyre!("event is not a JSON array"))?;
    if arr.len() < 2 {
        bail!("event array is too short");
    }
    let time = arr[0]
        .as_f64()
        .ok_or_else(|| color_eyre::eyre::eyre!("event time is not a number"))?;
    let kind = arr[1]
        .as_str()
        .ok_or_else(|| color_eyre::eyre::eyre!("event kind is not a string"))?;

    match kind {
        "o" => Ok(CastEvent::Output {
            time,
            data: arr
                .get(2)
                .and_then(|value| value.as_str())
                .unwrap_or_default()
                .to_string(),
        }),
        "r" => Ok(CastEvent::Other { time }),
        _ => Ok(CastEvent::Other { time }),
    }
}

fn normalize_time(time: f64) -> f64 {
    if time.is_finite() && time >= 0.0 {
        time
    } else {
        0.0
    }
}

fn draw(frame: &mut Frame<'_>, app: &mut App) {
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

    draw_heatmap(frame, left[0], app);
    draw_recordings(frame, left[1], app);
    draw_preview(frame, body[1], app);
    draw_status(frame, root[1], app);
}

fn draw_heatmap(frame: &mut Frame<'_>, area: Rect, app: &App) {
    let block = Block::default()
        .title(format!(" Activity: {} ", app.username))
        .borders(Borders::ALL);
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
            let symbol = if count == 0 { "  " } else { "██" };
            spans.push(Span::styled(symbol, heat_style(count, max_count)));
        }
        let label = if weekday == 0 {
            "Sun "
        } else if weekday == 3 {
            "Wed "
        } else if weekday == 6 {
            "Sat "
        } else {
            "    "
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

fn draw_recordings(frame: &mut Frame<'_>, area: Rect, app: &mut App) {
    let items: Vec<ListItem> = app
        .recordings
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
    if !app.recordings.is_empty() {
        state.select(Some(app.selected));
    }

    let list = List::new(items)
        .block(
            Block::default()
                .title(format!(" Recordings ({}) ", app.recordings.len()))
                .borders(Borders::ALL),
        )
        .highlight_style(
            Style::default()
                .fg(Color::Black)
                .bg(Color::Rgb(216, 199, 155))
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("▶ ");

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
    let controls = " q quit  ↑/↓ select  enter reload  r refresh ";
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
