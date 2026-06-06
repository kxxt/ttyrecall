use std::{io, path::PathBuf, time::Duration};

use crossterm::{
    event::{
        self, DisableMouseCapture, EnableMouseCapture, Event as CrosstermEvent, KeyCode, KeyEvent,
        KeyEventKind, KeyModifiers, MouseButton, MouseEvent, MouseEventKind,
    },
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::CrosstermBackend, Terminal};

use crate::web;

use self::app::App;

mod app;
mod playback;
mod ui;

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
    let restore_result = restore_terminal(&mut terminal);
    restore_result?;
    result
}

fn setup_terminal() -> color_eyre::Result<Terminal<CrosstermBackend<io::Stdout>>> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    terminal.clear()?;
    Ok(terminal)
}

fn restore_terminal(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
) -> color_eyre::Result<()> {
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        DisableMouseCapture,
        LeaveAlternateScreen
    )?;
    terminal.show_cursor()?;
    Ok(())
}

fn run_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    app: &mut App,
) -> color_eyre::Result<()> {
    let mut click_map = ui::ClickMap::default();
    let mut dragging = None;
    loop {
        let now = std::time::Instant::now();
        if now.duration_since(app.last_refresh) >= REFRESH_INTERVAL {
            app.refresh();
        }
        app.playback.tick(now);

        terminal.draw(|frame| ui::draw(frame, app, &mut click_map))?;

        if event::poll(FRAME_INTERVAL)? {
            match event::read()? {
                CrosstermEvent::Key(key) => {
                    if key.kind != KeyEventKind::Press {
                        continue;
                    }
                    if let Some(action) = action_from_key(key) {
                        if !apply_key_action(action, app) {
                            break;
                        }
                    }
                }
                CrosstermEvent::Mouse(mouse) => handle_mouse(mouse, app, &click_map, &mut dragging),
                _ => {}
            }
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KeyAction {
    Quit,
    SelectNext,
    SelectPrev,
    SelectFirst,
    SelectLast,
    ReloadSelected,
    Refresh,
    ClearDateFilter,
    ResizeMainSplit(i16),
    ResizeHeatmapSplit(i16),
    ScrollHeatmapWeeks(i16),
    ScrollHeatmapRows(i16),
}

fn action_from_key(key: KeyEvent) -> Option<KeyAction> {
    if key.modifiers.contains(KeyModifiers::CONTROL) {
        return match key.code {
            KeyCode::Left => Some(KeyAction::ResizeMainSplit(-2)),
            KeyCode::Right => Some(KeyAction::ResizeMainSplit(2)),
            KeyCode::Up => Some(KeyAction::ResizeHeatmapSplit(-1)),
            KeyCode::Down => Some(KeyAction::ResizeHeatmapSplit(1)),
            _ => None,
        };
    }

    match key.code {
        KeyCode::Char('q') | KeyCode::Esc => Some(KeyAction::Quit),
        KeyCode::Char('j') | KeyCode::Down => Some(KeyAction::SelectNext),
        KeyCode::Char('k') | KeyCode::Up => Some(KeyAction::SelectPrev),
        KeyCode::Left => Some(KeyAction::ScrollHeatmapWeeks(1)),
        KeyCode::Right => Some(KeyAction::ScrollHeatmapWeeks(-1)),
        KeyCode::PageUp => Some(KeyAction::ScrollHeatmapRows(-1)),
        KeyCode::PageDown => Some(KeyAction::ScrollHeatmapRows(1)),
        KeyCode::Home => Some(KeyAction::SelectFirst),
        KeyCode::End => Some(KeyAction::SelectLast),
        KeyCode::Enter | KeyCode::Char(' ') => Some(KeyAction::ReloadSelected),
        KeyCode::Char('r') => Some(KeyAction::Refresh),
        KeyCode::Char('a') => Some(KeyAction::ClearDateFilter),
        _ => None,
    }
}

fn apply_key_action(action: KeyAction, app: &mut App) -> bool {
    match action {
        KeyAction::Quit => return false,
        KeyAction::SelectNext => app.select_next(),
        KeyAction::SelectPrev => app.select_prev(),
        KeyAction::SelectFirst => app.select_first(),
        KeyAction::SelectLast => app.select_last(),
        KeyAction::ReloadSelected => app.reload_selected(),
        KeyAction::Refresh => app.refresh(),
        KeyAction::ClearDateFilter => app.clear_date_filter(),
        KeyAction::ResizeMainSplit(delta) => app.resize_main_split(delta),
        KeyAction::ResizeHeatmapSplit(delta) => app.resize_heatmap_rows(delta),
        KeyAction::ScrollHeatmapWeeks(delta) => app.scroll_heatmap_weeks(delta),
        KeyAction::ScrollHeatmapRows(delta) => app.scroll_heatmap_rows(delta),
    }
    true
}

fn handle_mouse(
    mouse: MouseEvent,
    app: &mut App,
    click_map: &ui::ClickMap,
    dragging: &mut Option<ui::ResizeTarget>,
) {
    match mouse.kind {
        MouseEventKind::Down(MouseButton::Left) => {
            if let Some(target) = click_map.hit_test(mouse.column, mouse.row) {
                match target {
                    ui::ClickTarget::HeatmapDate(date) => app.set_date_filter(date),
                    ui::ClickTarget::RecordingRow(index) => app.select_index(index),
                    ui::ClickTarget::Resize(target) => {
                        *dragging = Some(target);
                        apply_resize_drag(target, mouse.column, mouse.row, app, click_map);
                    }
                }
            }
        }
        MouseEventKind::Drag(MouseButton::Left) => {
            if let Some(target) = *dragging {
                apply_resize_drag(target, mouse.column, mouse.row, app, click_map);
            }
        }
        MouseEventKind::Up(MouseButton::Left) => {
            *dragging = None;
        }
        MouseEventKind::ScrollUp => {
            if click_map.is_heatmap(mouse.column, mouse.row) {
                app.scroll_heatmap_rows(-1);
            } else {
                app.select_prev();
            }
        }
        MouseEventKind::ScrollDown => {
            if click_map.is_heatmap(mouse.column, mouse.row) {
                app.scroll_heatmap_rows(1);
            } else {
                app.select_next();
            }
        }
        _ => {}
    }
}

fn apply_resize_drag(
    target: ui::ResizeTarget,
    x: u16,
    y: u16,
    app: &mut App,
    click_map: &ui::ClickMap,
) {
    let Some(geometry) = click_map.resize_geometry(target) else {
        return;
    };

    match target {
        ui::ResizeTarget::MainSplit => {
            let percent = match geometry.direction {
                ratatui::layout::Direction::Horizontal => {
                    percent_position(x, geometry.area.x, geometry.area.width)
                }
                ratatui::layout::Direction::Vertical => {
                    percent_position(y, geometry.area.y, geometry.area.height)
                }
            };
            app.set_main_split_percent(percent);
        }
        ui::ResizeTarget::HeatmapSplit => {
            let rows = y.saturating_sub(geometry.area.y).saturating_add(1);
            app.set_heatmap_rows(rows);
        }
    }
}

fn percent_position(position: u16, start: u16, length: u16) -> u16 {
    if length == 0 {
        return 50;
    }
    let offset = position.saturating_sub(start).min(length);
    ((offset as u32 * 100) / length as u32) as u16
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percent_position_maps_coordinate_to_percent() {
        assert_eq!(percent_position(50, 0, 100), 50);
        assert_eq!(percent_position(0, 10, 100), 0);
        assert_eq!(percent_position(200, 0, 100), 100);
    }

    #[test]
    fn ctrl_arrows_resize_panes() {
        assert_eq!(
            action_from_key(KeyEvent::new(KeyCode::Left, KeyModifiers::CONTROL)),
            Some(KeyAction::ResizeMainSplit(-2))
        );
        assert_eq!(
            action_from_key(KeyEvent::new(KeyCode::Right, KeyModifiers::CONTROL)),
            Some(KeyAction::ResizeMainSplit(2))
        );
        assert_eq!(
            action_from_key(KeyEvent::new(KeyCode::Up, KeyModifiers::CONTROL)),
            Some(KeyAction::ResizeHeatmapSplit(-1))
        );
        assert_eq!(
            action_from_key(KeyEvent::new(KeyCode::Down, KeyModifiers::CONTROL)),
            Some(KeyAction::ResizeHeatmapSplit(1))
        );
    }

    #[test]
    fn plain_arrows_keep_navigation_and_heatmap_scroll_behavior() {
        assert_eq!(
            action_from_key(KeyEvent::new(KeyCode::Down, KeyModifiers::NONE)),
            Some(KeyAction::SelectNext)
        );
        assert_eq!(
            action_from_key(KeyEvent::new(KeyCode::Up, KeyModifiers::NONE)),
            Some(KeyAction::SelectPrev)
        );
        assert_eq!(
            action_from_key(KeyEvent::new(KeyCode::Left, KeyModifiers::NONE)),
            Some(KeyAction::ScrollHeatmapWeeks(1))
        );
        assert_eq!(
            action_from_key(KeyEvent::new(KeyCode::Right, KeyModifiers::NONE)),
            Some(KeyAction::ScrollHeatmapWeeks(-1))
        );
    }

    #[test]
    fn uppercase_hljk_are_not_resize_bindings() {
        assert_eq!(
            action_from_key(KeyEvent::new(KeyCode::Char('H'), KeyModifiers::SHIFT)),
            None
        );
        assert_eq!(
            action_from_key(KeyEvent::new(KeyCode::Char('L'), KeyModifiers::SHIFT)),
            None
        );
        assert_eq!(
            action_from_key(KeyEvent::new(KeyCode::Char('K'), KeyModifiers::SHIFT)),
            None
        );
        assert_eq!(
            action_from_key(KeyEvent::new(KeyCode::Char('J'), KeyModifiers::SHIFT)),
            None
        );
    }
}
