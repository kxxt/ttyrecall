use std::{io, path::PathBuf, time::Duration};

use crossterm::{
    event::{
        self, DisableMouseCapture, EnableMouseCapture, Event as CrosstermEvent, KeyCode,
        KeyEventKind, MouseButton, MouseEvent, MouseEventKind,
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
                    match key.code {
                        KeyCode::Char('q') | KeyCode::Esc => break,
                        KeyCode::Char('j') | KeyCode::Down => app.select_next(),
                        KeyCode::Char('k') | KeyCode::Up => app.select_prev(),
                        KeyCode::Home => app.select_first(),
                        KeyCode::End => app.select_last(),
                        KeyCode::Enter | KeyCode::Char(' ') => app.reload_selected(),
                        KeyCode::Char('r') => app.refresh(),
                        KeyCode::Char('a') => app.clear_date_filter(),
                        _ => {}
                    }
                }
                CrosstermEvent::Mouse(mouse) => handle_mouse(mouse, app, &click_map),
                _ => {}
            }
        }
    }
    Ok(())
}

fn handle_mouse(mouse: MouseEvent, app: &mut App, click_map: &ui::ClickMap) {
    match mouse.kind {
        MouseEventKind::Down(MouseButton::Left) => {
            if let Some(target) = click_map.hit_test(mouse.column, mouse.row) {
                match target {
                    ui::ClickTarget::HeatmapDate(date) => app.set_date_filter(date),
                    ui::ClickTarget::RecordingRow(index) => app.select_index(index),
                }
            }
        }
        MouseEventKind::ScrollUp => app.select_prev(),
        MouseEventKind::ScrollDown => app.select_next(),
        _ => {}
    }
}
