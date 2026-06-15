#[cfg(test)]
use std::path::{Path, PathBuf};
use std::time::Instant;

use color_eyre::eyre::WrapErr;

use crate::{
    asciicast::{self, CastEvent, CastHeader},
    catalog,
};

const LOOP_HOLD_SECS: f64 = 1.0;

pub(super) struct Playback {
    pub(super) title: String,
    error: Option<String>,
    events: Vec<CastEvent>,
    next_event: usize,
    started_at: Instant,
    parser: vt100::Parser,
    parser_rows: u16,
    parser_cols: u16,
    start_offset: f64,
}

impl Playback {
    pub(super) fn empty() -> Self {
        Self {
            title: "Preview".to_string(),
            error: None,
            events: Vec::new(),
            next_event: 0,
            started_at: Instant::now(),
            parser: vt100::Parser::new(24, 80, 0),
            parser_rows: 24,
            parser_cols: 80,
            start_offset: 0.0,
        }
    }

    pub(super) fn error(title: String, error: String) -> Self {
        let mut playback = Self::empty();
        playback.title = title;
        playback.error = Some(error);
        playback
    }

    #[cfg(test)]
    pub(super) fn load_at(path: PathBuf, title: String, start_at: f64) -> color_eyre::Result<Self> {
        let (header, events) = load_cast(&path)?;
        Self::from_cast(header, events, title, start_at)
    }

    pub(super) fn load_recording(
        recording: catalog::RecordingFile,
        title: String,
        start_at: f64,
    ) -> color_eyre::Result<Self> {
        let source = recording.path.display().to_string();
        let bytes = recording
            .read_cast_bytes()
            .wrap_err_with(|| format!("failed to read {source}"))?;
        let (header, events) = asciicast::parse_cast_bytes(&bytes)
            .wrap_err_with(|| format!("invalid asciicast {source}"))?;
        Self::from_cast(header, events, title, start_at)
    }

    fn from_cast(
        header: CastHeader,
        events: Vec<CastEvent>,
        title: String,
        start_at: f64,
    ) -> color_eyre::Result<Self> {
        let rows = header.rows().unwrap_or(24).clamp(1, 200);
        let cols = header.cols().unwrap_or(80).clamp(1, 400);
        let start_offset = asciicast::normalize_time(start_at);
        let now = Instant::now();
        let mut playback = Self {
            title,
            error: None,
            events,
            next_event: 0,
            started_at: now,
            parser: vt100::Parser::new(rows, cols, 0),
            parser_rows: rows,
            parser_cols: cols,
            start_offset,
        };
        playback.seek_to(start_offset, now);
        Ok(playback)
    }

    pub(super) fn tick(&mut self, now: Instant) {
        if self.error.is_some() || self.events.is_empty() {
            return;
        }

        let elapsed = self.elapsed_at(now);
        while let Some(event) = self.events.get(self.next_event) {
            let event_time = asciicast::normalize_time(event.time());
            if event_time > elapsed {
                break;
            }
            self.apply_event(self.next_event);
            self.next_event += 1;
        }

        if self.next_event >= self.events.len()
            && elapsed >= self.last_event_time() + LOOP_HOLD_SECS
        {
            self.restart_at(now);
        }
    }

    pub(super) fn screen_text(&self) -> String {
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

    pub(super) fn screen(&self) -> Option<&vt100::Screen> {
        if self.error.is_some() || self.events.is_empty() {
            return None;
        }
        Some(self.parser.screen())
    }

    fn restart_at(&mut self, now: Instant) {
        self.seek_to(self.start_offset, now);
    }

    fn seek_to(&mut self, target_time: f64, now: Instant) {
        let target_time = asciicast::normalize_time(target_time).min(self.last_event_time());
        self.parser = vt100::Parser::new(self.parser_rows, self.parser_cols, 0);
        self.next_event = 0;
        while self.next_event < self.events.len() {
            let event_time = asciicast::normalize_time(self.events[self.next_event].time());
            if event_time > target_time {
                break;
            }
            self.apply_event(self.next_event);
            self.next_event += 1;
        }
        self.started_at = start_instant(now, target_time);
    }

    fn apply_event(&mut self, index: usize) {
        match &self.events[index] {
            CastEvent::Output { data, .. } => {
                self.parser.process(data.as_bytes());
            }
            CastEvent::Resize { width, height, .. } => {
                resize_parser(&mut self.parser, *width, *height);
            }
            CastEvent::Other { .. } => {}
        }
    }

    fn elapsed_at(&self, now: Instant) -> f64 {
        now.checked_duration_since(self.started_at)
            .map(|elapsed| elapsed.as_secs_f64())
            .unwrap_or(0.0)
    }

    fn last_event_time(&self) -> f64 {
        self.events
            .last()
            .map(|event| asciicast::normalize_time(event.time()))
            .unwrap_or(0.0)
    }
}

#[cfg(test)]
fn load_cast(path: &Path) -> color_eyre::Result<(CastHeader, Vec<CastEvent>)> {
    let bytes = catalog::read_cast_bytes(path)
        .wrap_err_with(|| format!("failed to read {}", path.display()))?;
    asciicast::parse_cast_bytes(&bytes)
        .wrap_err_with(|| format!("invalid asciicast {}", path.display()))
}

fn resize_parser(parser: &mut vt100::Parser, width: u16, height: u16) {
    if width == 0 || height == 0 {
        return;
    }
    parser.set_size(height.clamp(1, 200), width.clamp(1, 400));
}

fn start_instant(now: Instant, offset: f64) -> Instant {
    now.checked_sub(std::time::Duration::from_secs_f64(
        asciicast::normalize_time(offset),
    ))
    .unwrap_or(now)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_asciicast_v2_events() {
        let cast = br#"{"version":2,"width":80,"height":24}
[0.2,"o","hello"]
[0.4,"r","100x30"]
[0.5,"i","ignored"]
"#;

        let (header, events) = asciicast::parse_cast_bytes(cast).unwrap();
        assert_eq!(header.version, 2);
        assert_eq!(header.cols(), Some(80));
        assert_eq!(header.rows(), Some(24));
        assert_eq!(events.len(), 3);
        assert!(matches!(events[0], CastEvent::Output { .. }));
        assert!(matches!(
            events[1],
            CastEvent::Resize {
                width: 100,
                height: 30,
                ..
            }
        ));
    }

    #[test]
    fn parses_asciicast_v3_relative_events() {
        let cast = br#"{"version":3,"term":{"cols":80,"rows":24}}
[0.2,"o","hello"]
[0.4,"o"," world"]
"#;

        let (header, events) = asciicast::parse_cast_bytes(cast).unwrap();

        assert_eq!(header.version, 3);
        assert_eq!(header.cols(), Some(80));
        assert_eq!(header.rows(), Some(24));
        assert!(
            matches!(events[0], CastEvent::Output { time, .. } if (time - 0.2).abs() < f64::EPSILON)
        );
        assert!(
            matches!(events[1], CastEvent::Output { time, .. } if (time - 0.6).abs() < f64::EPSILON)
        );
    }

    #[test]
    fn rejects_unsupported_asciicast_version() {
        let cast = br#"{"version":1}
[0.2,"o","hello"]
"#;

        let err = asciicast::parse_cast_bytes(cast).unwrap_err().to_string();
        assert!(err.contains("unsupported asciicast version"));
    }

    #[test]
    fn playback_renders_due_output_and_loops() {
        let (_, events) = asciicast::parse_cast_bytes(
            br#"{"version":2,"width":80,"height":24}
[0.0,"o","first"]
"#,
        )
        .unwrap();
        let started_at = Instant::now();
        let mut playback = Playback {
            title: "test".to_string(),
            error: None,
            events,
            next_event: 0,
            started_at,
            parser: vt100::Parser::new(24, 80, 0),
            parser_rows: 24,
            parser_cols: 80,
            start_offset: 0.0,
        };

        playback.tick(started_at);
        assert!(playback.screen_text().contains("first"));
        assert_eq!(playback.next_event, 1);

        playback.tick(started_at + std::time::Duration::from_secs(2));
        assert!(playback.screen_text().contains("first"));
        assert_eq!(playback.next_event, 1);
    }

    #[test]
    fn playback_can_start_at_offset() {
        let path = std::env::temp_dir().join(format!(
            "ttyrecall-playback-offset-{}.cast",
            std::process::id()
        ));
        std::fs::write(
            &path,
            br#"{"version":2,"width":80,"height":24}
[0.0,"o","first"]
[2.0,"o"," second"]
"#,
        )
        .unwrap();

        let playback = Playback::load_at(path.clone(), "test".to_string(), 2.0).unwrap();

        assert!(playback.screen_text().contains("second"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn playback_start_offset_replays_resize_events_before_target() {
        let path = std::env::temp_dir().join(format!(
            "ttyrecall-playback-offset-resize-{}.cast",
            std::process::id()
        ));
        std::fs::write(
            &path,
            br#"{"version":2,"width":80,"height":24}
[0.0,"r","6x2"]
[0.1,"o","abcdef"]
[2.0,"o","Z"]
"#,
        )
        .unwrap();

        let playback = Playback::load_at(path.clone(), "test".to_string(), 2.0).unwrap();
        let screen = playback.screen().unwrap();

        assert_eq!(screen.size(), (2, 6));
        assert!(screen.contents().contains("abcdef"));
        assert!(screen.contents().contains('Z'));
        let _ = std::fs::remove_file(path);
    }
}
