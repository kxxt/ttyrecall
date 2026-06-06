use std::{
    path::{Path, PathBuf},
    time::Instant,
};

use color_eyre::eyre::{bail, WrapErr};
use serde::Deserialize;

use crate::catalog;

const LOOP_HOLD_SECS: f64 = 1.0;

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

pub(super) struct Playback {
    pub(super) title: String,
    error: Option<String>,
    events: Vec<CastEvent>,
    next_event: usize,
    started_at: Instant,
    parser: vt100::Parser,
    parser_rows: u16,
    parser_cols: u16,
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
        }
    }

    pub(super) fn error(title: String, error: String) -> Self {
        let mut playback = Self::empty();
        playback.title = title;
        playback.error = Some(error);
        playback
    }

    pub(super) fn load(path: PathBuf, title: String) -> color_eyre::Result<Self> {
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

    pub(super) fn ensure_size(&mut self, rows: u16, cols: u16) {
        let rows = rows.max(1);
        let cols = cols.max(1);
        if rows == self.parser_rows && cols == self.parser_cols {
            return;
        }
        self.parser_rows = rows;
        self.parser_cols = cols;
        self.restart_at(Instant::now());
    }

    pub(super) fn tick(&mut self, now: Instant) {
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

    fn restart_at(&mut self, now: Instant) {
        self.parser = vt100::Parser::new(self.parser_rows, self.parser_cols, 0);
        self.next_event = 0;
        self.started_at = now;
    }

    fn last_event_time(&self) -> f64 {
        self.events
            .last()
            .map(|event| normalize_time(event.time()))
            .unwrap_or(0.0)
    }
}

fn load_cast(path: &Path) -> color_eyre::Result<(CastHeader, Vec<CastEvent>)> {
    let bytes = catalog::read_cast_bytes(path)
        .wrap_err_with(|| format!("failed to read {}", path.display()))?;
    parse_cast_bytes(&bytes).wrap_err_with(|| format!("invalid asciicast {}", path.display()))
}

fn parse_cast_bytes(bytes: &[u8]) -> color_eyre::Result<(CastHeader, Vec<CastEvent>)> {
    let text = std::str::from_utf8(bytes).wrap_err("recording is not valid UTF-8")?;
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

        let (header, events) = parse_cast_bytes(cast).unwrap();
        assert_eq!(header.version, 2);
        assert_eq!(header.width, Some(80));
        assert_eq!(header.height, Some(24));
        assert_eq!(events.len(), 3);
        assert!(matches!(events[0], CastEvent::Output { .. }));
        assert!(matches!(events[1], CastEvent::Other { .. }));
    }

    #[test]
    fn rejects_unsupported_asciicast_version() {
        let cast = br#"{"version":1}
[0.2,"o","hello"]
"#;

        let err = parse_cast_bytes(cast).unwrap_err().to_string();
        assert!(err.contains("unsupported asciicast version"));
    }

    #[test]
    fn playback_renders_due_output_and_loops() {
        let (_, events) = parse_cast_bytes(
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
        };

        playback.tick(started_at);
        assert!(playback.screen_text().contains("first"));
        assert_eq!(playback.next_event, 1);

        playback.tick(started_at + std::time::Duration::from_secs(2));
        assert_eq!(playback.next_event, 0);
    }
}
