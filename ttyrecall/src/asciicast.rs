use color_eyre::eyre::{bail, WrapErr};
use serde::Deserialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Timing {
    Absolute,
    Relative,
}

#[derive(Debug, Deserialize)]
pub(crate) struct CastHeader {
    pub(crate) version: u32,
    width: Option<u16>,
    height: Option<u16>,
    term: Option<Term>,
}

#[derive(Debug, Deserialize)]
struct Term {
    cols: Option<u16>,
    rows: Option<u16>,
}

#[derive(Debug)]
pub(crate) enum CastEvent {
    Output { time: f64, data: String },
    Resize { time: f64, width: u16, height: u16 },
    Other { time: f64 },
}

#[derive(Debug)]
pub(crate) struct RawCastEvent {
    pub(crate) time: f64,
    kind: String,
    data: Option<String>,
}

impl CastHeader {
    pub(crate) fn parse(line: &str) -> color_eyre::Result<Self> {
        let header: Self = serde_json::from_str(line).wrap_err("invalid header")?;
        header.validate()?;
        Ok(header)
    }

    pub(crate) fn cols(&self) -> Option<u16> {
        if self.version == 3 {
            self.term.as_ref().and_then(|term| term.cols)
        } else {
            self.width
        }
    }

    pub(crate) fn rows(&self) -> Option<u16> {
        if self.version == 3 {
            self.term.as_ref().and_then(|term| term.rows)
        } else {
            self.height
        }
    }

    pub(crate) fn timing(&self) -> Timing {
        if self.version == 3 {
            Timing::Relative
        } else {
            Timing::Absolute
        }
    }

    fn validate(&self) -> color_eyre::Result<()> {
        match self.version {
            2 | 3 => Ok(()),
            version => {
                bail!("unsupported asciicast version {version}; only v2 and v3 are supported")
            }
        }
    }
}

impl CastEvent {
    pub(crate) fn time(&self) -> f64 {
        match self {
            Self::Output { time, .. } => *time,
            Self::Resize { time, .. } => *time,
            Self::Other { time } => *time,
        }
    }
}

impl RawCastEvent {
    pub(crate) fn parse(line: &str) -> color_eyre::Result<Self> {
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
            .ok_or_else(|| color_eyre::eyre::eyre!("event kind is not a string"))?
            .to_owned();
        let data = arr
            .get(2)
            .and_then(|value| value.as_str())
            .map(str::to_owned);
        Ok(Self { time, kind, data })
    }

    pub(crate) fn into_absolute_event(self, time: f64) -> color_eyre::Result<CastEvent> {
        match self.kind.as_str() {
            "o" => Ok(CastEvent::Output {
                time,
                data: self.data.unwrap_or_default(),
            }),
            "r" => {
                let raw = self
                    .data
                    .ok_or_else(|| color_eyre::eyre::eyre!("resize payload missing"))?;
                let (width, height) = parse_size(&raw)
                    .ok_or_else(|| color_eyre::eyre::eyre!("invalid resize payload: {raw}"))?;
                Ok(CastEvent::Resize {
                    time,
                    width,
                    height,
                })
            }
            _ => Ok(CastEvent::Other { time }),
        }
    }

    pub(crate) fn is_output(&self) -> bool {
        self.kind == "o"
    }

    pub(crate) fn data(&self) -> Option<&str> {
        self.data.as_deref()
    }
}

pub(crate) fn parse_cast_bytes(bytes: &[u8]) -> color_eyre::Result<(CastHeader, Vec<CastEvent>)> {
    let text = std::str::from_utf8(bytes).wrap_err("recording is not valid UTF-8")?;
    let mut lines = text.lines();
    let header_line = lines
        .next()
        .ok_or_else(|| color_eyre::eyre::eyre!("empty asciicast file"))?;
    let header = CastHeader::parse(header_line)?;

    let mut events = Vec::new();
    let mut elapsed = 0.0;
    for line in lines {
        let trimmed = line.trim();
        if should_skip_event_line(trimmed) {
            continue;
        }
        let raw = RawCastEvent::parse(trimmed)?;
        let event_time = absolute_event_time(header.timing(), raw.time, &mut elapsed);
        events.push(raw.into_absolute_event(event_time)?);
    }
    Ok((header, events))
}

pub(crate) fn event_delay(timing: Timing, raw_time: f64, last_time: &mut f64) -> f64 {
    let raw_time = normalize_time(raw_time);
    match timing {
        Timing::Absolute => {
            let delta = if raw_time > *last_time {
                raw_time - *last_time
            } else {
                0.0
            };
            *last_time = (*last_time).max(raw_time);
            delta
        }
        Timing::Relative => {
            *last_time += raw_time;
            raw_time
        }
    }
}

pub(crate) fn absolute_event_time(timing: Timing, raw_time: f64, elapsed: &mut f64) -> f64 {
    let raw_time = normalize_time(raw_time);
    match timing {
        Timing::Absolute => {
            *elapsed = (*elapsed).max(raw_time);
            raw_time
        }
        Timing::Relative => {
            *elapsed += raw_time;
            *elapsed
        }
    }
}

pub(crate) fn should_skip_event_line(line: &str) -> bool {
    line.is_empty() || line.starts_with('#')
}

pub(crate) fn parse_size(raw: &str) -> Option<(u16, u16)> {
    let mut parts = raw.split('x');
    let width = parts.next()?.parse().ok()?;
    let height = parts.next()?.parse().ok()?;
    if parts.next().is_some() {
        return None;
    }
    Some((width, height))
}

pub(crate) fn normalize_time(time: f64) -> f64 {
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
    fn parses_v2_absolute_events() {
        let cast = br#"{"version":2,"width":80,"height":24}
[0.2,"o","hello"]
[0.4,"r","100x30"]
"#;

        let (header, events) = parse_cast_bytes(cast).unwrap();

        assert_eq!(header.version, 2);
        assert_eq!(header.cols(), Some(80));
        assert_eq!(header.rows(), Some(24));
        assert!(matches!(events[0], CastEvent::Output { time: 0.2, .. }));
        assert!(matches!(
            events[1],
            CastEvent::Resize {
                time: 0.4,
                width: 100,
                height: 30
            }
        ));
    }

    #[test]
    fn parses_v3_relative_events_and_comments() {
        let cast = br#"{"version":3,"term":{"cols":80,"rows":24}}
# ignored
[0.2,"o","hello"]
[0.4,"o"," world"]
"#;

        let (header, events) = parse_cast_bytes(cast).unwrap();

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
    fn rejects_unsupported_version() {
        let err = parse_cast_bytes(br#"{"version":1}"#).unwrap_err();
        assert!(err.to_string().contains("unsupported asciicast version"));
    }
}
