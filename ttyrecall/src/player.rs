use std::{
    fs::File,
    io::{self, BufRead, BufReader, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    time::Duration,
};

use color_eyre::eyre::{bail, WrapErr};
use serde::Deserialize;

const ZSTD_MAGIC: [u8; 4] = [0x28, 0xB5, 0x2F, 0xFD];

#[derive(Debug, Deserialize)]
struct Header {
    version: u32,
    width: Option<u16>,
    height: Option<u16>,
}

#[derive(Debug)]
enum Event {
    Output { time: f64, data: String },
    Resize { time: f64, width: u16, height: u16 },
    Other { time: f64 },
}

pub async fn play(files: Vec<PathBuf>) -> color_eyre::Result<()> {
    for path in files {
        play_one(&path).await?;
    }
    Ok(())
}

async fn play_one(path: &Path) -> color_eyre::Result<()> {
    let mut reader = open_reader(path)?;
    let mut header_line = String::new();
    let bytes = reader
        .read_line(&mut header_line)
        .wrap_err_with(|| format!("failed to read header line from {path:?}"))?;
    if bytes == 0 {
        bail!("Empty asciicast file: {path:?}");
    }
    let header: Header = serde_json::from_str(trim_line(&header_line))
        .wrap_err_with(|| format!("invalid asciicast header in {path:?}"))?;
    if header.version != 2 {
        bail!(
            "Unsupported asciicast version {} in {path:?}. Only v2 is supported.",
            header.version
        );
    }

    let mut out = io::stdout();
    if let (Some(width), Some(height)) = (header.width, header.height) {
        apply_resize(&mut out, width, height)?;
        out.flush()?;
    }

    let mut last_time = 0.0f64;
    let mut line = String::new();
    loop {
        line.clear();
        let n = reader
            .read_line(&mut line)
            .wrap_err_with(|| format!("failed to read event line from {path:?}"))?;
        if n == 0 {
            break;
        }
        let trimmed = trim_line(&line);
        if trimmed.is_empty() {
            continue;
        }
        let event = parse_event(trimmed)
            .wrap_err_with(|| format!("invalid asciicast event in {path:?}: {trimmed}"))?;

        let event_time = normalize_time(event.time(), last_time);
        let delta = if event_time > last_time {
            event_time - last_time
        } else {
            0.0
        };
        last_time = last_time.max(event_time);
        if delta > 0.0 {
            tokio::time::sleep(Duration::from_secs_f64(delta)).await;
        }

        match event {
            Event::Output { data, .. } => {
                out.write_all(data.as_bytes())?;
                out.flush()?;
            }
            Event::Resize { width, height, .. } => {
                apply_resize(&mut out, width, height)?;
                out.flush()?;
            }
            Event::Other { .. } => {}
        }
    }
    Ok(())
}

fn trim_line(line: &str) -> &str {
    line.trim_end_matches(['\r', '\n'])
}

fn parse_event(line: &str) -> color_eyre::Result<Event> {
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
        "o" => {
            let data = arr
                .get(2)
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_owned();
            Ok(Event::Output { time, data })
        }
        "r" => {
            let raw = arr
                .get(2)
                .and_then(|v| v.as_str())
                .ok_or_else(|| color_eyre::eyre::eyre!("resize payload missing"))?;
            let (width, height) = parse_size(raw)
                .ok_or_else(|| color_eyre::eyre::eyre!("invalid resize payload: {raw}"))?;
            Ok(Event::Resize {
                time,
                width,
                height,
            })
        }
        _ => Ok(Event::Other { time }),
    }
}

fn parse_size(raw: &str) -> Option<(u16, u16)> {
    let mut parts = raw.split('x');
    let width = parts.next()?.parse().ok()?;
    let height = parts.next()?.parse().ok()?;
    if parts.next().is_some() {
        return None;
    }
    Some((width, height))
}

fn apply_resize(out: &mut dyn Write, width: u16, height: u16) -> io::Result<()> {
    if width == 0 || height == 0 {
        return Ok(());
    }
    write!(out, "\x1b[8;{};{}t", height, width)
}

fn normalize_time(time: f64, last_time: f64) -> f64 {
    if time.is_finite() && time >= 0.0 {
        time
    } else {
        last_time
    }
}

fn open_reader(path: &Path) -> color_eyre::Result<BufReader<Box<dyn Read>>> {
    let mut file = File::open(path).wrap_err_with(|| format!("failed to open {path:?}"))?;
    let is_zstd = is_zstd_file(path, &mut file)?;
    file.seek(SeekFrom::Start(0))
        .wrap_err("failed to rewind file after probing")?;
    let reader: Box<dyn Read> = if is_zstd {
        Box::new(zstd::Decoder::new(file).wrap_err("failed to init zstd decoder")?)
    } else {
        Box::new(file)
    };
    Ok(BufReader::new(reader))
}

fn is_zstd_file(path: &Path, file: &mut File) -> color_eyre::Result<bool> {
    let ext_is_zstd = path
        .extension()
        .and_then(|s| s.to_str())
        .map(|s| matches!(s.to_ascii_lowercase().as_str(), "zst" | "zstd"))
        .unwrap_or(false);
    let mut magic = [0u8; 4];
    let n = file.read(&mut magic)?;
    let magic_is_zstd = n == 4 && magic == ZSTD_MAGIC;
    Ok(ext_is_zstd || magic_is_zstd)
}

impl Event {
    fn time(&self) -> f64 {
        match self {
            Event::Output { time, .. } => *time,
            Event::Resize { time, .. } => *time,
            Event::Other { time } => *time,
        }
    }
}
