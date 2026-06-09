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

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_file(name: &str) -> PathBuf {
        let path = std::env::temp_dir()
            .join("ttyrecall-player")
            .join(std::process::id().to_string())
            .join(name);
        let _ = std::fs::remove_file(&path);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        path
    }

    #[test]
    fn trim_line_removes_crlf_without_touching_content() {
        assert_eq!(trim_line("hello\r\n"), "hello");
        assert_eq!(trim_line("hello\n"), "hello");
        assert_eq!(trim_line("hello"), "hello");
    }

    #[test]
    fn parses_output_resize_and_other_events() {
        let output = parse_event(r#"[1.25,"o","hello"]"#).unwrap();
        assert!(matches!(
            output,
            Event::Output {
                time: 1.25,
                ref data
            } if data == "hello"
        ));
        assert_eq!(output.time(), 1.25);

        let resize = parse_event(r#"[2.5,"r","120x40"]"#).unwrap();
        assert!(matches!(
            resize,
            Event::Resize {
                time: 2.5,
                width: 120,
                height: 40
            }
        ));

        let other = parse_event(r#"[3.0,"i","input"]"#).unwrap();
        assert!(matches!(other, Event::Other { time: 3.0 }));
    }

    #[test]
    fn parse_event_rejects_invalid_shapes() {
        assert!(parse_event(r#"{"time":1}"#).is_err());
        assert!(parse_event(r#"[1.0]"#).is_err());
        assert!(parse_event(r#"["bad","o","x"]"#).is_err());
        assert!(parse_event(r#"[1.0,2,"x"]"#).is_err());
        assert!(parse_event(r#"[1.0,"r"]"#).is_err());
        assert!(parse_event(r#"[1.0,"r","120"]"#).is_err());
    }

    #[test]
    fn parse_size_accepts_exact_width_by_height() {
        assert_eq!(parse_size("80x24"), Some((80, 24)));
        assert_eq!(parse_size("0x24"), Some((0, 24)));
        assert_eq!(parse_size("80"), None);
        assert_eq!(parse_size("80x24x1"), None);
        assert_eq!(parse_size("widextall"), None);
    }

    #[test]
    fn apply_resize_writes_terminal_escape_for_nonzero_size() {
        let mut out = Vec::new();
        apply_resize(&mut out, 120, 40).unwrap();
        assert_eq!(out, b"\x1b[8;40;120t");

        out.clear();
        apply_resize(&mut out, 0, 40).unwrap();
        apply_resize(&mut out, 120, 0).unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn normalize_time_uses_last_valid_time_for_invalid_values() {
        assert_eq!(normalize_time(1.5, 1.0), 1.5);
        assert_eq!(normalize_time(-1.0, 1.0), 1.0);
        assert_eq!(normalize_time(f64::NAN, 1.0), 1.0);
        assert_eq!(normalize_time(f64::INFINITY, 1.0), 1.0);
    }

    #[test]
    fn is_zstd_file_detects_extension_or_magic() {
        let zst_path = temp_file("extension.cast.zst");
        std::fs::write(&zst_path, b"plain").unwrap();
        let mut file = File::open(&zst_path).unwrap();
        assert!(is_zstd_file(&zst_path, &mut file).unwrap());

        let magic_path = temp_file("magic.cast");
        std::fs::write(&magic_path, ZSTD_MAGIC).unwrap();
        let mut file = File::open(&magic_path).unwrap();
        assert!(is_zstd_file(&magic_path, &mut file).unwrap());

        let plain_path = temp_file("plain.cast");
        std::fs::write(&plain_path, b"plain").unwrap();
        let mut file = File::open(&plain_path).unwrap();
        assert!(!is_zstd_file(&plain_path, &mut file).unwrap());

        let _ = std::fs::remove_file(zst_path);
        let _ = std::fs::remove_file(magic_path);
        let _ = std::fs::remove_file(plain_path);
    }

    #[test]
    fn open_reader_reads_plain_and_zstd_casts() {
        let plain = temp_file("reader.cast");
        std::fs::write(&plain, b"{\"version\":2}\n").unwrap();
        let mut reader = open_reader(&plain).unwrap();
        let mut text = String::new();
        reader.read_to_string(&mut text).unwrap();
        assert_eq!(text, "{\"version\":2}\n");

        let zst = temp_file("reader.cast.zst");
        let encoded = zstd::stream::encode_all(b"{\"version\":2}\n".as_slice(), 0).unwrap();
        std::fs::write(&zst, encoded).unwrap();
        let mut reader = open_reader(&zst).unwrap();
        text.clear();
        reader.read_to_string(&mut text).unwrap();
        assert_eq!(text, "{\"version\":2}\n");

        let _ = std::fs::remove_file(plain);
        let _ = std::fs::remove_file(zst);
    }
}
