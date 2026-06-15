use std::{
    fs::File,
    io::{self, BufRead, BufReader, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    time::Duration,
};

use color_eyre::eyre::{bail, WrapErr};

use crate::asciicast::{self, CastEvent, CastHeader, RawCastEvent};

const ZSTD_MAGIC: [u8; 4] = [0x28, 0xB5, 0x2F, 0xFD];

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
    let header = CastHeader::parse(trim_line(&header_line))
        .wrap_err_with(|| format!("invalid asciicast header in {path:?}"))?;

    let mut out = io::stdout();
    if let (Some(width), Some(height)) = (header.cols(), header.rows()) {
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
        if asciicast::should_skip_event_line(trimmed) {
            continue;
        }
        let raw_event = RawCastEvent::parse(trimmed)
            .wrap_err_with(|| format!("invalid asciicast event in {path:?}: {trimmed}"))?;

        let delta = asciicast::event_delay(header.timing(), raw_event.time, &mut last_time);
        if delta > 0.0 {
            tokio::time::sleep(Duration::from_secs_f64(delta)).await;
        }
        let event = raw_event
            .into_absolute_event(last_time)
            .wrap_err_with(|| format!("invalid asciicast event in {path:?}: {trimmed}"))?;

        match event {
            CastEvent::Output { data, .. } => {
                out.write_all(data.as_bytes())?;
                out.flush()?;
            }
            CastEvent::Resize { width, height, .. } => {
                apply_resize(&mut out, width, height)?;
                out.flush()?;
            }
            CastEvent::Other { .. } => {}
        }
    }
    Ok(())
}

fn trim_line(line: &str) -> &str {
    line.trim_end_matches(['\r', '\n'])
}

fn apply_resize(out: &mut dyn Write, width: u16, height: u16) -> io::Result<()> {
    if width == 0 || height == 0 {
        return Ok(());
    }
    write!(out, "\x1b[8;{};{}t", height, width)
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
        let output = RawCastEvent::parse(r#"[1.25,"o","hello"]"#)
            .unwrap()
            .into_absolute_event(1.25)
            .unwrap();
        assert!(matches!(
            output,
            CastEvent::Output {
                time: 1.25,
                ref data
            } if data == "hello"
        ));
        assert_eq!(output.time(), 1.25);

        let resize = RawCastEvent::parse(r#"[2.5,"r","120x40"]"#)
            .unwrap()
            .into_absolute_event(2.5)
            .unwrap();
        assert!(matches!(
            resize,
            CastEvent::Resize {
                time: 2.5,
                width: 120,
                height: 40
            }
        ));

        let other = RawCastEvent::parse(r#"[3.0,"i","input"]"#)
            .unwrap()
            .into_absolute_event(3.0)
            .unwrap();
        assert!(matches!(other, CastEvent::Other { time: 3.0 }));
    }

    #[test]
    fn parse_event_rejects_invalid_shapes() {
        assert!(RawCastEvent::parse(r#"{"time":1}"#).is_err());
        assert!(RawCastEvent::parse(r#"[1.0]"#).is_err());
        assert!(RawCastEvent::parse(r#"["bad","o","x"]"#).is_err());
        assert!(RawCastEvent::parse(r#"[1.0,2,"x"]"#).is_err());
        assert!(RawCastEvent::parse(r#"[1.0,"r"]"#)
            .unwrap()
            .into_absolute_event(1.0)
            .is_err());
        assert!(RawCastEvent::parse(r#"[1.0,"r","120"]"#)
            .unwrap()
            .into_absolute_event(1.0)
            .is_err());
    }

    #[test]
    fn parse_size_accepts_exact_width_by_height() {
        assert_eq!(asciicast::parse_size("80x24"), Some((80, 24)));
        assert_eq!(asciicast::parse_size("0x24"), Some((0, 24)));
        assert_eq!(asciicast::parse_size("80"), None);
        assert_eq!(asciicast::parse_size("80x24x1"), None);
        assert_eq!(asciicast::parse_size("widextall"), None);
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
    fn event_delay_handles_absolute_and_relative_timing() {
        let mut last = 1.0;
        assert_eq!(
            asciicast::event_delay(asciicast::Timing::Absolute, 1.5, &mut last),
            0.5
        );
        assert_eq!(last, 1.5);
        assert_eq!(
            asciicast::event_delay(asciicast::Timing::Absolute, 1.0, &mut last),
            0.0
        );
        assert_eq!(last, 1.5);

        let mut last = 1.0;
        assert_eq!(
            asciicast::event_delay(asciicast::Timing::Relative, 0.25, &mut last),
            0.25
        );
        assert_eq!(last, 1.25);
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
