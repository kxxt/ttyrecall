use std::{
    path::{Path, PathBuf},
    process::Command,
};

use color_eyre::eyre::{bail, WrapErr};
use serde::{Deserialize, Serialize};

use crate::catalog::{
    is_recording_file_name, recording_id_for_rel_path, recording_info, storage_rel_path,
};

#[derive(Debug, Clone)]
pub(crate) struct RipgrepSearchConfig {
    pub(crate) ripgrep_path: String,
    pub(crate) max_results: usize,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub(crate) struct SearchResult {
    pub(crate) recording_id: String,
    pub(crate) name: String,
    pub(crate) display: String,
    pub(crate) date: String,
    pub(crate) size: u64,
    pub(crate) compressed: bool,
    pub(crate) timestamp: f64,
    pub(crate) timestamp_ms: u64,
    pub(crate) text: String,
}

#[derive(Debug, Deserialize)]
struct RgMessage {
    #[serde(rename = "type")]
    kind: String,
    data: Option<RgData>,
}

#[derive(Debug, Deserialize)]
struct RgData {
    path: Option<RgText>,
    lines: Option<RgText>,
}

#[derive(Debug, Deserialize)]
struct RgText {
    text: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CastEvent(f64, String, Option<String>);

pub(crate) fn search_recordings(
    storage_root: &Path,
    uid: u32,
    query: &str,
    config: &RipgrepSearchConfig,
) -> color_eyre::Result<Vec<SearchResult>> {
    let query = query.trim();
    if query.is_empty() {
        return Ok(Vec::new());
    }

    let user_root = storage_root.join(uid.to_string());
    if !user_root.is_dir() {
        return Ok(Vec::new());
    }

    let output = Command::new(&config.ripgrep_path)
        .arg("--json")
        .arg("--fixed-strings")
        .arg("--ignore-case")
        .arg("--no-heading")
        .arg("--with-filename")
        .arg("-z")
        .arg("-g")
        .arg("*.cast")
        .arg("-g")
        .arg("*.cast.zst")
        .arg(query)
        .arg(&user_root)
        .output()
        .wrap_err_with(|| format!("failed to run {}", config.ripgrep_path))?;

    match output.status.code() {
        Some(0) | Some(1) => {}
        _ => bail!(
            "ripgrep search failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ),
    }

    parse_rg_json(storage_root, uid, &output.stdout, config.max_results)
}

fn parse_rg_json(
    storage_root: &Path,
    uid: u32,
    bytes: &[u8],
    max_results: usize,
) -> color_eyre::Result<Vec<SearchResult>> {
    let text = std::str::from_utf8(bytes).wrap_err("ripgrep output is not valid UTF-8")?;
    let mut results = Vec::new();

    for line in text.lines() {
        let message: RgMessage = serde_json::from_str(line).wrap_err("invalid ripgrep JSON")?;
        if message.kind != "match" {
            continue;
        }
        let Some(data) = message.data else {
            continue;
        };
        let Some(path) = data.path.and_then(|path| path.text) else {
            continue;
        };
        let Some(match_line) = data.lines.and_then(|lines| lines.text) else {
            continue;
        };
        let path = PathBuf::from(path);
        if let Some(result) = result_from_match(storage_root, uid, &path, &match_line) {
            results.push(result);
            if results.len() >= max_results {
                break;
            }
        }
    }

    Ok(results)
}

fn result_from_match(
    storage_root: &Path,
    uid: u32,
    path: &Path,
    line: &str,
) -> Option<SearchResult> {
    let file_name = path.file_name()?.to_str()?;
    if !is_recording_file_name(file_name) {
        return None;
    }

    let (path_uid, rel_path) = storage_rel_path(storage_root, path)?;
    if path_uid != uid {
        return None;
    }

    let user_root = storage_root.join(uid.to_string());
    let info = recording_info(&user_root, path)?;
    let event = parse_output_event(line.trim()).ok()??;
    let timestamp = normalize_time(event.0);
    Some(SearchResult {
        recording_id: recording_id_for_rel_path(&rel_path),
        name: info.name,
        display: info.display,
        date: info.date,
        size: info.size,
        compressed: info.compressed,
        timestamp,
        timestamp_ms: timestamp_to_ms(timestamp),
        text: searchable_text(event.2.as_deref().unwrap_or_default()),
    })
}

fn parse_output_event(line: &str) -> color_eyre::Result<Option<CastEvent>> {
    let event: CastEvent = serde_json::from_str(line)?;
    if event.1 != "o" {
        return Ok(None);
    }
    Ok(Some(event))
}

fn searchable_text(value: &str) -> String {
    strip_ansi(value)
        .chars()
        .filter(|ch| !ch.is_control() || ch.is_whitespace())
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn strip_ansi(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut chars = value.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch != '\u{1b}' {
            out.push(ch);
            continue;
        }

        if chars.next_if_eq(&'[').is_none() {
            continue;
        }
        for next in chars.by_ref() {
            if ('@'..='~').contains(&next) {
                break;
            }
        }
    }
    out
}

fn normalize_time(time: f64) -> f64 {
    if time.is_finite() && time >= 0.0 {
        time
    } else {
        0.0
    }
}

fn timestamp_to_ms(time: f64) -> u64 {
    (normalize_time(time) * 1000.0).round() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_root(name: &str) -> PathBuf {
        let root =
            std::env::temp_dir().join(format!("ttyrecall-search-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        root
    }

    fn write_file(path: &Path, content: &str) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, content).unwrap();
    }

    #[test]
    fn parses_ripgrep_matches_into_timestamped_results() {
        let root = temp_root("parse-rg");
        let recording = root.join("1000/2026/06/06/bash-pty2-10:30.cast");
        write_file(
            &recording,
            r#"{"version":2}
[1.25,"o","\u001b[31mhello search\u001b[0m"]
"#,
        );
        let rg = format!(
            r#"{{"type":"match","data":{{"path":{{"text":"{}"}},"lines":{{"text":"[1.25,\"o\",\"\\u001b[31mhello search\\u001b[0m\"]\n"}}}}}}"#,
            recording.display()
        );

        let results = parse_rg_json(&root, 1000, rg.as_bytes(), 10).unwrap();

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].timestamp_ms, 1250);
        assert_eq!(results[0].text, "hello search");
        assert_eq!(results[0].display, "2026-06-06 10:30");

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn ignores_unfinished_and_non_output_matches() {
        let root = temp_root("unfinished");
        let unfinished = root.join("1000/2026/06/06/bash-pty2-10:30.cast.unfinished");
        write_file(&unfinished, r#"{"version":2}"#);
        let rg = format!(
            r#"{{"type":"match","data":{{"path":{{"text":"{}"}},"lines":{{"text":"[1.25,\"o\",\"hello\"]\n"}}}}}}
{{"type":"match","data":{{"path":{{"text":"{}"}},"lines":{{"text":"[1.25,\"r\",\"80x24\"]\n"}}}}}}"#,
            unfinished.display(),
            root.join("1000/2026/06/06/bash-pty2-10:30.cast").display()
        );

        let results = parse_rg_json(&root, 1000, rg.as_bytes(), 10).unwrap();

        assert!(results.is_empty());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn ripgrep_search_finds_zstd_recordings() {
        let root = temp_root("rg-zstd");
        let recording = root.join("1000/2026/06/06/bash-pty2-10:30.cast.zst");
        std::fs::create_dir_all(recording.parent().unwrap()).unwrap();
        let cast = br#"{"version":2}
[2.5,"o","needle in compressed output"]
"#;
        let encoded = zstd::stream::encode_all(cast.as_slice(), 0).unwrap();
        std::fs::write(&recording, encoded).unwrap();

        let results = search_recordings(
            &root,
            1000,
            "needle",
            &RipgrepSearchConfig {
                ripgrep_path: "rg".to_string(),
                max_results: 10,
            },
        )
        .unwrap();

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].timestamp_ms, 2500);
        assert!(results[0].compressed);
        assert_eq!(results[0].text, "needle in compressed output");

        let _ = std::fs::remove_dir_all(root);
    }
}
