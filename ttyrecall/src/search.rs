use std::{
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
    process::Command,
};

use color_eyre::eyre::{bail, WrapErr};
use serde::{Deserialize, Serialize};

use crate::{
    asciicast,
    catalog::{
        is_recording_file_name, read_cast_bytes, recording_id_for_rel_path, recording_info,
        storage_rel_path, RecordingInfo,
    },
};

pub(crate) const MAX_SEARCH_QUERY_LEN: usize = 256;
const FIRST_EVENT_LINE_NUMBER: u64 = 2;

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
    line_number: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct RgText {
    text: Option<String>,
}

#[derive(Debug)]
struct PendingMatch {
    ordinal: usize,
    path: PathBuf,
    rel_path: PathBuf,
    info: RecordingInfo,
    line: String,
    line_number: Option<u64>,
}

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
    if query.len() > MAX_SEARCH_QUERY_LEN {
        bail!(
            "search query is too long; maximum length is {} bytes",
            MAX_SEARCH_QUERY_LEN
        );
    }

    let user_root = storage_root.join(uid.to_string());
    if !user_root.is_dir() {
        return Ok(Vec::new());
    }

    let output = Command::new(&config.ripgrep_path)
        .arg("--json")
        .arg("--no-config")
        .arg("--fixed-strings")
        .arg("--ignore-case")
        .arg("--no-heading")
        .arg("--with-filename")
        .arg("-z")
        .arg("-g")
        .arg("*.cast")
        .arg("-g")
        .arg("*.cast.zst")
        .arg("--")
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
    if max_results == 0 {
        return Ok(Vec::new());
    }

    let text = std::str::from_utf8(bytes).wrap_err("ripgrep output is not valid UTF-8")?;
    let mut pending = Vec::new();
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
        if let Some(candidate) = pending_match(
            storage_root,
            uid,
            &path,
            &match_line,
            data.line_number,
            pending.len(),
        ) {
            pending.push(candidate);
        }

        if pending.len() >= max_results {
            append_results_from_matches(&mut results, std::mem::take(&mut pending), max_results)?;
            if results.len() >= max_results {
                break;
            }
        }
    }

    if results.len() < max_results && !pending.is_empty() {
        append_results_from_matches(&mut results, pending, max_results)?;
    }

    Ok(results)
}

fn pending_match(
    storage_root: &Path,
    uid: u32,
    path: &Path,
    line: &str,
    line_number: Option<u64>,
    ordinal: usize,
) -> Option<PendingMatch> {
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
    Some(PendingMatch {
        ordinal,
        path: path.to_path_buf(),
        rel_path,
        info,
        line: line.to_string(),
        line_number,
    })
}

fn results_from_matches(
    pending: Vec<PendingMatch>,
    max_results: usize,
) -> color_eyre::Result<Vec<SearchResult>> {
    let mut by_path: HashMap<PathBuf, Vec<usize>> = HashMap::new();
    for (index, candidate) in pending.iter().enumerate() {
        by_path
            .entry(candidate.path.clone())
            .or_default()
            .push(index);
    }

    let mut resolved: HashMap<usize, (f64, String)> = HashMap::new();
    let mut resolved_paths = HashSet::new();
    let mut results = Vec::new();

    for candidate in &pending {
        if resolved_paths.insert(&candidate.path) {
            let indices = by_path
                .get(&candidate.path)
                .expect("candidate path was indexed");
            let bytes = read_cast_bytes(&candidate.path).wrap_err_with(|| {
                format!("failed to read recording {}", candidate.path.display())
            })?;
            for (index, output) in output_events_for_matches(&bytes, &pending, indices)? {
                resolved.insert(index, output);
            }
        }

        let Some((timestamp, text)) = resolved.remove(&candidate.ordinal) else {
            continue;
        };
        let timestamp = asciicast::normalize_time(timestamp);
        results.push(search_result(candidate, timestamp, text));
        if results.len() >= max_results {
            break;
        }
    }

    Ok(results)
}

fn append_results_from_matches(
    results: &mut Vec<SearchResult>,
    pending: Vec<PendingMatch>,
    max_results: usize,
) -> color_eyre::Result<()> {
    let remaining = max_results.saturating_sub(results.len());
    if remaining == 0 {
        return Ok(());
    }

    results.extend(results_from_matches(pending, remaining)?);
    Ok(())
}

fn search_result(candidate: &PendingMatch, timestamp: f64, text: String) -> SearchResult {
    SearchResult {
        recording_id: recording_id_for_rel_path(&candidate.rel_path),
        name: candidate.info.name.clone(),
        display: candidate.info.display.clone(),
        date: candidate.info.date.clone(),
        size: candidate.info.size,
        compressed: candidate.info.compressed,
        timestamp,
        timestamp_ms: timestamp_to_ms(timestamp),
        text: searchable_text(&text),
    }
}

fn output_events_for_matches(
    bytes: &[u8],
    pending: &[PendingMatch],
    indices: &[usize],
) -> color_eyre::Result<Vec<(usize, (f64, String))>> {
    let mut targets_by_line_number: HashMap<u64, Vec<usize>> = HashMap::new();
    let mut targets_by_line: HashMap<String, Vec<usize>> = HashMap::new();
    for index in indices {
        let candidate = &pending[*index];
        if let Some(line_number) = candidate.line_number {
            targets_by_line_number
                .entry(line_number)
                .or_default()
                .push(candidate.ordinal);
        } else {
            targets_by_line
                .entry(candidate.line.trim().to_string())
                .or_default()
                .push(candidate.ordinal);
        }
    }

    let text = std::str::from_utf8(bytes).wrap_err("recording is not valid UTF-8")?;
    let mut lines = text.lines();
    let header_line = lines
        .next()
        .ok_or_else(|| color_eyre::eyre::eyre!("empty asciicast file"))?;
    let header = asciicast::CastHeader::parse(header_line)?;
    let mut elapsed = 0.0;
    let mut resolved = Vec::new();

    for (line_index, line) in lines.enumerate() {
        let line_number = line_index as u64 + FIRST_EVENT_LINE_NUMBER;
        let trimmed = line.trim();
        if asciicast::should_skip_event_line(trimmed) {
            continue;
        }

        let raw = asciicast::RawCastEvent::parse(trimmed)?;
        let event_time = asciicast::absolute_event_time(header.timing(), raw.time, &mut elapsed);
        if raw.is_output() {
            let mut matching_ordinals = Vec::new();
            if let Some(ordinals) = targets_by_line_number.get(&line_number) {
                matching_ordinals.extend(ordinals.iter().copied());
            }
            if let Some(ordinals) = targets_by_line.get(trimmed) {
                matching_ordinals.extend(ordinals.iter().copied());
            }

            let data = raw.data().unwrap_or_default().to_owned();
            resolved.extend(
                matching_ordinals
                    .into_iter()
                    .map(|ordinal| (ordinal, (event_time, data.clone()))),
            );
        }
    }

    Ok(resolved)
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

fn timestamp_to_ms(time: f64) -> u64 {
    (asciicast::normalize_time(time) * 1000.0).round() as u64
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
    fn parse_rg_json_stops_after_max_results() {
        let root = temp_root("max-results");
        let first = root.join("1000/2026/06/06/bash-pty2-10:30.cast");
        let second = root.join("1000/2026/06/06/zsh-pty3-10:31.cast");
        write_file(
            &first,
            r#"{"version":2}
[1.0,"o","first match"]
"#,
        );
        write_file(
            &second,
            r#"{"version":2}
[2.0,"o","second match"]
"#,
        );
        let rg = format!(
            r#"{{"type":"match","data":{{"path":{{"text":"{}"}},"lines":{{"text":"[1.0,\"o\",\"first match\"]\n"}}}}}}
{{"type":"match","data":{{"path":{{"text":"{}"}},"lines":{{"text":"[2.0,\"o\",\"second match\"]\n"}}}}}}
not json
"#,
            first.display(),
            second.display()
        );

        let results = parse_rg_json(&root, 1000, rg.as_bytes(), 2).unwrap();

        assert_eq!(results.len(), 2);
        assert_eq!(results[0].text, "first match");
        assert_eq!(results[1].text, "second match");

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn parses_v3_ripgrep_matches_with_relative_timestamps() {
        let root = temp_root("parse-v3-rg");
        let recording = root.join("1000/2026/06/06/bash-pty2-10:30.cast");
        write_file(
            &recording,
            r#"{"version":3,"term":{"cols":80,"rows":24}}
[1.25,"o","first"]
[0.75,"o","hello search"]
"#,
        );
        let rg = format!(
            r#"{{"type":"match","data":{{"path":{{"text":"{}"}},"lines":{{"text":"[0.75,\"o\",\"hello search\"]\n"}},"line_number":3}}}}"#,
            recording.display()
        );

        let results = parse_rg_json(&root, 1000, rg.as_bytes(), 10).unwrap();

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].timestamp_ms, 2000);
        assert_eq!(results[0].text, "hello search");

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

    #[test]
    fn search_rejects_option_like_and_oversized_queries() {
        let root = temp_root("query-validation");
        let recording = root.join("1000/2026/06/06/bash-pty2-10:30.cast");
        write_file(&recording, r#"{"version":2}"#);
        let config = RipgrepSearchConfig {
            ripgrep_path: "rg".to_string(),
            max_results: 10,
        };

        let long_query = "a".repeat(MAX_SEARCH_QUERY_LEN + 1);
        let err = search_recordings(&root, 1000, &long_query, &config).unwrap_err();
        assert!(err.to_string().contains("too long"));

        let _ = std::fs::remove_dir_all(root);
    }
}
