use std::{
    path::{Path, PathBuf},
    time::Duration,
};

use color_eyre::eyre::{bail, WrapErr};
use log::{debug, error, info, warn};
use meilisearch_sdk::{
    client::Client,
    documents::DocumentDeletionQuery,
    indexes::Index,
    search::Selectors,
    task_info::TaskInfo,
    tasks::{FailedTask, Task},
};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

use crate::{
    catalog::{
        is_recording_file_name, read_cast_bytes, recording_id_for_rel_path, recording_info,
        storage_rel_path, RecordingInfo,
    },
    watcher::RecordingEventHandler,
};

const DEFAULT_MEILISEARCH_URL: &str = "http://127.0.0.1:7700";
const DEFAULT_INDEX_NAME: &str = "ttyrecall";
const DEFAULT_BATCH_SIZE: usize = 100;
const DEFAULT_MAX_SEARCH_RESULTS: usize = 50;
const SNIPPET_CROP_LENGTH: usize = 12;

#[derive(Debug, Clone)]
pub(crate) struct IndexerConfig {
    pub(crate) enabled: bool,
    pub(crate) root: PathBuf,
    pub(crate) meilisearch_url: String,
    pub(crate) api_key: Option<String>,
    pub(crate) index_name: String,
    pub(crate) batch_size: usize,
    pub(crate) max_search_results: usize,
}

#[derive(Debug, Deserialize, Default, Clone)]
pub(crate) struct IndexerConfigFile {
    pub(crate) enabled: Option<bool>,
    pub(crate) meilisearch_url: Option<String>,
    pub(crate) api_key: Option<String>,
    pub(crate) index_name: Option<String>,
    pub(crate) batch_size: Option<usize>,
    pub(crate) max_search_results: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub(crate) struct IndexedChunk {
    pub(crate) id: String,
    pub(crate) recording_id: String,
    pub(crate) uid: u32,
    pub(crate) path: String,
    pub(crate) path_prefixes: Vec<String>,
    pub(crate) name: String,
    pub(crate) display: String,
    pub(crate) date: String,
    pub(crate) timestamp: f64,
    pub(crate) timestamp_ms: u64,
    pub(crate) text: String,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub(crate) struct SearchResult {
    pub(crate) recording_id: String,
    pub(crate) name: String,
    pub(crate) display: String,
    pub(crate) date: String,
    pub(crate) timestamp: f64,
    pub(crate) timestamp_ms: u64,
    pub(crate) text: String,
    pub(crate) snippet: String,
}

#[derive(Clone)]
pub(crate) struct MeilisearchClient {
    index_name: String,
    client: Client,
    index: Index,
    api_key: Option<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct Indexer {
    config: IndexerConfig,
    meili: MeilisearchClient,
}

#[derive(Debug)]
struct IndexerRecordingHandler {
    events: mpsc::UnboundedSender<IndexEvent>,
}

#[derive(Debug)]
enum IndexEvent {
    Clear,
    Upsert(PathBuf),
    RemoveFile(PathBuf),
    RemoveTree(PathBuf),
}

#[derive(Debug, Deserialize)]
struct CastEvent {
    #[serde(default)]
    time: f64,
    #[serde(default)]
    kind: String,
    #[serde(default)]
    data: Option<String>,
}

#[derive(Debug, Deserialize)]
struct SearchHit {
    #[serde(rename = "recording_id")]
    recording_id: String,
    name: String,
    display: String,
    date: String,
    timestamp: f64,
    #[serde(rename = "timestamp_ms")]
    timestamp_ms: u64,
    text: String,
}

impl IndexerConfigFile {
    pub(crate) fn merge(self, override_config: Self) -> Self {
        Self {
            enabled: override_config.enabled.or(self.enabled),
            meilisearch_url: override_config.meilisearch_url.or(self.meilisearch_url),
            api_key: override_config.api_key.or(self.api_key),
            index_name: override_config.index_name.or(self.index_name),
            batch_size: override_config.batch_size.or(self.batch_size),
            max_search_results: override_config
                .max_search_results
                .or(self.max_search_results),
        }
    }
}

impl IndexerConfig {
    pub(crate) fn from_file(root: String, config: Option<IndexerConfigFile>) -> Self {
        let config = config.unwrap_or_default();
        Self {
            enabled: config.enabled.unwrap_or(false),
            root: PathBuf::from(root),
            meilisearch_url: config
                .meilisearch_url
                .unwrap_or_else(|| DEFAULT_MEILISEARCH_URL.to_string()),
            api_key: config.api_key,
            index_name: config
                .index_name
                .unwrap_or_else(|| DEFAULT_INDEX_NAME.to_string()),
            batch_size: config
                .batch_size
                .unwrap_or(DEFAULT_BATCH_SIZE)
                .clamp(1, 10_000),
            max_search_results: config
                .max_search_results
                .unwrap_or(DEFAULT_MAX_SEARCH_RESULTS)
                .clamp(1, 500),
        }
    }
}

impl MeilisearchClient {
    pub(crate) fn new(config: &IndexerConfig) -> color_eyre::Result<Self> {
        let client = Client::new(
            config.meilisearch_url.trim_end_matches('/'),
            config.api_key.as_deref(),
        )?;
        let index = client.index(&config.index_name);
        Ok(Self {
            index_name: config.index_name.clone(),
            client,
            index,
            api_key: config.api_key.clone(),
        })
    }

    pub(crate) fn index_name(&self) -> &str {
        &self.index_name
    }

    pub(crate) async fn configure_index(&self) -> color_eyre::Result<()> {
        if self.client.get_index(&self.index_name).await.is_err() {
            let task = self
                .client
                .create_index(&self.index_name, Some("id"))
                .await?;
            self.wait_for_task(task).await?;
        }

        let task = self
            .index
            .set_filterable_attributes(["uid", "recording_id", "path", "path_prefixes", "date"])
            .await?;
        self.wait_for_task(task).await?;

        let task = self.index.set_sortable_attributes(["timestamp_ms"]).await?;
        self.wait_for_task(task).await?;

        Ok(())
    }

    pub(crate) async fn upsert_chunks(&self, chunks: &[IndexedChunk]) -> color_eyre::Result<()> {
        if chunks.is_empty() {
            return Ok(());
        }

        debug!(
            "submitting {} search chunks to Meilisearch index {}",
            chunks.len(),
            self.index_name
        );
        let task = self.index.add_documents(chunks, Some("id")).await?;
        self.wait_for_task(task).await
    }

    pub(crate) async fn delete_recording(&self, recording_id: &str) -> color_eyre::Result<()> {
        self.delete_by_filter(&format!(
            "recording_id = {}",
            quote_filter_value(recording_id)
        ))
        .await
    }

    pub(crate) async fn delete_path_prefix(
        &self,
        uid: u32,
        prefix: &str,
    ) -> color_eyre::Result<()> {
        let filter = format!(
            "uid = {} AND path_prefixes = {}",
            uid,
            quote_filter_value(prefix)
        );
        self.delete_by_filter(&filter).await
    }

    pub(crate) async fn search(
        &self,
        uid: u32,
        query: &str,
        limit: usize,
    ) -> color_eyre::Result<Vec<SearchResult>> {
        let filter = format!("uid = {uid}");
        let crop = [("text", None)];
        let highlight = ["text"];
        let response = self
            .index
            .search()
            .with_query(query)
            .with_filter(&filter)
            .with_limit(limit)
            .with_attributes_to_highlight(Selectors::Some(&highlight))
            .with_attributes_to_crop(Selectors::Some(&crop))
            .with_crop_length(SNIPPET_CROP_LENGTH)
            .execute::<SearchHit>()
            .await?;
        Ok(response
            .hits
            .into_iter()
            .map(|hit| SearchResult {
                recording_id: hit.result.recording_id,
                name: hit.result.name,
                display: hit.result.display,
                date: hit.result.date,
                timestamp: hit.result.timestamp,
                timestamp_ms: hit.result.timestamp_ms,
                snippet: hit
                    .formatted_result
                    .as_ref()
                    .and_then(|formatted| formatted.get("text"))
                    .and_then(|value| value.as_str())
                    .map(str::to_string)
                    .unwrap_or_else(|| hit.result.text.clone()),
                text: hit.result.text,
            })
            .collect())
    }

    async fn delete_by_filter(&self, filter: &str) -> color_eyre::Result<()> {
        let mut query = DocumentDeletionQuery::new(&self.index);
        query.with_filter(filter);
        let task = self.index.delete_documents_with(&query).await?;
        self.wait_for_task(task).await
    }

    async fn delete_all_documents(&self) -> color_eyre::Result<()> {
        let task = self.index.delete_all_documents().await?;
        self.wait_for_task(task).await
    }

    async fn wait_for_task(&self, task: TaskInfo) -> color_eyre::Result<()> {
        let task = task
            .wait_for_completion(
                &self.client,
                Some(Duration::from_millis(250)),
                Some(Duration::from_secs(30)),
            )
            .await?;
        if let Task::Failed { content } = task {
            bail!("{}", format_task_failure(&content));
        }
        Ok(())
    }
}

impl std::fmt::Debug for MeilisearchClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MeilisearchClient")
            .field("index_name", &self.index_name)
            .field("api_key", &self.api_key.as_ref().map(|_| "<redacted>"))
            .finish_non_exhaustive()
    }
}

impl Indexer {
    pub(crate) async fn run(config: IndexerConfig) -> color_eyre::Result<()> {
        if !config.enabled {
            bail!("indexer is disabled in config; set [indexer].enabled = true");
        }
        let meili = MeilisearchClient::new(&config)?;
        meili.configure_index().await?;
        let scan_root = config.root.clone();
        let display_root = scan_root.display().to_string();
        let index_name = meili.index_name().to_string();
        let (events, receiver) = mpsc::unbounded_channel();
        tokio::spawn(index_event_worker(Self { config, meili }, receiver));
        crate::watcher::spawn_recording_watcher(
            vec![scan_root],
            IndexerRecordingHandler { events },
            "ttyrecall-indexer-inotify",
        )?;
        info!(
            "indexer watching {} and writing to Meilisearch index {}",
            display_root, index_name
        );
        tokio::signal::ctrl_c().await?;
        Ok(())
    }

    async fn index_file(&self, path: &Path) -> color_eyre::Result<()> {
        let Some(recording_id) = recording_id_for_path(&self.config.root, path) else {
            return Ok(());
        };
        debug!("indexing recording {} as {}", path.display(), recording_id);
        self.meili.delete_recording(&recording_id).await?;

        let chunks = indexed_chunks_for_path(&self.config.root, path)?;
        if chunks.is_empty() {
            debug!("recording {} produced no searchable chunks", path.display());
            return Ok(());
        }

        for (batch_index, batch) in chunks.chunks(self.config.batch_size).enumerate() {
            debug!(
                "upserting search chunk batch {} for {}: {} documents",
                batch_index + 1,
                path.display(),
                batch.len()
            );
            self.meili.upsert_chunks(batch).await?;
        }
        debug!("indexed {} chunks from {}", chunks.len(), path.display());
        Ok(())
    }

    async fn delete_path(&self, path: &Path) -> color_eyre::Result<()> {
        let Some(recording_id) = recording_id_for_path(&self.config.root, path) else {
            return Ok(());
        };
        self.meili.delete_recording(&recording_id).await
    }

    async fn delete_tree(&self, path: &Path) -> color_eyre::Result<()> {
        let Some((uid, rel_path)) = storage_rel_path(&self.config.root, path) else {
            return Ok(());
        };
        let prefix = rel_path.to_string_lossy().to_string();
        self.meili.delete_path_prefix(uid, &prefix).await
    }

    async fn clear(&self) -> color_eyre::Result<()> {
        self.meili.delete_all_documents().await
    }

    pub(crate) fn search_client(
        config: &IndexerConfig,
    ) -> color_eyre::Result<Option<SearchClient>> {
        if !config.enabled {
            return Ok(None);
        }
        Ok(Some(SearchClient {
            meili: MeilisearchClient::new(config)?,
            max_results: config.max_search_results,
        }))
    }
}

#[derive(Clone)]
pub(crate) struct SearchClient {
    meili: MeilisearchClient,
    max_results: usize,
}

impl SearchClient {
    pub(crate) async fn search(
        &self,
        uid: u32,
        query: &str,
    ) -> color_eyre::Result<Vec<SearchResult>> {
        self.meili.search(uid, query, self.max_results).await
    }
}

impl std::fmt::Debug for SearchClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SearchClient")
            .field("meili", &self.meili)
            .field("max_results", &self.max_results)
            .finish()
    }
}

impl RecordingEventHandler for IndexerRecordingHandler {
    fn clear(&mut self) {
        send_index_event(&self.events, IndexEvent::Clear);
    }

    fn upsert_file(&mut self, path: &Path) {
        send_index_event(&self.events, IndexEvent::Upsert(path.to_path_buf()));
    }

    fn remove_file(&mut self, path: &Path) {
        send_index_event(&self.events, IndexEvent::RemoveFile(path.to_path_buf()));
    }

    fn remove_tree(&mut self, path: &Path) {
        send_index_event(&self.events, IndexEvent::RemoveTree(path.to_path_buf()));
    }
}

async fn index_event_worker(indexer: Indexer, mut receiver: mpsc::UnboundedReceiver<IndexEvent>) {
    while let Some(event) = receiver.recv().await {
        match event {
            IndexEvent::Clear => {
                if let Err(err) = indexer.clear().await {
                    error!("failed to clear search index: {err}");
                }
            }
            IndexEvent::Upsert(path) => {
                if let Err(err) = indexer.index_file(&path).await {
                    warn!("failed to index {}: {err}", path.display());
                }
            }
            IndexEvent::RemoveFile(path) => {
                if let Err(err) = indexer.delete_path(&path).await {
                    warn!(
                        "failed to delete indexed data for {}: {err}",
                        path.display()
                    );
                }
            }
            IndexEvent::RemoveTree(path) => {
                if let Err(err) = indexer.delete_tree(&path).await {
                    warn!(
                        "failed to delete indexed data under {}: {err}",
                        path.display()
                    );
                }
            }
        }
    }
}

fn send_index_event(sender: &mpsc::UnboundedSender<IndexEvent>, event: IndexEvent) {
    if let Err(err) = sender.send(event) {
        warn!("failed to queue index event: {err}");
    }
}

pub(crate) fn indexed_chunks_for_path(
    storage_root: &Path,
    path: &Path,
) -> color_eyre::Result<Vec<IndexedChunk>> {
    let Some((uid, rel_path)) = storage_rel_path(storage_root, path) else {
        return Ok(Vec::new());
    };
    let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
        return Ok(Vec::new());
    };
    if !is_recording_file_name(file_name) {
        return Ok(Vec::new());
    }

    let user_root = storage_root.join(uid.to_string());
    let Some(info) = recording_info(&user_root, path) else {
        return Ok(Vec::new());
    };
    let bytes =
        read_cast_bytes(path).wrap_err_with(|| format!("failed to read {}", path.display()))?;
    indexed_chunks_from_bytes(&rel_path, uid, &info, &bytes)
        .wrap_err_with(|| format!("failed to parse {}", path.display()))
}

fn recording_id_for_path(storage_root: &Path, path: &Path) -> Option<String> {
    let (_, rel_path) = storage_rel_path(storage_root, path)?;
    let file_name = path.file_name()?.to_str()?;
    if !is_recording_file_name(file_name) {
        return None;
    }
    Some(recording_id_for_rel_path(&rel_path))
}

fn indexed_chunks_from_bytes(
    rel_path: &Path,
    uid: u32,
    info: &RecordingInfo,
    bytes: &[u8],
) -> color_eyre::Result<Vec<IndexedChunk>> {
    let text = std::str::from_utf8(bytes).wrap_err("recording is not valid UTF-8")?;
    let mut lines = text.lines();
    let Some(header) = lines.next() else {
        return Ok(Vec::new());
    };
    let header: serde_json::Value = serde_json::from_str(header).wrap_err("invalid header")?;
    if header.get("version").and_then(|value| value.as_u64()) != Some(2) {
        return Ok(Vec::new());
    }

    let path_prefixes = path_prefixes(rel_path);
    let rel_path = rel_path.to_string_lossy().to_string();
    let mut chunks = Vec::new();
    for (line_index, line) in lines.enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Some(event) = parse_cast_event(line)? else {
            continue;
        };
        if event.kind != "o" {
            continue;
        }
        let text = searchable_text(&event.data.unwrap_or_default());
        if text.is_empty() {
            continue;
        }
        let timestamp = normalize_time(event.time);
        let timestamp_ms = timestamp_to_ms(timestamp);
        chunks.push(IndexedChunk {
            id: chunk_id(&info.id, line_index),
            recording_id: info.id.clone(),
            uid,
            path: rel_path.clone(),
            path_prefixes: path_prefixes.clone(),
            name: info.name.clone(),
            display: info.display.clone(),
            date: info.date.clone(),
            timestamp,
            timestamp_ms,
            text,
        });
    }
    Ok(chunks)
}

fn path_prefixes(rel_path: &Path) -> Vec<String> {
    let mut prefixes = Vec::new();
    let mut current = PathBuf::new();
    let mut components = rel_path.components().peekable();
    while let Some(component) = components.next() {
        if components.peek().is_none() {
            break;
        }
        current.push(component.as_os_str());
        prefixes.push(current.to_string_lossy().to_string());
    }
    prefixes
}

fn chunk_id(recording_id: &str, line_index: usize) -> String {
    format!("{}__{}", recording_id, line_index)
}

fn parse_cast_event(line: &str) -> color_eyre::Result<Option<CastEvent>> {
    let value: serde_json::Value = serde_json::from_str(line)?;
    let Some(arr) = value.as_array() else {
        return Ok(None);
    };
    if arr.len() < 2 {
        return Ok(None);
    }
    Ok(Some(CastEvent {
        time: arr[0].as_f64().unwrap_or(0.0),
        kind: arr[1].as_str().unwrap_or_default().to_string(),
        data: arr
            .get(2)
            .and_then(|value| value.as_str())
            .map(str::to_string),
    }))
}

fn searchable_text(value: &str) -> String {
    let mut parser = vt100::Parser::new(24, 80, 0);
    parser.process(value.as_bytes());
    let rendered = parser.screen().contents();
    let rendered = rendered.trim();
    let text = if rendered.is_empty() { value } else { rendered };
    text.chars()
        .filter(|ch| !ch.is_control() || ch.is_whitespace())
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
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

fn quote_filter_value(value: &str) -> String {
    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
}

fn format_task_failure(failed: &FailedTask) -> String {
    format!(
        "Meilisearch task {} failed index={:?}: {} (code={}, type={}, link={})",
        failed.task.uid,
        failed.task.index_uid,
        failed.error.error_message,
        failed.error.error_code,
        failed.error.error_type,
        failed.error.error_link
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info() -> RecordingInfo {
        RecordingInfo {
            id: "recording".to_string(),
            name: "bash-pty2-10:30.cast".to_string(),
            display: "2026-06-06 10:30".to_string(),
            date: "2026-06-06".to_string(),
            size: 10,
            compressed: false,
        }
    }

    #[test]
    fn indexer_config_defaults_to_disabled() {
        let config = IndexerConfig::from_file("/tmp/root".to_string(), None);

        assert!(!config.enabled);
        assert_eq!(config.meilisearch_url, DEFAULT_MEILISEARCH_URL);
        assert_eq!(config.index_name, DEFAULT_INDEX_NAME);
        assert_eq!(config.batch_size, DEFAULT_BATCH_SIZE);
    }

    #[test]
    fn parses_output_events_into_searchable_chunks() {
        let cast = br#"{"version":2,"width":80,"height":24}
[0.2,"o","hello ttyrecall\r\n"]
[0.4,"r","100x30"]
[1.25,"o","\u001b[31mred text\u001b[0m"]
"#;

        let chunks = indexed_chunks_from_bytes(
            Path::new("2026/06/06/bash-pty2-10:30.cast"),
            1000,
            &info(),
            cast,
        )
        .unwrap();

        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0].uid, 1000);
        assert_eq!(chunks[0].id, "recording__0");
        assert_eq!(chunks[0].timestamp_ms, 200);
        assert_eq!(
            chunks[0].path_prefixes,
            vec!["2026", "2026/06", "2026/06/06"]
        );
        assert!(chunks[0].text.contains("hello ttyrecall"));
        assert_eq!(chunks[1].timestamp_ms, 1250);
        assert!(chunks[1].text.contains("red text"));
    }

    #[test]
    fn ignores_unsupported_recording_versions() {
        let cast = br#"{"version":1}
[0.2,"o","hello"]
"#;

        let chunks = indexed_chunks_from_bytes(
            Path::new("2026/06/06/bash-pty2-10:30.cast"),
            1000,
            &info(),
            cast,
        )
        .unwrap();

        assert!(chunks.is_empty());
    }

    #[test]
    fn indexed_chunks_for_path_ignores_unfinished_recordings() {
        let root = std::env::temp_dir().join(format!(
            "ttyrecall-indexer-unfinished-{}",
            std::process::id()
        ));
        let recording = root.join("1000/2026/06/06/bash-pty2-10:30.cast.unfinished");
        std::fs::create_dir_all(recording.parent().unwrap()).unwrap();
        std::fs::write(
            &recording,
            br#"{"version":2}
[0.2,"o","hello"]
"#,
        )
        .unwrap();

        let chunks = indexed_chunks_for_path(&root, &recording).unwrap();

        assert!(chunks.is_empty());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn quotes_filter_values() {
        assert_eq!(quote_filter_value("abc"), "\"abc\"");
        assert_eq!(quote_filter_value("a\"b\\c"), "\"a\\\"b\\\\c\"");
    }

    #[test]
    fn path_prefixes_skip_file_name() {
        assert_eq!(
            path_prefixes(Path::new("2026/06/06/bash-pty2-10:30.cast")),
            vec!["2026", "2026/06", "2026/06/06"]
        );
    }
}
