use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{Arc, RwLock as StdRwLock},
    time::SystemTime,
};

use axum::{
    body::Body,
    extract::{Path as AxumPath, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::IntoResponse,
    Json,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::{Local, NaiveDate};
use serde::{Deserialize, Serialize};
use tokio_util::io::ReaderStream;

use super::{session::require_session, state::AppState};

pub(super) const CAST_CACHE_MAX_ENTRIES: usize = 64;

#[derive(Debug, Serialize)]
struct RecordingsResponse {
    recordings: Vec<RecordingInfo>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct RecordingInfo {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) display: String,
    pub(crate) date: String,
    pub(crate) size: u64,
    pub(crate) compressed: bool,
}

#[derive(Debug, Deserialize)]
pub(super) struct DeleteRequest {
    ids: Vec<String>,
}

#[derive(Debug, Serialize)]
struct DeleteResponse {
    deleted: usize,
}

#[derive(Debug, Serialize)]
struct HeatmapResponse {
    today: String,
    counts: Vec<HeatmapDay>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct HeatmapDay {
    pub(crate) date: String,
    pub(crate) count: usize,
}

#[derive(Debug, Default)]
pub(crate) struct RecordingIndex {
    by_user: HashMap<u32, HashMap<PathBuf, RecordingInfo>>,
}

impl RecordingIndex {
    pub(super) fn clear(&mut self) {
        self.by_user.clear();
    }

    pub(super) fn upsert_path(&mut self, storage_root: &Path, path: &Path) {
        let Some((uid, rel_path, info)) = indexed_recording(storage_root, path) else {
            return;
        };

        self.by_user.entry(uid).or_default().insert(rel_path, info);
    }

    pub(super) fn remove_path(&mut self, storage_root: &Path, path: &Path) {
        let Some((uid, rel_path)) = storage_rel_path(storage_root, path) else {
            return;
        };

        if let Some(recordings) = self.by_user.get_mut(&uid) {
            recordings.remove(&rel_path);
            if recordings.is_empty() {
                self.by_user.remove(&uid);
            }
        }
    }

    pub(super) fn remove_tree(&mut self, storage_root: &Path, path: &Path) {
        let Some((uid, rel_prefix)) = storage_rel_path(storage_root, path) else {
            return;
        };

        if let Some(recordings) = self.by_user.get_mut(&uid) {
            recordings.retain(|rel_path, _| !rel_path.starts_with(&rel_prefix));
            if recordings.is_empty() {
                self.by_user.remove(&uid);
            }
        }
    }

    fn list_for_user(&self, uid: u32) -> Vec<RecordingInfo> {
        let Some(recordings) = self.by_user.get(&uid) else {
            return Vec::new();
        };

        let mut recordings: Vec<_> = recordings.values().cloned().collect();
        recordings.sort_by(|a, b| b.display.cmp(&a.display));
        recordings
    }

    fn heatmap_for_user(&self, uid: u32) -> Vec<HeatmapDay> {
        let Some(recordings) = self.by_user.get(&uid) else {
            return Vec::new();
        };

        let mut counts: HashMap<String, usize> = HashMap::new();
        for recording in recordings.values() {
            if recording.date.is_empty() {
                continue;
            }
            *counts.entry(recording.date.clone()).or_insert(0) += 1;
        }

        let mut days: Vec<_> = counts
            .into_iter()
            .map(|(date, count)| HeatmapDay { date, count })
            .collect();
        days.sort_by(|a, b| a.date.cmp(&b.date));
        days
    }
}

pub(super) async fn list_recordings(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let session = match require_session(&state, &headers).await {
        Ok(session) => session,
        Err(status) => return (status, "Not authenticated").into_response(),
    };

    let recordings = list_recordings_for_user(&state.recording_index, session.uid);
    Json(RecordingsResponse { recordings }).into_response()
}

pub(super) async fn delete_recordings(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<DeleteRequest>,
) -> impl IntoResponse {
    let session = match require_session(&state, &headers).await {
        Ok(session) => session,
        Err(status) => return (status, "Not authenticated").into_response(),
    };

    let mut deleted = 0;
    for id in payload.ids {
        if let Some(path) = resolve_recording_path(&state.storage_root, session.uid, &id) {
            if std::fs::remove_file(&path).is_ok() {
                state
                    .recording_index
                    .write()
                    .unwrap()
                    .remove_path(&state.storage_root, &path);
                deleted += 1;
            }
        }
    }

    Json(DeleteResponse { deleted }).into_response()
}

pub(super) async fn download_recording(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> impl IntoResponse {
    let session = match require_session(&state, &headers).await {
        Ok(session) => session,
        Err(status) => return (status, "Not authenticated").into_response(),
    };

    let path = match resolve_recording_path(&state.storage_root, session.uid, &id) {
        Some(path) => path,
        None => return (StatusCode::NOT_FOUND, "Not found").into_response(),
    };

    let file_name = download_filename(&path);
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_str(&format!("attachment; filename=\"{}\"", file_name)).unwrap(),
    );
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );

    if path.extension().and_then(|s| s.to_str()) == Some("zst") {
        let bytes = match get_cast_bytes(&state, path).await {
            Ok(bytes) => bytes,
            Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to read").into_response(),
        };
        let body = Body::from(bytes);
        return (StatusCode::OK, headers, body).into_response();
    }

    let file = match tokio::fs::File::open(&path).await {
        Ok(file) => file,
        Err(_) => return (StatusCode::NOT_FOUND, "Not found").into_response(),
    };
    let stream = ReaderStream::new(file);
    let body = Body::from_stream(stream);
    (StatusCode::OK, headers, body).into_response()
}

pub(super) async fn cast_recording(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> impl IntoResponse {
    let session = match require_session(&state, &headers).await {
        Ok(session) => session,
        Err(status) => return (status, "Not authenticated").into_response(),
    };

    let path = match resolve_recording_path(&state.storage_root, session.uid, &id) {
        Some(path) => path,
        None => return (StatusCode::NOT_FOUND, "Not found").into_response(),
    };

    let bytes = match get_cast_bytes(&state, path).await {
        Ok(bytes) => bytes,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to read").into_response(),
    };

    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    (StatusCode::OK, headers, bytes).into_response()
}

pub(super) async fn heatmap(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let session = match require_session(&state, &headers).await {
        Ok(session) => session,
        Err(status) => return (status, "Not authenticated").into_response(),
    };

    let counts = heatmap_for_user(&state.recording_index, session.uid);
    let today = Local::now().date_naive();
    let response = HeatmapResponse {
        today: today.format("%Y-%m-%d").to_string(),
        counts,
    };
    Json(response).into_response()
}

pub(crate) fn list_recordings_for_user(
    index: &Arc<StdRwLock<RecordingIndex>>,
    uid: u32,
) -> Vec<RecordingInfo> {
    index.read().unwrap().list_for_user(uid)
}

fn recording_info(user_root: &Path, path: &Path) -> Option<RecordingInfo> {
    let file_name = path.file_name()?.to_string_lossy().to_string();
    if !is_recording_file_name(&file_name) {
        return None;
    }

    let rel = path.strip_prefix(user_root).ok()?;
    let id = URL_SAFE_NO_PAD.encode(rel.to_string_lossy().as_bytes());

    let compressed = file_name.ends_with(".zst");
    let display = format_display(rel).unwrap_or_else(|| file_name.clone());
    let date = date_from_path(user_root, path)
        .map(|value| value.format("%Y-%m-%d").to_string())
        .unwrap_or_default();
    let size = path.metadata().ok()?.len();

    Some(RecordingInfo {
        id,
        name: file_name,
        display,
        date,
        size,
        compressed,
    })
}

fn is_recording_file_name(file_name: &str) -> bool {
    file_name.ends_with(".cast") || file_name.ends_with(".cast.zst")
}

pub(super) fn indexed_recording(
    storage_root: &Path,
    path: &Path,
) -> Option<(u32, PathBuf, RecordingInfo)> {
    let (uid, rel_path) = storage_rel_path(storage_root, path)?;
    let user_root = storage_root.join(uid.to_string());
    let info = recording_info(&user_root, path)?;
    Some((uid, rel_path, info))
}

pub(super) fn storage_rel_path(storage_root: &Path, path: &Path) -> Option<(u32, PathBuf)> {
    let rel = path.strip_prefix(storage_root).ok()?;
    let mut components = rel.components();
    let uid: u32 = components
        .next()?
        .as_os_str()
        .to_string_lossy()
        .parse()
        .ok()?;
    let remainder = components.as_path();
    if remainder.as_os_str().is_empty() {
        return None;
    }
    Some((uid, remainder.to_path_buf()))
}

fn format_display(rel: &Path) -> Option<String> {
    let components: Vec<_> = rel.components().collect();
    if components.len() < 4 {
        return None;
    }
    let year = components[0].as_os_str().to_string_lossy();
    let month = components[1].as_os_str().to_string_lossy();
    let day = components[2].as_os_str().to_string_lossy();
    let file = components.last()?.as_os_str().to_string_lossy();

    let base = file.trim_end_matches(".zst").trim_end_matches(".cast");

    let time = base.rsplit_once("-pty")?.1;
    let time = time.split('-').nth(1)?;
    Some(format!("{}-{}-{} {}", year, month, day, time))
}

pub(crate) fn resolve_recording_path(storage_root: &Path, uid: u32, id: &str) -> Option<PathBuf> {
    let decoded = URL_SAFE_NO_PAD.decode(id).ok()?;
    let rel = String::from_utf8(decoded).ok()?;
    let rel_path = PathBuf::from(rel);
    if rel_path.is_absolute() {
        return None;
    }
    for component in rel_path.components() {
        if matches!(component, std::path::Component::ParentDir) {
            return None;
        }
    }
    let user_root = storage_root.join(uid.to_string());
    let full = user_root.join(rel_path);
    let canonical = full.canonicalize().ok()?;
    if !canonical.starts_with(&user_root) {
        return None;
    }
    Some(canonical)
}

pub(crate) fn read_cast_bytes(path: &Path) -> Result<Vec<u8>, std::io::Error> {
    let bytes = std::fs::read(path)?;
    if path.extension().and_then(|s| s.to_str()) == Some("zst") {
        let decoded = zstd::stream::decode_all(bytes.as_slice())
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))?;
        Ok(decoded)
    } else {
        Ok(bytes)
    }
}

fn download_filename(path: &Path) -> String {
    let name = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("recording.cast");
    if let Some(stripped) = name.strip_suffix(".zst") {
        stripped.to_string()
    } else {
        name.to_string()
    }
}

async fn get_cast_bytes(
    state: &AppState,
    path: PathBuf,
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    let metadata = tokio::fs::metadata(&path).await?;
    let mtime = metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH);
    {
        let mut cache = state.cast_cache.lock().await;
        if let Some(bytes) = cache.get(&path, mtime) {
            return Ok(bytes);
        }
    }

    let path_for_read = path.clone();
    let bytes = tokio::task::spawn_blocking(move || read_cast_bytes(&path_for_read)).await??;

    let mut cache = state.cast_cache.lock().await;
    cache.insert(path, mtime, bytes.clone());
    Ok(bytes)
}

pub(crate) fn heatmap_for_user(
    index: &Arc<StdRwLock<RecordingIndex>>,
    uid: u32,
) -> Vec<HeatmapDay> {
    index.read().unwrap().heatmap_for_user(uid)
}

fn date_from_path(user_root: &Path, path: &Path) -> Option<NaiveDate> {
    let rel = path.strip_prefix(user_root).ok()?;
    let components: Vec<_> = rel.components().collect();
    if components.len() < 4 {
        return None;
    }
    let year: i32 = components[0].as_os_str().to_string_lossy().parse().ok()?;
    let month: u32 = components[1].as_os_str().to_string_lossy().parse().ok()?;
    let day: u32 = components[2].as_os_str().to_string_lossy().parse().ok()?;
    NaiveDate::from_ymd_opt(year, month, day)
}
