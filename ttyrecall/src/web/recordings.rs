use std::{
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
use chrono::Local;
use serde::{Deserialize, Serialize};
use tokio_util::io::ReaderStream;

use crate::catalog::{
    read_cast_bytes, resolve_recording_path, HeatmapDay, RecordingIndex, RecordingInfo,
};

use super::{session::require_session, state::AppState};

pub(super) const CAST_CACHE_MAX_ENTRIES: usize = 64;

#[derive(Debug, Serialize)]
struct RecordingsResponse {
    recordings: Vec<RecordingInfo>,
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

pub(super) fn list_recordings_for_user(
    index: &Arc<StdRwLock<RecordingIndex>>,
    uid: u32,
) -> Vec<RecordingInfo> {
    index.read().unwrap().list_for_user(uid)
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

pub(super) fn heatmap_for_user(
    index: &Arc<StdRwLock<RecordingIndex>>,
    uid: u32,
) -> Vec<HeatmapDay> {
    index.read().unwrap().heatmap_for_user(uid)
}
