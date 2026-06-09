use std::{
    path::{Path, PathBuf},
    sync::{Arc, RwLock as StdRwLock},
    time::SystemTime,
};

use axum::{
    body::Body,
    extract::{Path as AxumPath, Query, State},
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
const DEFAULT_RECORDINGS_LIMIT: usize = 100;
const MAX_RECORDINGS_LIMIT: usize = 500;

#[derive(Debug, Serialize)]
struct RecordingsResponse {
    recordings: Vec<RecordingInfo>,
    offset: usize,
    limit: usize,
    total: usize,
    has_more: bool,
}

#[derive(Debug, Deserialize)]
pub(super) struct RecordingsQuery {
    offset: Option<usize>,
    limit: Option<usize>,
    date: Option<String>,
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
    Query(query): Query<RecordingsQuery>,
) -> impl IntoResponse {
    let session = match require_session(&state, &headers).await {
        Ok(session) => session,
        Err(status) => return (status, "Not authenticated").into_response(),
    };

    let offset = query.offset.unwrap_or(0);
    let limit = query
        .limit
        .unwrap_or(DEFAULT_RECORDINGS_LIMIT)
        .clamp(1, MAX_RECORDINGS_LIMIT);
    let date = query.date.as_deref().filter(|date| !date.is_empty());
    let (recordings, total) =
        list_recordings_page_for_user(&state.recording_index, session.uid, date, offset, limit);
    let has_more = offset.saturating_add(recordings.len()) < total;

    Json(RecordingsResponse {
        recordings,
        offset,
        limit,
        total,
        has_more,
    })
    .into_response()
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

pub(super) fn list_recordings_page_for_user(
    index: &Arc<StdRwLock<RecordingIndex>>,
    uid: u32,
    date: Option<&str>,
    offset: usize,
    limit: usize,
) -> (Vec<RecordingInfo>, usize) {
    index
        .read()
        .unwrap()
        .list_for_user_page(uid, date, offset, limit)
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

#[cfg(test)]
mod tests {
    use std::{
        collections::HashMap,
        fs,
        sync::{Arc, RwLock as StdRwLock},
        time::{Duration, Instant},
    };

    use axum::body::to_bytes;
    use serde_json::Value;
    use tokio::sync::RwLock;

    use super::*;
    use crate::{
        catalog::{recording_id_for_rel_path, RecordingIndex},
        search::RipgrepSearchConfig,
        web::{config::SingleUser, state::Session},
    };

    fn temp_root(name: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "ttyrecall-web-recordings-{name}-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        root
    }

    fn write_file(path: &Path, content: &[u8]) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, content).unwrap();
    }

    fn state_with_recordings(root: PathBuf, uid: u32, paths: &[PathBuf]) -> Arc<AppState> {
        let mut index = RecordingIndex::default();
        for path in paths {
            index.upsert_path(&root, path);
        }
        Arc::new(AppState {
            storage_root: root,
            recording_index: Arc::new(StdRwLock::new(index)),
            pam_service: "login".to_string(),
            sessions: RwLock::new(HashMap::from([(
                "active".to_string(),
                Session {
                    username: "alice".to_string(),
                    uid,
                    last_seen: Instant::now(),
                },
            )])),
            session_ttl: Duration::from_secs(60),
            single_user: Some(SingleUser {
                uid,
                username: "alice".to_string(),
            }),
            frontend_root: PathBuf::from("/tmp/frontend"),
            single_user_token: Some("token".to_string()),
            cast_cache: tokio::sync::Mutex::new(super::super::state::CastCache::default()),
            search_enabled: false,
            search: RipgrepSearchConfig {
                ripgrep_path: "rg".to_string(),
                max_results: 50,
            },
        })
    }

    fn auth_headers() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(header::COOKIE, HeaderValue::from_static("session=active"));
        headers
    }

    fn id(rel: &str) -> String {
        recording_id_for_rel_path(Path::new(rel))
    }

    async fn json_body(response: axum::response::Response) -> Value {
        serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap()).unwrap()
    }

    #[tokio::test]
    async fn list_recordings_requires_auth_and_clamps_limit() {
        let root = temp_root("list");
        let first = root.join("1000/2026/06/06/bash-pty2-10:30.cast");
        let second = root.join("1000/2026/06/05/zsh-pty1-09:15.cast");
        write_file(&first, br#"{"version":2}"#);
        write_file(&second, br#"{"version":2}"#);
        let state = state_with_recordings(root.clone(), 1000, &[first, second]);

        let unauthenticated = list_recordings(
            State(state.clone()),
            HeaderMap::new(),
            Query(RecordingsQuery {
                offset: None,
                limit: None,
                date: None,
            }),
        )
        .await
        .into_response();
        assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);

        let response = list_recordings(
            State(state),
            auth_headers(),
            Query(RecordingsQuery {
                offset: Some(0),
                limit: Some(1000),
                date: Some("2026-06-06".to_string()),
            }),
        )
        .await
        .into_response();

        assert_eq!(response.status(), StatusCode::OK);
        let body = json_body(response).await;
        assert_eq!(body["limit"], MAX_RECORDINGS_LIMIT);
        assert_eq!(body["total"], 1);
        assert_eq!(body["recordings"][0]["display"], "2026-06-06 10:30");

        let _ = fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn delete_recordings_removes_only_authorized_existing_ids() {
        let root = temp_root("delete");
        let own = root.join("1000/2026/06/06/bash-pty2-10:30.cast");
        let other = root.join("1001/2026/06/06/fish-pty3-10:31.cast");
        write_file(&own, br#"{"version":2}"#);
        write_file(&other, br#"{"version":2}"#);
        let state = state_with_recordings(root.clone(), 1000, &[own.clone(), other.clone()]);

        let response = delete_recordings(
            State(state.clone()),
            auth_headers(),
            Json(DeleteRequest {
                ids: vec![
                    id("2026/06/06/bash-pty2-10:30.cast"),
                    id("../1001/2026/06/06/fish-pty3-10:31.cast"),
                    id("2026/06/06/missing.cast"),
                ],
            }),
        )
        .await
        .into_response();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(json_body(response).await["deleted"], 1);
        assert!(!own.exists());
        assert!(other.exists());
        assert!(state
            .recording_index
            .read()
            .unwrap()
            .list_for_user(1000)
            .is_empty());

        let _ = fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn cast_recording_reads_plain_and_rejects_missing_files() {
        let root = temp_root("cast");
        let recording = root.join("1000/2026/06/06/bash-pty2-10:30.cast");
        write_file(
            &recording,
            br#"{"version":2}
[0.0,"o","hello"]
"#,
        );
        let state = state_with_recordings(root.clone(), 1000, std::slice::from_ref(&recording));

        let response = cast_recording(
            State(state.clone()),
            auth_headers(),
            AxumPath(id("2026/06/06/bash-pty2-10:30.cast")),
        )
        .await
        .into_response();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/json"
        );
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert!(std::str::from_utf8(&body).unwrap().contains("hello"));

        let missing = cast_recording(
            State(state),
            auth_headers(),
            AxumPath(id("2026/06/06/missing.cast")),
        )
        .await
        .into_response();
        assert_eq!(missing.status(), StatusCode::NOT_FOUND);

        let _ = fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn download_recording_decompresses_zstd_and_sets_filename() {
        let root = temp_root("download");
        let recording = root.join("1000/2026/06/06/bash-pty2-10:30.cast.zst");
        let compressed = zstd::stream::encode_all(
            br#"{"version":2}
[0.0,"o","hello"]
"#
            .as_slice(),
            0,
        )
        .unwrap();
        write_file(&recording, &compressed);
        let state = state_with_recordings(root.clone(), 1000, std::slice::from_ref(&recording));

        let response = download_recording(
            State(state),
            auth_headers(),
            AxumPath(id("2026/06/06/bash-pty2-10:30.cast.zst")),
        )
        .await
        .into_response();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CONTENT_DISPOSITION).unwrap(),
            "attachment; filename=\"bash-pty2-10:30.cast\""
        );
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert!(std::str::from_utf8(&body).unwrap().contains("hello"));

        let _ = fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn heatmap_returns_counts_for_authenticated_user() {
        let root = temp_root("heatmap");
        let first = root.join("1000/2026/06/06/bash-pty2-10:30.cast");
        let second = root.join("1000/2026/06/06/zsh-pty3-11:30.cast");
        write_file(&first, br#"{"version":2}"#);
        write_file(&second, br#"{"version":2}"#);
        let state = state_with_recordings(root.clone(), 1000, &[first, second]);

        let response = heatmap(State(state), auth_headers()).await.into_response();

        assert_eq!(response.status(), StatusCode::OK);
        let body = json_body(response).await;
        assert_eq!(body["counts"][0]["date"], "2026-06-06");
        assert_eq!(body["counts"][0]["count"], 2);

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn download_filename_strips_only_zstd_suffix() {
        assert_eq!(
            download_filename(Path::new("bash-pty2.cast.zst")),
            "bash-pty2.cast"
        );
        assert_eq!(
            download_filename(Path::new("bash-pty2.cast")),
            "bash-pty2.cast"
        );
        assert_eq!(download_filename(Path::new("")), "recording.cast");
    }
}
