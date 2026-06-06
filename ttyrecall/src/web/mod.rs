use std::{
    collections::HashMap,
    ffi::OsString,
    path::{Path, PathBuf},
    sync::{Arc, RwLock as StdRwLock},
    time::{Duration, Instant, SystemTime},
};

use axum::{
    body::Body,
    extract::{Path as AxumPath, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::{Local, NaiveDate};
use constant_time_eq::constant_time_eq;
use inotify::{EventMask, Inotify, WatchDescriptor, WatchMask};
use log::{error, warn};
use nix::unistd::{Uid, User};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tokio_util::io::ReaderStream;
use tower_http::services::ServeDir;

mod pam;

#[derive(Clone, Debug)]
pub enum WebMode {
    Service,
    SingleUser { uid: u32, username: String },
}

#[derive(Debug, Deserialize, Default)]
struct WebConfigFile {
    bind: Option<String>,
    root: Option<String>,
    pam_service: Option<String>,
    session_ttl_minutes: Option<u64>,
    frontend_root: Option<String>,
    single_user_token: Option<String>,
    single_user_uid: Option<u32>,
    single_user_username: Option<String>,
}

#[derive(Debug, Clone)]
struct WebConfig {
    bind: String,
    root: PathBuf,
    pam_service: String,
    session_ttl: Duration,
    frontend_root: PathBuf,
    single_user_token: Option<String>,
    single_user_uid: Option<u32>,
    single_user_username: Option<String>,
}

#[derive(Debug, Clone)]
struct SingleUser {
    uid: u32,
    username: String,
}

#[derive(Debug)]
struct Session {
    username: String,
    uid: u32,
    last_seen: Instant,
}

#[derive(Debug)]
struct AppState {
    storage_root: PathBuf,
    recording_index: Arc<StdRwLock<RecordingIndex>>,
    pam_service: String,
    sessions: RwLock<HashMap<String, Session>>,
    session_ttl: Duration,
    single_user: Option<SingleUser>,
    frontend_root: PathBuf,
    single_user_token: Option<String>,
    cast_cache: tokio::sync::Mutex<CastCache>,
}

#[derive(Debug, Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
}

#[derive(Debug, Deserialize)]
struct TokenLoginRequest {
    token: String,
}

#[derive(Debug, Serialize)]
struct MeResponse {
    username: String,
    uid: u32,
}

#[derive(Debug, Serialize)]
struct RecordingsResponse {
    recordings: Vec<RecordingInfo>,
}

#[derive(Debug, Clone, Serialize)]
struct RecordingInfo {
    id: String,
    name: String,
    display: String,
    date: String,
    size: u64,
    compressed: bool,
}

#[derive(Debug, Deserialize)]
struct DeleteRequest {
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

#[derive(Debug, Serialize)]
struct HeatmapDay {
    date: String,
    count: usize,
}

const CAST_CACHE_MAX_ENTRIES: usize = 64;

#[derive(Debug)]
struct CastCacheEntry {
    mtime: SystemTime,
    bytes: Vec<u8>,
    last_access: Instant,
}

#[derive(Debug, Default)]
struct CastCache {
    entries: HashMap<PathBuf, CastCacheEntry>,
}

#[derive(Debug, Default)]
struct RecordingIndex {
    by_user: HashMap<u32, HashMap<PathBuf, RecordingInfo>>,
}

impl RecordingIndex {
    fn clear(&mut self) {
        self.by_user.clear();
    }

    fn upsert_path(&mut self, storage_root: &Path, path: &Path) {
        let Some((uid, rel_path, info)) = indexed_recording(storage_root, path) else {
            return;
        };

        self.by_user.entry(uid).or_default().insert(rel_path, info);
    }

    fn remove_path(&mut self, storage_root: &Path, path: &Path) {
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

    fn remove_tree(&mut self, storage_root: &Path, path: &Path) {
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

#[derive(Debug)]
struct RecordingWatcher {
    storage_root: PathBuf,
    index: Arc<StdRwLock<RecordingIndex>>,
    inotify: Inotify,
    watch_paths: HashMap<PathBuf, WatchDescriptor>,
    watched_dirs: HashMap<WatchDescriptor, PathBuf>,
}

impl RecordingWatcher {
    fn new(storage_root: PathBuf, index: Arc<StdRwLock<RecordingIndex>>) -> std::io::Result<Self> {
        Ok(Self {
            storage_root,
            index,
            inotify: Inotify::init()?,
            watch_paths: HashMap::new(),
            watched_dirs: HashMap::new(),
        })
    }

    fn rebuild(&mut self) -> std::io::Result<()> {
        self.inotify = Inotify::init()?;
        self.watch_paths.clear();
        self.watched_dirs.clear();
        self.index.write().unwrap().clear();
        self.scan_dir_recursive(self.storage_root.clone())
    }

    fn run(&mut self) -> std::io::Result<()> {
        let mut buffer = [0u8; 64 * 1024];
        loop {
            let events = self.inotify.read_events_blocking(&mut buffer)?;
            let events: Vec<_> = events.map(|event| event.to_owned()).collect();
            for event in events {
                self.handle_event(event)?;
            }
        }
    }

    fn handle_event(&mut self, event: inotify::Event<OsString>) -> std::io::Result<()> {
        if event.mask.contains(EventMask::Q_OVERFLOW) {
            warn!("recording watcher queue overflowed; rebuilding index");
            return self.rebuild();
        }

        if event.mask.contains(EventMask::IGNORED) {
            if let Some(path) = self.watched_dirs.remove(&event.wd) {
                self.watch_paths.remove(&path);
            }
            return Ok(());
        }

        if event.mask.contains(EventMask::UNMOUNT) {
            warn!("recording storage was unmounted; rebuilding index");
            return self.rebuild();
        }

        let Some(parent) = self.watched_dirs.get(&event.wd).cloned() else {
            return Ok(());
        };

        if event.mask.contains(EventMask::MOVE_SELF) {
            return self.rebuild();
        }

        let Some(name) = event.name else {
            return Ok(());
        };
        let path = parent.join(name);

        if event.mask.contains(EventMask::ISDIR) {
            return self.handle_dir_event(path, event.mask);
        }

        self.handle_file_event(path, event.mask);
        Ok(())
    }

    fn handle_dir_event(&mut self, path: PathBuf, mask: EventMask) -> std::io::Result<()> {
        if mask.intersects(EventMask::MOVED_FROM | EventMask::MOVED_TO) {
            return self.rebuild();
        }

        if mask.contains(EventMask::CREATE) {
            return match self.scan_dir_recursive(path) {
                Ok(()) => Ok(()),
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(err) => Err(err),
            };
        }

        if mask.intersects(EventMask::DELETE | EventMask::DELETE_SELF) {
            self.index
                .write()
                .unwrap()
                .remove_tree(&self.storage_root, &path);
        }

        Ok(())
    }

    fn handle_file_event(&mut self, path: PathBuf, mask: EventMask) {
        if mask.intersects(
            EventMask::CREATE | EventMask::MOVED_TO | EventMask::CLOSE_WRITE | EventMask::ATTRIB,
        ) {
            self.index
                .write()
                .unwrap()
                .upsert_path(&self.storage_root, &path);
        }

        if mask.intersects(EventMask::DELETE | EventMask::MOVED_FROM) {
            self.index
                .write()
                .unwrap()
                .remove_path(&self.storage_root, &path);
        }
    }

    fn scan_dir_recursive(&mut self, dir: PathBuf) -> std::io::Result<()> {
        self.watch_dir(&dir)?;

        let entries = match std::fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(err) => {
                warn!(
                    "failed to read recording directory {}: {err}",
                    dir.display()
                );
                return Ok(());
            }
        };

        for entry in entries {
            let entry = match entry {
                Ok(entry) => entry,
                Err(err) => {
                    warn!("failed to read recording directory entry: {err}");
                    continue;
                }
            };
            let path = entry.path();
            let file_type = match entry.file_type() {
                Ok(file_type) => file_type,
                Err(err) => {
                    warn!(
                        "failed to read recording entry type {}: {err}",
                        path.display()
                    );
                    continue;
                }
            };

            if file_type.is_dir() {
                self.scan_dir_recursive(path)?;
            } else if file_type.is_file() {
                self.index
                    .write()
                    .unwrap()
                    .upsert_path(&self.storage_root, &path);
            }
        }

        Ok(())
    }

    fn watch_dir(&mut self, dir: &Path) -> std::io::Result<()> {
        if self.watch_paths.contains_key(dir) {
            return Ok(());
        }

        let watch = self.inotify.watches().add(
            dir,
            WatchMask::CREATE
                | WatchMask::DELETE
                | WatchMask::MOVED_FROM
                | WatchMask::MOVED_TO
                | WatchMask::CLOSE_WRITE
                | WatchMask::ATTRIB
                | WatchMask::DELETE_SELF
                | WatchMask::MOVE_SELF
                | WatchMask::ONLYDIR,
        )?;

        self.watch_paths.insert(dir.to_path_buf(), watch.clone());
        self.watched_dirs.insert(watch, dir.to_path_buf());
        Ok(())
    }
}

impl CastCache {
    fn get(&mut self, path: &Path, mtime: SystemTime) -> Option<Vec<u8>> {
        if let Some(entry) = self.entries.get_mut(path) {
            if entry.mtime == mtime {
                entry.last_access = Instant::now();
                return Some(entry.bytes.clone());
            }
        }
        self.entries.remove(path);
        None
    }

    fn insert(&mut self, path: PathBuf, mtime: SystemTime, bytes: Vec<u8>) {
        self.entries.insert(
            path,
            CastCacheEntry {
                mtime,
                bytes,
                last_access: Instant::now(),
            },
        );
        if self.entries.len() > CAST_CACHE_MAX_ENTRIES {
            self.evict_oldest();
        }
    }

    fn evict_oldest(&mut self) {
        if let Some((oldest, _)) = self
            .entries
            .iter()
            .min_by_key(|(_, entry)| entry.last_access)
            .map(|(path, entry)| (path.clone(), entry.last_access))
        {
            self.entries.remove(&oldest);
        }
    }
}

pub async fn run(
    mode: WebMode,
    config_path: Option<PathBuf>,
    open: bool,
) -> color_eyre::Result<()> {
    let config = load_config(&mode, config_path)?;
    let mut single_user = match &mode {
        WebMode::Service => None,
        WebMode::SingleUser { uid, username } => Some(SingleUser {
            uid: *uid,
            username: username.clone(),
        }),
    };
    if let Some(single_user) = single_user.as_mut() {
        if let Some(username) = config.single_user_username.clone() {
            single_user.username = username;
        }
        if let Some(uid) = config.single_user_uid {
            single_user.uid = uid;
        }
        if config.single_user_uid.is_some() && config.single_user_username.is_none() {
            if let Ok(Some(user)) = User::from_uid(Uid::from_raw(single_user.uid)) {
                single_user.username = user.name;
            }
        }
        if config.single_user_username.is_some() && config.single_user_uid.is_none() {
            if let Ok(Some(user)) = User::from_name(&single_user.username) {
                single_user.uid = user.uid.as_raw();
            }
        }
    }
    let single_user_token = match &mode {
        WebMode::Service => None,
        WebMode::SingleUser { .. } => {
            let token = config
                .single_user_token
                .clone()
                .unwrap_or_else(new_session_token);
            let display_bind = display_bind(&config.bind);
            println!("Single user token: {token}");
            println!(
                "Single user login URL: http://{}/?token={}",
                display_bind, token
            );
            Some(token)
        }
    };
    let recording_index = Arc::new(StdRwLock::new(RecordingIndex::default()));
    spawn_recording_watcher(config.root.clone(), recording_index.clone())?;

    let state = Arc::new(AppState {
        storage_root: config.root.clone(),
        recording_index,
        pam_service: config.pam_service.clone(),
        sessions: RwLock::new(HashMap::new()),
        session_ttl: config.session_ttl,
        single_user,
        frontend_root: config.frontend_root.clone(),
        single_user_token,
        cast_cache: tokio::sync::Mutex::new(CastCache::default()),
    });

    let app = Router::new()
        .route("/", get(index))
        .route("/view/:id", get(view))
        .nest_service(
            "/_astro",
            ServeDir::new(config.frontend_root.join("_astro")),
        )
        .route("/api/login", post(login))
        .route("/api/token-login", post(token_login))
        .route("/api/logout", post(logout))
        .route("/api/me", get(me))
        .route("/api/recordings", get(list_recordings))
        .route("/api/recordings/delete", post(delete_recordings))
        .route("/api/recordings/:id/download", get(download_recording))
        .route("/api/recordings/:id/cast", get(cast_recording))
        .route("/api/heatmap", get(heatmap))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&config.bind).await?;
    if open {
        println!("Web UI available at http://{}", config.bind);
    } else {
        println!("Web UI listening on http://{}", config.bind);
    }
    axum::serve(listener, app).await?;
    Ok(())
}

fn load_config(mode: &WebMode, path: Option<PathBuf>) -> color_eyre::Result<WebConfig> {
    let default_bind = "127.0.0.1:8450".to_string();
    let default_storage = "/var/lib/ttyrecall".to_string();
    let default_pam = "login".to_string();
    let default_ttl = Duration::from_secs(60 * 60);

    let path = match path {
        Some(path) => path,
        None => match mode {
            WebMode::Service => PathBuf::from("/etc/ttyrecall/web.toml"),
            WebMode::SingleUser { .. } => default_user_config_path(),
        },
    };

    let file_config = if path.exists() {
        let content = std::fs::read_to_string(&path)?;
        toml::from_str::<WebConfigFile>(&content)?
    } else {
        WebConfigFile::default()
    };

    Ok(WebConfig {
        bind: file_config.bind.unwrap_or(default_bind),
        root: PathBuf::from(file_config.root.unwrap_or(default_storage)),
        pam_service: file_config.pam_service.unwrap_or(default_pam),
        session_ttl: Duration::from_secs(
            file_config
                .session_ttl_minutes
                .unwrap_or(default_ttl.as_secs() / 60)
                * 60,
        ),
        frontend_root: file_config
            .frontend_root
            .map(PathBuf::from)
            .unwrap_or_else(default_frontend_root),
        single_user_token: file_config.single_user_token,
        single_user_uid: file_config.single_user_uid,
        single_user_username: file_config.single_user_username,
    })
}

fn default_user_config_path() -> PathBuf {
    if let Some(path) = std::env::var_os("XDG_CONFIG_HOME") {
        return PathBuf::from(path).join("ttyrecall/web.toml");
    }
    if let Some(path) = std::env::var_os("HOME") {
        return PathBuf::from(path).join(".config/ttyrecall/web.toml");
    }
    PathBuf::from("./web.toml")
}

fn default_frontend_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("frontend")
        .join("dist")
}

fn display_bind(bind: &str) -> String {
    if let Some(port) = bind.rsplit_once(':').map(|(_, port)| port) {
        if bind.starts_with("0.0.0.0:") || bind.starts_with("[::]:") {
            return format!("127.0.0.1:{port}");
        }
    }
    bind.to_string()
}

async fn index(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    serve_html(state.frontend_root.join("index.html")).await
}

async fn view(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    serve_html(state.frontend_root.join("view.html")).await
}

async fn serve_html(path: PathBuf) -> impl IntoResponse {
    match tokio::fs::read_to_string(&path).await {
        Ok(html) => Html(html).into_response(),
        Err(_) => (StatusCode::NOT_FOUND, "Not found").into_response(),
    }
}

async fn login(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<LoginRequest>,
) -> impl IntoResponse {
    if state.single_user.is_some() {
        return (StatusCode::FORBIDDEN, "Use token login").into_response();
    }
    if payload.username.trim().is_empty() || payload.password.is_empty() {
        return (StatusCode::BAD_REQUEST, "Missing credentials").into_response();
    }

    match pam::authenticate(&state.pam_service, &payload.username, &payload.password) {
        Ok(()) => {}
        Err(_) => return (StatusCode::UNAUTHORIZED, "Authentication failed").into_response(),
    }

    let user =
        match User::from_name(&payload.username).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR) {
            Ok(Some(user)) => user,
            _ => return (StatusCode::UNAUTHORIZED, "Unknown user").into_response(),
        };

    create_session(&state, payload.username, user.uid.as_raw()).await
}

async fn token_login(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<TokenLoginRequest>,
) -> impl IntoResponse {
    let single_user = match state.single_user.as_ref() {
        Some(single_user) => single_user,
        None => return (StatusCode::FORBIDDEN, "Not available").into_response(),
    };
    let token = match state.single_user_token.as_deref() {
        Some(token) => token,
        None => return (StatusCode::FORBIDDEN, "Not available").into_response(),
    };
    if !constant_time_eq(payload.token.as_bytes(), token.as_bytes()) {
        return (StatusCode::UNAUTHORIZED, "Invalid token").into_response();
    }

    create_session(&state, single_user.username.clone(), single_user.uid).await
}

async fn logout(State(state): State<Arc<AppState>>, headers: HeaderMap) -> impl IntoResponse {
    if let Some(token) = session_token(&headers) {
        state.sessions.write().await.remove(&token);
    }
    let mut response_headers = HeaderMap::new();
    response_headers.insert(
        header::SET_COOKIE,
        HeaderValue::from_static("session=; HttpOnly; Max-Age=0; Path=/"),
    );
    (StatusCode::OK, response_headers).into_response()
}

async fn me(State(state): State<Arc<AppState>>, headers: HeaderMap) -> impl IntoResponse {
    match require_session(&state, &headers).await {
        Ok(session) => Json(MeResponse {
            username: session.username,
            uid: session.uid,
        })
        .into_response(),
        Err(status) => (status, "Not authenticated").into_response(),
    }
}

async fn create_session(state: &AppState, username: String, uid: u32) -> Response {
    let token = new_session_token();
    let session = Session {
        username: username.clone(),
        uid,
        last_seen: Instant::now(),
    };
    state.sessions.write().await.insert(token.clone(), session);

    let cookie = format!("session={}; HttpOnly; SameSite=Strict; Path=/", token);
    let mut headers = HeaderMap::new();
    headers.insert(header::SET_COOKIE, HeaderValue::from_str(&cookie).unwrap());

    (StatusCode::OK, headers, Json(MeResponse { username, uid })).into_response()
}

async fn list_recordings(
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

async fn delete_recordings(
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

async fn download_recording(
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

async fn cast_recording(
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

async fn heatmap(State(state): State<Arc<AppState>>, headers: HeaderMap) -> impl IntoResponse {
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

fn new_session_token() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn spawn_recording_watcher(
    storage_root: PathBuf,
    index: Arc<StdRwLock<RecordingIndex>>,
) -> color_eyre::Result<()> {
    let mut watcher = RecordingWatcher::new(storage_root, index)?;
    watcher.rebuild()?;
    std::thread::Builder::new()
        .name("ttyrecall-inotify".to_string())
        .spawn(move || {
            if let Err(err) = watcher.run() {
                error!("recording watcher stopped: {err}");
            }
        })?;
    Ok(())
}

fn session_token(headers: &HeaderMap) -> Option<String> {
    let cookie = headers.get(header::COOKIE)?.to_str().ok()?;
    for part in cookie.split(';') {
        let part = part.trim();
        if let Some(value) = part.strip_prefix("session=") {
            return Some(value.to_string());
        }
    }
    None
}

struct SessionInfo {
    username: String,
    uid: u32,
}

async fn require_session(state: &AppState, headers: &HeaderMap) -> Result<SessionInfo, StatusCode> {
    let token = session_token(headers).ok_or(StatusCode::UNAUTHORIZED)?;
    let mut sessions = state.sessions.write().await;
    if let Some(session) = sessions.get_mut(&token) {
        if session.last_seen.elapsed() > state.session_ttl {
            sessions.remove(&token);
            return Err(StatusCode::UNAUTHORIZED);
        }
        session.last_seen = Instant::now();
        return Ok(SessionInfo {
            username: session.username.clone(),
            uid: session.uid,
        });
    }
    Err(StatusCode::UNAUTHORIZED)
}

fn list_recordings_for_user(
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

fn indexed_recording(storage_root: &Path, path: &Path) -> Option<(u32, PathBuf, RecordingInfo)> {
    let (uid, rel_path) = storage_rel_path(storage_root, path)?;
    let user_root = storage_root.join(uid.to_string());
    let info = recording_info(&user_root, path)?;
    Some((uid, rel_path, info))
}

fn storage_rel_path(storage_root: &Path, path: &Path) -> Option<(u32, PathBuf)> {
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

fn resolve_recording_path(storage_root: &Path, uid: u32, id: &str) -> Option<PathBuf> {
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

fn read_cast_bytes(path: &Path) -> Result<Vec<u8>, std::io::Error> {
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

fn heatmap_for_user(index: &Arc<StdRwLock<RecordingIndex>>, uid: u32) -> Vec<HeatmapDay> {
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

pub fn current_user_mode() -> color_eyre::Result<WebMode> {
    let mut uid = Uid::current().as_raw();
    let mut username = User::from_uid(Uid::current())?
        .map(|user| user.name)
        .unwrap_or_else(|| uid.to_string());

    if uid == 0 {
        if let Ok(sudo_uid) = std::env::var("SUDO_UID") {
            if let Ok(parsed) = sudo_uid.parse::<u32>() {
                uid = parsed;
            }
        }
        if let Ok(sudo_user) = std::env::var("SUDO_USER") {
            username = sudo_user;
        }
        if username == "root" && uid != 0 {
            if let Ok(Some(user)) = User::from_uid(Uid::from_raw(uid)) {
                username = user.name;
            }
        }
    }
    Ok(WebMode::SingleUser { uid, username })
}
