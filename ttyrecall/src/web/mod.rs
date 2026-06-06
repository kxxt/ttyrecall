use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::Arc,
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

#[derive(Debug, Serialize)]
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

    let state = Arc::new(AppState {
        storage_root: config.root.clone(),
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

    let recordings = list_recordings_for_user(&state.storage_root, session.uid);
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

    let counts = heatmap_for_user(&state.storage_root, session.uid);
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

fn list_recordings_for_user(storage_root: &Path, uid: u32) -> Vec<RecordingInfo> {
    let user_root = storage_root.join(uid.to_string());
    let mut files = Vec::new();
    collect_files(&user_root, &mut files);

    let mut recordings = Vec::new();
    for path in files {
        if let Some(info) = recording_info(&user_root, &path) {
            recordings.push(info);
        }
    }
    recordings.sort_by(|a, b| b.display.cmp(&a.display));
    recordings
}

fn collect_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let metadata = match entry.metadata() {
            Ok(metadata) => metadata,
            Err(_) => continue,
        };
        if metadata.is_dir() {
            collect_files(&path, out);
        } else if metadata.is_file() {
            out.push(path);
        }
    }
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

fn heatmap_for_user(storage_root: &Path, uid: u32) -> Vec<HeatmapDay> {
    let user_root = storage_root.join(uid.to_string());
    let mut files = Vec::new();
    collect_files(&user_root, &mut files);

    let mut counts: HashMap<NaiveDate, usize> = HashMap::new();
    for path in files {
        let file_name = match path.file_name().and_then(|name| name.to_str()) {
            Some(name) => name,
            None => continue,
        };
        if !is_recording_file_name(file_name) {
            continue;
        }
        if let Some(date) = date_from_path(&user_root, &path) {
            *counts.entry(date).or_insert(0) += 1;
        }
    }

    let mut days: Vec<_> = counts
        .into_iter()
        .map(|(date, count)| HeatmapDay {
            date: date.format("%Y-%m-%d").to_string(),
            count,
        })
        .collect();
    days.sort_by(|a, b| a.date.cmp(&b.date));
    days
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
