use std::{
    path::PathBuf,
    sync::{Arc, RwLock as StdRwLock},
};

use axum::{
    routing::{get, post},
    Router,
};
use tower_http::services::ServeDir;

use crate::catalog::RecordingIndex;

mod config;
mod pages;
mod pam;
mod recordings;
mod session;
mod state;
mod watcher;

pub use config::{current_user_mode, WebMode};

pub(crate) struct BrowseContext {
    pub(crate) storage_root: PathBuf,
    pub(crate) uid: u32,
    pub(crate) username: String,
    pub(crate) recording_index: Arc<StdRwLock<RecordingIndex>>,
}

pub(crate) fn browse_context(config_path: Option<PathBuf>) -> color_eyre::Result<BrowseContext> {
    let mode = current_user_mode()?;
    let config = config::load_config(&mode, config_path)?;
    let single_user = config::resolve_single_user(&mode, &config)?;
    let Some(single_user) = single_user else {
        unreachable!("current_user_mode always resolves to a single-user context");
    };

    let recording_index = Arc::new(StdRwLock::new(RecordingIndex::default()));
    watcher::spawn_recording_watcher(
        config.root.clone(),
        recording_watch_roots(&config.root, single_user.uid),
        recording_index.clone(),
    )?;

    Ok(BrowseContext {
        storage_root: config.root,
        uid: single_user.uid,
        username: single_user.username,
        recording_index,
    })
}

pub async fn run(
    mode: WebMode,
    config_path: Option<PathBuf>,
    open: bool,
) -> color_eyre::Result<()> {
    let config = config::load_config(&mode, config_path)?;
    let single_user = config::resolve_single_user(&mode, &config)?;
    let single_user_token = config::prepare_single_user_token(&mode, &config);

    let recording_index = Arc::new(StdRwLock::new(RecordingIndex::default()));
    watcher::spawn_recording_watcher(
        config.root.clone(),
        recording_scan_roots(&config.root, single_user.as_ref()),
        recording_index.clone(),
    )?;

    let state = Arc::new(state::AppState::new(
        config.root.clone(),
        recording_index,
        config.pam_service.clone(),
        config.session_ttl,
        single_user,
        config.frontend_root.clone(),
        single_user_token,
    ));

    let app = Router::new()
        .route("/", get(pages::index))
        .route("/view/:id", get(pages::view))
        .nest_service(
            "/_astro",
            ServeDir::new(config.frontend_root.join("_astro")),
        )
        .route("/api/login", post(session::login))
        .route("/api/token-login", post(session::token_login))
        .route("/api/logout", post(session::logout))
        .route("/api/me", get(session::me))
        .route("/api/recordings", get(recordings::list_recordings))
        .route(
            "/api/recordings/delete",
            post(recordings::delete_recordings),
        )
        .route(
            "/api/recordings/:id/download",
            get(recordings::download_recording),
        )
        .route("/api/recordings/:id/cast", get(recordings::cast_recording))
        .route("/api/heatmap", get(recordings::heatmap))
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

fn recording_scan_roots(
    storage_root: &std::path::Path,
    single_user: Option<&config::SingleUser>,
) -> Vec<PathBuf> {
    match single_user {
        Some(single_user) => recording_watch_roots(storage_root, single_user.uid),
        None => vec![storage_root.to_path_buf()],
    }
}

fn recording_watch_roots(storage_root: &std::path::Path, uid: u32) -> Vec<PathBuf> {
    vec![storage_root.join(uid.to_string())]
}
