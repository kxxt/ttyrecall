use std::{
    path::PathBuf,
    sync::{Arc, RwLock as StdRwLock},
};

use axum::{
    routing::{get, post},
    Router,
};
use tower_http::services::ServeDir;

mod config;
mod pages;
mod pam;
mod recordings;
mod session;
mod state;
mod watcher;

pub use config::{current_user_mode, WebMode};

pub async fn run(
    mode: WebMode,
    config_path: Option<PathBuf>,
    open: bool,
) -> color_eyre::Result<()> {
    let config = config::load_config(&mode, config_path)?;
    let single_user = config::resolve_single_user(&mode, &config)?;
    let single_user_token = config::prepare_single_user_token(&mode, &config);

    let recording_index = Arc::new(StdRwLock::new(recordings::RecordingIndex::default()));
    watcher::spawn_recording_watcher(config.root.clone(), recording_index.clone())?;

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
