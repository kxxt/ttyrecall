use std::{path::PathBuf, sync::Arc};

use axum::{
    extract::State,
    http::StatusCode,
    response::{Html, IntoResponse},
};

use super::state::AppState;

pub(super) async fn index(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    serve_html(state.frontend_root.join("index.html")).await
}

pub(super) async fn view(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    serve_html(state.frontend_root.join("view.html")).await
}

async fn serve_html(path: PathBuf) -> impl IntoResponse {
    match tokio::fs::read_to_string(&path).await {
        Ok(html) => Html(html).into_response(),
        Err(_) => (StatusCode::NOT_FOUND, "Not found").into_response(),
    }
}
