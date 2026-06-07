use std::sync::Arc;

use axum::{
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use serde::{Deserialize, Serialize};

use crate::search::{search_recordings, SearchResult};

use super::{session::require_session, state::AppState};

#[derive(Debug, Deserialize)]
pub(super) struct SearchQuery {
    q: String,
}

#[derive(Debug, Serialize)]
struct SearchResponse {
    results: Vec<SearchResult>,
}

pub(super) async fn search(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<SearchQuery>,
) -> impl IntoResponse {
    let session = match require_session(&state, &headers).await {
        Ok(session) => session,
        Err(status) => return (status, "Not authenticated").into_response(),
    };

    if !state.search_enabled {
        return (StatusCode::NOT_FOUND, "Search is disabled").into_response();
    }

    let storage_root = state.storage_root.clone();
    let search_config = state.search.clone();
    let query = query.q;
    let result = tokio::task::spawn_blocking(move || {
        search_recordings(&storage_root, session.uid, &query, &search_config)
    })
    .await;

    match result {
        Ok(Ok(results)) => Json(SearchResponse { results }).into_response(),
        Ok(Err(err)) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Search failed: {err}"),
        )
            .into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Search task failed: {err}"),
        )
            .into_response(),
    }
}
